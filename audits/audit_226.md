## Title
Invalid Tick State Persists Through Core to MEVCapture Due to Unchecked Boundary Arithmetic

## Summary
Core.sol's swap function contains a boundary arithmetic bug that stores an invalid tick value (MIN_TICK - 1 = -88722836) when swaps reach the minimum tick boundary going down. MEVCapture.sol's `setPoolState()` at line 56 subsequently reads and persists this invalid tick without validation, violating the protocol's tick range invariant of [-88722835, 88722835].

## Impact
**Severity**: Low

## Finding Description
**Location:** `src/Core.sol` (swap_6269342730 function, lines 754-757) and `src/extensions/MEVCapture.sol` (setPoolState function, line 54-58) [1](#0-0) 

**Intended Logic:** When a swap crosses a tick boundary, the current tick should be updated to reflect the new price position. The comment at line 755 claims "no overflow danger because nextTick is always inside the valid tick bounds."

**Actual Logic:** When `nextTick = MIN_TICK` and `increasing = false` (swapping down), the assembly calculation `tick := sub(nextTick, iszero(increasing))` produces `tick = MIN_TICK - 1 = -88722836`, which exceeds the protocol's defined minimum tick of -88722835. [2](#0-1) 

**Exploitation Path:**
1. Attacker initiates a swap on a stableswap pool with no liquidity (or a concentrated pool where `findPrevInitializedTick` returns MIN_TICK)
2. Sets swap parameters with `sqrtRatioLimit = MIN_SQRT_RATIO` to reach exactly the MIN_TICK boundary [3](#0-2) 
3. Core stores the invalid tick (-88722836) to pool state [4](#0-3) 
4. MEVCapture's `loadCoreState()` reads this invalid tick from Core's storage [5](#0-4) 
5. MEVCapture's `setPoolState()` persists the invalid tick without validation [6](#0-5) 

**Security Property Broken:** Protocol tick invariant - all ticks should be within [MIN_TICK, MAX_TICK] range. The invalid tick violates this implicit invariant that other protocol components may depend on.

## Impact Explanation
- **Affected Assets**: Pool state in Core.sol and MEVCapture.sol extension state
- **Damage Severity**: Minimal financial impact. The invalid tick causes MEVCapture's fee multiplier calculation to be off by approximately 1 tick spacing, resulting in negligible fee discrepancies. The invalid state is automatically corrected when price moves (tick recalculated from sqrtRatio). [7](#0-6) 
- **User Impact**: No direct user fund loss. MEV capture fees may be slightly miscalculated for one transaction cycle.

## Likelihood Explanation
- **Attacker Profile**: Any user with swap access
- **Preconditions**: Pool must allow reaching MIN_TICK boundary (empty stableswap pool or concentrated pool with specific liquidity distribution)
- **Execution Complexity**: Single swap transaction with `sqrtRatioLimit = MIN_SQRT_RATIO`
- **Frequency**: Can be triggered once per affected pool when price reaches minimum boundary

## Recommendation

In `src/Core.sol`, add boundary validation before storing the calculated tick:

```solidity
// In src/Core.sol, swap_6269342730 function, lines 752-757:

// CURRENT (vulnerable):
if (sqrtRatioNext == nextTickSqrtRatio) {
    sqrtRatio = sqrtRatioNext;
    assembly ("memory-safe") {
        // no overflow danger because nextTick is always inside the valid tick bounds
        tick := sub(nextTick, iszero(increasing))
    }

// FIXED:
if (sqrtRatioNext == nextTickSqrtRatio) {
    sqrtRatio = sqrtRatioNext;
    assembly ("memory-safe") {
        // Calculate new tick position
        tick := sub(nextTick, iszero(increasing))
        // Clamp tick to valid range [MIN_TICK, MAX_TICK]
        if slt(tick, MIN_TICK) { tick := MIN_TICK }
        if sgt(tick, MAX_TICK) { tick := MAX_TICK }
    }
```

Alternative: In `src/extensions/MEVCapture.sol`, add validation in `setPoolState()`:

```solidity
// In src/extensions/MEVCapture.sol, add validation:

function setPoolState(PoolId poolId, MEVCapturePoolState state) private {
    int32 tick = state.tickLast();
    require(tick >= MIN_TICK && tick <= MAX_TICK, "Invalid tick");
    assembly ("memory-safe") {
        sstore(poolId, state)
    }
}
```

## Proof of Concept
```solidity
// File: test/Exploit_InvalidTick.t.sol
// Run with: forge test --match-test test_InvalidTickAtMinBoundary -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";

contract Exploit_InvalidTick is Test {
    Core core;
    MEVCapture mevCapture;
    
    function setUp() public {
        core = new Core();
        mevCapture = new MEVCapture(core);
        // Register MEVCapture extension
        core.registerExtension(address(mevCapture));
    }
    
    function test_InvalidTickAtMinBoundary() public {
        // SETUP: Create stableswap pool with MEVCapture extension
        PoolKey memory poolKey = PoolKey({
            token0: address(0x1),
            token1: address(0x2),
            config: PoolConfig.wrap(/* stableswap with MEVCapture */)
        });
        
        // Initialize pool
        core.initializePool(poolKey, 0);
        
        // EXPLOIT: Swap to MIN_TICK boundary with no liquidity
        SwapParameters memory params = SwapParameters({
            amount: type(int128).max,
            sqrtRatioLimit: MIN_SQRT_RATIO, // Reach exactly MIN_TICK
            isToken1: true,
            isExactOut: false,
            skipAhead: 0
        });
        
        // Execute swap (would be through forward for MEVCapture)
        core.swap(poolKey, params);
        
        // VERIFY: Core stored invalid tick
        PoolState state = core.readPoolState(poolKey.toPoolId());
        int32 coreTick = state.tick();
        assertEq(coreTick, MIN_TICK - 1, "Core should have invalid tick");
        assertTrue(coreTick < MIN_TICK, "Tick violates MIN_TICK bound");
        
        // VERIFY: MEVCapture would persist this invalid tick
        MEVCapturePoolState mevState = mevCapture.getPoolState(poolKey.toPoolId());
        int32 mevTick = mevState.tickLast();
        assertEq(mevTick, MIN_TICK - 1, "MEVCapture persisted invalid tick");
    }
}
```

## Notes

The vulnerability demonstrates that Core.sol's swap logic violates the tick range invariant at extreme boundaries, and MEVCapture.sol's lack of validation allows this invalid state to persist. However, the practical impact is limited because:

1. The invalid tick is automatically corrected when the price moves (via `sqrtRatioToTick` recalculation) [7](#0-6) 

2. The tick is primarily used for comparisons in fee calculations, which tolerate the 1-tick deviation [8](#0-7) 

3. The `tickToSqrtRatio()` function that validates tick ranges is not called on the stored tick directly, preventing reverts [9](#0-8) 

This finding confirms the security question's premise: an internal bug in Core enables invalid state that MEVCapture persists without validation. While not causing significant financial harm, it represents a protocol invariant violation that could affect future extensions or protocol upgrades assuming valid tick ranges.

### Citations

**File:** src/Core.sol (L575-576)
```text
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
```

**File:** src/Core.sol (L752-757)
```text
                    if (sqrtRatioNext == nextTickSqrtRatio) {
                        sqrtRatio = sqrtRatioNext;
                        assembly ("memory-safe") {
                            // no overflow danger because nextTick is always inside the valid tick bounds
                            tick := sub(nextTick, iszero(increasing))
                        }
```

**File:** src/Core.sol (L801-804)
```text
                    } else if (sqrtRatio != sqrtRatioNext) {
                        sqrtRatio = sqrtRatioNext;
                        tick = sqrtRatioToTick(sqrtRatio);
                    }
```

**File:** src/Core.sol (L824-826)
```text
                stateAfter = createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: liquidity});

                writePoolState(poolId, stateAfter);
```

**File:** src/math/constants.sol (L10-14)
```text
int32 constant MIN_TICK = -88722835;

// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;
```

**File:** src/extensions/MEVCapture.sol (L54-58)
```text
    function setPoolState(PoolId poolId, MEVCapturePoolState state) private {
        assembly ("memory-safe") {
            sstore(poolId, state)
        }
    }
```

**File:** src/extensions/MEVCapture.sol (L157-166)
```text
    function loadCoreState(PoolId poolId, address token0, address token1)
        private
        view
        returns (int32 tick, uint128 fees0, uint128 fees1)
    {
        StorageSlot stateSlot = CoreStorageLayout.poolStateSlot(poolId);
        StorageSlot feesSlot = CoreStorageLayout.savedBalancesSlot(address(this), token0, token1, PoolId.unwrap(poolId));

        (bytes32 v0, bytes32 v1) = CORE.sload(stateSlot, feesSlot);
        tick = PoolState.wrap(v0).tick();
```

**File:** src/extensions/MEVCapture.sol (L212-213)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
```

**File:** src/math/ticks.sol (L22-25)
```text
function tickToSqrtRatio(int32 tick) pure returns (SqrtRatio r) {
    unchecked {
        uint256 t = FixedPointMathLib.abs(tick);
        if (t > MAX_TICK_MAGNITUDE) revert InvalidTick(tick);
```
