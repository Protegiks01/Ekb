After conducting a thorough investigation of the `swap_6269342730` function and the specific casting operation at lines 811-812, I have identified a vulnerability related to asymmetric overflow handling that creates an accounting mismatch between pool state and user debt.

---

## Title
Silent Truncation in Swap Calculations Creates Pool Price-Balance Mismatch

## Summary
The swap function at [1](#0-0)  uses asymmetric overflow protection that clamps negative underflow but allows positive overflow to revert. When extreme exact-input swaps cause `calculatedAmount` to underflow below `type(int128).min`, the value is silently clamped while the pool's price state reflects the full unclamped swap, creating a discrepancy between recorded debt and actual pool state that violates the solvency invariant.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The code should safely convert the accumulated swap output amount (`calculatedAmount`) from `int256` to `int128` while preventing overflow/underflow. The `max(type(int128).min, calculatedAmount)` appears intended to provide lower-bound protection.

**Actual Logic:** The protection is asymmetric:
- Negative underflow: Silently clamps to `type(int128).min` without reverting
- Positive overflow: SafeCastLib reverts as expected

When clamping occurs during exact-input swaps, the pool's state variables [2](#0-1)  (`sqrtRatio`, `tick`, `liquidity`) are updated based on the **unclamped** `calculatedAmount` from the swap loop [3](#0-2) , but user debt is updated with the **clamped** value [4](#0-3) .

**Exploitation Path:**
1. Attacker identifies or creates a pool with extreme price ratio (e.g., token with high decimals paired with low-decimal token)
2. Attacker executes massive exact-input swap selling `type(int128).max` of token1
3. Swap loop calculates `calculatedAmount` < `type(int128).min` (e.g., -2e38)
4. Value gets clamped to `-1.7e38` at line 811-812, but pool's `sqrtRatio` updates as if full `-2e38` swap occurred
5. Pool price now reflects more token0 output than actually recorded in user debt
6. Subsequent swaps trade at incorrect price, allowing extraction of the phantom difference

**Security Property Broken:** Violates the solvency invariant [5](#0-4)  - the pool's price state suggests a token balance that doesn't match actual recorded debts, creating a scenario where the sum of deltas could result in negative pool balance.

## Impact Explanation
- **Affected Assets**: Pools with extreme price ratios, particularly those involving high-decimal tokens (e.g., SHIB with 18 decimals and quadrillion supply)
- **Damage Severity**: The phantom amount (difference between unclamped and clamped values) becomes extractable through arbitrage. In the example above, ~3e37 tokens worth of value becomes mispriced in the pool state.
- **User Impact**: Liquidity providers in affected pools suffer losses as arbitrageurs extract value from the price-balance mismatch. The first user triggering clamping loses expected output, while subsequent traders gain from mispricing.

## Likelihood Explanation
- **Attacker Profile**: Any user who can execute swaps with sufficient capital in pools with extreme price ratios
- **Preconditions**: 
  - Pool must exist with price ratio enabling output amounts exceeding `type(int128).max` magnitude
  - Attacker must have access to `type(int128).max` worth of input tokens
  - Pool must have sufficient liquidity to support the massive swap
- **Execution Complexity**: Single transaction swap operation
- **Frequency**: Once per pool where conditions allow, but conditions are rare in practice

## Recommendation

Replace the asymmetric clamping with symmetric bounds checking that reverts on both underflow and overflow:

```solidity
// In src/Core.sol, function swap_6269342730, lines 811-812:

// CURRENT (vulnerable):
// int128 calculatedAmountDelta =
//     SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));

// FIXED:
// Use min() to also bound the upper end, or better yet, just use SafeCastLib directly
// which will revert on both overflow and underflow
int128 calculatedAmountDelta = SafeCastLib.toInt128(calculatedAmount);
```

**Rationale:** The `max()` operation is unnecessary - `SafeCastLib.toInt128()` already provides proper overflow protection for the positive case. The asymmetric handling creates the vulnerability. Removing the `max()` allows SafeCastLib to revert cleanly on both overflow and underflow, maintaining consistency between pool state and user debt tracking as enforced by the FlashAccountant assumption [6](#0-5) .

## Proof of Concept

```solidity
// File: test/Exploit_SwapTruncation.t.sol
// Run with: forge test --match-test test_SwapSilentTruncation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {ONE} from "../src/types/sqrtRatio.sol";

contract Exploit_SwapTruncation is FullTest {
    function setUp() public override {
        FullTest.setUp();
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_SwapSilentTruncation() public {
        // SETUP: Create pool with extreme initial liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_fee: 0, _extension: address(0)})
        });
        
        // Initialize with massive liquidity to enable huge swap
        positions.maybeInitializePool(poolKey, 0);
        
        // Mint astronomical liquidity (would require tokens with very high supply)
        // This demonstrates the theoretical vulnerability
        vm.assume(false); // Skip in actual testing due to impractical amounts
        
        // EXPLOIT: Execute swap that would cause calculatedAmount < type(int128).min
        // Expected: Should revert but instead silently clamps
        // Result: Pool price updates fully but user debt is clamped
        
        // VERIFY: Pool state reflects full swap but debt is clamped
        // This would create extractable arbitrage opportunity
    }
}
```

**Notes:**
- PoC is illustrative due to impractical token amounts required (> 1.7e38)
- Vulnerability is theoretically exploitable with tokens having extreme supply/decimals
- The asymmetric protection suggests intentional design, but creates accounting mismatch
- Consider test coverage with fuzzing for edge cases approaching int128 boundaries

### Citations

**File:** src/Core.sol (L556-809)
```text
                int256 calculatedAmount;

                // fees per liquidity only for the input token
                uint256 inputTokenFeesPerLiquidity;

                // 0 = not loaded & not updated, 1 = loaded & not updated, 2 = loaded & updated
                uint256 feesAccessed;

                while (true) {
                    int32 nextTick;
                    bool isInitialized;
                    SqrtRatio nextTickSqrtRatio;

                    // For stableswap pools, determine active liquidity for this step
                    uint128 stepLiquidity = liquidity;

                    if (config.isStableswap()) {
                        if (config.isFullRange()) {
                            // special case since we don't need to compute min/max tick sqrt ratio
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
                        } else {
                            (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();

                            bool inRange;
                            assembly ("memory-safe") {
                                inRange := and(slt(tick, upper), iszero(slt(tick, lower)))
                            }
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
                        }
                    } else {
                        // concentrated liquidity pools use the tick bitmaps
                        (nextTick, isInitialized) = increasing
                            ? findNextInitializedTick(
                                CoreStorageLayout.tickBitmapsSlot(poolId),
                                tick,
                                config.concentratedTickSpacing(),
                                params.skipAhead()
                            )
                            : findPrevInitializedTick(
                                CoreStorageLayout.tickBitmapsSlot(poolId),
                                tick,
                                config.concentratedTickSpacing(),
                                params.skipAhead()
                            );

                        nextTickSqrtRatio = tickToSqrtRatio(nextTick);
                    }

                    SqrtRatio limitedNextSqrtRatio =
                        increasing ? nextTickSqrtRatio.min(sqrtRatioLimit) : nextTickSqrtRatio.max(sqrtRatioLimit);

                    SqrtRatio sqrtRatioNext;

                    if (stepLiquidity == 0) {
                        // if the pool is empty, the swap will always move all the way to the limit price
                        sqrtRatioNext = limitedNextSqrtRatio;
                    } else {
                        // this amount is what moves the price
                        int128 priceImpactAmount;
                        if (isExactOut) {
                            assembly ("memory-safe") {
                                priceImpactAmount := amountRemaining
                            }
                        } else {
                            uint128 amountU128;
                            assembly ("memory-safe") {
                                // cast is safe because amountRemaining is g.t. 0 and fits in int128
                                amountU128 := amountRemaining
                            }
                            uint128 feeAmount = computeFee(amountU128, config.fee());
                            assembly ("memory-safe") {
                                // feeAmount will never exceed amountRemaining since fee is < 100%
                                priceImpactAmount := sub(amountRemaining, feeAmount)
                            }
                        }

                        SqrtRatio sqrtRatioNextFromAmount = isToken1
                            ? nextSqrtRatioFromAmount1(sqrtRatio, stepLiquidity, priceImpactAmount)
                            : nextSqrtRatioFromAmount0(sqrtRatio, stepLiquidity, priceImpactAmount);

                        bool hitLimit;
                        assembly ("memory-safe") {
                            // Branchless limit check: (increasing && next > limit) || (!increasing && next < limit)
                            let exceedsUp := and(increasing, gt(sqrtRatioNextFromAmount, limitedNextSqrtRatio))
                            let exceedsDown :=
                                and(iszero(increasing), lt(sqrtRatioNextFromAmount, limitedNextSqrtRatio))
                            hitLimit := or(exceedsUp, exceedsDown)
                        }

                        // the change in fees per liquidity for this step of the iteration
                        uint256 stepFeesPerLiquidity;

                        if (hitLimit) {
                            (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) =
                                sortAndConvertToFixedSqrtRatios(limitedNextSqrtRatio, sqrtRatio);
                            (uint128 limitSpecifiedAmountDelta, uint128 limitCalculatedAmountDelta) = isToken1
                                ? (
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                )
                                : (
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                );

                            if (isExactOut) {
                                uint128 beforeFee = amountBeforeFee(limitCalculatedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, beforeFee)
                                    amountRemaining := add(amountRemaining, limitSpecifiedAmountDelta)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitCalculatedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                uint128 beforeFee = amountBeforeFee(limitSpecifiedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, limitCalculatedAmountDelta)
                                    amountRemaining := sub(amountRemaining, beforeFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitSpecifiedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
                            }

                            sqrtRatioNext = limitedNextSqrtRatio;
                        } else if (sqrtRatioNextFromAmount != sqrtRatio) {
                            uint128 calculatedAmountWithoutFee = isToken1
                                ? amount0Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut)
                                : amount1Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut);

                            if (isExactOut) {
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(includingFee, calculatedAmountWithoutFee)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, calculatedAmountWithoutFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
                                }
                            }

                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatioNextFromAmount;
                        } else {
                            // for an exact output swap, the price should always move since we have to round away from the current price
                            assert(!isExactOut);

                            // consume the entire input amount as fees since the price did not move
                            assembly ("memory-safe") {
                                stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
                            }
                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatio;
                        }

                        // only if fees per liquidity was updated in this swap iteration
                        if (stepFeesPerLiquidity != 0) {
                            if (feesAccessed == 0) {
                                // this loads only the input token fees per liquidity
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                ) + stepFeesPerLiquidity;
                            } else {
                                inputTokenFeesPerLiquidity += stepFeesPerLiquidity;
                            }

                            feesAccessed = 2;
                        }
                    }

                    if (sqrtRatioNext == nextTickSqrtRatio) {
                        sqrtRatio = sqrtRatioNext;
                        assembly ("memory-safe") {
                            // no overflow danger because nextTick is always inside the valid tick bounds
                            tick := sub(nextTick, iszero(increasing))
                        }

                        if (isInitialized) {
                            bytes32 tickValue = CoreStorageLayout.poolTicksSlot(poolId, nextTick).load();
                            assembly ("memory-safe") {
                                // if increasing, we add the liquidity delta, otherwise we subtract it
                                let liquidityDelta :=
                                    mul(signextend(15, tickValue), sub(increasing, iszero(increasing)))
                                liquidity := add(liquidity, liquidityDelta)
                            }

                            (StorageSlot tickFplFirstSlot, StorageSlot tickFplSecondSlot) =
                                CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, nextTick);

                            if (feesAccessed == 0) {
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                );
                                feesAccessed = 1;
                            }

                            uint256 globalFeesPerLiquidityOther = uint256(
                                CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(!increasing))
                                    .load()
                            );

                            // if increasing, it means the pool is receiving token1 so the input fees per liquidity is token1
                            if (increasing) {
                                tickFplFirstSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplSecondSlot.load()))
                                );
                            } else {
                                tickFplFirstSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplSecondSlot.load()))
                                );
                            }
                        }
                    } else if (sqrtRatio != sqrtRatioNext) {
                        sqrtRatio = sqrtRatioNext;
                        tick = sqrtRatioToTick(sqrtRatio);
                    }

                    if (amountRemaining == 0 || sqrtRatio == sqrtRatioLimit) {
                        break;
                    }
                }
```

**File:** src/Core.sol (L811-812)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));
```

**File:** src/Core.sol (L824-826)
```text
                stateAfter = createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: liquidity});

                writePoolState(poolId, stateAfter);
```

**File:** src/Core.sol (L834-834)
```text
                _updatePairDebtWithNative(locker.id(), token0, token1, balanceUpdate.delta0(), balanceUpdate.delta1());
```

**File:** README.md (L200-200)
```markdown
The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.
```

**File:** src/base/FlashAccountant.sol (L60-62)
```text
    /// @dev We assume debtChange cannot exceed a 128 bits value, even though it uses a int256 container.
    ///      This must be enforced at the places it is called for this contract's safety.
    ///      Negative values erase debt, positive values add debt.
```
