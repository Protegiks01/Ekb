# NoVulnerability found for this question.

After extensive analysis of the swap fee calculation logic in `swap_6269342730`, I've determined that the fee calculations are **mathematically consistent** between the "hit limit" case and the "not hit limit" case.

## Analysis Summary

**Hit Limit Case (exactIn):** [1](#0-0) 

The fee is calculated as `beforeFee - limitSpecifiedAmountDelta`, where `beforeFee = amountBeforeFee(limitSpecifiedAmountDelta, fee)`.

**Not Hit Limit Case (exactIn):** [2](#0-1) 

The fee is calculated as `amountRemaining - priceImpactAmount`, where `priceImpactAmount = amountRemaining - computeFee(amountRemaining, fee)`. [3](#0-2) 

## Mathematical Consistency

Both cases use the formula `computeFee(gross_input, fee)` where `gross_input` is the actual amount being consumed. The key property verified by the test suite ensures consistency: [4](#0-3) 

This test confirms that `amountBeforeFee(x, fee) - computeFee(amountBeforeFee(x, fee), fee) == x`, establishing the inverse relationship between the two functions.

## Conclusion

When the same price movement occurs (identical net amount for price impact), the fees are identical in both code paths. There are no exploitable discrepancies that would enable arbitrage. The fee calculation correctly charges `computeFee` on the gross input consumed, maintaining mathematical consistency across all swap scenarios.

**Notes:**
- The fee amounts differ between cases only when different amounts of input are consumed, which is expected and correct behavior
- No rounding errors or calculation inconsistencies that could be exploited for arbitrage
- The fee accumulation logic properly tracks fees per liquidity in both paths [5](#0-4)

### Citations

**File:** src/Core.sol (L639-643)
```text
                            uint128 feeAmount = computeFee(amountU128, config.fee());
                            assembly ("memory-safe") {
                                // feeAmount will never exceed amountRemaining since fee is < 100%
                                priceImpactAmount := sub(amountRemaining, feeAmount)
                            }
```

**File:** src/Core.sol (L686-694)
```text
                                uint128 beforeFee = amountBeforeFee(limitSpecifiedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, limitCalculatedAmountDelta)
                                    amountRemaining := sub(amountRemaining, beforeFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitSpecifiedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
```

**File:** src/Core.sol (L715-718)
```text
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
```

**File:** src/Core.sol (L737-749)
```text
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
```

**File:** test/math/fee.t.sol (L24-32)
```text
    function test_amountBeforeFee_computeFee(uint128 amount, uint64 fee) public view {
        vm.assumeNoRevert();

        uint128 before = this.abf(amount, fee);
        assertGe(before, amount);

        uint128 aft = before - computeFee(before, fee);
        assertEq(aft, amount);
    }
```
