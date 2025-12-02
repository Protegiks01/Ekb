# NoVulnerability found for this question.

After comprehensive investigation of the `maybeInsertSnapshot()` function and its handling of zero liquidity scenarios, I have determined this is **NOT an exploitable vulnerability** within the Ekubo protocol.

## Analysis Summary

**The Behavior is Intentional:**

The use of `nonZeroLiquidity = add(liquidity, iszero(liquidity))` when liquidity is zero is a deliberate design pattern to avoid division by zero [1](#0-0) . This same pattern is consistently applied in the `extrapolateSnapshotInternal` function using `FixedPointMathLib.max(1, state.liquidity())` [2](#0-1) .

**What It Affects:**

The zero-liquidity-as-one treatment only impacts `secondsPerLiquidityCumulative` accumulation [3](#0-2) . Critically, it does **NOT** affect `tickCumulative` (price TWAP), which continues to accumulate based solely on time and tick values.

**No In-Scope Financial Impact:**

1. **ERC7726 (Pricing Oracle) is Unaffected**: The price oracle only consumes `tickCumulative` for TWAP calculations, not `secondsPerLiquidityCumulative` [4](#0-3) .

2. **PriceFetcher is View-Only**: While PriceFetcher calculates liquidity TWAPs using `secondsPerLiquidityCumulative` [5](#0-4) , it is a lens contract that performs no state changes and makes no financial decisions.

3. **Core Contracts Don't Use Liquidity TWAP**: Core protocol contracts (Core, Router, Positions, MEVCapture, TWAMM, RevenueBuybacks, Incentives) do not reference or consume oracle liquidity TWAP data for any critical operations.

4. **Slippage Protection Uses Current State**: Position slippage checks use current pool state, not historical TWAP data [6](#0-5) .

**No Invariant Violations:**

The behavior does not violate any of the documented critical invariants:
- Solvency remains intact (no token transfers based on liquidity TWAP)
- Withdrawal availability is unaffected
- Flash accounting operates independently of oracle data
- Fee accounting is not impacted
- Extension isolation is maintained

## Notes

While an attacker could theoretically manipulate reported liquidity TWAP by controlling when zero-liquidity snapshots are taken, this manipulation has **no exploitable impact** on the Ekubo protocol itself. The design choice to treat zero liquidity as 1 prevents division-by-zero errors while maintaining continuous oracle operation, and no in-scope contracts rely on liquidity TWAP for financial decisions. External protocols consuming this data should be aware of this behavior as a documented limitation when liquidity is zero.

### Citations

**File:** src/extensions/Oracle.sol (L115-119)
```text
            uint128 liquidity = state.liquidity();
            uint256 nonZeroLiquidity;
            assembly ("memory-safe") {
                nonZeroLiquidity := add(liquidity, iszero(liquidity))
            }
```

**File:** src/extensions/Oracle.sol (L121-126)
```text
            Snapshot snapshot = createSnapshot({
                _timestamp: uint32(block.timestamp),
                _secondsPerLiquidityCumulative: last.secondsPerLiquidityCumulative()
                    + uint160(FixedPointMathLib.rawDiv(uint256(timePassed) << 128, nonZeroLiquidity)),
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });
```

**File:** src/extensions/Oracle.sol (L333-337)
```text
                    secondsPerLiquidityCumulative += uint160(
                        FixedPointMathLib.rawDiv(
                            uint256(timePassed) << 128, FixedPointMathLib.max(1, state.liquidity())
                        )
                    );
```

**File:** src/lens/ERC7726.sol (L98-101)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
```

**File:** src/lens/PriceFetcher.sol (L100-106)
```text
                return PeriodAverage(
                    uint128(
                        (uint160(endTime - startTime) << 128)
                            / (secondsPerLiquidityCumulativeEnd - secondsPerLiquidityCumulativeStart)
                    ),
                    tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(endTime - startTime))
                );
```

**File:** src/base/BasePositions.sol (L80-87)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
```
