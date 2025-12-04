# NoVulnerability found for this question.

## Validation Summary

After comprehensive validation using the Ekubo Protocol Validation Framework, I confirm the original determination is **CORRECT**. This is NOT an exploitable vulnerability.

## Verification of Key Claims

**1. Intentional Design Pattern Confirmed:**

The zero-liquidity-as-one treatment exists in two locations and is a deliberate design choice to prevent division by zero: [1](#0-0) [2](#0-1) 

**2. Impact Isolation Verified:**

The behavior only affects `secondsPerLiquidityCumulative` accumulation. The `tickCumulative` (price TWAP) calculation is completely separate and unaffected: [3](#0-2) 

**3. ERC7726 Price Oracle Uses Only Tick TWAP:**

The in-scope price oracle contract exclusively consumes `tickCumulative` for TWAP calculations, not `secondsPerLiquidityCumulative`: [4](#0-3) 

**4. PriceFetcher is View-Only:**

While PriceFetcher does calculate liquidity TWAPs using `secondsPerLiquidityCumulative`, it is a lens contract with no state-changing functions: [5](#0-4) 

Verification via grep search confirms PriceFetcher is only imported in test files, not by any core protocol contracts.

**5. Slippage Protection Uses Current State:**

Position operations use current pool state for slippage checks, not historical TWAP data: [6](#0-5) 

## No Invariant Violations

The behavior does not violate the documented critical invariants from the README:
- **Solvency invariant**: Pool balances remain unaffected (no token transfers based on liquidity TWAP)
- **Withdrawal availability**: Positions remain withdrawable (oracle data doesn't affect withdrawal logic)
- No core contracts consume liquidity TWAP for financial decisions

## Conclusion

The zero-liquidity-as-one treatment is an intentional design choice that:
1. Prevents division-by-zero errors in oracle calculations
2. Maintains continuous oracle operation across all pool states
3. Has zero exploitable impact on the Ekubo protocol
4. Does not affect price oracle accuracy (which uses tick TWAP)
5. Only impacts a view-only lens contract not used by core protocol logic

This is a design feature, not a vulnerability.

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
