# NoVulnerability found for this question.

After a thorough investigation of the calculation precision differences between `amount0Delta` and `amount1Delta`, I can confirm that while an **asymmetry exists by design**, it **cannot be exploited** to extract value.

## Summary of Findings

### The Asymmetry Confirmed [1](#0-0) 

The `amount0Delta` function performs **two divisions** (by `sqrtRatioUpper` and `sqrtRatioLower`), enabling double rounding when `roundUp=true` or double truncation when `roundUp=false`. [2](#0-1) 

The `amount1Delta` function performs **one division** (by 2^128), resulting in single rounding or truncation.

### Rounding Direction Analysis [3](#0-2) 

During swap execution, the protocol uses:
- `roundUp = !isExactOut` for the specified token (rounds up when taking input from user)
- `roundUp = isExactOut` for the calculated token (rounds up when calculating required input for exact output)

This ensures **all rounding favors the pool**, not the swapper.

### Inverse Operation Protection [4](#0-3) 

The test suite explicitly verifies that `nextSqrtRatioFromAmount0` and `amount0Delta` maintain inverse relationships where the user's input is always sufficient to achieve the price movement, accounting for rounding. [5](#0-4) 

Similarly for token1, the inverse relationship is validated to ensure no value extraction is possible.

### Solvency Invariant Protected [6](#0-5) 

The solvency invariant test tracks all `delta0` and `delta1` changes across operations and verifies that pool balances never go negative, confirming the rounding strategy prevents pool insolvency.

## Conclusion

The precision asymmetry between `amount0Delta` (double rounding/truncation) and `amount1Delta` (single rounding/truncation) is **intentional and secure**:

1. **Direction**: All precision loss favors the pool/LPs, never the swapper
2. **Magnitude**: Bounded to 0-2 units for token0 and 0-1 units for token1  
3. **Consistency**: Applied uniformly across all swap directions and pool operations
4. **Invariants**: Solvency and withdrawal availability invariants remain protected

**No concrete attack path exists** to extract value through asymmetric swaps, as round-trip operations always result in net loss for users due to combined effects of fees and LP-favorable rounding.

### Citations

**File:** src/math/delta.sol (L34-69)
```text
function amount0DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
{
    unchecked {
        uint256 liquidityX128;
        assembly ("memory-safe") {
            liquidityX128 := shl(128, liquidity)
        }
        if (roundUp) {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUp(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            assembly ("memory-safe") {
                let result := add(div(result0, sqrtRatioLower), iszero(iszero(mod(result0, sqrtRatioLower))))
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        } else {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUnchecked(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        }
    }
}
```

**File:** src/math/delta.sol (L80-117)
```text
function amount1DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount1)
{
    unchecked {
        uint256 difference = sqrtRatioUpper - sqrtRatioLower;
        uint256 liquidityU256;
        assembly ("memory-safe") {
            liquidityU256 := liquidity
        }

        if (roundUp) {
            uint256 result = FixedPointMathLib.fullMulDivN(difference, liquidityU256, 128);
            assembly ("memory-safe") {
                // addition is safe from overflow because the result of fullMulDivN will never equal type(uint256).max
                result := add(
                    result,
                    iszero(iszero(mulmod(difference, liquidityU256, 0x100000000000000000000000000000000)))
                )
                if shr(128, result) {
                    // cast sig "Amount1DeltaOverflow()"
                    mstore(0, 0x59d2b24a)
                    revert(0x1c, 0x04)
                }
                amount1 := result
            }
        } else {
            uint256 result = FixedPointMathLib.fullMulDivN(difference, liquidityU256, 128);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount1DeltaOverflow()"
                    mstore(0, 0x59d2b24a)
                    revert(0x1c, 0x04)
                }
                amount1 := result
            }
        }
    }
```

**File:** src/Core.sol (L665-673)
```text
                            (uint128 limitSpecifiedAmountDelta, uint128 limitCalculatedAmountDelta) = isToken1
                                ? (
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                )
                                : (
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                );
```

**File:** test/math/sqrtRatio.t.sol (L33-83)
```text
    function test_nextSqrtRatioFromAmount0_compared_amount0Delta(
        uint256 sqrtRatioFixed,
        uint128 liquidity,
        int128 amount
    ) public pure {
        sqrtRatioFixed = bound(sqrtRatioFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed());
        liquidity = uint128(bound(liquidity, 1, type(uint128).max));
        SqrtRatio sqrtRatio = toSqrtRatio(sqrtRatioFixed, false);
        sqrtRatioFixed = sqrtRatio.toFixed();

        SqrtRatio sqrtRatioNext = nextSqrtRatioFromAmount0(sqrtRatio, liquidity, amount);

        unchecked {
            // this assertion ensures that the next sqrt ratio we compute is either sufficient to produce the requested amount0,
            // or more than the amount required to move to that price
            if (amount < 0) {
                assertGt(sqrtRatioNext.toFixed(), sqrtRatioFixed, "next price increasing");
                if (SqrtRatio.unwrap(sqrtRatioNext) == type(uint96).max) {
                    // if we overflowed, the amount in the pool is not enough to support the trade
                    uint256 amountAvailable = (uint256(liquidity) << 128) / sqrtRatioFixed;
                    if (amountAvailable > uint128(-amount)) {
                        uint256 roundedAmountAvailable = amount0Delta(sqrtRatio, MAX_SQRT_RATIO, liquidity, false);
                        assertLe(
                            roundedAmountAvailable,
                            uint128(-amount),
                            "the amount available for the liquidity is too low"
                        );
                    }
                } else {
                    uint256 result0 = FixedPointMathLib.fullMulDiv(
                        (uint256(liquidity) << 128),
                        (sqrtRatioNext.toFixed() - sqrtRatio.toFixed()),
                        sqrtRatioNext.toFixed()
                    );
                    uint256 amountAvailable = result0 / sqrtRatio.toFixed();

                    assertLe(uint128(-amount), amountAvailable, "amount taken out is less than the delta");
                }
            } else if (amount > 0) {
                assertLe(SqrtRatio.unwrap(sqrtRatioNext), SqrtRatio.unwrap(sqrtRatio), "sqrt ratio decreased");
                assertGe(
                    uint128(amount),
                    amount0Delta(sqrtRatio, sqrtRatioNext, liquidity, true),
                    "the amount is g.e. the delta"
                );
            } else {
                assertEq(SqrtRatio.unwrap(sqrtRatioNext), SqrtRatio.unwrap(sqrtRatio), "price did not move");
                assertEq(amount, 0, "amount is 0");
            }
        }
    }
```

**File:** test/math/sqrtRatio.t.sol (L102-147)
```text
    function test_nextSqrtRatioFromAmount1_compared_amount1Delta(
        uint256 sqrtRatioFixed,
        uint128 liquidity,
        int128 amount
    ) public pure {
        sqrtRatioFixed = bound(sqrtRatioFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed());
        liquidity = uint128(bound(liquidity, 1, type(uint128).max));

        SqrtRatio sqrtRatio = toSqrtRatio(sqrtRatioFixed, false);
        sqrtRatioFixed = sqrtRatio.toFixed();

        SqrtRatio sqrtRatioNext = nextSqrtRatioFromAmount1(sqrtRatio, liquidity, amount);

        // this assertion ensures that the next sqrt ratio we compute is either sufficient to produce the requested amount0,
        // or more than the amount required to move to that price
        unchecked {
            if (amount < 0) {
                assertLt(SqrtRatio.unwrap(sqrtRatioNext), SqrtRatio.unwrap(sqrtRatio));
                // if we overflowed, the amount in the pool is not enough to support the trade
                if (SqrtRatio.unwrap(sqrtRatioNext) == 0) {
                    assertLe(
                        FixedPointMathLib.fullMulDivN(sqrtRatioFixed, liquidity, 128),
                        // we add one here because it's possible that sqrt ratio next happens to equal 0 without underflow
                        uint128(-amount) + 1,
                        "insufficient amount available"
                    );
                } else {
                    assertLe(
                        uint128(-amount),
                        amount1Delta(sqrtRatio, sqrtRatioNext, liquidity, false),
                        "amount taken out is less than the delta"
                    );
                }
            } else if (amount > 0) {
                assertGe(SqrtRatio.unwrap(sqrtRatioNext), SqrtRatio.unwrap(sqrtRatio), "ratio increases for token1 > 0");
                assertGe(
                    uint128(amount),
                    amount1Delta(sqrtRatio, sqrtRatioNext, liquidity, true),
                    "sqrt ratio increase is rounded down"
                );
            } else {
                assertSqrtRatioEq(sqrtRatioNext, sqrtRatio);
                assertEq(amount, 0);
            }
        }
    }
```

**File:** test/SolvencyInvariantTest.t.sol (L268-274)
```text
    function checkAllPoolsHavePositiveBalance() public view {
        for (uint256 i = 0; i < allPoolKeys.length; i++) {
            PoolId poolId = allPoolKeys[i].toPoolId();
            assertGe(poolBalances[poolId].amount0, 0);
            assertGe(poolBalances[poolId].amount1, 0);
        }
    }
```
