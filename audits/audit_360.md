# NoVulnerability found for this question.

After conducting a thorough analysis of the `amount0DeltaSorted()` function, I determined that using `fullMulDivUnchecked` instead of `fullMulDiv` when `roundUp` is false does NOT cause intermediate overflows that corrupt the amount0 calculation.

## Analysis Summary

**Mathematical Bounds Guarantee Safety:**
The calculation `(liquidityX128 * (sqrtRatioUpper - sqrtRatioLower)) / sqrtRatioUpper` is mathematically equivalent to `liquidityX128 * (1 - sqrtRatioLower/sqrtRatioUpper)`. Since `sqrtRatioLower < sqrtRatioUpper` (enforced by sorting), this ratio is always less than 1, ensuring the result is strictly less than `liquidityX128`, which itself is less than 2^256. [1](#0-0) 

**Validated Assumptions:**
The function explicitly documents its assumption that "sqrt ratios are non-zero and sorted." Callers in Core.sol properly validate these assumptions using `sortAndConvertToFixedSqrtRatios()` before invoking the function. [2](#0-1) [3](#0-2) 

**Explicit Overflow Protection:**
Even if `fullMulDivUnchecked` were to produce an incorrect intermediate value (which the mathematical bounds prevent), lines 59-64 include an explicit check that reverts with `Amount0DeltaOverflow()` if the final result exceeds 128 bits. [4](#0-3) 

**Intentional Gas Optimization:**
The use of `fullMulDivUnchecked` when `roundUp=false` is a deliberate gas optimization that relies on proven mathematical invariants rather than runtime checks. The safer `fullMulDivUp` is used when `roundUp=true` primarily for rounding behavior, not overflow concerns. [5](#0-4) 

**Notes:**
This is a gas-optimized implementation where the unchecked variant is safe because the intermediate calculation result is mathematically guaranteed to fit within 256 bits given the protocol's sqrt ratio bounds (MIN_SQRT_RATIO to MAX_SQRT_RATIO), and there's explicit validation afterward.

### Citations

**File:** src/math/delta.sol (L10-22)
```text
function sortAndConvertToFixedSqrtRatios(SqrtRatio sqrtRatioA, SqrtRatio sqrtRatioB)
    pure
    returns (uint256 sqrtRatioLower, uint256 sqrtRatioUpper)
{
    sqrtRatioLower = sqrtRatioA.toFixed();
    sqrtRatioUpper = sqrtRatioB.toFixed();
    assembly ("memory-safe") {
        let diff := mul(sub(sqrtRatioLower, sqrtRatioUpper), gt(sqrtRatioLower, sqrtRatioUpper))

        sqrtRatioLower := sub(sqrtRatioLower, diff)
        sqrtRatioUpper := add(sqrtRatioUpper, diff)
    }
}
```

**File:** src/math/delta.sol (L33-37)
```text
/// @dev Assumes that the sqrt ratios are non-zero and sorted
function amount0DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
{
```

**File:** src/math/delta.sol (L43-54)
```text
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
```

**File:** src/math/delta.sol (L55-67)
```text
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
```

**File:** src/Core.sol (L663-673)
```text
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
```
