# NoVulnerability found for this question.

After comprehensive analysis of the codebase, I can confirm that the nested ceiling divisions in `amount0DeltaSorted()` when `roundUp=true` **cannot** allow users to withdraw more token0 than deposited. Here's why:

## Mathematical Relationship

The protocol uses opposite rounding directions for deposits vs withdrawals:

**Deposit (liquidityDelta > 0):** [1](#0-0) 
Sets `isPositive = true`, which becomes `roundUp = true` in `amount0DeltaSorted`. [2](#0-1) 
This executes nested ceiling divisions that round UP, causing users to pay MORE than the mathematically exact amount.

**Withdrawal (liquidityDelta < 0):** [1](#0-0) 
Sets `isPositive = false`, which becomes `roundUp = false` in `amount0DeltaSorted`. [3](#0-2) 
This executes double floor divisions that round DOWN, causing users to receive LESS than the mathematically exact amount.

## Why This Protects Solvency

Mathematically: `ceil(ceil(x/y)/z) ≥ x/(y*z) ≥ floor(floor(x/y)/z)` for all positive values.

Therefore: **amount_deposited ≥ true_value ≥ amount_withdrawn**

The protocol's solvency invariant is protected because users always deposit at least as much as they can later withdraw. [4](#0-3) 

## Verification

The solvency invariant test explicitly tracks this: [5](#0-4) 

Pool balances increase on deposit and decrease on withdrawal. If users could withdraw more than deposited, `poolBalances` would eventually go negative and this invariant would fail.

## Notes

The nested ceiling divisions do accumulate rounding "errors," but these errors favor the **protocol**, not the users. The maximum rounding error is approximately 1-2 units per operation, which is negligible for typical liquidity amounts and protects against insolvency rather than enabling it.

### Citations

**File:** src/math/liquidity.sol (L32-32)
```text
        bool isPositive = (liquidityDelta > 0);
```

**File:** src/math/delta.sol (L44-47)
```text
            uint256 result0 =
                FixedPointMathLib.fullMulDivUp(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            assembly ("memory-safe") {
                let result := add(div(result0, sqrtRatioLower), iszero(iszero(mod(result0, sqrtRatioLower))))
```

**File:** src/math/delta.sol (L56-58)
```text
            uint256 result0 =
                FixedPointMathLib.fullMulDivUnchecked(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
```

**File:** README.md (L199-200)
```markdown

The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.
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
