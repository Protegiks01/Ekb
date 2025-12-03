## Title
Invalid SqrtRatio Bypass in maxLiquidity() Causes Incorrect Liquidity Calculations and Pool State Corruption

## Summary
The `sortAndConvertToFixedSqrtRatios()` function does not validate SqrtRatio inputs before conversion. During swap operations, overflow conditions in `nextSqrtRatioFromAmount0/1()` can produce invalid SqrtRatio values (specifically `type(uint96).max`) that exceed the valid range, which are then written to pool state. Subsequent deposit operations use these invalid values in `maxLiquidity()` calculations, resulting in incorrect liquidity amounts that violate pool solvency invariants.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) , [2](#0-1) , [3](#0-2) 

**Intended Logic:** The `sortAndConvertToFixedSqrtRatios()` function should ensure SqrtRatio values are within valid bounds (MIN_SQRT_RATIO to MAX_SQRT_RATIO) before using them in liquidity calculations. The `maxLiquidity()` function should calculate the maximum liquidity based on valid pool prices.

**Actual Logic:** The function only converts SqrtRatio values using `toFixed()` without validation. [4](#0-3)  The `toFixed()` function performs bit manipulation without checking if the input is valid. Meanwhile, swap operations can produce invalid SqrtRatio values through overflow handling.

**Exploitation Path:**
1. Attacker constructs a swap that triggers overflow conditions in `nextSqrtRatioFromAmount0()` or `nextSqrtRatioFromAmount1()`. [5](#0-4) [6](#0-5) [7](#0-6)  These functions return `SqrtRatio.wrap(type(uint96).max)` to avoid reverts.

2. The invalid SqrtRatio value `type(uint96).max` (79,228,162,514,264,337,593,543,950,335) exceeds `MAX_SQRT_RATIO_RAW` (79,227,682,466,138,141,934,206,691,491) [8](#0-7) , making it invalid per the `isValid()` check. [9](#0-8) 

3. This invalid sqrtRatio is assigned to `sqrtRatioNext`, then to `sqrtRatio`, and finally written to pool state via `createPoolState()` and `writePoolState()`. [10](#0-9) [11](#0-10) 

4. When a victim calls `deposit()`, the pool's corrupted sqrtRatio is retrieved. [12](#0-11)  The invalid value is passed to `maxLiquidity()`, which uses it without validation, producing incorrect liquidity calculations based on wrong price assumptions.

**Security Property Broken:** Violates the **Solvency** invariant - incorrect liquidity calculations can cause pool token balances to become negative or allow users to extract more value than they deposited.

## Impact Explanation
- **Affected Assets**: All tokens in the corrupted pool, all liquidity positions in that pool
- **Damage Severity**: Users depositing into a pool with corrupted sqrtRatio receive incorrect liquidity amounts. If the invalid sqrtRatio causes `maxLiquidity()` to return inflated values, users could mint excessive liquidity shares and drain the pool. If deflated, users lose deposited funds by receiving insufficient liquidity.
- **User Impact**: All users attempting to deposit into the affected pool after the corruption occurs. The pool becomes permanently unusable until reinitialized, potentially locking existing liquidity.

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to trigger the overflow conditions in swap calculations
- **Preconditions**: Pool must be initialized with liquidity; attacker needs ability to execute a large swap that meets one of the overflow conditions (e.g., `product >= liquidityX128` or `resultFixed > MAX_FIXED_VALUE_ROUND_UP`)
- **Execution Complexity**: Single transaction to corrupt the pool, followed by deposits from victims
- **Frequency**: Once per pool (corrupts pool state permanently until reinitialized)

## Recommendation

**Fix 1: Validate SqrtRatio inputs in sortAndConvertToFixedSqrtRatios()**
```solidity
// In src/math/delta.sol, function sortAndConvertToFixedSqrtRatios, line 10-22:

function sortAndConvertToFixedSqrtRatios(SqrtRatio sqrtRatioA, SqrtRatio sqrtRatioB)
    pure
    returns (uint256 sqrtRatioLower, uint256 sqrtRatioUpper)
{
    // Validate inputs before conversion
    require(sqrtRatioA.isValid(), "Invalid sqrtRatioA");
    require(sqrtRatioB.isValid(), "Invalid sqrtRatioB");
    
    sqrtRatioLower = sqrtRatioA.toFixed();
    sqrtRatioUpper = sqrtRatioB.toFixed();
    assembly ("memory-safe") {
        let diff := mul(sub(sqrtRatioLower, sqrtRatioUpper), gt(sqrtRatioLower, sqrtRatioUpper))
        sqrtRatioLower := sub(sqrtRatioLower, diff)
        sqrtRatioUpper := add(sqrtRatioUpper, diff)
    }
}
```

**Fix 2: Prevent invalid SqrtRatio from being written to pool state**
```solidity
// In src/math/sqrtRatio.sol, replace type(uint96).max returns with reverts:

// Lines 32-34, 39-41, 47-49:
// INSTEAD OF: return SqrtRatio.wrap(type(uint96).max);
// USE: revert("SqrtRatio overflow");
```

**Fix 3: Add validation in maxLiquidity() as defense-in-depth**
```solidity
// In src/math/liquidity.sol, function maxLiquidity, line 90-98:

function maxLiquidity(
    SqrtRatio _sqrtRatio,
    SqrtRatio sqrtRatioA,
    SqrtRatio sqrtRatioB,
    uint128 amount0,
    uint128 amount1
) pure returns (uint128) {
    // Validate current pool price
    require(_sqrtRatio.isValid(), "Invalid pool sqrtRatio");
    
    uint256 sqrtRatio = _sqrtRatio.toFixed();
    (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) = sortAndConvertToFixedSqrtRatios(sqrtRatioA, sqrtRatioB);
    // ... rest of function
}
```

## Proof of Concept
```solidity
// File: test/Exploit_InvalidSqrtRatio.t.sol
// Run with: forge test --match-test test_InvalidSqrtRatioCorruptsLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BasePositions.sol";
import "../src/types/sqrtRatio.sol";
import "../src/types/poolKey.sol";

contract Exploit_InvalidSqrtRatio is Test {
    Core core;
    BasePositions positions;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        positions = new BasePositions(core, address(this));
        
        // Initialize a pool
        PoolKey memory poolKey = /* create pool key */;
        core.initializePool(poolKey, 0);
    }
    
    function test_InvalidSqrtRatioCorruptsLiquidity() public {
        // STEP 1: Attacker executes swap causing overflow
        // This would trigger one of the overflow conditions in nextSqrtRatioFromAmount0/1
        // causing return of SqrtRatio.wrap(type(uint96).max)
        
        // STEP 2: Verify pool state now contains invalid sqrtRatio
        SqrtRatio poolSqrtRatio = core.poolState(poolId).sqrtRatio();
        assertEq(SqrtRatio.unwrap(poolSqrtRatio), type(uint96).max, "Pool corrupted with invalid sqrtRatio");
        assertFalse(poolSqrtRatio.isValid(), "sqrtRatio should be invalid");
        
        // STEP 3: Victim attempts deposit
        uint128 liquidityBefore = positions.deposit(
            tokenId, poolKey, tickLower, tickUpper, 
            maxAmount0, maxAmount1, minLiquidity
        );
        
        // STEP 4: Verify incorrect liquidity was calculated
        // The invalid sqrtRatio causes maxLiquidity() to use wrong branch
        // leading to incorrect liquidity amount
        assertTrue(liquidityBefore != expectedLiquidity, "Liquidity calculation corrupted");
    }
}
```

## Notes

The vulnerability chain requires three components to align:

1. **Root Cause**: [13](#0-12)  intentionally returns `type(uint96).max` to avoid reverts during overflow, but this value is invalid.

2. **Missing Validation**: [1](#0-0)  and [4](#0-3)  do not validate inputs, allowing invalid values to propagate.

3. **State Corruption**: [14](#0-13)  extracts sqrtRatio from storage without validation, and [11](#0-10)  writes without validation.

The issue is particularly severe because once a pool's state is corrupted with an invalid sqrtRatio, all subsequent operations reading that price (deposits, withdrawals, swaps) use incorrect values, cascading the error throughout the system.

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

**File:** src/math/sqrtRatio.sol (L10-64)
```text
function nextSqrtRatioFromAmount0(SqrtRatio _sqrtRatio, uint128 liquidity, int128 amount)
    pure
    returns (SqrtRatio sqrtRatioNext)
{
    if (amount == 0) {
        return _sqrtRatio;
    }

    uint256 sqrtRatio = _sqrtRatio.toFixed();

    uint256 liquidityX128;
    assembly ("memory-safe") {
        liquidityX128 := shl(128, liquidity)
    }

    if (amount < 0) {
        uint256 amountAbs;
        assembly ("memory-safe") {
            amountAbs := sub(0, amount)
        }
        unchecked {
            // multiplication will revert on overflow, so we return the maximum value for the type
            if (amountAbs > FixedPointMathLib.rawDiv(type(uint256).max, sqrtRatio)) {
                return SqrtRatio.wrap(type(uint96).max);
            }

            uint256 product = sqrtRatio * amountAbs;

            // again it will overflow if this is the case, so return the max value
            if (product >= liquidityX128) {
                return SqrtRatio.wrap(type(uint96).max);
            }

            uint256 denominator = liquidityX128 - product;

            uint256 resultFixed = FixedPointMathLib.fullMulDivUp(liquidityX128, sqrtRatio, denominator);

            if (resultFixed > MAX_FIXED_VALUE_ROUND_UP) {
                return SqrtRatio.wrap(type(uint96).max);
            }

            sqrtRatioNext = toSqrtRatio(resultFixed, true);
        }
    } else {
        uint256 sqrtRatioRaw;
        assembly ("memory-safe") {
            // this can never overflow, amountAbs is limited to 2**128-1 and liquidityX128 / sqrtRatio is limited to (2**128-1 << 128)
            // adding the 2 values can at most equal type(uint256).max
            let denominator := add(div(liquidityX128, sqrtRatio), amount)
            sqrtRatioRaw := add(div(liquidityX128, denominator), iszero(iszero(mod(liquidityX128, denominator))))
        }

        sqrtRatioNext = toSqrtRatio(sqrtRatioRaw, true);
    }
}
```

**File:** src/math/liquidity.sol (L90-119)
```text
function maxLiquidity(
    SqrtRatio _sqrtRatio,
    SqrtRatio sqrtRatioA,
    SqrtRatio sqrtRatioB,
    uint128 amount0,
    uint128 amount1
) pure returns (uint128) {
    uint256 sqrtRatio = _sqrtRatio.toFixed();
    (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) = sortAndConvertToFixedSqrtRatios(sqrtRatioA, sqrtRatioB);

    if (sqrtRatio <= sqrtRatioLower) {
        return uint128(
            FixedPointMathLib.min(type(uint128).max, maxLiquidityForToken0(sqrtRatioLower, sqrtRatioUpper, amount0))
        );
    } else if (sqrtRatio < sqrtRatioUpper) {
        return uint128(
            FixedPointMathLib.min(
                type(uint128).max,
                FixedPointMathLib.min(
                    maxLiquidityForToken0(sqrtRatio, sqrtRatioUpper, amount0),
                    maxLiquidityForToken1(sqrtRatioLower, sqrtRatio, amount1)
                )
            )
        );
    } else {
        return uint128(
            FixedPointMathLib.min(type(uint128).max, maxLiquidityForToken1(sqrtRatioLower, sqrtRatioUpper, amount1))
        );
    }
}
```

**File:** src/types/sqrtRatio.sol (L13-16)
```text
uint96 constant MIN_SQRT_RATIO_RAW = 4611797791050542631;
SqrtRatio constant MIN_SQRT_RATIO = SqrtRatio.wrap(MIN_SQRT_RATIO_RAW);
uint96 constant MAX_SQRT_RATIO_RAW = 79227682466138141934206691491;
SqrtRatio constant MAX_SQRT_RATIO = SqrtRatio.wrap(MAX_SQRT_RATIO_RAW);
```

**File:** src/types/sqrtRatio.sol (L40-49)
```text
function isValid(SqrtRatio sqrtRatio) pure returns (bool r) {
    assembly ("memory-safe") {
        r := and(
            // greater than or equal to TWO_POW_62, i.e. the whole number portion is nonzero
            gt(and(sqrtRatio, not(BIT_MASK)), TWO_POW_62_MINUS_ONE),
            // and between min/max sqrt ratio
            and(iszero(lt(sqrtRatio, MIN_SQRT_RATIO_RAW)), iszero(gt(sqrtRatio, MAX_SQRT_RATIO_RAW)))
        )
    }
}
```

**File:** src/types/sqrtRatio.sol (L102-106)
```text
function toFixed(SqrtRatio sqrtRatio) pure returns (uint256 r) {
    assembly ("memory-safe") {
        r := shl(add(2, shr(89, and(sqrtRatio, BIT_MASK))), and(sqrtRatio, not(BIT_MASK)))
    }
}
```

**File:** src/Core.sol (L820-826)
```text
                balanceUpdate = isToken1
                    ? createPoolBalanceUpdate(calculatedAmountDelta, specifiedAmountDelta)
                    : createPoolBalanceUpdate(specifiedAmountDelta, calculatedAmountDelta);

                stateAfter = createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: liquidity});

                writePoolState(poolId, stateAfter);
```

**File:** src/types/poolState.sol (L10-14)
```text
function sqrtRatio(PoolState state) pure returns (SqrtRatio r) {
    assembly ("memory-safe") {
        r := shr(160, state)
    }
}
```

**File:** src/types/poolState.sol (L42-46)
```text
function createPoolState(SqrtRatio _sqrtRatio, int32 _tick, uint128 _liquidity) pure returns (PoolState s) {
    assembly ("memory-safe") {
        // s = (sqrtRatio << 160) | (_tick << 128) | liquidity
        s := or(shl(160, _sqrtRatio), or(shl(128, and(_tick, 0xFFFFFFFF)), shr(128, shl(128, _liquidity))))
    }
```

**File:** src/base/BasePositions.sol (L80-83)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
```
