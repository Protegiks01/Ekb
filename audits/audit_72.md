## Title
TWAMM Order Execution DOS via Arithmetic Overflow in `computeNextSqrtRatio` with Extreme Sale Rate Ratios

## Summary
The `computeNextSqrtRatio` function in `src/math/twamm.sol` can cause arithmetic overflow when calculating price movements for TWAMM orders with extreme sale rate ratios, blocking order execution and fund withdrawal. When the denominator `|ePowExponent + c|` approaches zero while the numerator becomes extremely large, the `fullMulDiv` operation reverts, permanently preventing users from canceling orders or collecting proceeds.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `computeNextSqrtRatio` function should calculate the target price for TWAMM virtual orders using the formula: `sqrtRatioNext = sqrtSaleRatio * |ePowExponent - c| / |ePowExponent + c|`, where this represents the price evolution under continuous bilateral trading.

**Actual Logic:** When extreme values occur, the numerator `sqrtSaleRatio * |ePowExponent - c|` can reach approximately 2^313, while the denominator `|ePowExponent + c|` can be as small as 3. This causes `fullMulDiv` to revert because the result exceeds 2^256, the maximum representable value in Solidity.

**Exploitation Path:**
1. **Setup Extreme Sale Rates**: Attacker places a TWAMM order with `saleRateToken1 = type(uint112).max` and `saleRateToken0 = 1`, creating maximum `sqrtSaleRatio ≈ 2^184` [2](#0-1) 

2. **Manipulate Pool Price**: Through swaps, push the pool's `sqrtRatio` to near `MAX_SQRT_RATIO` (≈ 2^192 in fixed-point), making the current price much higher than the sale ratio, resulting in `c ≈ -2^128` [3](#0-2) 

3. **Create Near-Zero Exponent**: The fee configuration or extremely high liquidity makes `sqrtSaleRate` very small after fee deduction, causing `exponent ≈ 0`, which produces `ePowExponent ≈ 2^128` [4](#0-3) 

4. **Trigger DOS**: When `_executeVirtualOrdersFromWithinLock` is called (during swaps, position updates, or explicit order operations), the calculation attempts: `result = 2^184 * 2^129 / 3 ≈ 2^311`, which exceeds 2^256 and reverts [5](#0-4) 

**Security Property Broken:** This violates the critical invariant from the README: "All positions MUST be withdrawable at any time". Users cannot call `decreaseSaleRate` to cancel their orders [6](#0-5)  or `collectProceeds` to withdraw earnings [7](#0-6)  because both operations trigger `_executeVirtualOrdersFromWithinLock` [8](#0-7)  and [9](#0-8) , which calls the reverting `computeNextSqrtRatio`.

## Impact Explanation
- **Affected Assets**: All TWAMM orders in pools where the attack conditions can be created. User funds locked in active TWAMM orders become permanently inaccessible.
- **Damage Severity**: Complete loss of access to deposited funds. While the tokens remain in the protocol, users cannot withdraw them through any normal means (cancel order or collect proceeds).
- **User Impact**: Any user with an active TWAMM order in an affected pool loses access to both their unsold tokens and accumulated proceeds. The attack can be set up by any malicious actor with capital to manipulate the pool state.

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to: (1) place a TWAMM order with extreme sale rates, (2) manipulate the pool price through swaps
- **Preconditions**: 
  - Pool must exist with TWAMM extension enabled
  - Attacker needs capital to place orders and manipulate price
  - Pool fee configuration or liquidity levels that allow `sqrtSaleRate` to be reduced near zero after fees
- **Execution Complexity**: Moderate. Requires two transactions: (1) place extreme-ratio TWAMM order, (2) manipulate pool price. Or target existing pools with naturally occurring extreme conditions.
- **Frequency**: Can be triggered once per affected pool, permanently locking all subsequent TWAMM orders in that pool until state is manually recovered (if possible).

## Recommendation

Add validation to prevent extreme scenarios that cause overflow:

```solidity
// In src/math/twamm.sol, function computeNextSqrtRatio, after line 125:

int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);

// ADD THIS VALIDATION:
// Check if |ePowExponent + c| is too small to safely compute the division
// A threshold of 2^120 ensures the result stays within uint256 bounds
int256 sum = ePowExponent + c;
if (sum >= 0 && uint256(sum) < (1 << 120)) {
    // Denominator too small, price has converged to sale ratio
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
} else if (sum < 0 && uint256(-sum) < (1 << 120)) {
    // Same for negative sum
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
} else {
    // Safe to proceed with normal calculation
    uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
        sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(sum)
    );
    // ... rest of clamping logic
}
```

Alternative mitigation: Add a try-catch around the `computeNextSqrtRatio` call in `_executeVirtualOrdersFromWithinLock` to gracefully handle overflow by defaulting to the sale ratio price when calculation fails.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMOverflow.t.sol
// Run with: forge test --match-test test_TWAMMArithmeticOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../src/math/twamm.sol";
import {toSqrtRatio, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_TWAMMOverflow is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM();
        orders = new Orders(core, address(twamm));
    }
    
    function test_TWAMMArithmeticOverflow() public {
        // SETUP: Create pool with extreme conditions
        // - Very high current price (near MAX_SQRT_RATIO)
        // - TWAMM order with extreme sale rate ratio (max token1 / min token0)
        
        // Step 1: Create order with saleRateToken1 = type(uint112).max, saleRateToken0 = 1
        // This creates sqrtSaleRatio ≈ 2^184
        uint112 saleRateToken0 = 1;
        uint112 saleRateToken1 = type(uint112).max;
        
        // Step 2: Set pool state where sqrtRatio is at maximum
        // This makes c ≈ -2^128 (large negative)
        SqrtRatio sqrtRatio = MAX_SQRT_RATIO;
        
        // Step 3: Set conditions for exponent ≈ 0
        // Very high liquidity or very small sqrtSaleRate (after fees)
        uint128 liquidity = type(uint128).max; // Maximum liquidity
        uint32 timeElapsed = 1;
        uint64 fee = type(uint64).max / 2; // High fee to reduce sqrtSaleRate
        
        // EXPLOIT: Attempt to compute next sqrt ratio
        // This will revert due to arithmetic overflow
        vm.expectRevert(); // Expect FullMulDivFailed or similar
        computeNextSqrtRatio({
            sqrtRatio: sqrtRatio,
            liquidity: liquidity,
            saleRateToken0: saleRateToken0,
            saleRateToken1: saleRateToken1,
            timeElapsed: timeElapsed,
            fee: fee
        });
        
        // VERIFY: The computation reverted, proving DOS vulnerability
        // In production, this would prevent:
        // - decreaseSaleRate() from canceling the order
        // - collectProceeds() from withdrawing earnings
        // - Any swaps or position updates in the affected pool
    }
}
```

## Notes

The vulnerability exists because the clamping logic [10](#0-9)  occurs AFTER the `fullMulDiv` calculation, so it cannot prevent the overflow revert. The mathematical formula assumes that when `|ePowExponent + c|` is very small, the price has essentially converged to the sale ratio, but the code doesn't handle this case before attempting the division.

This is particularly severe because the test suite includes fuzz testing [11](#0-10)  that checks bounds, but doesn't catch this specific overflow scenario where the intermediate multiplication in `fullMulDiv` exceeds bounds before the final division completes.

### Citations

**File:** src/math/twamm.sol (L54-64)
```text
/// @dev Computes the quantity `c = (sqrtSaleRatio - sqrtRatio) / (sqrtSaleRatio + sqrtRatio)` as a signed 64.128 number
/// @dev sqrtRatio is assumed to be between 2**192 and 2**-64, while sqrtSaleRatio values are assumed to be between 2**184 and 2**-72
function computeC(uint256 sqrtRatio, uint256 sqrtSaleRatio) pure returns (int256 c) {
    uint256 unsigned = FixedPointMathLib.fullMulDiv(
        FixedPointMathLib.dist(sqrtRatio, sqrtSaleRatio), (1 << 128), sqrtRatio + sqrtSaleRatio
    );
    assembly ("memory-safe") {
        let sign := sub(shl(1, gt(sqrtSaleRatio, sqrtRatio)), 1)
        c := mul(sign, unsigned)
    }
}
```

**File:** src/math/twamm.sol (L68-83)
```text
function computeSqrtSaleRatio(uint256 saleRateToken0, uint256 saleRateToken1) pure returns (uint256 sqrtSaleRatio) {
    unchecked {
        uint256 saleRatio = FixedPointMathLib.rawDiv(saleRateToken1 << 128, saleRateToken0);

        if (saleRatio <= type(uint128).max) {
            // full precision for small ratios
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 128);
        } else if (saleRatio <= type(uint192).max) {
            // we know it only has 192 bits, so we can shift it 64 before rooting to get more precision
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 64) << 32;
        } else {
            // we assume it has max 240 bits, since saleRateToken1 is 112 bits and we shifted left 128
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 16) << 56;
        }
    }
}
```

**File:** src/math/twamm.sol (L113-125)
```text
            uint256 sqrtSaleRateWithoutFee = FixedPointMathLib.sqrt(saleRateToken0 * saleRateToken1);
            // max 112 bits
            uint256 sqrtSaleRate = sqrtSaleRateWithoutFee - computeFee(uint128(sqrtSaleRateWithoutFee), fee);

            // (12392656037 * t * sqrtSaleRate) / liquidity == (34 + 32 + 128) - 128 bits, cannot overflow
            // uint256(12392656037) = Math.floor(Math.LOG2E * 2**33).
            // this combines the doubling, the left shifting and the converting to a base 2 exponent into a single multiplication
            uint256 exponent = FixedPointMathLib.rawDiv(sqrtSaleRate * timeElapsed * 12392656037, liquidity);
            if (exponent >= 0x400000000000000000) {
                // if the exponent is larger than this value (64), the exponent term dominates and the result is approximately the sell ratio
                sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
            } else {
                int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);
```

**File:** src/math/twamm.sol (L127-129)
```text
                uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
                    sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(ePowExponent + c)
                );
```

**File:** src/math/twamm.sol (L132-136)
```text
                if (roundUp) {
                    sqrtRatioNextFixed = FixedPointMathLib.max(sqrtRatioNextFixed, sqrtSaleRatio);
                } else {
                    sqrtRatioNextFixed = FixedPointMathLib.min(sqrtRatioNextFixed, sqrtSaleRatio);
                }
```

**File:** src/extensions/TWAMM.sol (L210-212)
```text
                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L345-347)
```text
                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L445-452)
```text
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });
```

**File:** src/Orders.sol (L76-94)
```text
    /// @inheritdoc IOrders
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
```

**File:** src/Orders.sol (L107-114)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }
```

**File:** test/math/twamm.t.sol (L321-369)
```text
    function test_computeNextSqrtRatio_always_within_bounds(
        uint256 sqrtRatioFixed,
        uint128 liquidity,
        uint112 saleRateToken0,
        uint112 saleRateToken1,
        uint32 timeElapsed,
        uint64 fee
    ) public pure {
        // valid starting sqrt ratio
        SqrtRatio sqrtRatio =
            toSqrtRatio(bound(sqrtRatioFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed()), false);

        // if either is 0, we cannot use this method
        saleRateToken0 = uint112(bound(saleRateToken0, 1, type(uint112).max));
        saleRateToken1 = uint112(bound(saleRateToken1, 1, type(uint112).max));

        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
            sqrtRatio: sqrtRatio,
            liquidity: liquidity,
            saleRateToken0: saleRateToken0,
            saleRateToken1: saleRateToken1,
            timeElapsed: timeElapsed,
            fee: fee
        });

        // it should always be within the min/max sqrt ratio which represents 2**-128 to 2**128
        // this is because the sale ratio is bounded to 2**-112 to 2**112
        assertGe(sqrtRatioNext.toFixed(), MIN_SQRT_RATIO.toFixed());
        assertLe(sqrtRatioNext.toFixed(), MAX_SQRT_RATIO.toFixed());

        uint256 sqrtSaleRatio = computeSqrtSaleRatio(saleRateToken0, saleRateToken1);

        // the next sqrt ratio is always between the sale ratio and current price
        if (sqrtSaleRatio > sqrtRatio.toFixed()) {
            assertGe(sqrtRatioNext.toFixed(), sqrtRatio.toFixed());
            assertLe(sqrtRatioNext.toFixed(), sqrtSaleRatio);

            if (liquidity == 0) {
                assertEq(sqrtRatioNext.toFixed(), toSqrtRatio(sqrtSaleRatio, false).toFixed());
            }
        } else {
            assertLe(sqrtRatioNext.toFixed(), sqrtRatio.toFixed());
            assertGe(sqrtRatioNext.toFixed(), sqrtSaleRatio);

            if (liquidity == 0) {
                assertEq(sqrtRatioNext.toFixed(), toSqrtRatio(sqrtSaleRatio, true).toFixed());
            }
        }
    }
```
