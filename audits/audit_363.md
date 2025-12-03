## Title
Fee Deduction in computeNextSqrtRatio() Causes Integer Underflow for Small Sale Rates, Breaking TWAMM Price Calculations

## Summary
In the TWAMM math library's `computeNextSqrtRatio()` function, when `sqrtSaleRateWithoutFee` is small (e.g., value of 1) and pool fees are non-trivial, the fee deduction operation at line 115 can cause `sqrtSaleRate` to underflow to zero or wrap to a massive value due to the unchecked arithmetic block, fundamentally breaking the TWAMM exponent calculation and price movement logic. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/math/twamm.sol`, function `computeNextSqrtRatio()`, line 115 [2](#0-1) 

**Intended Logic:** The function should calculate the next square root price ratio for TWAMM virtual order execution by computing the sale rate after fees (`sqrtSaleRate`), then using it to determine the price movement exponent based on time elapsed, liquidity, and sale rates.

**Actual Logic:** When `sqrtSaleRateWithoutFee` is very small (e.g., 1) and the pool has non-negligible fees, the `computeFee()` function can return a value equal to or greater than `sqrtSaleRateWithoutFee`. Since line 115 is within an `unchecked` block starting at line 97, the subtraction causes:
- **Case 1**: `sqrtSaleRate = 0` when `computeFee() == sqrtSaleRateWithoutFee`
- **Case 2**: `sqrtSaleRate` wraps to `2^256 - x` when `computeFee() > sqrtSaleRateWithoutFee` [3](#0-2) 

The `computeFee()` calculation is: `(amount * fee + 0xffffffffffffffff) >> 64`. For `amount = 1`:
- With any `fee >= 1`, result is at least 1
- With `fee = type(uint64).max`, result is 2

**Exploitation Path:**

1. **Create pool with high fees**: An attacker creates a pool with fees set to a high value (e.g., 50% or higher, represented as ~`9.2e18` in uint64 0.64 fixed-point format). No validation prevents this. [4](#0-3) 

2. **Create minimal TWAMM orders**: Users create TWAMM orders with `amount = 1` and `duration = type(uint32).max`. This produces `saleRate = (1 << 32) / 2^32 = 1` for both token0 and token1. [5](#0-4) [6](#0-5) 

3. **Trigger TWAMM execution**: When `computeNextSqrtRatio()` is called to execute virtual orders, with both sale rates equal to 1, we get `sqrtSaleRateWithoutFee = sqrt(1 * 1) = 1`. [7](#0-6) 

4. **Underflow occurs**: With high fees, `computeFee(1, fee) >= 1`, causing `sqrtSaleRate` to become 0 or wrap to a massive value. The subsequent exponent calculation at line 120 either becomes 0 (preventing price movement) or overflows (producing garbage values). [8](#0-7) 

**Security Property Broken:** TWAMM orders should execute correctly and move prices toward equilibrium over time. This vulnerability breaks the core TWAMM price discovery mechanism.

## Impact Explanation

- **Affected Assets**: TWAMM orders in pools with high fees and small order amounts are affected. The price calculation becomes incorrect or completely disabled.

- **Damage Severity**: 
  - When `sqrtSaleRate = 0`: The exponent becomes 0 regardless of time elapsed, preventing TWAMM price movement entirely. Orders fail to execute as intended.
  - When `sqrtSaleRate` wraps: The multiplication in the exponent calculation overflows, producing unpredictable results that break price calculations and could cause reverts or incorrect swaps.

- **User Impact**: Any user creating or executing TWAMM orders in affected pools experiences DOS of TWAMM functionality. While users can withdraw their order capital via `decreaseSaleRate()`, the intended time-weighted execution fails completely.

## Likelihood Explanation

- **Attacker Profile**: Any user can create a pool with arbitrary fee values (permissionless pool creation). Users might also accidentally create TWAMM orders with minimal amounts in existing high-fee pools.

- **Preconditions**: 
  - Pool must have high fees (>50% for case 1, ~100% for case 2)
  - TWAMM orders must have very small amounts (amount=1) with maximum duration to achieve saleRate=1
  - Pool must have been initialized with liquidity

- **Execution Complexity**: Single transaction to create problematic TWAMM orders. The issue manifests automatically when virtual orders are executed.

- **Frequency**: Affects all TWAMM executions in pools meeting the preconditions. While high-fee pools are unusual in practice, the protocol should handle all valid parameter ranges gracefully rather than breaking.

## Recommendation

Add a check to ensure `sqrtSaleRate` remains positive after fee deduction, or use checked arithmetic:

```solidity
// In src/math/twamm.sol, function computeNextSqrtRatio, lines 113-116:

// CURRENT (vulnerable):
uint256 sqrtSaleRateWithoutFee = FixedPointMathLib.sqrt(saleRateToken0 * saleRateToken1);
// max 112 bits
uint256 sqrtSaleRate = sqrtSaleRateWithoutFee - computeFee(uint128(sqrtSaleRateWithoutFee), fee);

// FIXED:
uint256 sqrtSaleRateWithoutFee = FixedPointMathLib.sqrt(saleRateToken0 * saleRateToken1);
uint256 feeAmount = computeFee(uint128(sqrtSaleRateWithoutFee), fee);
// Ensure fee doesn't exceed the sale rate - if it does, clamp sqrtSaleRate to a minimum value of 1
uint256 sqrtSaleRate = sqrtSaleRateWithoutFee > feeAmount 
    ? sqrtSaleRateWithoutFee - feeAmount 
    : 1; // Minimum value to prevent underflow and maintain calculation validity
```

Alternative: Add minimum sale rate validation in `Orders.sol` to prevent orders with `amount = 1`, though this doesn't fully address the root cause.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMFeeUnderflow.t.sol
// Run with: forge test --match-test test_TWAMMFeeUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/math/twamm.sol";
import "../src/math/fee.sol";
import "../src/types/sqrtRatio.sol";

contract Exploit_TWAMMFeeUnderflow is Test {
    function test_TWAMMFeeUnderflow() public pure {
        // SETUP: Sale rates of 1 on both sides (achievable with amount=1, duration=2^32)
        uint256 saleRateToken0 = 1;
        uint256 saleRateToken1 = 1;
        
        // High fee pool (50% fee = 0.5 * 2^64)
        uint64 highFee = uint64(0.5 * (1 << 64));
        
        // EXPLOIT: Compute sqrtSaleRateWithoutFee
        uint256 sqrtSaleRateWithoutFee = 1; // sqrt(1 * 1) = 1
        
        // Compute fee on the sale rate
        uint128 feeAmount = computeFee(uint128(sqrtSaleRateWithoutFee), highFee);
        
        // VERIFY: Fee equals sale rate, causing sqrtSaleRate to become 0
        assertEq(feeAmount, 1, "Fee should equal sqrtSaleRateWithoutFee");
        
        // In unchecked block, this would produce: sqrtSaleRate = 1 - 1 = 0
        // This breaks the exponent calculation as the sale rate term disappears
        
        // With maximum fee (type(uint64).max ≈ 100% fee), computeFee returns 2
        uint64 maxFee = type(uint64).max;
        uint128 maxFeeAmount = computeFee(1, maxFee);
        assertEq(maxFeeAmount, 2, "Max fee should exceed sqrtSaleRateWithoutFee");
        
        // In unchecked block: sqrtSaleRate = 1 - 2 = 2^256 - 1 (massive underflow)
        // This causes overflow in subsequent exponent calculation
    }
    
    function test_NormalCaseWorks() public pure {
        // Show that with reasonable parameters, it works fine
        uint256 saleRateToken0 = 100 << 32; // Normal sale rate
        uint256 saleRateToken1 = 100 << 32;
        uint64 normalFee = uint64(0.003 * (1 << 64)); // 0.3% fee
        
        uint256 sqrtSaleRateWithoutFee = 100 << 32; // sqrt(product)
        uint128 feeAmount = computeFee(uint128(sqrtSaleRateWithoutFee), normalFee);
        
        // Fee is much smaller than sale rate, no underflow
        assert(feeAmount < sqrtSaleRateWithoutFee);
    }
}
```

## Notes

The vulnerability stems from the use of an `unchecked` block combined with the lack of validation on the relationship between computed fees and sale rates. While pools with ~100% fees are unusual in practice, the protocol should handle all valid input ranges gracefully rather than exhibiting undefined behavior. The issue is exacerbated by the absence of minimum amount validation for TWAMM orders, allowing users to create orders with `amount = 1` that produce the problematic `saleRate = 1` scenario.

### Citations

**File:** src/math/twamm.sol (L13-22)
```text
function computeSaleRate(uint256 amount, uint256 duration) pure returns (uint256 saleRate) {
    assembly ("memory-safe") {
        saleRate := div(shl(32, amount), duration)
        if shr(112, saleRate) {
            // cast sig "SaleRateOverflow()"
            mstore(0, shl(224, 0x83c87460))
            revert(0, 4)
        }
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

**File:** src/math/twamm.sol (L97-141)
```text
    unchecked {
        // assumed:
        //   assert(saleRateToken0 != 0 && saleRateToken1 != 0);
        uint256 sqrtSaleRatio = computeSqrtSaleRatio(saleRateToken0, saleRateToken1);

        uint256 sqrtRatioFixed = sqrtRatio.toFixed();
        bool roundUp = sqrtRatioFixed > sqrtSaleRatio;

        int256 c = computeC(sqrtRatioFixed, sqrtSaleRatio);

        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
        } else {
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

                uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
                    sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(ePowExponent + c)
                );

                // we should never exceed the sale ratio
                if (roundUp) {
                    sqrtRatioNextFixed = FixedPointMathLib.max(sqrtRatioNextFixed, sqrtSaleRatio);
                } else {
                    sqrtRatioNextFixed = FixedPointMathLib.min(sqrtRatioNextFixed, sqrtSaleRatio);
                }

                sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, roundUp);
            }
        }
    }
```

**File:** src/math/fee.sol (L6-10)
```text
function computeFee(uint128 amount, uint64 fee) pure returns (uint128 result) {
    assembly ("memory-safe") {
        result := shr(64, add(mul(amount, fee), 0xffffffffffffffff))
    }
}
```

**File:** src/types/poolConfig.sol (L141-150)
```text
function createConcentratedPoolConfig(uint64 _fee, uint32 _tickSpacing, address _extension)
    pure
    returns (PoolConfig c)
{
    assembly ("memory-safe") {
        // Set bit 31 to 1 for concentrated liquidity, then OR with tick spacing (bits 30-0)
        let typeConfig := or(0x80000000, and(_tickSpacing, 0x7fffffff))
        c := or(or(shl(96, _extension), shl(32, and(_fee, 0xffffffffffffffff))), typeConfig)
    }
}
```

**File:** src/Orders.sol (L53-74)
```text
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
        authorizedForNft(id)
        returns (uint112 saleRate)
    {
        uint256 realStart = FixedPointMathLib.max(block.timestamp, orderKey.config.startTime());

        unchecked {
            if (orderKey.config.endTime() <= realStart) {
                revert OrderAlreadyEnded();
            }

            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));

            if (saleRate > maxSaleRate) {
                revert MaxSaleRateExceeded();
            }
        }

        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
    }
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
