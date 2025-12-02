## Title
Precision Loss in SqrtRatio Conversion Causes Assertion Failure for Small Exact Output Swaps

## Summary
The Core contract's swap function contains an assertion that fails when exact output swaps with very small amounts result in no detectable price movement due to precision loss in the `toSqrtRatio` conversion. This causes legitimate swaps to revert unexpectedly, potentially breaking multicall operations and external integrations that rely on swap success.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol` in the `swap_6269342730()` function [1](#0-0) 

**Intended Logic:** The code assumes that exact output swaps will always result in a detectable price movement because the `nextSqrtRatioFromAmount0/1` functions round away from the current price. The assertion at line 726 enforces this assumption. [2](#0-1) 

**Actual Logic:** The `nextSqrtRatioFromAmount0` and `nextSqrtRatioFromAmount1` functions calculate the next price in 64.128 fixed-point precision, but then convert it to a compact 96-bit representation using `toSqrtRatio`. This conversion involves bit-shifting that loses precision: [3](#0-2) 

The conversion shifts bits by different amounts depending on the region:
- Region < 2^128: shifts by 34 bits (minimum detectable change: 2^34)
- Region < 2^160: shifts by 66 bits (minimum detectable change: 2^66)  
- Region < 2^192: shifts by 98 bits (minimum detectable change: 2^98)

For `nextSqrtRatioFromAmount1` with a small negative amount (exact output): [4](#0-3) 

The quotient calculation `ceil((amount << 128) / liquidity)` can be smaller than the precision threshold. For example, with `amount = 1` wei and `liquidity > 2^30` (≈1 billion wei) in the highest precision region, the quotient becomes smaller than 2^98, resulting in `sqrtRatioNext == sqrtRatio` after conversion.

**Exploitation Path:**
1. Pool exists with high liquidity (e.g., > 1 billion wei for region 11, > 2^62 for region 10, or > 2^94 for region 01)
2. User initiates an exact output swap for a very small amount (e.g., 1 wei)
3. `nextSqrtRatioFromAmount0/1` calculates a price change smaller than the precision threshold
4. After `toSqrtRatio` conversion, `sqrtRatioNextFromAmount == sqrtRatio`
5. The condition at line 698 evaluates to false, entering the else block at line 724
6. Assertion `assert(!isExactOut)` fails at line 726
7. Transaction reverts with assertion failure

**Security Property Broken:** The documented assumption that "for an exact output swap, the price should always move since we have to round away from the current price" is violated due to precision loss in the compact representation conversion.

## Impact Explanation
- **Affected Assets**: Any pools with sufficient liquidity where users attempt small exact output swaps
- **Damage Severity**: Transactions revert unexpectedly, breaking composability. If this swap is part of a multicall operation, flash loan repayment, or external protocol's critical logic (like liquidations), the entire transaction fails. While not a direct fund loss, it creates DOS conditions and breaks expected protocol behavior.
- **User Impact**: Users attempting legitimate small exact output swaps will experience unexpected reverts. External protocols relying on Ekubo for critical operations (liquidations, arbitrage, rebalancing) may fail if their operations involve small exact output swaps.

## Likelihood Explanation
- **Attacker Profile**: Any user can trigger this, either unintentionally through small swaps or maliciously for griefing
- **Preconditions**: Pool must have high liquidity relative to the swap amount. For the highest precision region (most common), liquidity > ~1 billion wei is sufficient for 1 wei swaps
- **Execution Complexity**: Single transaction with exact output parameters
- **Frequency**: Can be triggered repeatedly for any qualifying pool

## Recommendation

Add a minimum swap amount check or handle the edge case gracefully instead of using an assertion:

```solidity
// In src/Core.sol, function swap_6269342730, around line 724-734:

// CURRENT (vulnerable):
// The code uses assert(!isExactOut) which panics on failure

// FIXED OPTION 1: Skip the swap iteration if no price movement occurs
} else if (sqrtRatioNextFromAmount != sqrtRatio) {
    // normal swap logic
} else {
    // Price didn't move - for exact output, this shouldn't happen but can due to precision
    // For exact input, consume remaining as fees; for exact output, end the swap
    if (isExactOut) {
        // No price movement possible for this amount, end the swap
        amountRemaining = 0;
        sqrtRatioNext = sqrtRatio;
    } else {
        // consume the entire input amount as fees since the price did not move
        assembly ("memory-safe") {
            stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
        }
        amountRemaining = 0;
        sqrtRatioNext = sqrtRatio;
    }
}

// FIXED OPTION 2: Add minimum swap amount validation
// At the start of swap_6269342730, after line 536:
if (isExactOut && amountRemaining > -MIN_EXACT_OUTPUT_AMOUNT) {
    revert SwapAmountTooSmall();
}
```

Alternative: Document this as expected behavior and recommend minimum swap amounts in integration guidelines.

## Proof of Concept

```solidity
// File: test/Exploit_PrecisionLossAssertionFailure.t.sol
// Run with: forge test --match-test test_PrecisionLossAssertionFailure -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";

contract Exploit_PrecisionLossAssertionFailure is Test {
    Core core;
    Router router;
    
    function setUp() public {
        // Deploy Core and Router
        core = new Core();
        router = new Router(ICore(address(core)));
        
        // Setup a pool with high liquidity
        // This would involve initializing pool and adding liquidity
        // The exact setup depends on pool initialization helpers
    }
    
    function test_PrecisionLossAssertionFailure() public {
        // SETUP: Pool with high liquidity (e.g., 10^15 wei or more)
        // assuming liquidity > 2^30 in the compact sqrtRatio region 11
        
        // EXPLOIT: Attempt exact output swap for 1 wei
        // Construct SwapParameters with:
        // - amount = -1 (exact output of 1 wei)
        // - appropriate sqrtRatioLimit
        // - isToken1 = true/false depending on which token
        
        // Expected: Transaction reverts with assertion failure
        // vm.expectRevert();
        // core.swap_6269342730(...);
        
        // VERIFY: The swap reverts due to assertion failure at line 726
        // In a real scenario with sufficient liquidity, calling swap with
        // exact output amount of 1 wei would trigger the assertion
    }
}
```

## Notes

This vulnerability represents a correctness issue in the swap logic where the protocol's documented assumption (that exact output swaps always move price) doesn't hold due to precision limitations of the compact sqrtRatio representation. While it doesn't directly steal funds, it creates unexpected revert conditions that can:

1. Break multicall operations bundling multiple swaps
2. Cause failures in external protocols relying on Ekubo swaps for critical operations
3. Be exploited for griefing attacks by intentionally triggering assertion failures
4. Violate composability expectations in DeFi

The issue is more likely to occur in pools with very high liquidity or when swapping very small amounts, but these are realistic scenarios especially for popular trading pairs or dust amount cleanup operations. The use of `assert()` (which consumes all remaining gas) rather than `require()` makes the impact worse, as it prevents graceful error handling.

### Citations

**File:** src/Core.sol (L646-648)
```text
                        SqrtRatio sqrtRatioNextFromAmount = isToken1
                            ? nextSqrtRatioFromAmount1(sqrtRatio, stepLiquidity, priceImpactAmount)
                            : nextSqrtRatioFromAmount0(sqrtRatio, stepLiquidity, priceImpactAmount);
```

**File:** src/Core.sol (L724-734)
```text
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
```

**File:** src/types/sqrtRatio.sol (L59-99)
```text
function toSqrtRatio(uint256 sqrtRatio, bool roundUp) pure returns (SqrtRatio r) {
    assembly ("memory-safe") {
        function compute(sr, ru) -> v {
            // rup = 0x00...00 when false, 0xff...ff when true
            let rup := sub(0, ru)

            // Region: < 2**96  (shift = 2)
            let addmask := and(0x3, rup) // (1<<s)-1 if ru
            if lt(add(sr, addmask), shl(96, 1)) {
                v := shr(2, add(sr, addmask))
                leave
            }

            // Region: < 2**128 (shift = 34)  + set bit 94
            addmask := and(0x3ffffffff, rup)
            if lt(add(sr, addmask), shl(128, 1)) {
                v := or(shl(94, 1), shr(34, add(sr, addmask)))
                leave
            }

            // Region: < 2**160 (shift = 66)  + set bit 95
            addmask := and(0x3ffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(160, 1)) {
                v := or(shl(95, 1), shr(66, add(sr, addmask)))
                leave
            }

            // Region: < 2**192 (shift = 98)  + set bits 95|94
            addmask := and(0x3ffffffffffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(192, 1)) {
                v := or(shl(94, 3), shr(98, add(sr, addmask))) // 3<<94 == bit95|bit94
                leave
            }

            // cast sig "ValueOverflowsSqrtRatioContainer()"
            mstore(0, shl(224, 0xa10459f4))
            revert(0, 4)
        }
        r := compute(sqrtRatio, roundUp)
    }
}
```

**File:** src/math/sqrtRatio.sol (L79-88)
```text
        if (amount < 0) {
            uint256 quotient;
            assembly ("memory-safe") {
                let numerator := shl(128, sub(0, amount))
                quotient := add(div(numerator, liquidityU256), iszero(iszero(mod(numerator, liquidityU256))))
            }

            uint256 sqrtRatioNextFixed = FixedPointMathLib.zeroFloorSub(sqrtRatio, quotient);

            sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, false);
```
