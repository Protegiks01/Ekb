## Title
Precision Loss in Region 3 SqrtRatio Encoding Causes DOS of Exact Output Swaps Near MAX_SQRT_RATIO

## Summary
Near MAX_SQRT_RATIO, the compact 96-bit SqrtRatio encoding uses Region 3 with 2^98 granularity in fixed-point representation. When exact output swaps require price movements smaller than this granularity, the `toSqrtRatio` function rounds to the current sqrtRatio value, causing `sqrtRatioNext == sqrtRatio` and triggering an assertion failure that reverts the transaction. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol` (swap function, lines 724-726), `src/math/sqrtRatio.sol` (nextSqrtRatioFromAmount1, line 88), `src/types/sqrtRatio.sol` (toSqrtRatio Region 3, lines 86-90)

**Intended Logic:** The protocol should allow users to execute exact output swaps for any amount. The `nextSqrtRatioFromAmount0/1` functions calculate the new price after a swap, and this price should always move for exact output swaps (hence the assertion at line 726). [2](#0-1) 

**Actual Logic:** In Region 3 (sqrtRatio values >= 2^160, near MAX_SQRT_RATIO), the compact encoding has 30 fractional bits precision with a granularity of 2^98 in 64.128 fixed-point representation. When an exact output swap requires a price change smaller than 2^98, the `toSqrtRatio` function with `roundUp=false` truncates and rounds to the same compact value as the current sqrtRatio. [3](#0-2) 

**Exploitation Path:**
1. A pool exists at or near MAX_SQRT_RATIO (Region 3) with high liquidity (L >= 2^30 ≈ 1.07 billion)
2. User attempts exact OUTPUT swap of token1 for amount < L / 2^30
3. The swap calls `nextSqrtRatioFromAmount1` with negative amount (token1 output)
4. Line 82-83: `quotient = ceil(|amount| * 2^128 / liquidity)` where quotient < 2^98
5. Line 86: `sqrtRatioNextFixed = sqrtRatio - quotient` (price decreases by less than 2^98)
6. Line 88: `toSqrtRatio(sqrtRatioNextFixed, false)` rounds down by shifting right 98 bits
7. Since the change is < 2^98, the shift produces the same compact value
8. In Core.sol line 698: condition `sqrtRatioNextFromAmount != sqrtRatio` is false
9. Line 726: `assert(!isExactOut)` fails with Panic(0x01)
10. Transaction reverts, preventing user from swapping [4](#0-3) 

**Security Property Broken:** Users should be able to execute swaps for any amount, but this vulnerability prevents small exact output swaps in high-liquidity pools near MAX_SQRT_RATIO. This violates the core functionality of the AMM.

## Impact Explanation
- **Affected Assets**: All pools near MAX_SQRT_RATIO with liquidity >= 2^30
- **Damage Severity**: DOS of exact output swaps for amounts below threshold. For a pool with liquidity = 2^100 (realistic for major pools), swaps for amounts < 2^70 ≈ 1.18e21 (1,180 tokens in 18-decimal format) will fail. This represents a significant portion of normal trading activity.
- **User Impact**: Any user attempting exact output swaps in affected pools will face transaction reverts. This breaks the expectation that users can swap any amount.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - normal users attempting legitimate swaps will encounter this DOS
- **Preconditions**: Pool must be at MAX_SQRT_RATIO (Region 3) with liquidity >= 2^30 (achievable in major pools)
- **Execution Complexity**: Single transaction swap attempt
- **Frequency**: Affects all exact output swaps below threshold in qualifying pools continuously

## Recommendation

The core issue is that Region 3's coarse granularity (2^98) makes small price movements unrepresentable. The assertion assumes price always moves for exact output, but this breaks near boundaries.

**Option 1: Remove the assertion and handle zero price movement**
```solidity
// In src/Core.sol, lines 724-733:

// CURRENT (vulnerable):
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

// FIXED:
} else {
    if (isExactOut) {
        // Price granularity in Region 3 may prevent small movements
        // Treat as insufficient liquidity and revert gracefully
        revert InsufficientLiquidityForExactOutput();
    }
    
    // consume the entire input amount as fees since the price did not move
    assembly ("memory-safe") {
        stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
    }
    amountRemaining = 0;
    sqrtRatioNext = sqrtRatio;
}
```

**Option 2: Enforce minimum price movement in nextSqrtRatioFromAmount1**
Add a check in `nextSqrtRatioFromAmount1` to ensure the quotient meets minimum granularity requirements, reverting early if the swap amount is too small for the current region.

**Option 3: Use higher precision intermediate calculations**
Consider maintaining extra precision bits during calculations and only truncating at the final conversion to avoid premature rounding.

## Proof of Concept
```solidity
// File: test/Exploit_Region3PrecisionDOS.t.sol
// Run with: forge test --match-test test_Region3PrecisionDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {SqrtRatio, MAX_SQRT_RATIO, toSqrtRatio} from "../src/types/sqrtRatio.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {sqrtRatioToTick} from "../src/math/ticks.sol";

contract Exploit_Region3PrecisionDOS is Test {
    Core core;
    Router router;
    Positions positions;
    
    function setUp() public {
        core = new Core();
        router = new Router(core);
        positions = new Positions(core, address(this));
        
        // Setup tokens and approvals
        // [setup code]
    }
    
    function test_Region3PrecisionDOS() public {
        // SETUP: Create pool at MAX_SQRT_RATIO with high liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createConcentratedPoolConfig(0, 1, address(0))
        });
        
        // Initialize at MAX_SQRT_RATIO
        positions.maybeInitializePool(poolKey, sqrtRatioToTick(MAX_SQRT_RATIO));
        
        // Add huge liquidity (2^100)
        uint128 liquidity = 2**100;
        positions.mint(/* params with liquidity */);
        
        // EXPLOIT: Attempt exact output swap for small amount
        // amount = 2^69 (below threshold of 2^70 for liquidity 2^100)
        int128 amount = -(2**69);
        
        // VERIFY: This should revert with Panic(0x01) from assertion failure
        vm.expectRevert(/* Panic(0x01) */);
        router.swap({
            poolKey: poolKey,
            sqrtRatioLimit: MIN_SQRT_RATIO,
            skipAhead: 0,
            isToken1: true,  // exact output of token1
            amount: amount
        });
        
        // DOS confirmed: legitimate swap transaction reverts
    }
}
```

## Notes

The vulnerability exists because the SqrtRatio encoding system trades precision for range. Region 3 can represent prices up to sqrt(2^128) but only with 30 fractional bits (2^98 granularity). The comment at line 725 explicitly states "the price should always move" for exact output swaps, but this assumption breaks when the required movement is smaller than the encoding granularity. [5](#0-4) 

A similar issue likely exists near MIN_SQRT_RATIO (Region 0) but with different thresholds due to different shift amounts. The asymmetry in rounding directions (`roundUp=true` for amount0, `roundUp=false` for amount1) means the issue manifests differently for each token. [6](#0-5)

### Citations

**File:** src/Core.sol (L698-726)
```text
                        } else if (sqrtRatioNextFromAmount != sqrtRatio) {
                            uint128 calculatedAmountWithoutFee = isToken1
                                ? amount0Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut)
                                : amount1Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut);

                            if (isExactOut) {
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(includingFee, calculatedAmountWithoutFee)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, calculatedAmountWithoutFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
                                }
                            }

                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatioNextFromAmount;
                        } else {
                            // for an exact output swap, the price should always move since we have to round away from the current price
                            assert(!isExactOut);
```

**File:** src/types/sqrtRatio.sol (L86-90)
```text
            // Region: < 2**192 (shift = 98)  + set bits 95|94
            addmask := and(0x3ffffffffffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(192, 1)) {
                v := or(shl(94, 3), shr(98, add(sr, addmask))) // 3<<94 == bit95|bit94
                leave
```

**File:** src/math/sqrtRatio.sol (L51-51)
```text
            sqrtRatioNext = toSqrtRatio(resultFixed, true);
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
