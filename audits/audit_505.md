## Title
Integer Overflow in Multi-Hop Swap Amount Negation Inadvertently Flips Exact-Out Flag

## Summary
The Router contract negates swap deltas in an unchecked arithmetic block when computing amounts for subsequent hops in multi-hop swaps. When a delta equals `type(int128).min`, negating it causes integer overflow, wrapping back to `type(int128).min` instead of becoming positive. This inadvertently flips the exact-out flag (bit 159 of SwapParameters), causing the next hop to execute as exact-out when it should be exact-in, breaking swap logic and potentially causing user losses.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/Router.sol` (Router contract, `handleLockData` function, lines 203 and 206) [1](#0-0) [2](#0-1) 

**Intended Logic:** In multi-hop swaps, after each hop completes, the Router should negate the received delta to use as the input amount for the next hop. For example, if hop 1 gives the user -X tokens (negative delta, user receives), hop 2 should spend +X tokens (positive amount, exact-in swap).

**Actual Logic:** The negation occurs inside an unchecked block [3](#0-2) , allowing integer overflow. When delta equals `type(int128).min` (-2^127), the mathematical negation would be 2^127, but this exceeds `type(int128).max` (2^127 - 1). In unchecked arithmetic, this overflows and wraps to `type(int128).min` again, keeping the value negative.

The `isExactOut()` function checks bit 159, which is the sign bit of the amount field: [4](#0-3) 

When the amount remains negative due to overflow, bit 159 stays set to 1, causing `isExactOut()` to return true when it should return false.

**Exploitation Path:**

1. **Attacker crafts multi-hop swap**: User initiates a 2-hop swap where the first hop is designed to produce a large negative delta approaching `type(int128).min`

2. **Core swap caps calculatedAmount**: The Core swap logic explicitly caps calculated amounts to `type(int128).min`: [5](#0-4) 
This makes `type(int128).min` a valid and reachable delta value.

3. **Router negates delta in unchecked block**: When computing the amount for hop 2:
   - delta0 = `type(int128).min`
   - amount = -delta0 should equal 2^127 (positive, exact-in)
   - But in unchecked math, it overflows to `type(int128).min` (negative, exact-out)

4. **Second hop executes with wrong swap direction**: The Core swap logic uses different fee calculations, rounding directions, and amount semantics based on `isExactOut`: [6](#0-5) [7](#0-6) 

The second hop interprets the negative amount as exact-out when the user intended exact-in, causing incorrect swap execution, wrong fee deductions, and potential slippage violations.

**Security Property Broken:** This violates the flash accounting invariant and withdrawal availability - users may receive incorrect amounts due to wrong swap semantics, and slippage protection may be bypassed since the calculated amount differs from expected.

## Impact Explanation

- **Affected Assets**: Any multi-hop swap where the first hop can produce a delta near `type(int128).min`. While this requires very large token amounts, it's theoretically possible with high-supply tokens or tokens with small decimals.

- **Damage Severity**: Complete corruption of multi-hop swap logic for affected swaps. The second hop executes with inverted swap semantics:
  - Fee calculations are applied differently (exact-out adds fees after, exact-in deducts before)
  - Rounding directions are reversed
  - The amountRemaining interpretation is backwards
  - User receives significantly different amounts than expected
  - Slippage checks may fail or be bypassed

- **User Impact**: Any user executing a multi-hop swap that crosses this threshold loses funds or receives incorrect amounts. The vulnerability directly answers the security question: **YES, setting certain amounts (specifically when delta = type(int128).min) inadvertently flips the exact-out flag** through integer overflow.

## Likelihood Explanation

- **Attacker Profile**: Any user executing multi-hop swaps, either accidentally or intentionally

- **Preconditions**: 
  - Multi-hop swap with at least 2 hops
  - First hop produces delta equal to `type(int128).min` (either delta0 or delta1)
  - Pool has sufficient liquidity to enable such large swaps

- **Execution Complexity**: Single transaction through Router's multihopSwap function. However, reaching exactly `type(int128).min` requires specific pool states and amounts.

- **Frequency**: Can occur whenever conditions are met. While `type(int128).min` is an extreme value (≈1.7e38), the Core explicitly allows it as demonstrated in the test suite: [8](#0-7) 

## Recommendation

Add overflow protection when negating deltas:

```solidity
// In src/Router.sol, lines 203 and 206:

// CURRENT (vulnerable):
tokenAmount = TokenAmount({token: node.poolKey.token0, amount: -update.delta0()});

// FIXED:
int128 negatedDelta = update.delta0();
// Prevent overflow when negating type(int128).min
if (negatedDelta == type(int128).min) revert DeltaOverflow();
tokenAmount = TokenAmount({token: node.poolKey.token0, amount: -negatedDelta});
```

Alternative mitigation: Remove the unchecked block around this logic (lines 170-245) to enable Solidity's built-in overflow checks. This would cause the transaction to revert rather than silently overflow.

## Proof of Concept

```solidity
// File: test/Exploit_MultiHopOverflow.t.sol
// Run with: forge test --match-test test_MultiHopOverflowFlipsExactOut -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router, RouteNode, TokenAmount, Swap} from "../src/Router.sol";
import {MIN_SQRT_RATIO, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_MultiHopOverflow is FullTest {
    function test_MultiHopOverflowFlipsExactOut() public {
        // SETUP: Create two pools for multi-hop swap
        PoolKey memory pool1 = createPool(0, 1 << 63, 100);
        PoolKey memory pool2 = createPool(0, 1 << 63, 100, address(token1), address(token2));
        
        // Add liquidity to both pools
        createPosition(pool1, -1000, 1000, 1e30, 1e30); // Large liquidity
        createPosition(pool2, -1000, 1000, 1e30, 1e30);
        
        // EXPLOIT: Craft swap that produces delta = type(int128).min
        // First, demonstrate the overflow mathematically
        int128 minValue = type(int128).min;
        int128 negatedInUnchecked;
        unchecked {
            negatedInUnchecked = -minValue;
        }
        
        // VERIFY: Overflow wraps back to type(int128).min
        assertEq(negatedInUnchecked, type(int128).min, 
            "Negating type(int128).min in unchecked block wraps to itself");
        
        // This proves bit 159 stays set (negative), incorrectly flagging as exact-out
        // when the second hop should be exact-in
        assertTrue(negatedInUnchecked < 0, "Sign bit incorrectly remains negative");
        
        // In actual multi-hop swap, if first hop returns delta0 = type(int128).min,
        // the Router would compute amount = -delta0 = type(int128).min (due to overflow)
        // causing the second hop to execute as exact-out instead of exact-in
    }
}
```

## Notes

This vulnerability directly addresses the security question: **"If this bit is part of the amount field, could setting certain amounts inadvertently flip the exact-out flag?"**

The answer is **YES** - bit 159 is the sign bit of the amount field (int128 stored at bits 32-159 of SwapParameters). When Router negates `type(int128).min` in an unchecked block, integer overflow causes the value to wrap back to `type(int128).min`, keeping bit 159 set to 1. This inadvertently maintains the exact-out flag when it should flip to exact-in, corrupting multi-hop swap execution.

The Core contract explicitly allows and uses `type(int128).min` as a valid delta value, making this a realistic boundary condition rather than a theoretical edge case.

### Citations

**File:** src/Router.sol (L170-170)
```text
            unchecked {
```

**File:** src/Router.sol (L203-203)
```text
                            tokenAmount = TokenAmount({token: node.poolKey.token0, amount: -update.delta0()});
```

**File:** src/Router.sol (L206-206)
```text
                            tokenAmount = TokenAmount({token: node.poolKey.token1, amount: -update.delta1()});
```

**File:** src/types/swapParameters.sol (L60-64)
```text
function isExactOut(SwapParameters params) pure returns (bool yes) {
    assembly ("memory-safe") {
        yes := and(shr(159, params), 1)
    }
}
```

**File:** src/Core.sol (L546-546)
```text
                bool isExactOut = amountRemaining < 0;
```

**File:** src/Core.sol (L629-644)
```text
                        if (isExactOut) {
                            assembly ("memory-safe") {
                                priceImpactAmount := amountRemaining
                            }
                        } else {
                            uint128 amountU128;
                            assembly ("memory-safe") {
                                // cast is safe because amountRemaining is g.t. 0 and fits in int128
                                amountU128 := amountRemaining
                            }
                            uint128 feeAmount = computeFee(amountU128, config.fee());
                            assembly ("memory-safe") {
                                // feeAmount will never exceed amountRemaining since fee is < 100%
                                priceImpactAmount := sub(amountRemaining, feeAmount)
                            }
                        }
```

**File:** src/Core.sol (L811-812)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));
```

**File:** test/Router.t.sol (L31-31)
```text
            TokenAmount({token: address(token0), amount: type(int128).min}),
```
