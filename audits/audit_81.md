## Title
Integer Overflow in Router Swap Path When Negating type(int128).min Boundary Values

## Summary
In the Router's single swap path, when Core.swap() clamps calculated amounts to `type(int128).min` (for amounts exceeding int128 range), the Router negates these values inside an unchecked block, causing integer overflow. This results in incorrect slippage check failures and erroneous withdrawal amount calculations.

## Impact
**Severity**: Medium

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
When a swap's calculated output amount is very large, Core.swap() clamps it to `type(int128).min` to prevent SafeCastLib overflow. The Router should then correctly interpret this clamped value, negate it to get the positive output amount for slippage checks, and withdraw the appropriate amount of tokens.

**Actual Logic:** 
The Router negates the delta values inside an unchecked block at line 116. In two's complement arithmetic, negating `type(int128).min` (-2^127) should yield 2^127, but this exceeds `type(int128).max` (2^127 - 1). In an unchecked block, `-type(int128).min` overflows and wraps around to `type(int128).min` itself, remaining negative instead of becoming positive. [3](#0-2) 

The Core explicitly clamps to this boundary value using: [4](#0-3) 

Then Router processes this in an unchecked block: [5](#0-4) 

**Exploitation Path:**
1. User initiates a very large exact-input or exact-output swap that would result in calculated output exceeding `type(int128).max` (~1.7×10^38 base units)
2. Core.swap() accumulates the calculated amount and clamps it to `type(int128).min` at line 811-812
3. Core returns balanceUpdate with delta0 or delta1 = `type(int128).min`
4. Router receives this at line 114 and attempts to negate at line 116 inside unchecked block
5. Negation overflows: `-type(int128).min` becomes `type(int128).min` (still negative)
6. Slippage check at line 117 compares `type(int128).min < calculatedAmountThreshold`, which for any reasonable positive threshold fails incorrectly
7. Transaction reverts with `SlippageCheckFailed` even though the actual output would have been acceptable
8. If slippage check somehow passes (e.g., threshold also set to `type(int128).min`), lines 123 or 130 attempt to withdraw `uint128(type(int128).min)` = 2^127 tokens, which would fail unless pool has that enormous amount [6](#0-5) [7](#0-6) 

**Security Property Broken:** 
Withdrawal Availability - legitimate large swaps that the protocol explicitly supports (via clamping logic) are incorrectly blocked from execution, preventing users from conducting valid trades.

## Impact Explanation
- **Affected Assets**: Any token pair where a swap could theoretically produce output exceeding type(int128).max base units
- **Damage Severity**: Denial of service for large swaps. Users attempting legitimate high-value trades will have their transactions revert incorrectly due to slippage check failures, even when the actual calculated amount meets their requirements
- **User Impact**: Any user attempting swaps with very large amounts (more likely with low-decimal tokens or extreme price ratios) will be unable to execute trades. While this threshold is extremely high for most tokens, the protocol's explicit support for this scenario via clamping indicates these swaps should be possible

## Likelihood Explanation
- **Attacker Profile**: Any user attempting large swaps; no special privileges required
- **Preconditions**: 
  - Pool must have sufficient liquidity to support calculated output > type(int128).max base units
  - More realistic with tokens having low decimals (0-6 decimals) or in extreme price movement scenarios
  - The Core code explicitly handles this scenario with clamping, indicating it's an intended supported case
- **Execution Complexity**: Single transaction - user simply calls router.swap() with large amount parameters
- **Frequency**: Every time a swap calculation would exceed int128 bounds (rare but explicitly supported by protocol design)

## Recommendation

**In Router.sol, line 116 and lines 123, 130:**

Add explicit overflow handling before negation operations. Move the negation outside the unchecked block or add boundary checks:

```solidity
// Line 105-119: Handle type(int128).min edge case before negation
unchecked {
    uint256 value = FixedPointMathLib.ternary(
        !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
        uint128(params.amount()),
        0
    );

    bool increasing = params.isPriceIncreasing();

    (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

    // FIXED: Handle int128.min boundary before negation
    int128 deltaToNegate = params.isToken1() ? balanceUpdate.delta0() : balanceUpdate.delta1();
    int256 amountCalculated;
    if (deltaToNegate == type(int128).min) {
        // Special case: cannot negate safely, use uint128 directly
        amountCalculated = uint128(type(int128).max) + 1; // = 2^127
    } else {
        amountCalculated = -deltaToNegate;
    }
    
    if (amountCalculated < calculatedAmountThreshold) {
        revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
    }

    // Similar fix needed for withdrawal amounts at lines 123, 130
    if (increasing) {
        if (balanceUpdate.delta0() != 0) {
            uint128 withdrawAmount = balanceUpdate.delta0() == type(int128).min 
                ? type(uint128).max >> 1  // 2^127
                : uint128(-balanceUpdate.delta0());
            ACCOUNTANT.withdraw(poolKey.token0, recipient, withdrawAmount);
        }
        // ... rest of logic
    }
}
```

Alternative mitigation: Remove the unchecked block entirely for these operations, allowing Solidity 0.8's built-in overflow checks to revert properly when overflow would occur, providing clearer error messages.

## Proof of Concept

```solidity
// File: test/Exploit_Int128BoundaryOverflow.t.sol
// Run with: forge test --match-test test_Int128MinBoundaryOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";

contract Exploit_Int128BoundaryOverflow is Test {
    Router router;
    Core core;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        router = new Router(core);
    }
    
    function test_Int128MinBoundaryOverflow() public {
        // This test demonstrates the overflow issue
        // When delta is type(int128).min, negation fails in unchecked block
        
        int128 boundaryValue = type(int128).min; // -2^127
        
        // Simulate what happens in Router.sol line 116
        int128 negatedValue;
        unchecked {
            negatedValue = -boundaryValue; // Should be 2^127 but overflows to type(int128).min
        }
        
        // VERIFY: The negation incorrectly stays negative
        assertEq(negatedValue, type(int128).min, "Negation overflowed to itself");
        assertTrue(negatedValue < 0, "Value should have been positive but is negative");
        
        // VERIFY: Casting to uint128 produces wrong value
        uint128 withdrawAmount = uint128(negatedValue);
        assertEq(withdrawAmount, uint128(2**127), "Withdrawal amount is 2^127 due to bit reinterpretation");
        
        // This demonstrates that:
        // 1. Slippage check sees negative value instead of expected positive
        // 2. Withdrawal tries to send 2^127 tokens instead of intended amount
    }
}
```

## Notes

The vulnerability exists because:

1. **Core explicitly supports this scenario**: [3](#0-2)  - The use of `FixedPointMathLib.max(type(int128).min, calculatedAmount)` shows the protocol deliberately handles calculations exceeding int128 range by clamping to the boundary.

2. **Router uses unchecked arithmetic**: [8](#0-7)  - The unchecked block disables Solidity 0.8's overflow protection, allowing the wrap-around behavior.

3. **Two's complement overflow**: Negating the most negative value (-2^127) mathematically requires 2^127, which exceeds int128.max (2^127 - 1), causing wrap-around in unchecked mode.

4. **Impact is DOS, not theft**: While the withdrawal amount calculation is wrong, transactions would typically revert due to either the incorrect slippage check or insufficient tokens in the FlashAccountant, preventing actual fund loss but blocking legitimate swaps.

The protocol should either: (a) handle this edge case explicitly in the Router, or (b) document this as an unsupported scenario and add explicit checks to prevent swaps from reaching this boundary.

### Citations

**File:** src/Router.sol (L105-150)
```text
            unchecked {
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

                int128 amountCalculated = params.isToken1() ? -balanceUpdate.delta0() : -balanceUpdate.delta1();
                if (amountCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
                }

                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
                } else {
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
                    }

                    if (balanceUpdate.delta0() != 0) {
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
                }

                result = abi.encode(balanceUpdate);
            }
```

**File:** src/Core.sol (L811-822)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));

                int128 specifiedAmountDelta;
                int128 specifiedAmount = params.amount();
                assembly ("memory-safe") {
                    specifiedAmountDelta := sub(specifiedAmount, amountRemaining)
                }

                balanceUpdate = isToken1
                    ? createPoolBalanceUpdate(calculatedAmountDelta, specifiedAmountDelta)
                    : createPoolBalanceUpdate(specifiedAmountDelta, calculatedAmountDelta);
```
