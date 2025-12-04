# Audit Report

## Title
Integer Boundary Asymmetry in TokenWrapper Causes Permanent Token Lock for Amounts at 2^127

## Summary
The `TokenWrapper.handleForwardData()` function contains a critical integer boundary asymmetry where wrapping exactly 2^127 token units succeeds but unwrapping permanently fails due to SafeCastLib overflow. This creates an irreversible one-way door that violates the contract's documented design guarantee, causing 100% permanent loss of user funds with no recovery mechanism.

## Impact
**Severity**: High

Users who wrap exactly 2^127 token units lose permanent access to their underlying tokens. The tokens become permanently locked in the Core contract with no recovery path, even after the unlock time expires. This represents 100% permanent loss of the wrapped amount and directly violates the contract's documented guarantee that wrapped tokens are unwrappable after the unlock time.

## Finding Description

**Location:** `src/TokenWrapper.sol:163-182`, function `handleForwardData()` [1](#0-0) 

**Intended Logic:**
According to the function documentation, wrapped tokens should be unwrappable after the unlock time expires: "For unwrap: the specified amount of the underlying will be credited to the locker and the same amount of this wrapper token will be debited, iff block.timestamp > unlockTime and at least that much token has been wrapped." [2](#0-1) 

**Actual Logic:**
The function uses `SafeCastLib.toInt128(-amount)` at line 179 for both wrap and unwrap operations. Due to two's complement asymmetry in int128 representation:
- int128 range: [-2^127, 2^127-1]
- type(int128).min = -2^127 (valid)
- type(int128).max = 2^127-1 (valid)

**Wrap Operation (amount = 2^127):**
- Line 179 calculates: `SafeCastLib.toInt128(-2^127)`
- Result: -2^127 = type(int128).min ✓ (valid int128, succeeds)

**Unwrap Operation (amount = -2^127):**
- Line 179 calculates: `SafeCastLib.toInt128(-(-2^127))` = `SafeCastLib.toInt128(2^127)`
- Result: 2^127 > type(int128).max ✗ (overflow, reverts)

**Exploitation Path:**
1. User calls wrap operation with amount = 2^127 through TokenWrapperPeriphery
2. TokenWrapper.handleForwardData receives positive amount = 2^127
3. Line 171-177: `updateSavedBalances` succeeds (2^127 < uint128.max)
4. Line 179: `SafeCastLib.toInt128(-2^127)` succeeds (equals type(int128).min)
5. Wrap completes successfully, user receives 2^127 wrapper tokens
6. After unlock time expires, user attempts unwrap with amount = -2^127
7. Line 167-168: Timestamp check passes
8. Line 171-177: `updateSavedBalances` would succeed
9. Line 179: `SafeCastLib.toInt128(2^127)` reverts with SafeCastLib.Overflow
10. Unwrap permanently fails - tokens irretrievably locked in Core contract

**Security Property Broken:**
Violates the documented design guarantee that wrapped tokens become unwrappable after the unlock time expires. The contract allows an operation (wrap) that can never be reversed (unwrap), despite the documentation explicitly stating this should be possible.

**Code Evidence:**
The vulnerability exists at the SafeCastLib.toInt128 call: [3](#0-2) 

**Supporting Evidence from Test Suite:**
The test file deliberately bounds wrap amounts to `type(int128).max`, proving developers recognized this as the safe limit but failed to enforce it in the production contract: [4](#0-3) [5](#0-4) 

**Comparison with Other Protocol Contracts:**
BasePositions explicitly validates this boundary with custom errors, demonstrating that the protocol is aware of this limitation and validates it elsewhere: [6](#0-5) [7](#0-6) 

## Impact Explanation

**Affected Assets**: Any ERC20 token wrapped via TokenWrapper with amount = 2^127 raw units
- For 18-decimal tokens: ~170 billion tokens
- For 6-decimal tokens: ~170 quintillion tokens
- More realistic for high-supply tokens with fewer decimals or users testing boundary values

**Damage Severity**:
- 100% permanent loss of wrapped tokens for affected users
- Tokens locked in Core contract forever with no recovery mechanism
- No admin functions or emergency withdrawal capabilities exist in TokenWrapper
- Violates core design guarantee documented in the contract

**User Impact**: Any user wrapping exactly 2^127 token units loses permanent access to their underlying tokens. While the amount is large, it's within valid int256 range and represents the boundary value (type(int128).max + 1) that users testing maximum safe values or automated systems might attempt.

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient tokens; no special privileges required

**Preconditions**:
1. TokenWrapper deployed for any underlying token
2. User has 2^127 units of underlying token
3. No other special state or timing requirements

**Execution Complexity**: Single wrap transaction succeeds via normal contract interaction. Subsequent unwrap attempts permanently fail after unlock time.

**Economic Cost**: Only gas fees for initial wrap transaction

**Frequency**: Deterministic failure for this exact boundary value. While 2^127 is large for most tokens, it represents the maximum "safe-looking" value (type(int128).max + 1) that boundary-testing users might attempt.

**Overall Likelihood**: Medium - Requires specific boundary value but no other preconditions or special states

## Recommendation

Add explicit validation to enforce symmetric int128 bounds:

```solidity
// In src/TokenWrapper.sol, function handleForwardData, after line 164:

(int256 amount) = abi.decode(data, (int256));

// Enforce symmetric int128 bounds to ensure both wrap and unwrap succeed
if (amount > int256(uint256(uint128(type(int128).max)))) {
    revert AmountTooLarge();
}

if (amount < -int256(uint256(uint128(type(int128).max)))) {
    revert AmountTooLarge();
}

// unwrap
if (amount < 0) {
    if (block.timestamp < UNLOCK_TIME) revert TooEarly();
}
```

Add custom error:
```solidity
error AmountTooLarge();
```

This ensures wrapped amounts stay within the range where negation fits in int128 for both wrap and unwrap operations, matching the validation pattern used in BasePositions.

## Notes

This vulnerability exists due to the asymmetry in two's complement integer representation where the negative range includes one more value (-2^127) than the positive range (up to 2^127-1). The contract allows wrapping at the boundary where `-amount` equals type(int128).min (valid), but prevents unwrapping where `-amount` would equal type(int128).max + 1 (invalid).

The test suite's deliberate bounding to `type(int128).max` and BasePositions' explicit validation of this boundary with `DepositOverflow` and `WithdrawOverflow` errors confirm this is a bug rather than intended behavior. The missing validation in TokenWrapper represents an oversight that breaks the documented design guarantee of unwrappability after unlock time.

### Citations

**File:** src/TokenWrapper.sol (L158-161)
```text
    /// @dev Encode (int256 delta) in the forwarded data, where a positive amount means wrapping and a negative amount means unwrapping
    /// For wrap: the specified amount of this wrapper token will be credited to the locker and the same amount of underlying will be debited
    /// For unwrap: the specified amount of the underlying will be credited to the locker and the same amount of this wrapper token will be debited, iff block.timestamp > unlockTime and at least that much token has been wrapped
    /// @param data Encoded int256 delta (positive for wrap, negative for unwrap)
```

**File:** src/TokenWrapper.sol (L163-182)
```text
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory) {
        (int256 amount) = abi.decode(data, (int256));

        // unwrap
        if (amount < 0) {
            if (block.timestamp < UNLOCK_TIME) revert TooEarly();
        }

        CORE.updateSavedBalances({
            token0: address(UNDERLYING_TOKEN),
            token1: address(type(uint160).max),
            salt: bytes32(0),
            delta0: amount,
            delta1: 0
        });

        CORE.updateDebt(SafeCastLib.toInt128(-amount));

        return bytes("");
    }
```

**File:** test/TokenWrapper.t.sol (L115-115)
```text
        wrapAmount = uint128(bound(wrapAmount, 0, uint128(type(int128).max)));
```

**File:** test/TokenWrapper.t.sol (L139-139)
```text
        wrapAmount = uint128(bound(wrapAmount, 1, uint128(type(int128).max)));
```

**File:** src/base/BasePositions.sol (L89-91)
```text
        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }
```

**File:** src/base/BasePositions.sol (L277-277)
```text
            if (liquidity > uint128(type(int128).max)) revert WithdrawOverflow();
```
