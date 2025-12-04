# Audit Report

## Title
Integer Boundary Asymmetry in TokenWrapper Causes Permanent Token Lock for Amounts at 2^127

## Summary
TokenWrapper.handleForwardData() contains an integer boundary asymmetry where wrapping exactly 2^127 token units succeeds but unwrapping permanently fails due to SafeCastLib overflow, causing irreversible loss of user funds with no recovery mechanism.

## Impact
**Severity**: High

Users who wrap exactly 2^127 token units (type(int128).max + 1) lose permanent access to their underlying tokens. The tokens become locked in the Core contract with no recovery path, even after the unlock time expires. This represents 100% permanent loss of the wrapped amount.

## Finding Description

**Location:** `src/TokenWrapper.sol:163-182`, function `handleForwardData()` [1](#0-0) 

**Intended Logic:**
According to the function documentation at lines 158-160, wrapped tokens should be unwrappable after the unlock time expires: "For unwrap: the specified amount of the underlying will be credited to the locker and the same amount of this wrapper token will be debited, iff block.timestamp > unlockTime and at least that much token has been wrapped." [2](#0-1) 

**Actual Logic:**
The function uses `SafeCastLib.toInt128(-amount)` at line 179 for both operations. Due to two's complement asymmetry in int128 representation:
- int128 range: [-2^127, 2^127-1]
- type(int128).min = -2^127 (valid)
- type(int128).max = 2^127-1 (valid)

When wrapping with amount = 2^127:
- Line 179 calculates: `SafeCastLib.toInt128(-2^127)`
- Result: -2^127 = type(int128).min ✓ (valid int128)

When unwrapping with amount = -2^127:
- Line 179 calculates: `SafeCastLib.toInt128(-(-2^127))` = `SafeCastLib.toInt128(2^127)`
- Result: 2^127 > type(int128).max ✗ (overflow, reverts)

**Exploitation Path:**
1. User initiates wrap by calling Core.lock() which forwards to TokenWrapper with amount = 2^127
2. Line 171-177: updateSavedBalances succeeds (2^127 < uint128.max)
3. Line 179: SafeCastLib.toInt128(-2^127) succeeds (equals type(int128).min)
4. Wrap completes, user receives 2^127 wrapper tokens
5. After unlock time, user attempts unwrap with amount = -2^127
6. Line 167-169: Timestamp check passes
7. Line 171-177: updateSavedBalances would succeed
8. Line 179: SafeCastLib.toInt128(2^127) reverts with overflow
9. Unwrap permanently fails - tokens irretrievably locked

**Security Property Broken:**
Violates README line 202 principle that positions should be withdrawable. While TokenWrapper isn't technically a position, the design intent that wrapped tokens become unwrappable after unlock time is violated.

**Code Evidence:**
The vulnerability exists at the SafeCastLib.toInt128 call on line 179: [3](#0-2) 

**Supporting Evidence from Test Suite:**
The existing test file deliberately bounds wrap amounts to type(int128).max, proving developers recognized this as the safe limit but failed to enforce it in the contract: [4](#0-3) [5](#0-4) 

## Impact Explanation

**Affected Assets**: Any ERC20 token wrapped via TokenWrapper with amount = 2^127 raw units
- For 18-decimal tokens: ~170 billion tokens
- For 6-decimal tokens: ~170 quintillion tokens (unrealistic)
- More realistic for high-supply tokens with fewer decimals

**Damage Severity**:
- 100% permanent loss of wrapped tokens
- Tokens locked in Core contract forever
- No admin functions or emergency withdrawal mechanisms exist
- Affects individual users who wrap this specific boundary amount

**User Impact**: Any user wrapping exactly 2^127 token units loses permanent access to underlying tokens. While the amount is large, it's within valid int256 range and could be attempted by users testing maximum safe values or automated systems.

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient tokens; no special privileges required

**Preconditions**:
1. TokenWrapper deployed (any underlying token, any unlock time)
2. User has 2^127 units of underlying token
3. No other special state required

**Execution Complexity**: Single wrap transaction succeeds via normal contract interaction. Subsequent unwrap attempts permanently fail.

**Economic Cost**: Only gas fees for initial wrap transaction

**Frequency**: Deterministic failure for this exact boundary value. While 2^127 is large for most tokens, it represents the maximum "safe" looking value (type(int128).max + 1) that users testing boundaries might attempt.

**Overall Likelihood**: Medium - Requires specific boundary value but no other constraints

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

This ensures wrapped amounts stay within the range where negation fits in int128 for both wrap and unwrap operations.

## Notes

This vulnerability exists due to the asymmetry in two's complement integer representation where the negative range includes one more value than the positive range. The contract allows wrapping at the boundary where `-amount` equals type(int128).min (valid), but prevents unwrapping where `-amount` equals type(int128).max + 1 (invalid).

The existing test suite's deliberate bounding to type(int128).max confirms this is a bug rather than intended behavior. The fix is straightforward: validate amounts stay within symmetric int128 bounds before the negation operation.

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
