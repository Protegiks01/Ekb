# Audit Report

## Title
Payment Tracking State Leakage Allows Nested Locks to Steal Credits from Outer Locks

## Summary
The `startPayments()` and `completePayments()` functions in FlashAccountant use global transient storage slots that are not scoped by lock ID. This allows a nested lock created during reentrancy to consume payment tracking state set by an outer lock, enabling theft of user funds through misdirected payment credits.

## Impact
**Severity**: High

Direct theft of user funds combined with denial of service. An attacker can steal 100% of tokens that victims transfer to the accountant during lock operations by exploiting reentrancy during `withdraw()` callbacks. The victim's transaction reverts with `DebtsNotZeroed`, while the attacker extracts tokens without settling their corresponding debt, violating the flash accounting invariant.

## Finding Description

**Location:** `src/base/FlashAccountant.sol`, functions `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319)

**Intended Logic:** 
The payment tracking system allows users to credit tokens to their lock's debt by calling `startPayments()` before transferring tokens, then `completePayments()` afterward. The payment amount should be calculated as the balance difference and credited to the same lock that initiated the payment.

**Actual Logic:**
Payment tracking state is stored in a global transient storage slot per token without lock ID scoping. [1](#0-0) 

In contrast, debt tracking IS properly scoped by lock ID: [2](#0-1) 

When `completePayments()` executes, it reads the current lock ID, then reads and clears the global payment slot, and finally credits the payment to the current lock's debt: [3](#0-2) [4](#0-3) [5](#0-4) 

This means any nested lock can consume the payment tracking state set by an outer lock.

**Exploitation Path:**

1. **Victim initiates lock (ID 0):** Victim calls `lock()` and inside the callback calls `startPayments([USDC])`, storing the current USDC balance in global slot `_PAYMENT_TOKEN_ADDRESS_OFFSET + USDC`

2. **Victim transfers tokens:** Victim transfers 1000 USDC to the accountant, increasing its balance

3. **Victim calls withdraw():** Victim calls `withdraw()` to send 1 ETH to an attacker-controlled address

4. **Reentrancy trigger:** During the ETH transfer, the attacker's `receive()` function executes: [6](#0-5) 

5. **Attacker creates nested lock (ID 1):** Inside the callback, attacker calls `lock()` again, creating a nested lock with incremented ID

6. **Attacker steals payment credit:** Inside the nested lock's callback, attacker calls `completePayments([USDC])`:
   - Reads victim's stored balance from the global payment slot
   - Clears the global payment slot to 0
   - Calculates payment based on victim's tracked balance
   - Credits payment to lock ID 1's debt (attacker's lock)

7. **Attacker extracts tokens:** Attacker withdraws 1000 USDC using the stolen credit and exits nested lock with zero debt

8. **Victim's lock fails:** When control returns to victim's lock (ID 0), `completePayments([USDC])` reads 0 from the cleared slot, provides no credit, and the lock reverts with `DebtsNotZeroed(0)`

**Security Guarantee Broken:**
This violates the flash accounting invariant that all flash loans must be repaid within the same transaction with proper accounting. Payment credits are misdirected to the wrong lock, allowing attackers to withdraw tokens without settling corresponding debt.

## Impact Explanation

**Affected Assets**: All ERC20 tokens used with the `startPayments()/completePayments()` flow

**Damage Severity**:
- Attacker steals 100% of tokens that victims transfer to the accountant during payment tracking
- Victim's transaction reverts (denial of service)
- Attacker extracts tokens without paying corresponding debt
- Protocol's flash accounting invariant is violated

**User Impact**: Any user performing operations involving `startPayments()` → token transfer → `withdraw()` to an attacker-controlled address. This includes LP operations, swaps, and position management where callbacks occur to attacker-controlled addresses.

**Trigger Conditions**: Requires victim to withdraw ETH or tokens to attacker address during their lock operation - common in routing/swap scenarios where tokens are sent to user-specified recipients.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user who can receive ETH or tokens during a `withdraw()` callback

**Preconditions**:
1. Victim uses `startPayments()/completePayments()` flow
2. Victim calls `withdraw()` to transfer to attacker-controlled address during their lock
3. Attacker implements malicious `receive()` or transfer callback

**Execution Complexity**: Single transaction with reentrancy via callback. Straightforward to execute once victim triggers `withdraw()` to attacker's address.

**Economic Cost**: Only gas fees required, no capital lockup

**Frequency**: Exploitable on every transaction where victim sends ETH/tokens to attacker address within their lock

**Overall Likelihood**: HIGH - Common preconditions, trivial execution

## Recommendation

Scope payment tracking storage by lock ID to prevent cross-lock contamination:

In `startPayments()` at line 249, include lock ID in slot calculation:
```solidity
let lockerId := shr(160, tload(_CURRENT_LOCKER_SLOT))
let paymentSlot := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, lockerId), token))
tstore(paymentSlot, add(tokenBalance, success))
```

In `completePayments()` at line 267, use the same lock-scoped slot:
```solidity
let paymentSlot := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
let offset := paymentSlot
```

This ensures each lock's payment tracking state is isolated and cannot be accessed or cleared by nested locks.

## Proof of Concept

The provided PoC demonstrates:
1. Victim starts payment tracking and transfers 1000 tokens
2. Victim withdraws ETH to attacker, triggering reentrancy
3. Attacker creates nested lock and steals payment credit
4. Attacker withdraws stolen tokens and exits with zero debt
5. Victim's lock reverts with `DebtsNotZeroed(0)`
6. Attacker successfully extracted 1000 tokens without paying debt

**Expected Result**: 
- Victim transaction reverts
- Attacker balance increases by 1000 tokens
- Tokens remain in accountant but credit was stolen

## Notes

The vulnerability exists because payment tracking was optimized using global transient storage per token, breaking isolation between nested locks. The developers acknowledged reentrancy at line 345-347 and claimed safety due to delta-based updates to `nzdCountChange`: [7](#0-6) 

However, this safety guarantee only applies to the local `nzdCountChange` variable, NOT to payment tracking slots in transient storage. The payment tracking slots (`_PAYMENT_TOKEN_ADDRESS_OFFSET + token`) can be consumed by any lock calling `completePayments()`, enabling the attack.

Debt tracking itself is properly scoped by lock ID, preventing direct debt manipulation. However, the payment tracking bypass allows attackers to credit debt incorrectly, achieving the same effect of stealing funds.

### Citations

**File:** src/base/FlashAccountant.sol (L69-69)
```text
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
```

**File:** src/base/FlashAccountant.sol (L249-249)
```text
                tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))
```

**File:** src/base/FlashAccountant.sol (L258-258)
```text
        uint256 id = _getLocker().id();
```

**File:** src/base/FlashAccountant.sol (L267-269)
```text
                let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token)
                let lastBalance := tload(offset)
                tstore(offset, 0)
```

**File:** src/base/FlashAccountant.sol (L299-307)
```text
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)

                    // never overflows because of the payment overflow check that bounds payment to 128 bits
                    let next := sub(current, payment)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)
```

**File:** src/base/FlashAccountant.sol (L345-347)
```text
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
```

**File:** src/base/FlashAccountant.sol (L349-355)
```text
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
```
