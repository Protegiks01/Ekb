# Audit Report

## Title
Payment Tracking State Leakage Allows Nested Locks to Steal Credits from Outer Locks

## Summary
The `startPayments()` and `completePayments()` functions in FlashAccountant use global transient storage slots that are not scoped by lock ID. This architectural flaw allows nested locks created during reentrancy to consume payment tracking state set by outer locks, enabling direct theft of user funds through misdirected payment credits that bypass the flash accounting invariant.

## Impact
**Severity**: High

Direct theft of user funds with complete loss of victim assets. An unprivileged attacker can steal 100% of tokens that victims transfer to the FlashAccountant during lock operations by exploiting reentrancy in `withdraw()` callbacks. The victim's transaction reverts with `DebtsNotZeroed` while the attacker extracts tokens without settling corresponding debt, violating the core flash accounting invariant that all debts must be properly tracked and settled within the same transaction.

## Finding Description

**Location:** `src/base/FlashAccountant.sol`, functions `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319)

**Intended Logic:** 
The payment tracking system allows users to credit tokens to their lock's debt by calling `startPayments()` before transferring tokens, then `completePayments()` afterward. The payment amount is calculated as the balance difference and should be credited exclusively to the lock that initiated the payment tracking, ensuring proper debt settlement for each isolated lock context.

**Actual Logic:**

Payment tracking state is stored in a global transient storage slot per token without lock ID scoping: [1](#0-0) 

In direct contrast, debt tracking IS properly scoped by lock ID: [2](#0-1) 

When `completePayments()` executes, it retrieves the current lock ID: [3](#0-2) 

Then reads and clears the global payment slot (not scoped by lock ID): [4](#0-3) 

Finally credits the payment to the current lock's debt: [5](#0-4) 

This mismatch means any nested lock can consume the payment tracking state set by an outer lock, stealing the payment credit.

**Exploitation Path:**

1. **Victim initiates lock (ID 0):** Victim calls `lock()` and inside the callback calls `startPayments([USDC])`, storing the current USDC balance in global slot `_PAYMENT_TOKEN_ADDRESS_OFFSET + USDC`

2. **Victim transfers tokens:** Victim transfers 1000 USDC to the FlashAccountant contract, increasing its USDC balance

3. **Victim calls withdraw():** Victim calls `withdraw()` to send 1 ETH to an attacker-controlled address as part of their operation

4. **Reentrancy trigger:** During the ETH transfer, the attacker's `receive()` function executes: [6](#0-5) 

5. **Attacker creates nested lock (ID 1):** Inside the callback, attacker calls `lock()` again, which increments the lock ID and creates a nested lock context

6. **Attacker steals payment credit:** Inside the nested lock's callback, attacker calls `completePayments([USDC])`:
   - Reads current lock ID = 1
   - Reads victim's stored balance from the global payment slot
   - Clears the global payment slot to 0
   - Calculates payment = current balance - stored balance = 1000 USDC
   - Credits 1000 USDC to lock ID 1's debt (attacker's lock)

7. **Attacker extracts tokens:** Attacker calls `withdraw()` to extract 1000 USDC using the stolen credit and exits nested lock with zero debt

8. **Victim's lock fails:** When control returns to victim's lock (ID 0), `completePayments([USDC])` reads 0 from the cleared slot, provides no credit, leaving victim with unpaid debt. The lock reverts with `DebtsNotZeroed(0)`.

**Security Guarantee Broken:**

This violates the flash accounting invariant that all flash loans must be repaid within the same transaction with proper per-lock accounting. Payment credits are misdirected from the outer lock to nested locks, allowing attackers to withdraw tokens without settling their corresponding debt while the victim who actually transferred the tokens receives no credit.

## Impact Explanation

**Affected Assets**: All ERC20 tokens and native ETH used with the `startPayments()/completePayments()` flow in FlashAccountant.

**Damage Severity**:
- Attacker steals 100% of tokens that victims transfer to the FlashAccountant during payment tracking operations
- Victim's transaction reverts with `DebtsNotZeroed`, resulting in denial of service
- Attacker extracts tokens without paying corresponding debt, violating core protocol invariant
- Protocol's flash accounting system is completely bypassed
- No recovery mechanism - funds are permanently lost once extracted by attacker

**User Impact**: Any user performing operations involving `startPayments()` → token transfer → `withdraw()` or any callback to an attacker-controlled address. This includes LP operations, swaps, position management, and any interaction where tokens are sent to user-specified recipients during a lock operation.

**Trigger Conditions**: Requires victim to withdraw ETH or tokens to an attacker-controlled address during their lock operation. This is common in routing/swap scenarios where tokens are sent to user-specified recipients, making the attack vector highly realistic.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user who can receive ETH or tokens during a `withdraw()` callback. No special permissions, positions, or capital required.

**Preconditions**:
1. Victim uses `startPayments()/completePayments()` flow (standard pattern for token transfers)
2. Victim calls `withdraw()` to transfer ETH/tokens to attacker-controlled address during their lock
3. Attacker implements malicious `receive()` or ERC20 transfer callback that reenters

**Execution Complexity**: Single transaction with reentrancy via callback. Straightforward to execute - attacker simply needs to be the recipient of a `withdraw()` call and implement reentrancy logic.

**Economic Cost**: Only gas fees required (~0.01-0.05 ETH), no capital lockup or liquidity requirements

**Frequency**: Exploitable on every transaction where victim sends ETH/tokens to attacker address within their lock. Can be repeated across multiple victims.

**Overall Likelihood**: HIGH - Common preconditions (users regularly withdraw to addresses), trivial execution complexity, minimal cost.

## Recommendation

**Primary Fix:**

Scope payment tracking storage by lock ID to prevent cross-lock contamination, mirroring the debt tracking approach:

In `startPayments()`, include lock ID in slot calculation:
```solidity
// Add at beginning of function
uint256 id = _getLocker().id();

// Then in assembly at line 249:
let paymentSlot := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
tstore(paymentSlot, add(tokenBalance, success))
```

In `completePayments()` at line 267, use the same lock-scoped slot:
```solidity
// Replace line 267:
let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
```

This ensures each lock's payment tracking state is isolated and cannot be accessed or cleared by nested locks, maintaining proper accounting boundaries.

**Additional Mitigations**:
- Add explicit documentation warning about the reentrancy implications of `withdraw()`
- Consider adding a reentrancy guard specifically for payment tracking operations
- Add assertion that payment slots are cleared only by the lock that set them

## Proof of Concept

The vulnerability can be demonstrated with a Foundry test showing:

1. Victim starts payment tracking for USDC and transfers 1000 tokens to FlashAccountant
2. Victim withdraws 1 ETH to attacker contract, triggering reentrancy
3. Attacker's `receive()` creates nested lock (ID 1) and calls `completePayments([USDC])`
4. Attacker's nested lock reads victim's payment tracking state (1000 USDC credit)
5. Attacker clears the global payment slot and credits 1000 USDC to their own lock's debt
6. Attacker withdraws 1000 USDC and exits nested lock with zero debt
7. Control returns to victim's lock (ID 0)
8. Victim calls `completePayments([USDC])` but finds slot cleared (0 credit given)
9. Victim's lock fails with `DebtsNotZeroed(0)` 
10. Attacker successfully extracted 1000 USDC without settling debt

**Expected Result:**
- Victim transaction reverts with `DebtsNotZeroed(0)`
- Attacker balance increases by 1000 USDC
- Tokens remain in FlashAccountant but payment credit was stolen from victim and given to attacker

## Notes

The vulnerability exists because payment tracking was implemented using global transient storage per token as an optimization, inadvertently breaking isolation between nested lock contexts. The developers acknowledged reentrancy is possible: [7](#0-6) 

However, this safety guarantee explicitly applies only to the local `nzdCountChange` variable, NOT to payment tracking slots in transient storage. The payment tracking slots (`_PAYMENT_TOKEN_ADDRESS_OFFSET + token`) are global and can be consumed by any lock calling `completePayments()`, enabling this attack.

Debt tracking itself is correctly scoped by lock ID (as shown in the code citations), preventing direct debt manipulation. However, the payment tracking bypass allows attackers to credit debt incorrectly by consuming another lock's payment tracking state, achieving theft through misdirection rather than direct manipulation.

The mismatch between global payment tracking and lock-scoped debt tracking creates an exploitable inconsistency that violates the fundamental isolation principle of the lock system.

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
