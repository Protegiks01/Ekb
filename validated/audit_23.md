# Audit Report

## Title
Payment Tracking State Leakage Allows Nested Locks to Steal Credits from Outer Locks

## Summary
The payment tracking mechanism in FlashAccountant uses global transient storage that is not scoped by lock ID, creating an architectural vulnerability where nested locks can steal payment credits intended for outer locks during reentrancy callbacks. This enables direct theft of user funds through flash accounting manipulation.

## Impact
**Severity**: High

An attacker can steal 100% of tokens that victims transfer to settle their lock debts by exploiting the global payment tracking state during reentrancy. The vulnerability allows unauthorized withdrawal of tokens without properly crediting the victim's debt, while the attacker's nested lock receives the stolen payment credit and can exit with zero debt. The victim's transaction reverts with `DebtsNotZeroed`, and their transferred tokens remain locked in the contract while the attacker extracts equivalent value.

## Finding Description

**Location:** `src/base/FlashAccountant.sol`, functions `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319)

**Intended Logic:** 
The payment tracking system allows users to credit tokens to their lock's debt by calling `startPayments()` before token transfers and `completePayments()` afterward. The system should isolate each lock's payment state to prevent cross-contamination between nested locks.

**Actual Logic:**
The payment tracking storage uses a slot calculated as `_PAYMENT_TOKEN_ADDRESS_OFFSET + token` without lock ID scoping [1](#0-0) , while debt tracking correctly uses `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (id << 160) + token` [2](#0-1) . This asymmetry means all locks share the same payment tracking state per token. When `completePayments()` reads and clears this global state [3](#0-2) , it credits the payment to the current lock ID [4](#0-3) , enabling state theft between locks.

**Exploitation Path:**
1. **Victim initiates lock ID 0**: Calls `lock()` and within callback calls `startPayments([USDC])`, storing current balance in global slot `_PAYMENT_TOKEN_ADDRESS_OFFSET + USDC`
2. **Victim transfers 1000 USDC**: Increases accountant's USDC balance
3. **Victim calls withdraw(ETH, attacker, 1 ETH)**: Increases victim's ETH debt in lock 0 and triggers ETH transfer to attacker [5](#0-4) 
4. **Reentrancy callback**: Attacker's `receive()` function is triggered during the ETH transfer
5. **Attacker creates nested lock ID 1**: Calls `lock()` from within the callback, which increments the lock ID [6](#0-5) 
6. **Attacker steals payment credit**: Calls `completePayments([USDC])` which reads the victim's stored balance from the global slot, clears it, calculates the payment, and credits it to lock ID 1's debt instead of lock ID 0
7. **Attacker withdraws tokens**: Calls `withdraw()` to extract 1000 USDC and exits the nested lock with zero debt
8. **Victim's lock fails**: When control returns, victim calls `completePayments([USDC])` but the global slot is now 0 (cleared by attacker), resulting in no credit. Lock completion check reverts with `DebtsNotZeroed(0)` [7](#0-6)  because victim has ETH debt without corresponding USDC credit

**Security Guarantee Broken:**
This violates the flash accounting invariant that all debts must be properly settled within a lock, and the isolation guarantee that each lock's state should be independent.

## Impact Explanation

**Affected Assets**: All ERC20 tokens and native ETH used in the protocol through the flash accounting system

**Damage Severity**:
- Attacker extracts 100% of tokens the victim transfers during their lock operation
- Victim loses transferred tokens while their transaction reverts
- Protocol accounting is violated as attacker withdraws without proper debt settlement
- Multiple victims can be targeted in separate transactions

**User Impact**: Any user performing operations involving `startPayments()/completePayments()` combined with `withdraw()` to an untrusted address is vulnerable. This affects routing scenarios, multi-hop swaps, and complex DeFi operations where intermediate transfers occur.

**Trigger Conditions**: Requires victim to call `withdraw()` transferring ETH or tokens to an attacker-controlled address during their lock, which is common in routing and swap execution scenarios.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or contract that can receive ETH/ERC20 transfers and implement a malicious callback

**Preconditions**:
1. Victim uses the `startPayments()/completePayments()` flow (legitimate usage pattern)
2. Victim calls `withdraw()` to transfer assets to attacker's address during the lock (common in routing)
3. Attacker's address implements malicious `receive()` or ERC20 transfer hook (trivial)

**Execution Complexity**: Single transaction exploiting reentrancy via standard callback mechanisms. No special timing, state manipulation, or multi-block coordination required.

**Economic Cost**: Only transaction gas fees (~$20-50), no capital lockup or collateral needed

**Frequency**: Exploitable on every transaction where victims transfer assets to attacker addresses within their locks, which occurs regularly in DeFi routing scenarios

**Overall Likelihood**: HIGH - Simple execution, common preconditions, affects standard usage patterns

## Recommendation

**Primary Fix:**
Scope payment tracking storage by lock ID to match the debt tracking pattern. In `startPayments()` at line 249, change the storage slot calculation from `_PAYMENT_TOKEN_ADDRESS_OFFSET + token` to `_PAYMENT_TOKEN_ADDRESS_OFFSET + (lockerId << 160) + token`. Apply the same change in `completePayments()` at line 267 to use `_PAYMENT_TOKEN_ADDRESS_OFFSET + (id << 160) + token`.

This ensures each lock maintains isolated payment tracking state that cannot be accessed or consumed by nested locks, matching the protection already present in the debt tracking mechanism.

**Additional Mitigations**:
- Add explicit validation that payment tracking state belongs to the current lock before crediting debt
- Consider adding a lock depth counter to detect and limit nested lock scenarios
- Document the reentrancy behavior and payment tracking isolation requirements

## Proof of Concept

The provided PoC demonstrates the complete exploitation path:
1. Victim creates lock 0 and calls `startPayments([USDC])`
2. Victim transfers 1000 USDC to accountant
3. Victim calls `withdraw()` sending 1 ETH to attacker, triggering reentrancy
4. Attacker's `receive()` creates nested lock 1 and calls `completePayments([USDC])`, stealing the payment credit
5. Attacker withdraws 1000 USDC and exits with zero debt
6. Victim's `completePayments()` finds the tracking slot cleared, fails to credit debt
7. Victim's lock reverts with `DebtsNotZeroed(0)`
8. Assertion confirms attacker extracted 1000 tokens while victim's tokens remain locked

**Expected PoC Result:**
- **If Vulnerable**: Victim's transaction reverts with `DebtsNotZeroed(0)`, attacker's balance increases by 1000 tokens
- **If Fixed**: Nested lock cannot access outer lock's payment tracking state, exploitation fails

## Notes

The vulnerability exists because payment tracking was optimized using global transient storage per token for gas efficiency, but this breaks the isolation guarantee between nested locks. The code acknowledges reentrancy is possible at lines 345-347 [8](#0-7)  and claims safety through delta-based updates to `nzdCountChange`. However, this protection does not extend to the payment tracking state, which uses a different storage pattern without lock ID scoping.

The architectural inconsistency is evident: debt tracking properly scopes storage by lock ID using `(id << 160)`, while payment tracking omits this scoping. This asymmetry creates the vulnerability where nested locks can consume outer locks' payment state, violating the fundamental isolation principle required for secure flash accounting.

### Citations

**File:** src/base/FlashAccountant.sol (L69-69)
```text
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
```

**File:** src/base/FlashAccountant.sol (L148-153)
```text
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))
```

**File:** src/base/FlashAccountant.sol (L175-180)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
```

**File:** src/base/FlashAccountant.sol (L249-249)
```text
                tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))
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
