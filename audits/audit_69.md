# Audit Report

## Title
Payment Tracking State Collision Causes Debt Misattribution in Nested Lock Contexts

## Summary
The `FlashAccountant` contract stores payment tracking state in transient storage indexed only by token address, without including the locker ID. This creates a critical mismatch with debt tracking (which IS indexed by locker ID), allowing nested lock contexts to interfere with each other's payment accounting and causing legitimate transactions to revert.

## Impact
**Severity**: Medium

Transactions that properly transfer tokens will incorrectly revert with `DebtsNotZeroed` errors due to payment tracking state being consumed by nested lock contexts. This breaks the flash accounting integrity and can be weaponized for denial-of-service attacks against users and extensions that utilize the `forward()` mechanism.

## Finding Description

**Location:** `src/base/FlashAccountant.sol`, functions `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319)

**Intended Logic:** 
Payment tracking should isolate state per lock context (by locker ID), ensuring each locker's debts are accurately tracked when tokens are transferred to the accountant, consistent with how debt tracking itself operates.

**Actual Logic:**
Payment tracking uses global transient storage indexed ONLY by token address at `_PAYMENT_TOKEN_ADDRESS_OFFSET + token`, while debt tracking uses per-locker-ID storage at `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (id << 160) + token`. This architectural mismatch allows nested locks to read and clear payment tracking state from parent locks. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. **Setup**: Outer lock (ID 0) calls `forward(maliciousContract)` to delegate operations
2. **Payment Tracking Started**: Malicious contract calls `startPayments([tokenX])`, storing balance at global slot `_PAYMENT_TOKEN_ADDRESS_OFFSET + tokenX`
3. **Token Transfer**: Malicious contract transfers tokens to accountant (balance increases)
4. **Nested Lock Created**: Malicious contract calls `lock()`, creating nested lock with ID 1
5. **State Collision**: Within ID 1 callback:
   - Calls `completePayments([tokenX])` which reads ID 0's payment tracking state
   - Calculates payment based on ID 0's starting balance
   - Reduces debt for ID 1 (wrong locker)
   - Clears the shared payment tracking storage
6. **Parent Lock Fails**: Back in ID 0 context:
   - Calls `completePayments([tokenX])` but finds `lastBalance = 0` (was cleared)
   - Payment calculation yields 0 due to condition failure
   - ID 0's debt remains unreduced
   - Lock exits with `DebtsNotZeroed` revert [4](#0-3) [5](#0-4) 

**Security Property Broken:**
Violates flash accounting integrity - debts are misattributed across lock contexts, causing legitimate operations with correct token payments to fail. This contradicts the fundamental principle that each lock context should have isolated accounting state.

## Impact Explanation

**Affected Assets**: All tokens used in payment operations within nested lock contexts. The vulnerability affects any code path that combines `forward()` with nested locks and payment tracking.

**Damage Severity**:
- Legitimate transactions revert with `DebtsNotZeroed` despite correct token payments
- Breaks flash accounting system integrity by allowing cross-context state interference
- Enables denial-of-service attacks against users and extensions using forwarding
- No direct fund theft (transaction reverts prevent state commitment)

**User Impact**: Users and extensions utilizing `forward()` for operations like TWAMM orders, MEV capture swaps, or custom extension logic are vulnerable to griefing attacks.

## Likelihood Explanation

**Attacker Profile**: Any user or contract capable of calling `forward()` and creating nested locks. No special privileges required.

**Preconditions**:
1. Active lock context with `forward()` call to attacker-controlled contract
2. Attacker calls `startPayments()` in forwarded context
3. Attacker creates nested lock via `lock()`
4. Nested lock calls `completePayments()`

**Execution Complexity**: Single transaction with straightforward call sequence. Can be executed by malicious contracts implementing `IForwardee` interface.

**Economic Cost**: Only gas costs (~0.01-0.05 ETH), no capital requirements.

**Frequency**: Exploitable on every transaction meeting preconditions. Pattern is specific but achievable.

**Overall Likelihood**: MEDIUM - Requires deliberate exploit pattern but is technically feasible with no protections in place.

## Recommendation

**Primary Fix:**
Index payment tracking storage by locker ID to match debt tracking architecture: [6](#0-5) 

In `startPayments()`, modify line 249 to include locker ID in storage calculation:
```solidity
// Get locker ID before assembly block
uint256 id = _getLocker().id();
// Inside assembly:
tstore(add(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, shl(160, id)), token), add(tokenBalance, success))
``` [7](#0-6) 

In `completePayments()`, modify line 267 to use locker ID (already retrieved at line 258):
```solidity
// Update storage offset calculation at line 267:
let offset := add(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, shl(160, id)), token)
```

This ensures payment tracking is isolated per locker ID, preventing cross-context interference and maintaining consistency with debt tracking architecture.

**Alternative Mitigation**: Add explicit validation to prevent `completePayments()` from accessing payment tracking state initialized by different locker IDs, though this is more complex and less gas-efficient than the primary fix.

## Notes

The vulnerability stems from an architectural inconsistency where payment tracking uses global storage (token-only indexing) while debt tracking correctly uses per-locker-ID storage. This mismatch is evidenced by comparing storage slot calculations: payment tracking at lines 249 and 267 versus debt tracking at line 299.

The existing test suite (`test/base/FlashAccountant.t.sol`) includes nested lock tests but does not cover the specific pattern of calling `startPayments()` in a parent lock and `completePayments()` in a nested lock, which explains why this issue was not caught during testing.

While the immediate impact is denial-of-service rather than direct fund theft, this represents a critical breakdown in the flash accounting system's integrity guarantees and violates the principle of lock context isolation that underpins the entire singleton architecture.

### Citations

**File:** src/base/FlashAccountant.sol (L176-181)
```text
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
```

**File:** src/base/FlashAccountant.sol (L224-254)
```text
    function startPayments() external {
        assembly ("memory-safe") {
            // 0-52 are used for the balanceOf calldata
            mstore(20, address()) // Store the `account` argument.
            mstore(0, 0x70a08231000000000000000000000000) // `balanceOf(address)`.

            let free := mload(0x40)

            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                // clean upper 96 bits of the token argument at i
                let token := shr(96, shl(96, calldataload(i)))

                let returnLocation := add(free, sub(i, 4))

                let success := staticcall(gas(), token, 0x10, 0x24, returnLocation, 0x20)

                let tokenBalance :=
                    mul(
                        mload(returnLocation),
                        and(
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            success
                        )
                    )

                tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))
            }

            return(free, sub(calldatasize(), 4))
        }
    }
```

**File:** src/base/FlashAccountant.sol (L257-319)
```text
    function completePayments() external {
        uint256 id = _getLocker().id();

        assembly ("memory-safe") {
            let paymentAmounts := mload(0x40)
            let nzdCountChange := 0

            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                let token := shr(96, shl(96, calldataload(i)))

                let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token)
                let lastBalance := tload(offset)
                tstore(offset, 0)

                mstore(20, address()) // Store the `account` argument.
                mstore(0, 0x70a08231000000000000000000000000) // `balanceOf(address)`.

                let currentBalance :=
                    mul( // The arguments of `mul` are evaluated from right to left.
                        mload(0),
                        and( // The arguments of `and` are evaluated from right to left.
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            staticcall(gas(), token, 0x10, 0x24, 0, 0x20)
                        )
                    )

                let payment :=
                    mul(
                        and(gt(lastBalance, 0), not(lt(currentBalance, lastBalance))),
                        sub(currentBalance, sub(lastBalance, 1))
                    )

                // We never expect tokens to have this much total supply
                if shr(128, payment) {
                    // cast sig "PaymentOverflow()"
                    mstore(0x00, 0x9cac58ca)
                    revert(0x1c, 4)
                }

                mstore(add(paymentAmounts, mul(16, div(i, 32))), shl(128, payment))

                if payment {
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)

                    // never overflows because of the payment overflow check that bounds payment to 128 bits
                    let next := sub(current, payment)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)
                }
            }

            // Update nzdCountSlot only once if there were any changes
            if nzdCountChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), nzdCountChange))
            }

            return(paymentAmounts, mul(16, div(calldatasize(), 32)))
        }
    }
```
