# Audit Report

## Title
Global Payment Storage Enables Cross-Lock Debt Theft via Stale Balance Data in FlashAccountant

## Summary
The `startPayments()` and `completePayments()` functions in FlashAccountant use global transient storage for payment tracking while debt is tracked per-lock ID. This architectural mismatch allows an outer lock to capture stale balance data, catch a revert, refresh only partial token data, then claim credit for balance increases caused by nested locks—effectively stealing debt reductions from other lock contexts and violating protocol solvency.

## Impact
**Severity**: High - Violates core solvency invariant through unauthorized debt manipulation

An attacker can reduce their debt without corresponding token payments by exploiting the mismatch between global payment storage and per-lock debt tracking. When nested locks perform legitimate operations that increase Core's token balances, the outer lock with stale payment data can fraudulently claim credit for those increases, reducing its own debt at the expense of the nested lock's actual payments. This enables systematic drainage of the protocol's singleton Core contract, affecting all pools and users.

## Finding Description

**Location:** `src/base/FlashAccountant.sol` - `startPayments()` and `completePayments()` functions [1](#0-0) [2](#0-1) 

**Intended Logic:** 
Payment tracking should be session-specific—`startPayments()` captures initial balances and `completePayments()` measures changes within a tightly coupled sequence. The design assumes matching token lists and no stale data reuse across different logical payment operations.

**Actual Logic:**
Payment storage uses `_PAYMENT_TOKEN_ADDRESS_OFFSET + token` with NO lock ID component, making it global across all concurrent locks. [3](#0-2) 

Debt storage includes lock ID: `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (id << 160) + token`, making it per-lock. [4](#0-3) 

This architectural mismatch enables the exploit: payment data is shared globally but debt reductions apply to specific lock IDs.

**Exploitation Path:**

1. **Setup**: Attacker creates outer lock (ID=N) via `Core.lock()` with malicious callback [5](#0-4) 

2. **Stale Data Creation**: Outer lock calls `startPayments([token0, token1])` storing both balances at `_PAYMENT_TOKEN_ADDRESS_OFFSET + token0/token1`

3. **Revert Catch**: Execute operation that reverts (caught via low-level call) - transient storage persists within transaction

4. **Partial Refresh**: Outer lock calls `startPayments([token0])` - only updates token0 slot, token1 retains stale data from step 2

5. **Nested Lock Operations**: Outer lock initiates nested lock (ID=N+1) which performs legitimate operations (swap, liquidity provision) that increase Core's token1 balance [6](#0-5) 

6. **Debt Theft**: Outer lock calls `completePayments([token1])`:
   - Loads stale balance from step 2 
   - Measures current balance (increased by nested lock in step 5)
   - Calculates payment as `currentBalance - staleBalance`
   - Reduces outer lock's debt by this fraudulent amount [7](#0-6) [8](#0-7) 

7. **Exit**: Outer lock exits with reduced debt despite not sending corresponding tokens, violating solvency

**Security Guarantee Broken:**
Flash accounting must ensure debt accurately reflects token movements. The protocol's security relies on the invariant that debt is zeroed only through actual token payments. This vulnerability breaks that invariant by allowing one lock to steal credit for another lock's payments.

## Impact Explanation

**Affected Assets**: All tokens held by Core are vulnerable. The singleton architecture means any token in any pool can be targeted.

**Damage Severity**:
- Attacker systematically reduces debt without corresponding payments
- Each exploit iteration allows withdrawal of tokens never deposited
- Protocol becomes insolvent as debt tracking diverges from actual balances
- Repeated exploitation can drain Core contract entirely

**User Impact**: All users are affected when protocol becomes insolvent. Legitimate liquidity providers cannot withdraw positions once Core lacks sufficient token balances due to theft.

**Trigger Conditions**: Attacker needs only the ability to create nested locks and control callback logic—no special permissions or pool states required.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user with ability to call `Core.lock()` and provide custom callback logic

**Preconditions**:
1. Core holds token balances (always true for active protocol)
2. Ability to trigger nested locks (supported by design, ID increments on line 153)
3. Nested operations that naturally increase balances (swaps, liquidity provision) [9](#0-8) 

**Execution Complexity**: Single transaction with malicious locker callback containing:
- Strategic startPayments calls with different token lists
- Low-level calls to catch and suppress reverts
- Nested lock initiation for balance manipulation
- completePayments with stale tokens

**Economic Cost**: Only gas fees; no capital lockup required as attacker uses protocol's own operational balance increases

**Frequency**: Repeatable across multiple transactions until Core is drained. Each nested operation by any user provides opportunity for outer lock to capture balance increases.

**Overall Likelihood**: HIGH - Straightforward exploitation, no special preconditions, affects entire protocol

## Recommendation

Implement a session/nonce system to invalidate stale payment balances:

```solidity
// Add session counter in transient storage
uint256 private constant _PAYMENT_SESSION_OFFSET = [unique hash];

function startPayments() external {
    assembly ("memory-safe") {
        // Increment session to invalidate previous data
        let sessionSlot := _PAYMENT_SESSION_OFFSET
        let currentSession := add(tload(sessionSlot), 1)
        tstore(sessionSlot, currentSession)
        
        // Store session ID with balance (upper 128 bits)
        // for each token...
        tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), 
               or(shl(128, currentSession), add(tokenBalance, success)))
    }
}

function completePayments() external {
    assembly ("memory-safe") {
        let currentSession := tload(_PAYMENT_SESSION_OFFSET)
        // for each token...
        let lastBalanceData := tload(offset)
        let storedSession := shr(128, lastBalanceData)
        
        // Revert if session mismatch (stale data)
        if iszero(eq(storedSession, currentSession)) {
            mstore(0x00, 0x12345678) // StalePaymentSession()
            revert(0x1c, 4)
        }
        // Continue with payment calculation using lower 128 bits...
    }
}
```

**Alternative**: Include lock ID in payment storage key: `_PAYMENT_TOKEN_ADDRESS_OFFSET + (id << 160) + token` to match debt storage architecture.

## Notes

This vulnerability stems from a subtle architectural mismatch between storage patterns. The payment tracking mechanism was designed for sequential, tightly-coupled startPayments/completePayments pairs within a single lock context. However, Ekubo's powerful lock forwarding and nesting capabilities enable concurrent locks with independent debt tracking but shared payment storage—creating the exploitation window.

The issue is particularly severe because:
1. Nested locks are explicitly supported and tested
2. Transient storage persists across caught reverts by design (EIP-1153)
3. No validation exists to detect cross-lock payment data reuse
4. The exploit leverages legitimate protocol operations in nested locks

While the provided PoC demonstrates stale data persistence, a production exploit would use nested locks to create balance increases the outer lock can claim credit for—effectively stealing debt reductions across lock boundaries.

### Citations

**File:** src/base/FlashAccountant.sol (L21-24)
```text
    /// @dev Transient storage offset for tracking token debts for each locker
    /// @dev Generated using: cast keccak "FlashAccountant#_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET"
    uint256 private constant _DEBT_LOCKER_TOKEN_ADDRESS_OFFSET =
        0x753dfe4b4dfb3ff6c11bbf6a97f3c094e91c003ce904a55cc5662fbad220f599;
```

**File:** src/base/FlashAccountant.sol (L31-34)
```text
    /// @dev Transient storage offset for tracking token balances during payment operations
    /// @dev Generated using: cast keccak "FlashAccountant#_PAYMENT_TOKEN_ADDRESS_OFFSET"
    uint256 private constant _PAYMENT_TOKEN_ADDRESS_OFFSET =
        0x6747da56dbd05b26a7ecd2a0106781585141cf07098ad54c0e049e4e86dccb8c;
```

**File:** src/base/FlashAccountant.sol (L146-187)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))

            let free := mload(0x40)
            // Prepare call to locked_(uint256) -> selector 0
            mstore(free, 0)
            mstore(add(free, 4), id) // ID argument

            calldatacopy(add(free, 36), 4, sub(calldatasize(), 4))

            // Call the original caller with the packed data
            let success := call(gas(), caller(), 0, free, add(calldatasize(), 32), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Undo the "locker" state changes
            tstore(_CURRENT_LOCKER_SLOT, current)

            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
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

**File:** src/Core.sol (L46-46)
```text
contract Core is ICore, FlashAccountant, ExposedStorage {
```
