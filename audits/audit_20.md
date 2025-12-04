# Audit Report

## Title
Locker ID Corruption via Dirty Bits in forward() Function Enables Flash Loan Debt Bypass

## Summary
The `forward(address to)` function in FlashAccountant fails to clean the upper 96 bits of the `to` parameter before using it in assembly, allowing an attacker to corrupt the Locker's ID field through a low-level call with crafted calldata. This causes debt to be tracked under a corrupted ID that is never checked during settlement, enabling the attacker to withdraw tokens without repayment.

## Impact
**Severity**: High

An attacker can steal all tokens managed by FlashAccountant by corrupting the Locker ID to bypass the flash loan settlement check. The attack exploits the inconsistency between `forward()` which uses address parameters directly in assembly, versus `startPayments()` and `completePayments()` which explicitly clean address parameters before use.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The forward function should preserve the original lock ID while updating only the locker address, maintaining proper debt tracking for the original lock context as stated in the code comment: "update this lock's locker to the forwarded address for the duration of the forwarded call".

**Actual Logic:**
The function uses the `to` parameter directly in assembly without masking the upper 96 bits. When an attacker crafts calldata with dirty upper bits using a low-level call, these bits OR with the ID bits when the Locker is reconstructed, corrupting the stored ID field.

**Exploitation Path:**
1. **Setup**: Attacker deploys a contract that inherits from BaseLocker and calls `lock()`, receiving ID=0 (stored as 1 in upper 96 bits of the Locker)
2. **Trigger**: Inside the `handleLockData()` callback, attacker makes a low-level call: `address(ACCOUNTANT).call(abi.encodePacked(selector, bytes32((0xFF << 160) | targetAddr)))` to forward() with dirty upper bits
3. **State Change**: Line 196 executes `or(shl(160, shr(160, locker)), to)` where `to` contains dirty bits, corrupting the Locker to have ID=(1|0xFF)=0xFF instead of 1, stored in `_CURRENT_LOCKER_SLOT`
4. **Exploitation**: The forwarded contract calls `withdraw()` which reads the corrupted Locker from storage via `_requireLocker()`. The debt is tracked at slot: `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (0xFF << 160) + token` [2](#0-1) 
5. **Bypass**: forward() restores the original Locker. When lock() ends, it checks debt for the original ID=0 at slot: `_NONZERO_DEBT_COUNT_OFFSET + 0`, which is zero. The corrupted ID's debt counter at `_NONZERO_DEBT_COUNT_OFFSET + 0xFF` is never checked
6. **Result**: Attacker keeps all withdrawn tokens without repayment, violating the flash accounting invariant

**Security Guarantee Broken:**
Per README: "All assembly blocks should be treated as suspect and inputs to functions that are used in assembly should be checked that they are always cleaned beforehand if not cleaned in the function." [3](#0-2) 

**Code Evidence:**
The codebase demonstrates clear awareness of this issue through defensive cleaning patterns in other functions [4](#0-3)  and explicit masking with comments [5](#0-4) , but forward() lacks this protection.

## Impact Explanation

**Affected Assets**: All tokens held by the FlashAccountant during lock operations, including tokens from pools, positions, and any flash loan withdrawals

**Damage Severity**:
- Attacker can drain the entire FlashAccountant balance in a single transaction by corrupting the ID to an unused value (e.g., 0xFF)
- The `DebtsNotZeroed` check at lock termination operates on the original uncorrupted ID, allowing the lock to complete successfully despite unpaid debts
- Protocol becomes insolvent as balances go negative for the affected tokens
- All subsequent operations depending on those tokens may fail

**User Impact**: Any user or protocol using FlashAccountant's lock mechanism is vulnerable. The attacker only needs the ability to call `lock()` which is available to any contract.

**Trigger Conditions**: No special preconditions required - works with any active lock context

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user who can deploy a contract and call FlashAccountant's `lock()` function

**Preconditions**:
1. FlashAccountant must hold tokens (always true for active protocol)
2. Attacker must be current locker (achieved by calling lock())
3. No other preconditions required

**Execution Complexity**: Single transaction with low-level call using crafted calldata: `address(accountant).call(abi.encodePacked(bytes4(selector), bytes32(dirtyAddress)))`

**Economic Cost**: Only gas fees (~$5-10), no capital required

**Frequency**: Repeatable for every lock, can drain all available tokens

**Overall Likelihood**: HIGH - Trivial to execute, affects any user of FlashAccountant

## Recommendation

**Primary Fix:**
Apply the same cleaning pattern used elsewhere in the codebase [6](#0-5)  to the `to` parameter in forward():

```solidity
// At line 196, change from:
tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

// To:
tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), shr(96, shl(96, to))))
```

This masks the upper 96 bits of the address parameter, ensuring only the lower 160 bits (the actual address) are used.

**Alternative Fix:**
```solidity
tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), and(to, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)))
```

## Notes

This vulnerability exists due to an inconsistency in the codebase's handling of address parameters in assembly. While `startPayments()` and `completePayments()` explicitly clean address parameters read from calldata, and `swapParameters.sol` includes a comment "Mask each field to ensure dirty bits don't interfere", the `forward()` function omits this critical protection.

The README's warning about cleaning inputs to assembly functions is a general guideline, not a declaration that specific functions are known to be vulnerable. The codebase's defensive patterns in other functions demonstrate this should be applied to `forward()` as well.

The Locker type packs the ID in the upper 96 bits and address in the lower 160 bits [7](#0-6) . When dirty bits in the upper 96 bits of the `to` parameter are OR'd with the ID bits, the resulting corrupted ID causes all debt tracking operations to write to wrong transient storage slots that are never checked during settlement.

### Citations

**File:** src/base/FlashAccountant.sol (L67-84)
```text
    function _accountDebt(uint256 id, address token, int256 debtChange) internal {
        assembly ("memory-safe") {
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
            let current := tload(deltaSlot)

            // we know this never overflows because debtChange is only ever derived from 128 bit values in inheriting contracts
            let next := add(current, debtChange)

            let countChange := sub(iszero(current), iszero(next))

            if countChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), countChange))
            }

            tstore(deltaSlot, next)
        }
    }
```

**File:** src/base/FlashAccountant.sol (L190-196)
```text
    function forward(address to) external {
        Locker locker = _requireLocker();

        // update this lock's locker to the forwarded address for the duration of the forwarded
        // call, meaning only the forwarded address can update state
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))
```

**File:** src/base/FlashAccountant.sol (L232-234)
```text
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                // clean upper 96 bits of the token argument at i
                let token := shr(96, shl(96, calldataload(i)))
```

**File:** src/base/FlashAccountant.sol (L264-265)
```text
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                let token := shr(96, shl(96, calldataload(i)))
```

**File:** README.md (L194-196)
```markdown
### Assembly Block Usage

We use a custom storage layout and also regularly use stack values without cleaning bits and make extensive use of assembly for optimization. All assembly blocks should be treated as suspect and inputs to functions that are used in assembly should be checked that they are always cleaned beforehand if not cleaned in the function. The ABDK audit points out many cases where we assume the unused bits in narrow types (e.g. the most significant 160 bits in a uint96) are cleaned.
```

**File:** src/types/swapParameters.sol (L46-49)
```text
    assembly ("memory-safe") {
        // p = (sqrtRatioLimit << 160) | (amount << 32) | (isToken1 << 31) | skipAhead
        // Mask each field to ensure dirty bits don't interfere
        // For isToken1, use iszero(iszero()) to convert any non-zero value to 1
```

**File:** src/types/locker.sol (L8-18)
```text
function id(Locker locker) pure returns (uint256 v) {
    assembly ("memory-safe") {
        v := sub(shr(160, locker), 1)
    }
}

function addr(Locker locker) pure returns (address v) {
    assembly ("memory-safe") {
        v := shr(96, shl(96, locker))
    }
}
```
