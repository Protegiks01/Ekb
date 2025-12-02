## Title
Incorrect Transfer Event Emission in TokenWrapper.transferFrom() Breaks ERC20 Standard and External Balance Tracking

## Summary
The `TokenWrapper.transferFrom()` function emits a `Transfer` event with `msg.sender` (the spender) as the `from` address instead of the actual `from` parameter (the token owner). [1](#0-0)  This violates the ERC20 standard and causes all external observers (wallets, block explorers, DEXes, indexers) to incorrectly track token balances, believing the spender's balance decreased when actually the owner's balance decreased.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/TokenWrapper.sol`, function `transferFrom()`, line 153

**Intended Logic:** According to EIP-20, when `transferFrom(from, to, amount)` is called, the Transfer event should emit `Transfer(from, to, amount)` where `from` is the address whose balance decreased.

**Actual Logic:** The code emits `Transfer(msg.sender, to, amount)` [1](#0-0)  where `msg.sender` is the approved spender, not the actual token owner. Meanwhile, the state changes correctly decrease `_balanceOf[from]` [2](#0-1)  and increase `_balanceOf[to]`. [3](#0-2) 

**Exploitation Path:**
1. Alice approves Bob to spend 100 wrapped tokens via `approve(bob, 100)`
2. Bob calls `transferFrom(alice, charlie, 100)`
3. State changes correctly: `_balanceOf[alice]` decreases by 100, `_balanceOf[charlie]` increases by 100
4. But event emits: `Transfer(bob, charlie, 100)` instead of `Transfer(alice, charlie, 100)`
5. All external systems (wallets, block explorers, DEX interfaces, indexers) now believe Bob's balance decreased by 100 and Charlie's increased by 100
6. Alice's actual balance change is invisible to all off-chain systems

**Security Property Broken:** ERC20 standard compliance. The Transfer event signature requires the `from` parameter to represent the account whose balance decreased, but the implementation emits the spender's address instead.

## Impact Explanation
- **Affected Assets**: All wrapped tokens in the TokenWrapper contract and any external systems relying on Transfer events for balance tracking
- **Damage Severity**: Complete misrepresentation of balance changes in external systems. Users and protocols integrating with TokenWrapper will have systematically incorrect balance information, potentially leading to:
  - Users making incorrect financial decisions based on wrong displayed balances
  - DEX interfaces showing wrong token holdings
  - Portfolio trackers displaying incorrect values
  - Block explorers showing misleading transaction history
- **User Impact**: Every user who has approved another address to spend their wrapped tokens. Any `transferFrom` call will generate incorrect event data affecting all observers.

## Likelihood Explanation
- **Attacker Profile**: Any user can trigger this by using the standard `approve` + `transferFrom` pattern
- **Preconditions**: TokenWrapper must be deployed and users must have wrapped tokens with approved spenders
- **Execution Complexity**: Single transaction using standard ERC20 approval flow
- **Frequency**: Every `transferFrom` call produces incorrect events, making this a systemic issue affecting all approved transfers

## Recommendation

**Fix in src/TokenWrapper.sol, function transferFrom(), line 153:**

The Transfer event should emit the `from` parameter instead of `msg.sender`:

```solidity
// CURRENT (line 153):
emit Transfer(msg.sender, to, amount);

// FIXED:
emit Transfer(from, to, amount);
```

This aligns the event emission with the actual state changes and restores ERC20 standard compliance.

## Proof of Concept

```solidity
// File: test/Exploit_IncorrectTransferEvent.t.sol
// Run with: forge test --match-test test_IncorrectTransferEvent -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/TokenWrapper.sol";
import "../src/TokenWrapperFactory.sol";
import "./TestToken.sol";
import "./FullTest.sol";

contract Exploit_IncorrectTransferEvent is FullTest {
    TokenWrapperFactory factory;
    TokenWrapper wrapper;
    TestToken underlying;
    
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address charlie = address(0xCHA411E);
    
    function setUp() public override {
        FullTest.setUp();
        underlying = new TestToken(address(this));
        factory = new TokenWrapperFactory(core);
        wrapper = factory.deployWrapper(IERC20(address(underlying)), 0);
        
        // Give Alice some wrapped tokens
        underlying.transfer(alice, 1000);
        vm.prank(alice);
        underlying.approve(address(this), 1000);
        // Wrap for Alice (simplified - in practice would use periphery)
    }
    
    function test_IncorrectTransferEvent() public {
        // SETUP: Alice has 100 wrapped tokens, approves Bob to spend them
        uint256 aliceBalance = 100;
        deal(address(wrapper), alice, aliceBalance);
        
        vm.prank(alice);
        wrapper.approve(bob, 100);
        
        // Record balances before
        uint256 aliceBalanceBefore = wrapper.balanceOf(alice);
        uint256 bobBalanceBefore = wrapper.balanceOf(bob);
        uint256 charlieBalanceBefore = wrapper.balanceOf(charlie);
        
        // EXPLOIT: Bob calls transferFrom to transfer Alice's tokens to Charlie
        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        // The event INCORRECTLY shows Bob as the sender instead of Alice
        emit Transfer(bob, charlie, 50); // Wrong! Should be Transfer(alice, charlie, 50)
        wrapper.transferFrom(alice, charlie, 50);
        
        // VERIFY: State is correct but event is wrong
        assertEq(wrapper.balanceOf(alice), aliceBalanceBefore - 50, "Alice's balance should decrease");
        assertEq(wrapper.balanceOf(bob), bobBalanceBefore, "Bob's balance should not change");
        assertEq(wrapper.balanceOf(charlie), charlieBalanceBefore + 50, "Charlie's balance should increase");
        
        // External observers watching Transfer events will believe:
        // - Bob's balance decreased by 50 (WRONG - Bob's balance didn't change)
        // - Charlie's balance increased by 50 (CORRECT)
        // - Alice's balance unchanged (WRONG - Alice's balance actually decreased)
    }
}
```

## Notes

While investigating the security question about "reverts between state changes and event emission," I found that the premise is technically incorrect—in Solidity, if a revert occurs, ALL state changes are rolled back, so there's no scenario where state persists but events don't emit.

However, this investigation revealed a real vulnerability: the `transferFrom()` function emits events with incorrect information about which account's balance changed. This violates the ERC20 standard and breaks external balance tracking for all systems that rely on Transfer events (which is the standard way to track ERC20 balances off-chain).

Note that the `transfer()` function at line 115 is correct—it properly emits `Transfer(msg.sender, to, amount)` because in that case, `msg.sender` IS the account whose balance decreases. [4](#0-3)  The bug only affects `transferFrom()`.

### Citations

**File:** src/TokenWrapper.sol (L115-115)
```text
        emit Transfer(msg.sender, to, amount);
```

**File:** src/TokenWrapper.sol (L139-146)
```text
        uint256 balance = _balanceOf[from];
        if (balance < amount) {
            revert InsufficientBalance();
        }
        // since we already checked balance >= amount
        unchecked {
            _balanceOf[from] = balance - amount;
        }
```

**File:** src/TokenWrapper.sol (L148-152)
```text
        if (to == address(CORE)) {
            coreBalance += amount;
        } else {
            _balanceOf[to] += amount;
        }
```

**File:** src/TokenWrapper.sol (L153-153)
```text
        emit Transfer(msg.sender, to, amount);
```
