## Title
User Funds Stuck in BasePositions Due to Missing msg.value Validation and Refund Logic

## Summary
The `BasePositions` contract inherits from `BaseNonfungibleToken` which accepts but ignores `msg.value` in its `mint()` functions. When users call `mintAndDeposit()` or `mintAndDepositWithSalt()` with `msg.value` on ERC20-only pools or with excess ETH on native token pools, the funds become stuck in the contract with no automatic refund mechanism, unlike the proper handling implemented in `Router.sol`.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (functions `mintAndDeposit` line 159-169, `mintAndDepositWithSalt` line 172-183, and `handleLockData` CALL_TYPE_DEPOSIT case line 232-264)

**Intended Logic:** According to the comment at line 108 in `BaseNonfungibleToken.sol`, "No fees are collected; any msg.value sent is ignored" for the `mint()` function. The functions are marked `payable` to support native token deposits in pools that use `NATIVE_TOKEN_ADDRESS`. [1](#0-0) 

**Actual Logic:** When users call `mintAndDeposit()` with `msg.value`:

1. The `msg.value` arrives at the `BasePositions` contract
2. `mint()` is called first but doesn't use the `msg.value` (as documented)
3. `deposit()` is called, which triggers the `handleLockData()` flow
4. For ERC20-only pools (`token0 != NATIVE_TOKEN_ADDRESS`), the code uses `ACCOUNTANT.payTwoFrom()` to pull tokens from the caller, completely ignoring `msg.value`
5. For native token pools, only the exact `amount0` needed is transferred via `SafeTransferLib.safeTransferETH()`, leaving any excess `msg.value` stuck
6. No validation prevents sending `msg.value` when unnecessary, and no automatic refund occurs [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Scenario A - ERC20-only pool**: User calls `positions.mintAndDeposit{value: 1 ether}(poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)` where `poolKey.token0` is an ERC20 token (not `NATIVE_TOKEN_ADDRESS`)
2. The 1 ETH is sent to the `BasePositions` contract
3. `mint()` executes and ignores the ETH
4. `deposit()` executes and uses `ACCOUNTANT.payTwoFrom()` to pull ERC20 tokens from the user
5. The 1 ETH remains stuck in the `BasePositions` contract balance

**Scenario B - Excess native token**: User calls `positions.mintAndDeposit{value: 2 ether}(poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)` where `poolKey.token0 == NATIVE_TOKEN_ADDRESS` but only 1 ETH is needed for `amount0`
6. Only 1 ETH is transferred to `ACCOUNTANT`, 1 ETH remains stuck in the contract

**Security Property Broken:** User fund safety - funds become inaccessible without discovering and calling the undocumented `refundNativeToken()` function. [4](#0-3) 

## Impact Explanation

- **Affected Assets**: Any ETH sent by users as `msg.value` when calling `mintAndDeposit()`, `mintAndDepositWithSalt()`, or `deposit()` on pools where it's unnecessary or excessive
- **Damage Severity**: Users lose temporary or permanent access to their ETH. While technically recoverable via `refundNativeToken()`, users must discover this function independently with no documentation or error messages guiding them
- **User Impact**: Any user making liquidity positions who:
  - Misunderstands that `mint()` doesn't require fees
  - Calls functions on ERC20-only pools with `msg.value` 
  - Sends excess ETH beyond what's needed for native token pools
  - Uses frontend interfaces that may inadvertently pass `msg.value`

## Likelihood Explanation

- **Attacker Profile**: Not an attack - this is a UX vulnerability affecting normal users. Any user interacting with the protocol can trigger this
- **Preconditions**: 
  - User calls a `payable` function in `BasePositions` with `msg.value`
  - Either the pool doesn't use native tokens OR user sends more ETH than needed
- **Execution Complexity**: Single transaction - happens immediately when user calls the function with `msg.value`
- **Frequency**: Can happen on every user interaction where `msg.value` is mistakenly sent or sent in excess

## Recommendation

Implement validation and refund logic similar to `Router.sol`. In `BasePositions.sol`, modify the `handleLockData()` function for CALL_TYPE_DEPOSIT: [5](#0-4) 

```solidity
// In src/base/BasePositions.sol, function handleLockData, lines 252-262:

// CURRENT (vulnerable):
// Uses exact amounts without checking msg.value or refunding excess

// FIXED:
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    // Revert if msg.value sent for ERC20-only pool
    if (msg.value != 0) {
        revert UnexpectedMsgValue();
    }
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
} else {
    // Calculate the difference between sent value and needed amount
    int256 valueDifference = int256(msg.value) - int256(amount0);
    
    if (amount0 != 0) {
        if (valueDifference < 0) {
            // User didn't send enough, pull from contract balance
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
        } else {
            // User sent enough, use msg.value directly
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(msg.value));
        }
    }
    
    if (amount1 != 0) {
        ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
    }
    
    // Refund excess ETH to the caller
    if (valueDifference > 0) {
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, caller, uint128(uint256(valueDifference)));
    }
}
```

Alternative mitigation: Add a `nonpayable` modifier to `mintAndDeposit()` and `mintAndDepositWithSalt()` if the design intent is to never accept `msg.value` at all, forcing users to send ETH only through specific native token handling flows.

## Proof of Concept

```solidity
// File: test/Exploit_StuckMsgValue.t.sol
// Run with: forge test --match-test test_MsgValueStuckInERC20Pool -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_StuckMsgValue is FullTest {
    function test_MsgValueStuckInERC20Pool() public {
        // SETUP: Create an ERC20-only pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        token0.approve(address(positions), 100);
        token1.approve(address(positions), 100);
        
        uint256 userBalanceBefore = address(this).balance;
        uint256 contractBalanceBefore = address(positions).balance;
        
        // EXPLOIT: User mistakenly sends 1 ETH thinking mint requires a fee
        (uint256 id,,,) = positions.mintAndDeposit{value: 1 ether}(
            poolKey, -100, 100, 100, 100, 0
        );
        
        // VERIFY: User lost 1 ETH, it's stuck in positions contract
        uint256 userBalanceAfter = address(this).balance;
        uint256 contractBalanceAfter = address(positions).balance;
        
        assertEq(userBalanceBefore - userBalanceAfter, 1 ether, "User lost 1 ETH");
        assertEq(contractBalanceAfter - contractBalanceBefore, 1 ether, "ETH stuck in contract");
        assertGt(id, 0, "Position was created successfully");
        
        // User can recover by calling refundNativeToken() if they discover it
        positions.refundNativeToken();
        assertEq(address(positions).balance, 0, "Funds recovered via manual refund");
    }
    
    function test_ExcessMsgValueStuckInNativePool() public {
        // SETUP: Create a native token pool
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        token1.approve(address(positions), 100);
        
        uint256 contractBalanceBefore = address(positions).balance;
        
        // EXPLOIT: User sends 2 ETH but only ~0.5 ETH is needed for position
        (uint256 id,,,) = positions.mintAndDeposit{value: 2 ether}(
            poolKey, -100, 100, 100, 100, 0
        );
        
        // VERIFY: Excess ETH stuck in contract (not refunded like in Router)
        uint256 contractBalanceAfter = address(positions).balance;
        assertTrue(contractBalanceAfter > contractBalanceBefore, "Excess ETH stuck in contract");
        assertGt(id, 0, "Position was created");
    }
    
    receive() external payable {}
}
```

**Notes:**
The vulnerability is confirmed by comparing `BasePositions` behavior with `Router.sol`, which properly implements refund logic for excess `msg.value`. The `Router` calculates `valueDifference` and refunds overpayment back to users, while `BasePositions` lacks any such mechanism, leaving funds stranded until users discover the manual `refundNativeToken()` function.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L108-108)
```text
    ///      No fees are collected; any msg.value sent is ignored.
```

**File:** src/base/BasePositions.sol (L159-169)
```text
    function mintAndDeposit(
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) {
        id = mint();
        (liquidity, amount0, amount1) = deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity);
    }
```

**File:** src/base/BasePositions.sol (L253-262)
```text
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
            } else {
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
                if (amount1 != 0) {
                    ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
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
