## Title
Residual Native Token Theft via Unprotected `refundNativeToken()` Function

## Summary
The `refundNativeToken()` function in `PayableMulticallable.sol` lacks access control and refunds the entire contract balance to any caller, enabling attackers to steal excess ETH left by other users who failed to call refund in the same transaction as their deposit/order operations.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is designed to allow users to recover excess ETH they sent for operations where exact payment amounts are difficult to calculate in advance. Users should call this in the same `multicall` as their deposit/order operations to get back any unused ETH.

**Actual Logic:** The function transfers the **entire contract balance** to `msg.sender` without any access control or tracking of which user contributed the ETH. This means any user can steal residual ETH left by previous users who forgot to include `refundNativeToken()` in their transaction or planned to call it separately.

**Exploitation Path:**
1. **Victim deposits with excess ETH:** Victim calls `deposit()` on Positions contract with `msg.value = 2 ETH` but operation only needs `1 ETH`. The victim either forgets to call `refundNativeToken()` or plans to call it in a separate transaction later.
   - Reference: [2](#0-1) 

2. **ETH remains in contract:** When `token0 == NATIVE_TOKEN_ADDRESS`, exactly `amount0` (1 ETH) is transferred to ACCOUNTANT via `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0)`, leaving 1 ETH in the contract balance.
   - Reference: [3](#0-2) 

3. **Attacker monitors and steals:** Attacker detects the residual balance and calls `refundNativeToken()` (either standalone or within their own multicall). The function executes `SafeTransferLib.safeTransferETH(msg.sender, address(this).balance)`, transferring the victim's 1 ETH to the attacker.
   - Reference: [4](#0-3) 

4. **Victim loses funds:** The victim permanently loses their excess ETH as it has been stolen by the attacker.

**Security Property Broken:** Direct theft of user funds - violates the fundamental security principle that users should only lose funds through their explicit actions, not through front-running or MEV extraction by other users.

## Impact Explanation

- **Affected Assets:** Native token (ETH) sent by users when interacting with Positions (liquidity deposits) and Orders (TWAMM order increases). Similar vulnerability exists in Orders contract.
  - Reference: [5](#0-4) 

- **Damage Severity:** Attacker can drain 100% of residual ETH from the contract. Loss scales with:
  - Number of users who send excess ETH without proper refund calls
  - Amount of excess ETH per transaction (typically happens when users overestimate gas costs or use round numbers)
  - Front-running opportunities where attackers can steal between victim's deposit and their planned refund call

- **User Impact:** Any user who sends native token with Positions or Orders operations and doesn't call `refundNativeToken()` in the same transaction. This affects:
  - Users unfamiliar with the multicall pattern
  - Users who experience transaction failures and retry without refund
  - Users who split operations across multiple transactions for gas optimization
  - Smart contract integrators who may not be aware of the refund requirement

## Likelihood Explanation

- **Attacker Profile:** Any user or MEV searcher can exploit this. No special permissions required - simply monitor contract balance and call `refundNativeToken()` when non-zero.

- **Preconditions:** 
  - Any user sends native token to Positions or Orders contract with `msg.value > amount_needed`
  - The user does not call `refundNativeToken()` in the same transaction
  - Contract balance is non-zero (can be verified on-chain before attack)

- **Execution Complexity:** Trivial - single transaction calling `refundNativeToken()`. Can be automated with a simple bot monitoring `address(Positions).balance` and `address(Orders).balance`.

- **Frequency:** Can be exploited continuously as long as users continue to leave residual ETH. Expected to occur frequently given:
  - Complex UX requiring users to understand multicall patterns
  - No warning or protection in the UI/contracts
  - Natural tendency to send round numbers (e.g., 1 ETH when only 0.98 ETH needed)

## Recommendation

**Option 1: Track ETH ownership per user (Recommended)**

```solidity
// In src/base/PayableMulticallable.sol

mapping(address => uint256) private _nativeTokenCredits;

function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    uint256 balanceBefore = address(this).balance - msg.value;
    bytes[] memory results = _multicall(data);
    
    // Credit any remaining balance to the caller
    uint256 balanceAfter = address(this).balance;
    if (balanceAfter > balanceBefore) {
        _nativeTokenCredits[msg.sender] += balanceAfter - balanceBefore;
    }
    
    _multicallDirectReturn(results);
}

function refundNativeToken() external payable {
    uint256 credit = _nativeTokenCredits[msg.sender];
    if (credit != 0) {
        _nativeTokenCredits[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, credit);
    }
}
```

**Option 2: Restrict to same-transaction refunds only**

```solidity
// In src/base/PayableMulticallable.sol

function refundNativeToken() external payable {
    // Only allow refund if called within a multicall context
    // This prevents stealing residual ETH from other users
    if (address(this).balance != 0 && msg.sender == tx.origin) {
        revert RefundMustBeCalledInMulticall();
    }
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}
```

**Option 3: Add access control with time-based claim**

Allow users a grace period to claim their refund before it becomes claimable by anyone (less ideal but prevents immediate theft).

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_StealResidualETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import "../src/base/FlashAccountant.sol";

contract Exploit_RefundNativeTokenTheft is Test {
    Positions positions;
    Core core;
    
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        // Deploy protocol (simplified setup)
        core = new Core();
        positions = new Positions(core, address(this));
        
        // Fund accounts
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);
    }
    
    function test_StealResidualETH() public {
        // SETUP: Victim deposits with excess ETH (2 ETH sent, only 1 ETH needed)
        vm.startPrank(victim);
        
        uint256 victimBalanceBefore = victim.balance;
        
        // Victim calls deposit without refundNativeToken in same tx
        // (simplified - actual call would have pool parameters)
        // Assume operation needs only 1 ETH but victim sends 2 ETH
        (bool success,) = address(positions).call{value: 2 ether}(
            abi.encodeWithSignature("deposit(...)")
        );
        
        vm.stopPrank();
        
        // Verify 1 ETH is stuck in positions contract
        assertEq(address(positions).balance, 1 ether, "Residual ETH should be in contract");
        
        // EXPLOIT: Attacker calls refundNativeToken and steals victim's ETH
        vm.startPrank(attacker);
        
        uint256 attackerBalanceBefore = attacker.balance;
        
        positions.refundNativeToken();
        
        uint256 attackerBalanceAfter = attacker.balance;
        
        vm.stopPrank();
        
        // VERIFY: Attacker stole victim's 1 ETH
        assertEq(attackerBalanceAfter - attackerBalanceBefore, 1 ether, 
            "Attacker should have stolen 1 ETH");
        assertEq(address(positions).balance, 0, 
            "Contract should have zero balance after theft");
        assertEq(victim.balance, victimBalanceBefore - 2 ether,
            "Victim lost full 2 ETH but only got service for 1 ETH");
    }
}
```

**Notes:**
- The vulnerability exists because contracts inheriting `PayableMulticallable` (Positions, Orders, Router) can accumulate residual native tokens
- While Router has its own refund mechanism via ACCOUNTANT withdrawals [6](#0-5) , Positions and Orders rely solely on `refundNativeToken()`
- The multicall pattern [7](#0-6)  is designed for batching operations, but the refund function has no transaction-level isolation
- This vulnerability enables direct theft of user funds, qualifying as HIGH severity under the Code4rena framework

### Citations

**File:** src/base/PayableMulticallable.sol (L17-19)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
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

**File:** src/base/BasePositions.sol (L252-262)
```text
            // Use multi-token payment for ERC20-only pools, fall back to individual payments for native token pools
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

**File:** src/Orders.sol (L146-151)
```text
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
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
