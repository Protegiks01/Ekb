## Title
NFT Transfer Vulnerability: New Owner Gains Unauthorized Control Over Active Orders and Can Steal All Deposited Funds and Proceeds

## Summary
The Orders contract implements NFT-based order management where transferring an order NFT grants the new owner complete control over the order, including the ability to withdraw all remaining deposited tokens and collect all accumulated proceeds. This occurs because the `authorizedForNft` modifier only validates current NFT ownership without tracking the original depositor, enabling fund theft through NFT transfer via phishing, social engineering, or marketplace exploitation.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Orders.sol` (functions `decreaseSaleRate` at lines 77-104 and `collectProceeds` at lines 107-119) and `src/base/BaseNonfungibleToken.sol` (modifier `authorizedForNft` at lines 81-86)

**Intended Logic:** The Orders contract represents TWAMM orders as transferable ERC721 NFTs, where each NFT ID corresponds to an active order. The system is designed to allow authorized parties to manage orders by decreasing sale rates (getting refunds of unsold tokens) and collecting proceeds (withdrawing purchased tokens).

**Actual Logic:** The authorization mechanism only checks current NFT ownership via the `authorizedForNft` modifier, which calls `_isApprovedOrOwner(msg.sender, id)`. [1](#0-0)  When an order NFT is transferred from Alice (original creator) to Bob (new owner), Bob immediately gains full control because the modifier now considers Bob as the authorized party. Both critical functions use this modifier without any additional checks: [2](#0-1)  and [3](#0-2) 

**Exploitation Path:**
1. Alice creates a TWAMM order by calling `mintAndIncreaseSellAmount`, depositing 1000 USDC to be sold over 30 days. [4](#0-3) 
2. After 15 days, 500 USDC has been sold and the order has accumulated 50 ETH in proceeds
3. Bob tricks Alice into transferring the order NFT (via phishing, fake marketplace listing, or social engineering claiming it's a "collectible" with no value)
4. Once Bob owns the NFT, he calls `decreaseSaleRate(id, orderKey, fullSaleRate, bob)` to get the remaining 500 USDC refunded to his address. [5](#0-4) 
5. Bob then calls `collectProceeds(id, orderKey, bob)` to withdraw the 50 ETH proceeds to his address. [6](#0-5) 
6. Alice loses all 1000 USDC (500 refunded + 500 worth of ETH proceeds) with no recourse

**Security Property Broken:** The system violates the fundamental principle that users should not lose their deposited funds through normal operations like NFT transfers. This also breaks the implicit expectation that the original depositor retains rights to their funds.

## Impact Explanation
- **Affected Assets**: All deposited tokens in active TWAMM orders (both remaining unsold tokens and accumulated proceeds in the buy token)
- **Damage Severity**: Complete loss of user funds - an attacker gains 100% of the victim's deposited tokens and all accumulated proceeds from the order. If a user has deposited $10,000 worth of tokens, the attacker can steal the entire amount.
- **User Impact**: Any user who transfers their order NFT loses all associated value. This affects users who: (1) list NFTs on marketplaces without understanding they control active orders, (2) get phished into transferring NFTs, (3) approve operators for legitimate purposes who then transfer the NFT maliciously, or (4) transfer NFTs believing they're just collectibles.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged actor can exploit this. The attacker only needs to convince or trick a user into transferring an order NFT, or purchase it from a marketplace if listed.
- **Preconditions**: (1) An active TWAMM order exists with remaining tokens or accumulated proceeds, (2) The order owner transfers the NFT to another address (either directly, via approval, or through a marketplace)
- **Execution Complexity**: Single transaction immediately after receiving the NFT. The attacker calls `decreaseSaleRate` and `collectProceeds` in sequence to extract all value.
- **Frequency**: This can be exploited continuously for every order NFT that gets transferred, and there are no rate limits or cooldowns to prevent repeated attacks.

## Recommendation

Implement fund ownership tracking separate from NFT ownership to prevent unauthorized fund extraction after transfers:

```solidity
// In src/Orders.sol, add a mapping to track original depositors:
mapping(uint256 => address) public orderDepositor;

// In src/Orders.sol, function mintAndIncreaseSellAmount, after line 48:
// CURRENT (vulnerable):
id = mint();
saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);

// FIXED:
id = mint();
orderDepositor[id] = msg.sender; // Track original depositor
saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);

// In src/Orders.sol, function decreaseSaleRate, line 80:
// CURRENT (vulnerable):
authorizedForNft(id)

// FIXED:
modifier authorizedForFunds(uint256 id) {
    require(msg.sender == orderDepositor[id] || msg.sender == ownerOf(id), "Not authorized for funds");
    _;
}
// Then use authorizedForFunds(id) instead of authorizedForNft(id)

// Alternative: Add a transfer hook to block transfers of active orders
function _beforeTokenTransfer(address from, address to, uint256 id) internal override {
    if (from != address(0) && to != address(0)) { // Skip on mint/burn
        // Check if order has remaining value
        revert("Cannot transfer active order NFT");
    }
}
```

**Alternative mitigation**: Implement a time-locked transfer mechanism where NFT transfers of active orders require a waiting period, giving the original owner time to extract their funds before the transfer completes.

## Proof of Concept

```solidity
// File: test/Exploit_OrderNFTTheft.t.sol
// Run with: forge test --match-test test_OrderNFTTheftViaTransfer -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {BaseOrdersTest} from "./Orders.t.sol";
import {OrderKey} from "../src/interfaces/extensions/ITWAMM.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";

contract Exploit_OrderNFTTheft is BaseOrdersTest {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    
    function setUp() public override {
        BaseOrdersTest.setUp();
        
        // Fund alice with tokens
        vm.startPrank(alice);
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
        vm.stopPrank();
    }
    
    function test_OrderNFTTheftViaTransfer() public {
        // SETUP: Alice creates an order with 1000 tokens
        uint64 fee = uint64((uint256(5) << 64) / 100);
        int32 tick = 0;
        
        vm.startPrank(alice);
        
        // Create pool with liquidity
        createTwammPool({fee: fee, tick: tick});
        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);
        
        uint64 startTime = uint64(block.timestamp);
        uint64 endTime = startTime + 1000;
        
        OrderKey memory key = OrderKey({
            token0: address(token0),
            token1: address(token1),
            config: createOrderConfig({
                _fee: fee,
                _isToken1: false,
                _startTime: startTime,
                _endTime: endTime
            })
        });
        
        // Alice creates order, depositing 1000 token0
        (uint256 orderId, uint112 saleRate) = orders.mintAndIncreaseSellAmount(
            key,
            1000e18,
            type(uint112).max
        );
        
        uint256 aliceInitialBalance0 = token0.balanceOf(alice);
        uint256 aliceInitialBalance1 = token1.balanceOf(alice);
        
        // Verify Alice owns the NFT
        assertEq(orders.ownerOf(orderId), alice);
        
        // Time passes, order accumulates proceeds
        vm.warp(block.timestamp + 500);
        
        // EXPLOIT: Alice transfers NFT to Bob (tricked via phishing/marketplace)
        orders.transferFrom(alice, bob, orderId);
        vm.stopPrank();
        
        // Verify Bob now owns the NFT
        assertEq(orders.ownerOf(orderId), bob);
        
        // Bob steals all remaining tokens and proceeds
        vm.startPrank(bob);
        
        // Bob decreases sale rate to get refund of remaining tokens
        uint112 refund = orders.decreaseSaleRate(orderId, key, saleRate, bob);
        
        // Bob collects all accumulated proceeds
        uint128 proceeds = orders.collectProceeds(orderId, key, bob);
        
        vm.stopPrank();
        
        // VERIFY: Bob received the funds, Alice lost everything
        assertGt(token0.balanceOf(bob), 0, "Bob stole remaining token0");
        assertGt(token1.balanceOf(bob), 0, "Bob stole proceeds (token1)");
        
        // Alice cannot recover funds - she lost ownership
        vm.startPrank(alice);
        vm.expectRevert();
        orders.collectProceeds(orderId, key, alice);
        vm.stopPrank();
        
        // Final balances prove theft
        console.log("Bob's stolen token0:", token0.balanceOf(bob));
        console.log("Bob's stolen token1:", token1.balanceOf(bob));
        console.log("Alice's remaining token0:", token0.balanceOf(alice) - aliceInitialBalance0);
        console.log("Alice's remaining token1:", token1.balanceOf(alice) - aliceInitialBalance1);
    }
}
```

## Notes

This vulnerability stems from the design decision to use pure ERC721 ownership for fund management without any additional safeguards. While NFT transferability enables position trading (which may be desirable), the complete lack of protective mechanisms creates a critical security flaw. The codebase contains no warnings in documentation [7](#0-6) , no tests covering transfer scenarios, and no time-locks or approval mechanisms to prevent accidental or malicious transfers of valuable order NFTs.

The vulnerability affects not just intentional transfers, but also any scenario where users approve operators (for marketplaces, aggregators, etc.) who could then transfer the NFT. The `recipient` parameter in both `decreaseSaleRate` and `collectProceeds` enables immediate fund extraction to any address chosen by the new owner, making the attack instantaneous and irreversible.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L81-86)
```text
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
```

**File:** src/Orders.sol (L43-50)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```

**File:** src/Orders.sol (L77-95)
```text
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
    }
```

**File:** src/Orders.sol (L107-114)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }
```

**File:** src/interfaces/IOrders.sol (L7-10)
```text
/// @title Orders Interface
/// @notice Interface for managing TWAMM (Time-Weighted Average Market Maker) orders as NFTs
/// @dev Defines the interface for creating, modifying, and collecting proceeds from long-term orders
interface IOrders is IBaseNonfungibleToken {
```
