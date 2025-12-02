## Title
Burning Order NFTs Causes Permanent Loss of TWAMM Order Proceeds

## Summary
The Orders contract allows users to burn NFTs that represent active TWAMM orders, permanently locking all accumulated and future order proceeds. Once an order NFT is burned, the order continues executing in the TWAMM extension, but the `collectProceeds()` and `decreaseSaleRate()` functions become permanently inaccessible due to the `authorizedForNft(id)` modifier requirement, violating the protocol's "Withdrawal Availability" invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BaseNonfungibleToken.sol` (burn function) and `src/Orders.sol` (collectProceeds and decreaseSaleRate functions)

**Intended Logic:** The Orders contract manages TWAMM orders as NFTs, where users can create orders, collect proceeds, and cancel orders by modifying the sale rate. The NFT burn functionality is intended to allow gas refunds when NFTs are no longer needed.

**Actual Logic:** The `burn()` function does not verify whether the NFT has an active order before burning. [1](#0-0) 

Order state is stored independently in the TWAMM extension, indexed by `bytes32(id)`, not tied to NFT ownership. [2](#0-1) 

Both critical functions require NFT ownership:
- `collectProceeds()` requires `authorizedForNft(id)` [3](#0-2) 
- `decreaseSaleRate()` requires `authorizedForNft(id)` [4](#0-3) 

**Exploitation Path:**
1. User calls `mintAndIncreaseSellAmount()` to create an order with NFT [5](#0-4) 
2. Order begins executing in TWAMM, selling tokens over time and accumulating proceeds
3. User (intentionally or accidentally) calls `burn(id)` to burn the NFT [1](#0-0) 
4. Order state remains in TWAMM storage and continues executing, but NFT no longer exists
5. User cannot call `collectProceeds(id, ...)` - reverts with `NotUnauthorizedForToken` due to missing NFT [6](#0-5) 
6. User cannot call `decreaseSaleRate(id, ...)` to cancel order - same revert
7. All proceeds are permanently locked in the contract

**Security Property Broken:** Violates the "Withdrawal Availability" invariant: "All positions MUST be withdrawable at any time (except third-party extensions; in-scope extensions MUST NOT block withdrawal)". The burned order's proceeds cannot be withdrawn under any circumstances.

## Impact Explanation
- **Affected Assets**: All tokens held as proceeds from the TWAMM order (buyToken in the OrderKey)
- **Damage Severity**: 100% loss of all current and future order proceeds. The order continues executing until its endTime, accumulating more proceeds that also become permanently locked
- **User Impact**: Any user who burns an order NFT loses all proceeds. This can happen accidentally (user doesn't realize burn affects active orders) or through UI/wallet issues. The multicall pattern mentioned in the question makes this especially dangerous - a user could batch mint + increase + burn operations without realizing the consequences.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a user-inflicted loss that can happen accidentally. Any order creator can trigger this.
- **Preconditions**: User must have an active order (created via `mintAndIncreaseSellAmount` or separate `mint` + `increaseSellAmount`)
- **Execution Complexity**: Single transaction calling `burn(id)` where id corresponds to an active order
- **Frequency**: Can happen anytime a user burns an order NFT. With multicall support, this becomes more likely as users might batch operations without understanding the implications.

## Recommendation

Add a check in the `burn()` function to prevent burning NFTs with active orders, or override the burn function in the Orders contract:

```solidity
// In src/Orders.sol, add override for burn function:

/// @notice Burns an order NFT
/// @dev Prevents burning NFTs with active orders to protect user funds
/// @param id The token ID to burn
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Check if order has any active sale rate or remaining balance
    OrderKey memory orderKey = /* user must provide orderKey */;
    
    // Get current order state
    (uint112 saleRate, , , ) = TWAMM_EXTENSION.executeVirtualOrdersAndGetCurrentOrderInfo(
        address(this), 
        bytes32(id), 
        orderKey
    );
    
    // Prevent burning if order is still active
    if (saleRate > 0) {
        revert CannotBurnActiveOrder();
    }
    
    _burn(id);
}
```

**Alternative Mitigation:** Modify `collectProceeds()` and `decreaseSaleRate()` to store the original minter address during order creation and allow that address to collect/cancel even after NFT is burned. This requires adding storage to track the original creator per order ID.

## Proof of Concept

```solidity
// File: test/Exploit_BurnedOrderLocksProceeds.t.sol
// Run with: forge test --match-test test_BurnedOrderLocksProceeds -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {nextValidTime} from "../src/math/time.sol";

contract Exploit_BurnedOrderLocksProceeds is Test {
    Orders orders;
    Core core;
    // ... other contract instances
    
    function setUp() public {
        // Initialize protocol: deploy core, twamm, orders contracts
        // Create pool with liquidity
        // Approve tokens for orders contract
    }
    
    function test_BurnedOrderLocksProceeds() public {
        // SETUP: Create an order
        uint64 startTime = uint64(nextValidTime(block.timestamp, block.timestamp));
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        
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
        
        // Create order - mint NFT and increase sell amount
        (uint256 orderId, uint112 saleRate) = orders.mintAndIncreaseSellAmount(
            key,
            1000 ether,  // amount to sell
            type(uint112).max  // max sale rate
        );
        
        // Advance time so order executes and accumulates proceeds
        vm.warp(startTime + (endTime - startTime) / 2);
        
        // EXPLOIT: User burns the NFT (accidentally or intentionally)
        orders.burn(orderId);
        
        // VERIFY: Order proceeds are now permanently locked
        vm.expectRevert(); // Will revert with NotUnauthorizedForToken
        orders.collectProceeds(orderId, key, address(this));
        
        // Cannot cancel order either
        vm.expectRevert(); // Will revert with NotUnauthorizedForToken  
        orders.decreaseSaleRate(orderId, key, saleRate);
        
        // Order state still exists in TWAMM (can query but not collect)
        (uint112 currentRate, uint256 sold, uint256 remaining, uint128 purchased) = 
            orders.executeVirtualOrdersAndGetCurrentOrderInfo(orderId, key);
        
        assertGt(purchased, 0, "Order has accumulated proceeds");
        assertGt(currentRate, 0, "Order is still active");
        // But these proceeds are now permanently locked!
    }
}
```

## Notes

The question's phrasing about "mint fails after increaseSellAmount" is somewhat confusing since in `mintAndIncreaseSellAmount`, the mint occurs first. However, the core issue identified is correct: orders can exist without an NFT owner (after burning), making them permanently uncollectable. This can happen via multicall by batching `mint()` + `increaseSellAmount()` + `burn()` operations, or simply by a user burning an NFT after creating an order.

The vulnerability is particularly severe because:
1. It results in permanent loss of funds (High severity per Code4rena framework)
2. It violates the documented "Withdrawal Availability" invariant
3. It can happen accidentally through user error or UI issues
4. The multicall functionality makes batched operations more likely, increasing risk

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

**File:** src/base/BaseNonfungibleToken.sol (L133-135)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
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

**File:** src/Orders.sol (L77-94)
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

**File:** src/Orders.sol (L141-142)
```text
            int256 amount =
                CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));
```
