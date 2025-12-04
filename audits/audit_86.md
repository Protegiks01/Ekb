# Audit Report

## Title
Burning Order NFTs Causes Permanent Loss of TWAMM Order Proceeds

## Summary
The Orders contract allows users to burn NFTs representing active TWAMM orders without verification, permanently locking all order proceeds. The order state persists in the TWAMM extension and continues executing, but users cannot collect proceeds or cancel orders due to `authorizedForNft` modifier requirements on critical functions, resulting in irreversible fund loss.

## Impact
**Severity**: High

Users who burn order NFTs lose 100% of accumulated and future order proceeds permanently. Orders created via `mintAndIncreaseSellAmount()` use randomly-generated NFT IDs that cannot be recreated, making fund recovery impossible. This affects all tokens accumulated as order proceeds and can occur accidentally through user error or batched multicall operations.

## Finding Description

**Location:** [1](#0-0)  (burn function) and [2](#0-1)  (collectProceeds), [3](#0-2)  (decreaseSaleRate)

**Intended Logic:** 
The Orders contract manages TWAMM orders as NFTs. Users create orders to sell tokens over time, collect accumulated proceeds, and cancel orders by decreasing sale rates. The burn function enables gas refunds when NFTs are no longer needed, with the design comment suggesting NFTs can be "recreated by the original minter by reusing the salt" [4](#0-3) .

**Actual Logic:**
The `burn()` function only checks authorization via `authorizedForNft(id)` modifier [5](#0-4)  but performs no validation of active order state before burning [1](#0-0) .

Order state is stored independently in the TWAMM extension indexed by `(Orders contract address, bytes32(id), orderId)` [6](#0-5)  and persists after NFT destruction.

Both critical functions require NFT ownership:
- `collectProceeds()` has `authorizedForNft(id)` modifier [2](#0-1) 
- `decreaseSaleRate()` has `authorizedForNft(id)` modifier [3](#0-2) 

**Critical Design Flaw:** The standard order creation flow `mintAndIncreaseSellAmount()` calls `mint()` without parameters [7](#0-6) , which generates a random salt using `prevrandao()` and `gas()` [8](#0-7) . This salt cannot be reproduced, making NFT recreation impossible despite the design comment suggesting otherwise.

**Exploitation Path:**
1. User calls `mintAndIncreaseSellAmount()` creating order with random NFT ID
2. Order executes in TWAMM, accumulating proceeds in the buy token
3. User burns NFT via `burn(id)` (accidentally or intentionally)
4. Order state remains in TWAMM storage [9](#0-8)  and continues executing
5. `collectProceeds()` reverts with `NotUnauthorizedForToken` due to missing NFT [10](#0-9) 
6. `decreaseSaleRate()` also reverts - cannot cancel order
7. All current and future proceeds permanently locked with no recovery mechanism

## Impact Explanation

**Affected Assets**: All tokens accumulated as proceeds from the burned order (the buyToken specified in OrderKey)

**Damage Severity**:
- 100% permanent loss of all current order proceeds
- 100% permanent loss of all future proceeds (order continues executing until endTime)
- No recovery mechanism exists - NFT cannot be recreated with random salt
- Order continues accumulating more locked proceeds over time

**User Impact**: 
- Any user who burns an active order NFT loses all proceeds
- Can occur accidentally (user unaware burn affects active orders)
- Multicall batching increases risk - users could combine mint+increase+burn without understanding consequences
- No warning or protection in the protocol

**Trigger Conditions**: Single transaction calling `burn(id)` on any active order NFT

## Likelihood Explanation

**Attacker Profile**: Not malicious - this is user-inflicted permanent loss

**Preconditions**:
1. User has active order created via `mintAndIncreaseSellAmount()` or `mint()` + `increaseSellAmount()`
2. Order has accumulated or will accumulate proceeds
3. No other preconditions required

**Execution Complexity**: Single external call to `burn(id)` - trivial execution

**Economic Cost**: Only gas fees for burn transaction

**Frequency**: Can occur anytime during order lifetime (between startTime and endTime)

**Overall Likelihood**: MEDIUM-HIGH
- Common user flow uses vulnerable `mintAndIncreaseSellAmount()`
- Burn function available without warnings
- Multicall support enables accidental batched operations
- Users may not understand NFT burn affects order access

## Recommendation

**Primary Fix - Override burn in Orders contract:**

```solidity
// In src/Orders.sol
function burn(uint256 id) external payable override authorizedForNft(id) {
    // User must provide OrderKey to check order state
    // This requires interface change to include OrderKey parameter
    // Verify order has zero sale rate before allowing burn
    _burn(id);
}
```

**Alternative Fix - Remove authorization requirement:**

Store original minter address during order creation and allow that address to collect proceeds and modify orders even after NFT burn. Requires additional storage mapping:

```solidity
mapping(uint256 => address) public orderCreators;
// Check orderCreators[id] instead of NFT ownership in collectProceeds/decreaseSaleRate
```

**Immediate Mitigation:**
Document the risk prominently and warn users never to burn order NFTs with active orders or uncollected proceeds.

## Proof of Concept

The conceptual PoC demonstrates the issue (full implementation requires test setup):

```solidity
// 1. Create order using standard flow
(uint256 orderId, ) = orders.mintAndIncreaseSellAmount(orderKey, amount, maxRate);

// 2. Time passes, order executes and accumulates proceeds
vm.warp(block.timestamp + duration);

// 3. User burns NFT (accidentally or intentionally)  
orders.burn(orderId);

// 4. Attempting to collect proceeds reverts
vm.expectRevert(); // NotUnauthorizedForToken
orders.collectProceeds(orderId, orderKey, user);

// 5. Cannot cancel order either
vm.expectRevert(); // NotUnauthorizedForToken
orders.decreaseSaleRate(orderId, orderKey, saleRate);

// 6. Order state still exists and continues executing
(uint112 rate, , , uint128 proceeds) = 
    orders.executeVirtualOrdersAndGetCurrentOrderInfo(orderId, orderKey);
// rate > 0 and proceeds > 0, but permanently inaccessible
```

## Notes

**Invariant Clarification**: The README "Withdrawal Availability" invariant (line 202) specifically states "All **positions** MUST be withdrawable at any time" referring to liquidity positions, not TWAMM orders. While the claim extends this principle to orders, the core issue remains valid: permanent loss of user funds due to a design flaw is always High severity regardless of documented invariants.

**Design vs Implementation Gap**: The comment at [4](#0-3)  suggests NFTs can be recreated by reusing the salt, but the standard order creation flow [11](#0-10)  uses random salt generation [8](#0-7)  that cannot be reproduced.

**Root Cause**: The Orders contract provides no way to:
1. Create orders with known/recorded salts for later recreation
2. Prevent burning NFTs with active orders  
3. Access order proceeds without NFT ownership

Any one of these mitigations would prevent the vulnerability.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L19-19)
```text
    error NotUnauthorizedForToken(address caller, uint256 id);
```

**File:** src/base/BaseNonfungibleToken.sol (L81-86)
```text
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
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

**File:** src/base/BaseNonfungibleToken.sol (L129-131)
```text
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
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

**File:** src/extensions/TWAMM.sol (L216-217)
```text
                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);
```

**File:** src/extensions/TWAMM.sol (L221-222)
```text
                OrderState order = OrderState.wrap(orderStateSlot.load());
                uint256 rewardRateSnapshot = uint256(orderRewardRateSnapshotSlot.load());
```
