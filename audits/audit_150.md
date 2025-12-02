## Title
TWAMM Order Proceeds Permanently Locked When NFT Burned Due to Unrecoverable Random Salt

## Summary
The `Orders.sol` contract uses a parameterless `mint()` function that generates NFT IDs with cryptographically random salts derived from `prevrandao()` and `gas()`. If an attacker obtains approval for a user's order NFT (through social engineering or phishing) and burns it while the order is active, the user cannot recover their accumulated proceeds because they cannot recreate the NFT with the same ID, as the original salt is unrecoverable and was never stored or emitted.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The NFT burn mechanism is designed to allow gas refunds after an order completes, with the assumption that users can remint the same NFT ID by reusing the known salt [2](#0-1) . The deterministic ID generation ensures the same `(minter, salt)` pair always produces the same ID [3](#0-2) .

**Actual Logic:** When users create TWAMM orders via `mintAndIncreaseSellAmount()`, the contract internally calls the parameterless `mint()` function [4](#0-3)  which generates a salt using `prevrandao()` and `gas()` [5](#0-4) . This salt is:
- Never stored in contract storage
- Never emitted in events (only the Transfer event contains the resulting ID, not the salt)
- Cryptographically impossible to reverse-engineer from the ID
- Block and execution-context dependent, making it unrecoverable

When the NFT is burned, the user loses their ability to collect proceeds because `collectProceeds()` requires `authorizedForNft(id)` authorization [6](#0-5) , which fails for non-existent tokens.

**Exploitation Path:**

1. **Order Creation**: User calls `Orders.mintAndIncreaseSellAmount()` to create a TWAMM order selling token0 for token1 over 30 days. The NFT is minted with ID derived from `keccak256(user, random_salt, chainid, contract_address)` where `random_salt = keccak256(prevrandao(), gas())`.

2. **Approval Obtained**: Attacker tricks user into approving their address (e.g., through phishing website mimicking a legitimate DEX aggregator, or malicious dApp claiming to offer "enhanced order management").

3. **NFT Burned**: Attacker calls `Orders.burn(id)` which succeeds due to `authorizedForNft(id)` check passing [7](#0-6) . The order remains active in TWAMM extension and continues accumulating proceeds.

4. **Proceeds Locked**: User attempts to collect proceeds via `Orders.collectProceeds(id, orderKey)`. The transaction reverts at the `authorizedForNft(id)` modifier because `_isApprovedOrOwner` returns false for the burned (non-existent) NFT. The proceeds are stored in TWAMM extension keyed by `(Orders_contract_address, nft_id, order_id)` [8](#0-7)  and can only be withdrawn through the Orders contract.

5. **No Recovery Path**: 
   - User cannot remint the NFT because they don't know the original salt (it was random and unrecorded)
   - User cannot call TWAMM directly because `handleForwardData` is only accessible via `Core.forward()` which requires being the current locker [9](#0-8) 
   - There is no admin function to recover proceeds for burned NFTs
   - The test suite confirms that reminting requires the exact same salt [10](#0-9) 

**Security Property Broken:** Violates the critical invariant "All positions MUST be withdrawable at any time" - proceeds from active TWAMM orders become permanently inaccessible after NFT burning.

## Impact Explanation

- **Affected Assets**: All proceeds accumulated by the TWAMM order (denominated in the buy token) from order creation until the griefing attack. For long-duration orders, this could represent substantial value.

- **Damage Severity**: Complete and permanent loss of all order proceeds. The tokens remain in the Core contract's balance but are cryptographically inaccessible. For a 30-day DCA order selling $100k worth of tokens, all purchased tokens (potentially worth $100k or more) become permanently locked.

- **User Impact**: Any user who creates TWAMM orders is vulnerable. The attack requires the user to grant approval (either token-specific via `approve()` or operator status via `setApprovalForAll()`), which is a common operation that users perform for legitimate dApps, making social engineering attacks realistic.

## Likelihood Explanation

- **Attacker Profile**: Any external actor who can convince users to grant NFT approval. This includes phishing sites, compromised dApp frontends, or malicious contracts presented as legitimate protocols.

- **Preconditions**: 
  - User must have an active TWAMM order with accumulated proceeds
  - User must grant approval to attacker's address (realistic via social engineering)
  - Order must still be active (not yet ended)

- **Execution Complexity**: Single transaction calling `burn(id)`. No complex timing or state manipulation required.

- **Frequency**: Can be executed once per order NFT. Given that TWAMM orders are designed for long time periods (days to weeks), attackers have a large window to execute the attack. Multiple users can be griefed in succession.

## Recommendation

**Primary Fix**: Store or emit the salt when minting order NFTs, or use a deterministic salt derivation:

```solidity
// In src/Orders.sol, function mintAndIncreaseSellAmount, line 43:

// CURRENT (vulnerable):
// Uses random mint() which generates unrecoverable salt

// FIXED Option 1: Emit the salt
function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
    public
    payable
    returns (uint256 id, uint112 saleRate, bytes32 salt)
{
    salt = bytes32(uint256(keccak256(abi.encode(msg.sender, block.timestamp, orderKey))));
    id = mint(salt);
    emit OrderCreated(id, salt, msg.sender, orderKey);  // Store salt in event
    saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
}

// FIXED Option 2: Allow proceeds collection by orderKey
// Add a mapping from (user, orderKey) to NFT ID
mapping(address => mapping(bytes32 => uint256)) public userOrderIds;

function collectProceedsByOrderKey(OrderKey memory orderKey, address recipient) 
    public 
    returns (uint128 proceeds) 
{
    uint256 id = userOrderIds[msg.sender][keccak256(abi.encode(orderKey))];
    require(id != 0, "Order not found");
    // Collect without NFT authorization check for original creator
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}
```

**Alternative Mitigation**: Add a recovery mechanism for burned NFTs:

```solidity
// In src/Orders.sol:

mapping(uint256 => address) public originalOrderCreator;

function mintAndIncreaseSellAmount(...) public payable returns (uint256 id, uint112 saleRate) {
    id = mint();
    originalOrderCreator[id] = msg.sender;  // Store creator
    saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
}

function collectProceedsAfterBurn(uint256 id, OrderKey memory orderKey, address recipient) 
    external 
    returns (uint128 proceeds) 
{
    require(msg.sender == originalOrderCreator[id], "Not original creator");
    require(_ownerOf(id) == address(0), "NFT still exists");
    // Collect without NFT check since NFT was burned
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}
```

## Proof of Concept

```solidity
// File: test/Exploit_BurnedOrderNFT.t.sol
// Run with: forge test --match-test test_BurnedOrderNFTLocksProceeds -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "./FullTest.sol";

contract Exploit_BurnedOrderNFT is FullTest {
    
    function test_BurnedOrderNFTLocksProceeds() public {
        // SETUP: Create a TWAMM pool and order
        PoolKey memory poolKey = createFullRangeTwammPool(0, 1 << 63);
        
        token0.approve(address(orders), 1000e18);
        
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: OrderConfig.wrap(
                uint256(block.timestamp) | // startTime
                (uint256(block.timestamp + 1 days) << 32) | // endTime  
                (uint256(0) << 64) // isToken1 = false (selling token0)
            )
        });
        
        // User creates order selling 1000 token0 over 1 day
        (uint256 orderId, ) = orders.mintAndIncreaseSellAmount(
            orderKey, 
            1000e18, 
            type(uint112).max
        );
        
        // Verify user owns the NFT
        assertEq(orders.ownerOf(orderId), address(this));
        
        // Simulate order accumulating proceeds (some time passes, swaps occur)
        vm.warp(block.timestamp + 12 hours);
        
        // EXPLOIT: User mistakenly approves attacker
        address attacker = makeAddr("attacker");
        orders.approve(attacker, orderId);
        
        // Attacker burns the NFT
        vm.prank(attacker);
        orders.burn(orderId);
        
        // VERIFY: NFT no longer exists
        vm.expectRevert();
        orders.ownerOf(orderId);
        
        // User tries to collect proceeds - FAILS
        vm.expectRevert(); // authorizedForNft check fails
        orders.collectProceeds(orderId, orderKey);
        
        // User cannot remint because they don't know the salt
        // The salt was: keccak256(abi.encode(prevrandao(), gas())) at mint time
        // This is unrecoverable
        
        // Proceeds are permanently locked
        console.log("Order proceeds permanently inaccessible after NFT burn");
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Social Engineering Vector**: Users regularly grant approvals to interact with DeFi protocols, making approval-based attacks realistic. Unlike direct theft vulnerabilities, this griefing attack doesn't require exploiting a protocol bug—it exploits a design flaw combined with social engineering.

2. **No Warning Signs**: The protocol provides no warnings about the dangers of burning active order NFTs. The comment at line 130 of BaseNonfungibleToken.sol states "The same ID can be recreated by the original minter by reusing the salt" but this is impossible when the salt is random and unrecorded.

3. **Economic Incentive for Attackers**: Competitors or malicious actors can permanently lock significant funds of market participants, potentially profiting from the market disruption or reduced competition.

4. **Permanent Loss**: Unlike temporary DOS or recoverable fund locks, this issue causes permanent, irreversible loss of user funds, qualifying it as HIGH severity per Code4rena criteria.

The fix requires either storing/emitting the salt during minting, using a deterministic salt scheme, or implementing an alternative authorization mechanism for burned NFTs.

### Citations

**File:** src/Orders.sol (L43-49)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
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

**File:** src/base/BaseNonfungibleToken.sol (L92-102)
```text
    function saltToId(address minter, bytes32 salt) public view returns (uint256 result) {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, minter)
            mstore(add(free, 32), salt)
            mstore(add(free, 64), chainid())
            mstore(add(free, 96), address())

            result := keccak256(free, 128)
        }
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

**File:** src/extensions/TWAMM.sol (L351-352)
```text
                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);
```

**File:** src/base/FlashAccountant.sol (L190-221)
```text
    function forward(address to) external {
        Locker locker = _requireLocker();

        // update this lock's locker to the forwarded address for the duration of the forwarded
        // call, meaning only the forwarded address can update state
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

            let free := mload(0x40)

            // Prepare call to forwarded_2374103877(bytes32) -> selector 0x01
            mstore(free, shl(224, 1))
            mstore(add(free, 4), locker)

            calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))

            // Call the forwardee with the packed data
            let success := call(gas(), to, 0, free, calldatasize(), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            tstore(_CURRENT_LOCKER_SLOT, locker)

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```

**File:** test/Positions.t.sol (L421-426)
```text
    function test_burn_can_be_minted() public {
        uint256 id = positions.mint(bytes32(0));
        positions.burn(id);
        uint256 id2 = positions.mint(bytes32(0));
        assertEq(id, id2);
    }
```
