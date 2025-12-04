# Audit Report

## Title
TWAMM Order Proceeds Permanently Locked When NFT Burned Due to Unrecoverable Random Salt

## Summary
The `Orders.sol` contract uses a parameterless `mint()` function that generates NFT IDs with cryptographically random salts. When an order NFT is burned (either by the owner or an approved address), users permanently lose access to their accumulated TWAMM order proceeds because they cannot recreate the NFT with the same ID, as the original random salt was never stored or emitted and cannot be recovered.

## Impact
**Severity**: High

This vulnerability causes permanent, irreversible loss of user funds. TWAMM order proceeds (the tokens purchased through the order) become cryptographically inaccessible after the NFT is burned, violating the protocol's core invariant that "All positions should be able to be withdrawn at any time." [1](#0-0) 

## Finding Description

**Location:** Multiple locations across `src/Orders.sol` and `src/base/BaseNonfungibleToken.sol`

**Intended Logic:** 
According to the code comment, the NFT burn mechanism is designed to allow gas refunds after an order completes, with the explicit design assumption that "The same ID can be recreated by the original minter by reusing the salt." [2](#0-1) 

The deterministic ID generation ensures the same `(minter, salt)` pair always produces the same ID: [3](#0-2) 

**Actual Logic:**
When users create TWAMM orders via `mintAndIncreaseSellAmount()`, the contract internally calls the parameterless `mint()` function: [4](#0-3) 

This parameterless `mint()` generates a salt using `prevrandao()` and `gas()`, which are non-deterministic and execution-context dependent: [5](#0-4) 

This salt is:
- Never stored in contract storage
- Never emitted in events (only the Transfer event contains the resulting ID, not the salt)
- Cryptographically impossible to reverse-engineer from the resulting ID
- Completely unrecoverable once the transaction completes

When the NFT is burned, users lose their ability to collect proceeds because `collectProceeds()` requires the `authorizedForNft(id)` authorization: [6](#0-5) 

This modifier checks `_isApprovedOrOwner(msg.sender, id)`, which always returns false for non-existent (burned) tokens.

**Exploitation Path:**

1. **Order Creation**: User calls `Orders.mintAndIncreaseSellAmount()` to create a TWAMM order. The NFT is minted with a random salt derived from `keccak256(prevrandao(), gas())`.

2. **NFT Burned**: The user burns the NFT (either accidentally for gas refund, or an approved address burns it). The order remains active in the TWAMM extension and continues accumulating proceeds.

3. **Proceeds Locked**: User attempts to collect proceeds via `Orders.collectProceeds(id, orderKey)`. The transaction reverts at the `authorizedForNft(id)` modifier because the NFT no longer exists.

4. **No Recovery Path**: 
   - User cannot remint the NFT because they don't know the original random salt
   - User cannot call TWAMM directly because `handleForwardData` is only accessible via `Core.forward()` which requires being the current locker [7](#0-6) 
   
   - The proceeds are stored in TWAMM extension keyed by `(Orders_contract_address, nft_id, order_id)`: [8](#0-7) 
   
   - There is no admin function or alternative mechanism to recover proceeds for burned NFTs

**Security Property Broken:**
This violates the critical invariant stated in the README: "All positions should be able to be withdrawn at any time." TWAMM order proceeds become permanently inaccessible after NFT burning, and the in-scope TWAMM extension blocks withdrawal not due to gas limits, but due to missing access control. [1](#0-0) 

## Impact Explanation

**Affected Assets**: All proceeds accumulated by TWAMM orders (denominated in the buy token) from order creation until NFT burning. For long-duration DCA orders, this could represent substantial value.

**Damage Severity**: Complete and permanent loss of all order proceeds. The tokens remain in the Core contract's balance but are cryptographically inaccessible to the rightful owner.

**User Impact**: Any user who burns their TWAMM order NFT (whether accidentally for gas refund, or through an approved address burning it). This affects the core functionality of TWAMM orders where users expect to collect accumulated proceeds at any time during or after the order period.

## Likelihood Explanation

**Attacker Profile**: This can occur without any attacker - users may accidentally burn their own NFTs believing they can recreate them (as suggested by the code comment). In the malicious case, any address with NFT approval can burn the NFT.

**Preconditions**:
1. User has an active TWAMM order with accumulated proceeds
2. The order NFT is burned (either by owner or approved address)

**Execution Complexity**: Single transaction calling `burn(id)`. No complex setup or timing required.

**Frequency**: Can occur for any TWAMM order where the NFT is burned before collecting proceeds.

**Overall Likelihood**: MEDIUM to HIGH - The misleading code comment suggesting NFTs can be recreated may lead users to burn NFTs thinking they can remint them later. The parameterless `mint()` function with random salt makes this impossible.

## Recommendation

**Primary Fix**: Use a deterministic salt derivation or store/emit the salt when minting order NFTs:

```solidity
// Option 1: Use deterministic salt based on order parameters
function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
    public
    payable
    returns (uint256 id, uint112 saleRate)
{
    bytes32 salt = keccak256(abi.encode(msg.sender, block.timestamp, orderKey));
    id = mint(salt);
    // Emit event with salt for user reference
    emit OrderCreated(id, salt, msg.sender, orderKey);
    saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
}
```

**Alternative Mitigation**: Add a recovery mechanism that allows original order creators to collect proceeds even after burning:

```solidity
// Store original creator when minting
mapping(uint256 => address) public originalOrderCreator;

function collectProceedsAfterBurn(uint256 id, OrderKey memory orderKey, address recipient) 
    external 
    returns (uint128 proceeds) 
{
    require(msg.sender == originalOrderCreator[id], "Not original creator");
    require(_ownerOf(id) == address(0), "NFT still exists");
    // Collect without NFT authorization check
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}
```

## Notes

This vulnerability is distinct from the known behavior where proceeds cannot be collected after stopping an order (calling `decreaseSaleRate` to zero). That issue allows calling `collectProceeds()` which returns 0 (by design). This NFT burning issue prevents calling `collectProceeds()` entirely, violating both the documented design intent and the core invariant about position withdrawability.

The test suite confirms that NFTs can only be recreated if the original salt is known: [9](#0-8) 

This test uses an explicit salt (`bytes32(0)`), demonstrating the intended reminting behavior. However, the Orders contract uses the parameterless `mint()` with a random, unrecoverable salt, breaking this design pattern.

### Citations

**File:** README.md (L202-202)
```markdown
All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
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

**File:** src/extensions/TWAMM.sol (L351-352)
```text
                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);
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
