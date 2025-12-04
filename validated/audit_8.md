# Audit Report

## Title
Approved Addresses Can Permanently Lock User Funds by Burning Position NFTs with Active Liquidity

## Summary
The `burn()` function allows approved addresses to destroy Position NFTs without validating that associated liquidity has been withdrawn. This creates permanent fund loss because all position operations require NFT ownership verification, positions are stored under the Positions contract's address requiring calls through that contract, and users who minted via `mintAndDeposit()` cannot recreate their NFTs due to unrecoverable pseudo-random salts.

## Impact
**Severity**: High

Permanent and complete loss of 100% of user liquidity and accumulated fees. Once a Position NFT is burned with active liquidity, funds become permanently inaccessible because: (1) all withdrawal functions require the `authorizedForNft(id)` modifier which fails for burned NFTs, (2) positions are stored in Core by the Positions contract's address as locker and require calls through the Positions contract due to the `_requireLocker()` check, and (3) users cannot recreate the NFT ID without the original pseudo-random salt that was never stored or emitted.

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol:133-135` (`burn()` function) and `src/base/BasePositions.sol:71,100,120` (position management functions)

**Intended Logic:**
Per the documentation, `burn()` is designed to allow gas refunds "after the NFT is no longer needed" and states "the same ID can be recreated by the original minter by reusing the salt." [1](#0-0)  The protocol guarantees that "all positions should be able to be withdrawn at any time." [2](#0-1) 

**Actual Logic:**
The `burn()` function performs no validation of whether liquidity exists in positions associated with the NFT. [3](#0-2)  When an approved address burns an NFT with active liquidity:

1. The NFT is permanently destroyed through `_burn(id)`
2. All position operations require the `authorizedForNft(id)` modifier [4](#0-3) [5](#0-4) [6](#0-5) 
3. The `authorizedForNft` modifier checks `_isApprovedOrOwner(msg.sender, id)` which fails for burned NFTs [7](#0-6) 
4. Positions are stored in Core by the locker's address (the Positions contract), and Core functions require `_requireLocker()` check ensuring only the current locker can call them [8](#0-7) [9](#0-8) 
5. Users who called `mintAndDeposit()` cannot recreate their NFT because it uses a pseudo-random salt generated from `prevrandao()` and `gas()` that is never stored or emitted [10](#0-9) [11](#0-10) 

**Exploitation Path:**

1. **Setup**: User calls `mintAndDeposit()` to create a position with liquidity. This internally calls `mint()` which generates a pseudo-random salt that is never stored or emitted
2. **Approval**: User grants approval to a marketplace contract via `setApprovalForAll()` for NFT trading convenience (standard practice)
3. **Burn**: The approved address (malicious, compromised, or buggy) calls `burn(id)` on the user's Position NFT. The `authorizedForNft(id)` modifier passes because the address is approved
4. **Lock**: User attempts to call `withdraw()` or `collectFees()`, but these revert because the `authorizedForNft(id)` modifier fails - the NFT no longer exists
5. **No Recovery**: User cannot recreate the NFT ID because they don't know the pseudo-random salt. The liquidity remains in Core contract but is permanently inaccessible through any authorized pathway

**Security Guarantee Broken:**

This directly violates the protocol's documented invariant: "All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit)." [2](#0-1)  The position is not using a third-party extension, yet becomes permanently unwithdrawable.

## Impact Explanation

**Affected Assets**: All tokens (both principal liquidity and accumulated trading fees) in any liquidity position whose NFT has been burned. This includes positions in any token pair across any pool.

**Damage Severity**:
- Complete and permanent loss of 100% of deposited liquidity and accumulated fees
- No recovery mechanism exists - the liquidity remains in the Core contract but is inaccessible
- The NFT cannot be recreated without the original pseudo-random salt
- Unlike temporary locks, this is irreversible without protocol intervention (emergency upgrade)

**User Impact**: All users who:
- Created positions using `mintAndDeposit()` (the most common and convenient method)
- Granted approvals to marketplace contracts, router contracts, or other third-party protocols
- This includes users who listed Position NFTs on NFT marketplaces or approved aggregator contracts

**Trigger Conditions**: Requires only that an approved address calls `burn(id)` - a single transaction with no complex state setup required.

## Likelihood Explanation

**Attacker Profile**: Any address with approval, including:
- Malicious marketplace contracts
- Compromised legitimate contracts
- Contracts with bugs that accidentally burn NFTs
- Phishing contracts that obtained approval

**Preconditions**:
1. User created position using `mintAndDeposit()` without explicit salt (most common usage pattern)
2. Position has active liquidity (always true for active positions)
3. User granted approval via `approve()` or `setApprovalForAll()` (common for marketplace integrations)
4. Approved address calls `burn(id)` (single transaction)

**Execution Complexity**: Single transaction calling `burn(id)` - no complex timing, state manipulation, or multi-step process required.

**Economic Cost**: Only gas fees, no capital lockup required.

**Frequency**: Can affect all positions owned by users who granted approvals to the malicious/compromised contract.

**Overall Likelihood**: MEDIUM - While intentionally malicious burns are unlikely, accidental burns via buggy contracts or compromised integrations are realistic given how commonly users grant marketplace approvals for NFT trading.

## Recommendation

**Primary Fix - Add liquidity validation in burn():**

Override `burn()` in `BasePositions.sol` or `Positions.sol` to prevent burning NFTs with active liquidity:

```solidity
/// @notice Burns a position NFT after verifying no active liquidity
/// @param id The token ID to burn
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Verify no active liquidity exists
    // Option 1: Maintain mapping of NFT ID -> active position keys during deposit/withdraw
    // Option 2: Require explicit check across all known pools (gas-intensive)
    // Option 3: Require users to call separate "verifyNoLiquidity" before burn
    
    require(hasNoActiveLiquidity(id), "Cannot burn NFT with active liquidity");
    _burn(id);
}
```

**Alternative Fix - Emit salt for recovery:**

Modify `mint()` in `BaseNonfungibleToken.sol` to emit the salt so users can recreate their NFTs:

```solidity
event NFTMinted(address indexed minter, uint256 indexed id, bytes32 salt);

function mint() public payable returns (uint256 id) {
    bytes32 salt;
    assembly ("memory-safe") {
        mstore(0, prevrandao())
        mstore(32, gas())
        salt := keccak256(0, 64)
    }
    id = mint(salt);
    emit NFTMinted(msg.sender, id, salt);
}
```

**Recommended Complete Solution:**

1. Store mapping of NFT ID → active position keys when liquidity is deposited
2. Remove from mapping when position is fully withdrawn
3. Check mapping is empty before allowing burn
4. Additionally emit salt in minting events as backup recovery mechanism

## Proof of Concept

```solidity
// 1. User creates position with liquidity via mintAndDeposit()
(uint256 id, , , ) = positions.mintAndDeposit(poolKey, tickLower, tickUpper, amount0, amount1, minLiquidity);

// 2. User grants approval to marketplace
positions.setApprovalForAll(marketplace, true);

// 3. Marketplace (malicious/buggy) burns the NFT
vm.prank(marketplace);
positions.burn(id);

// 4. User's withdraw() call reverts
vm.expectRevert(); // NotUnauthorizedForToken
positions.withdraw(id, poolKey, tickLower, tickUpper, liquidity);

// 5. Liquidity remains in Core but is permanently inaccessible
```

The PoC demonstrates permanent fund lock using only standard contract functions without requiring any protocol modifications.

## Notes

This vulnerability is particularly critical because:

1. **Common user behavior**: Granting marketplace approvals is standard practice for NFT trading
2. **Unintuitive consequence**: Users don't expect that approving an address for transfers also gives power to permanently lock their funds
3. **Irrecoverable**: Unlike most DeFi vulnerabilities, this causes permanent loss with no recovery path
4. **Violates documented invariant**: The protocol explicitly promises that positions are always withdrawable
5. **Design vs implementation gap**: The documentation claims NFTs can be recreated by "reusing the salt," but this is impossible for the pseudo-random salt used by `mintAndDeposit()`

The current design assumes users will either: (a) only burn after withdrawing all liquidity, or (b) save their salt for recreation. Neither assumption is realistic for most users who use the convenient `mintAndDeposit()` function and grant standard marketplace approvals.

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

**File:** src/base/BaseNonfungibleToken.sol (L128-132)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
```

**File:** src/base/BaseNonfungibleToken.sol (L133-135)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```

**File:** README.md (L202-202)
```markdown
All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
```

**File:** src/base/BasePositions.sol (L71-79)
```text
    function deposit(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
```

**File:** src/base/BasePositions.sol (L100-107)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
    }
```

**File:** src/base/BasePositions.sol (L120-128)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
```

**File:** src/base/BasePositions.sol (L159-169)
```text
    function mintAndDeposit(
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) {
        id = mint();
        (liquidity, amount0, amount1) = deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity);
    }
```

**File:** src/Core.sol (L381-381)
```text
            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
```

**File:** src/base/FlashAccountant.sol (L54-56)
```text
    function _requireLocker() internal view returns (Locker locker) {
        locker = _getLocker();
        if (locker.addr() != msg.sender) revert LockerOnly();
```
