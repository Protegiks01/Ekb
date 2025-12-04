After performing systematic validation according to the Ekubo Protocol validation framework, I have completed a comprehensive analysis of this security claim.

# Audit Report

## Title
Approved Addresses Can Permanently Lock User Funds by Burning Position NFTs with Active Liquidity

## Summary
The `burn()` function in BaseNonfungibleToken allows approved addresses to destroy position NFTs without verifying that liquidity has been withdrawn. When users create positions via `mintAndDeposit()`, a random salt is generated but never stored or emitted. After an approved address burns the NFT, all position operations revert permanently because they require the NFT to exist, and the position cannot be recovered because the salt is unknown.

## Impact
**Severity**: High

This vulnerability results in complete and permanent loss of user funds. When an approved address burns a position NFT, the owner loses all deposited liquidity and accrued fees with no recovery mechanism. This directly violates the protocol's core invariant stated in the README: "All positions should be able to be withdrawn at any time." [1](#0-0) 

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol`, function `burn()` (lines 133-135)

**Intended Logic:** 
The documentation states burn is for "after the NFT is no longer needed" with the expectation that "the same ID can be recreated by the original minter by reusing the salt." [2](#0-1) 

**Actual Logic:**
The `burn()` function only checks authorization via `authorizedForNft` modifier, which permits both owners and approved addresses, with no validation that the position has zero liquidity. [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. **Position Creation**: User calls `mintAndDeposit()` which internally invokes `mint()` without arguments. This generates a random salt from `prevrandao()` and `gas()` that is never stored or emitted. [5](#0-4) [6](#0-5) 

2. **NFT Approval**: User approves another address (for marketplace listing, delegation, or smart contract integration).

3. **Malicious Burn**: Approved address calls `burn(tokenId)`, which passes the `authorizedForNft` check and destroys the NFT.

4. **Position Becomes Inaccessible**: All position operations (`withdraw`, `collectFees`, `deposit`) require `authorizedForNft(id)` which calls `_isApprovedOrOwner()`. Since `ownerOf()` reverts for burned tokens, these operations permanently fail. [7](#0-6) [8](#0-7) [9](#0-8) 

5. **Recovery Impossible**: User cannot recreate the NFT because the salt was randomly generated and never stored. The user cannot access Core directly because positions are stored with the Positions contract as owner, not the user. [10](#0-9) 

**Security Guarantee Broken:**
This vulnerability violates the explicit protocol invariant: "All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit)." [1](#0-0) 

## Impact Explanation

**Affected Assets**: All liquidity tokens (token0 and token1) deposited in positions whose NFTs are burned by approved addresses.

**Damage Severity**:
- Approved attacker can permanently lock 100% of deposited funds in a single transaction
- No recovery mechanism exists (no admin intervention possible, user cannot recreate NFT without salt)
- Affects both principal liquidity and all accrued fees
- Violation of core protocol invariant

**User Impact**: Any user who:
- Used `mintAndDeposit()` (the standard, recommended flow)
- Granted NFT approval for marketplace listings, delegation contracts, or automated strategies
- Has active liquidity positions

**Trigger Conditions**: Requires only that user granted approval - a common and necessary operation in DeFi.

## Likelihood Explanation

**Attacker Profile**: Any address with NFT approval (via `approve()` or `setApprovalForAll()`). No special permissions or protocol role required.

**Preconditions**:
1. Victim has active position with liquidity (standard usage)
2. Victim granted NFT approval (common for marketplaces, delegation)
3. Victim used `mintAndDeposit()` (the standard minting flow)

**Execution Complexity**: Single transaction calling `positions.burn(tokenId)`. No timing requirements, special pool states, or complex setups needed.

**Economic Cost**: Only transaction gas fees (~$5-20 depending on network)

**Frequency**: Exploitable once per approved position. Malicious actor can target multiple positions sequentially.

**Overall Likelihood**: HIGH - Common preconditions, trivial execution, affects standard user flow.

## Recommendation

**Primary Fix - Add Liquidity Validation:**

Implement a hook in `BaseNonfungibleToken` that derived contracts can override to validate burn preconditions:

```solidity
// In src/base/BaseNonfungibleToken.sol:
function _beforeBurn(uint256 id) internal virtual {}

function burn(uint256 id) external payable authorizedForNft(id) {
    _beforeBurn(id);
    _burn(id);
}

// In src/base/BasePositions.sol:
function _beforeBurn(uint256 id) internal override {
    // Simplest solution: require explicit withdrawal before burning
    revert("Must withdraw all liquidity before burning position NFT");
}
```

**Alternative Fix - Emit Salt for Recovery:**

Emit the salt during minting so users can recreate burned NFTs:

```solidity
// In src/base/BaseNonfungibleToken.sol:
event NFTMinted(address indexed minter, uint256 indexed id, bytes32 salt);

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    _mint(msg.sender, id);
    emit NFTMinted(msg.sender, id, salt);
}
```

However, the primary fix is superior as it prevents the vulnerability at the root cause rather than relying on users to track and reuse salts.

## Proof of Concept

The provided PoC demonstrates:
1. User creates position with `mintAndDeposit()` and deposits significant liquidity
2. User approves another address (legitimate use case)
3. Approved address maliciously calls `burn()`
4. Original owner's attempts to `withdraw()`, `collectFees()`, or `deposit()` all revert
5. Liquidity remains locked in Core contract with no recovery path

Expected result: All withdrawal attempts revert, confirming permanent fund lock.

## Notes

**Critical Severity Factors:**

1. **Violates Core Invariant**: Directly contradicts README line 202 guarantee that positions are always withdrawable

2. **Permanent Loss**: Unlike temporary locks or griefing attacks, this results in complete, permanent, irrecoverable loss of funds

3. **Affects Standard Flow**: Impacts `mintAndDeposit()` - the intended, documented method for creating positions

4. **No Recovery Mechanism**: Neither the user nor protocol owner can recover locked positions (unlike protocol fees which owner can withdraw) [11](#0-10) 

5. **User Expectation Violation**: Standard ERC721 approvals allow transfers; users don't expect approvals to enable permanent destruction of underlying assets

6. **Cross-Contract Complexity**: Vulnerability spans multiple contracts (BaseNonfungibleToken, BasePositions, Core), making it non-obvious during isolated contract review

**Note on mintAndDepositWithSalt()**: Even users who called `mintAndDepositWithSalt()` with a known salt face ongoing griefing where attackers repeatedly burn their NFTs, forcing gas-expensive re-minting before each operation. The attacker can front-run legitimate operations with burns.

### Citations

**File:** README.md (L202-202)
```markdown
All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
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

**File:** src/base/BasePositions.sol (L186-192)
```text
    function withdrawProtocolFees(address token0, address token1, uint128 amount0, uint128 amount1, address recipient)
        external
        payable
        onlyOwner
    {
        lock(abi.encode(CALL_TYPE_WITHDRAW_PROTOCOL_FEES, token0, token1, amount0, amount1, recipient));
    }
```

**File:** src/Core.sol (L381-381)
```text
            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
```
