# Audit Report

## Title
Original Minter Can Steal Transferred Positions via Burn-and-Re-mint Attack

## Summary
The deterministic NFT ID generation in `BaseNonfungibleToken` allows original minters to recreate burned NFTs using the same salt, even after transferring ownership. When a new owner burns an NFT with an active position or order, the original minter can re-mint the identical NFT ID and gain unauthorized access to withdraw the position's funds. This creates a rug-pull vector where malicious actors can sell position NFTs and later reclaim them after the buyer burns the token.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds from liquidity positions and TWAMM orders. An attacker who mints and transfers an NFT retains permanent backdoor access through deterministic ID recreation. When the new owner burns the NFT (encouraged by gas refund comments in the code), the attacker can re-mint and withdraw all liquidity and accumulated fees. The victim loses 100% of their position value with no recovery mechanism. This affects both the Positions and Orders contracts, creating systemic risk for any NFT marketplace or DeFi protocol integrating with Ekubo positions.

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol` (lines 123-126), function `mint(bytes32 salt)`

**Intended Logic:** 
The NFT system uses deterministic IDs for gas efficiency and predictability. The comment at line 130 states burned NFTs can be "recreated by the original minter by reusing the salt" to enable gas refunds after positions are withdrawn. [1](#0-0) 

**Actual Logic:**
The `mint(bytes32 salt)` function generates IDs using `saltToId(msg.sender, salt)` which incorporates only the caller's address, not tracking transfer history or current ownership. [2](#0-1)  The ID computation uses `keccak256(minter, salt, chainid, address())` [3](#0-2) , creating a permanent association between the original minter and the ID. The `burn` function only destroys NFT ownership without checking position status or preventing re-minting. [4](#0-3) 

**Exploitation Path:**

1. **Setup**: Alice mints NFT with `salt_X` → receives deterministic ID = `keccak256(Alice, salt_X, chainid, contract)`
2. **Position Creation**: Alice deposits significant liquidity using `mintAndDepositWithSalt` [5](#0-4) . Position is stored in Core contract keyed by the NFT ID (first 24 bytes) + tick range.
3. **Transfer**: Alice transfers NFT to Bob via standard ERC721 transfer. Bob now owns the NFT and can manage the position through `authorizedForNft` checks. [6](#0-5) 
4. **Burn**: Bob burns the NFT to claim gas refunds or by mistake. The burn function only calls `_burn(id)` without validating position status or deleting Core state. Position data remains intact in Core storage.
5. **Re-mint**: Alice calls `mint(salt_X)` with the original salt. Since the ID is deterministic and the NFT no longer exists, `_mint` succeeds and Alice receives the **exact same NFT ID**.
6. **Theft**: Alice calls `withdraw` [7](#0-6) , passes the `authorizedForNft` check (she owns the NFT), and withdraws Bob's entire position including all accumulated fees.

**Security Guarantee Broken:**
- **Withdrawal Availability Invariant**: "All positions should be able to be withdrawn at any time" (README line 202) - Bob cannot withdraw after burning, but Alice can steal the position.
- **NFT Ownership Integrity**: Transferred NFT ownership should be exclusive. The original minter retains permanent "admin access" to any NFT they create.
- **Direct Theft of User Funds**: Unauthorized withdrawal of positions that rightfully belong to the current (burned) NFT holder.

## Impact Explanation

**Affected Assets**: All liquidity positions managed by the Positions contract and TWAMM orders in the Orders contract. Any user who receives an NFT via transfer (purchase, gift, collateral) is at risk.

**Damage Severity**:
- Complete loss of position liquidity and accumulated fees (100% of position value)
- For a $1M position, victim loses $1M
- Attacker can drain positions immediately after burn with zero capital requirement
- No recovery mechanism exists once theft occurs

**User Impact**: 
- Any user who purchases/receives transferred NFTs and subsequently burns them
- Creates a rug-pull attack vector: malicious users sell valuable position NFTs on marketplaces, wait for buyers to burn them (for gas refunds or after position becomes unprofitable), then reclaim and drain the positions
- Affects DeFi protocols that accept Ekubo position NFTs as collateral

**Trigger Conditions**: 
- Victim must burn an NFT that was previously transferred to them
- The comment "Can be used to refund some gas after the NFT is no longer needed" actively encourages this behavior
- No warnings exist about the security implications of burning transferred NFTs

## Likelihood Explanation

**Attacker Profile**: Original NFT minter - requires no special privileges, any user who mints an NFT can execute this attack

**Preconditions**:
1. Attacker mints NFT with deterministic salt and deposits valuable position
2. Attacker transfers NFT to victim (via sale, gift, or DeFi protocol interaction)
3. Victim burns the NFT (encouraged by gas refund comment, or after position becomes unprofitable)

**Execution Complexity**: 
- Trivial - single transaction calling `mint(salt)` with the original salt
- Can be automated with monitoring bots to immediately front-run position theft when any transferred NFT is burned
- No economic cost beyond gas fees (~$10-50)

**Frequency**: 
- Can be exploited once per NFT transfer-and-burn cycle
- With NFT marketplaces and DeFi integrations, creates persistent attack surface
- Multiple positions per NFT possible (different tick ranges), amplifying potential theft

**Overall Likelihood**: HIGH - Simple execution, actively encouraged by code comments, affects all transferred NFTs with active positions

## Recommendation

**Primary Fix - Track Transfer History (Recommended)**:
Add storage mapping to prevent re-minting of transferred NFTs:

```solidity
// In src/base/BaseNonfungibleToken.sol
mapping(uint256 => bool) private _hasBeenTransferred;

function _beforeTokenTransfer(address from, address to, uint256 id) internal virtual {
    if (from != address(0) && to != address(0) && from != to) {
        _hasBeenTransferred[id] = true;
    }
}

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    require(!_hasBeenTransferred[id], "Cannot re-mint transferred NFT");
    _mint(msg.sender, id);
}
```

**Alternative Fix - Force Position Withdrawal on Burn**:
Override burn in BasePositions to automatically withdraw all positions before burning, preventing orphaned positions:

```solidity
// In src/base/BasePositions.sol
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Require all positions withdrawn before burn
    // Or auto-withdraw all positions (requires tracking positions per NFT)
    _burn(id);
}
```

**Additional Mitigations**:
- Add explicit documentation warning against burning NFTs with active positions
- Consider removing deterministic salt-based minting for transferred NFTs
- Implement position-to-owner mapping that invalidates on transfer

## Notes

The vulnerability stems from the design decision to allow deterministic NFT ID generation for gas refunds, without accounting for the security implications of NFT transfers. The explicit comment "The same ID can be recreated by the original minter by reusing the salt" confirms this behavior is intentional, but it fundamentally breaks NFT ownership guarantees.

Once an NFT is transferred, the previous owner should have no special privileges over it. The current implementation creates a permanent backdoor where original minters retain "superuser" access to any NFT they create, violating the core principle of NFT ownership and creating a systemic rug-pull vulnerability.

The attack is economically rational: sell high-value position NFTs, wait for buyers to burn them (either for gas refunds as encouraged by the code, or after positions become unprofitable), then immediately reclaim and drain the positions. This can be automated and scales across all transferred NFTs in the protocol.

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

**File:** src/base/BaseNonfungibleToken.sol (L123-126)
```text
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-131)
```text
    /// @inheritdoc IBaseNonfungibleToken
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

**File:** src/base/BasePositions.sol (L120-133)
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
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L172-183)
```text
    function mintAndDepositWithSalt(
        bytes32 salt,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) {
        id = mint(salt);
        (liquidity, amount0, amount1) = deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity);
    }
```
