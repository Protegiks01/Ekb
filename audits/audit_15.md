# Audit Report

## Title
NFT Burn/Re-mint Vulnerability Allows Original Minter to Steal Subsequent Owner's Position Liquidity

## Summary
The `burn()` function in `BaseNonfungibleToken.sol` lacks validation to ensure associated positions are empty before burning. Combined with deterministic NFT ID generation, this allows the original minter to re-mint the same NFT ID after a subsequent owner burns it, gaining unauthorized access to positions funded by that owner.

## Impact
**Severity**: High

This represents direct theft of user funds. A subsequent NFT owner (Bob) who deposits liquidity and later burns the NFT loses 100% of deposited funds to the original minter (Alice) who can re-mint the same NFT ID and withdraw all liquidity. The impact is permanent and unrecoverable for the victim.

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol:133-135`, function `burn()`

**Intended Logic:** 
The burn function is documented to "refund some gas after the NFT is no longer needed" with the ability to recreate the same ID by reusing the salt. [1](#0-0) 

**Actual Logic:**
The burn function only verifies the caller is authorized for the NFT via the `authorizedForNft(id)` modifier, then immediately calls `_burn(id)` without any checks on associated position state. [2](#0-1) 

Position data is stored in Core using a storage slot computed from `(poolId, Positions contract address, positionId)` where positionId is derived from the NFT ID. [3](#0-2)  The burn operation does not interact with Core storage or clear position data.

**Exploitation Path:**

1. **Alice mints NFT**: Alice calls `mint(salt)` which generates a deterministic ID via `keccak256(minter, salt, chainid(), contract_address)`. [4](#0-3) 

2. **Alice deposits liquidity**: Alice deposits tokens to a position. The position is stored in Core at a location computed from the Positions contract address and positionId derived from `bytes24(uint192(id))`. [5](#0-4) 

3. **Alice transfers NFT to Bob**: Standard ERC721 transfer changes ownership to Bob.

4. **Bob adds liquidity**: Bob calls `deposit()` which passes the `authorizedForNft(id)` check since he owns the NFT. [6](#0-5)  Bob adds to the same position (same positionId) increasing total liquidity.

5. **Bob burns the NFT**: Bob calls `burn(id)` which succeeds because he is the current owner. The NFT is destroyed but the position data in Core remains intact. [2](#0-1) 

6. **Alice re-mints same ID**: Alice calls `mint(salt)` with her original salt. The deterministic `saltToId()` function generates the same ID. Since the NFT no longer exists (Bob burned it), the mint succeeds. This behavior is confirmed by the existing test. [7](#0-6) 

7. **Alice withdraws all liquidity**: Alice calls `withdraw()` which passes the `authorizedForNft(id)` check because she now owns the re-minted NFT. [8](#0-7)  The withdraw accesses the same position (same positionId derived from the NFT ID) and Alice extracts all liquidity including Bob's deposits.

**Security Property Broken:**
This violates the fundamental invariant that users maintain exclusive control over their deposited liquidity. Bob's liquidity becomes accessible to Alice through the reminting mechanism, despite Bob being the legitimate owner who funded the position.

## Impact Explanation

**Affected Assets**: 
- All liquidity positions in Positions contract where NFT ownership changed hands
- All TWAMM orders in Orders contract (same vulnerability pattern) [9](#0-8) [10](#0-9) 

**Damage Severity**:
- Complete (100%) loss of liquidity deposited by any owner after NFT transfer
- Original minter gains all liquidity from subsequent owners
- If Bob deposits $1M in liquidity and burns the NFT, Alice can steal the entire $1M

**User Impact**: 
- NFT marketplace buyers who add liquidity then burn
- Users receiving NFTs as gifts/transfers who misunderstand the burn mechanism  
- Any user following UI that suggests burning "empty" NFTs
- Applies protocol-wide to both Positions and Orders contracts

**Trigger Conditions**: 
Victim must burn the NFT without fully withdrawing all liquidity first. While this requires user error, the error is highly plausible because:
- Documentation mentions gas refunds but not withdrawal requirements
- No warnings or checks prevent burning with active positions
- "No longer needed" is ambiguous and could be misinterpreted
- Malicious UIs could deliberately mislead users

## Likelihood Explanation

**Attacker Profile**: 
Any user who has ever minted a Position or Order NFT and subsequently transferred/sold it.

**Preconditions**:
1. Attacker mints NFT and optionally deposits initial liquidity
2. Attacker transfers NFT to victim via sale, gift, or other mechanism  
3. Victim deposits additional liquidity to the position
4. Victim burns NFT without fully withdrawing (key precondition requiring user error)

**Execution Complexity**: 
Trivial. Attacker simply calls `mint(originalSalt)` after detecting the burn, then calls `withdraw()` to extract all liquidity. No special transaction ordering, front-running, or complex setup required.

**Economic Cost**: 
Only gas fees (~$0.01-$1 depending on network). No capital lockup or other economic barriers.

**Frequency**: 
Can be exploited once per NFT that gets burned. With active NFT trading markets for positions (a stated goal of having tradeable position NFTs), this attack vector could affect numerous users.

**Overall Likelihood**: 
MEDIUM - Requires victim error (burning without withdrawing), but the error is plausible given poor documentation and non-intuitive behavior. The high impact and trivial execution make this a serious threat.

## Recommendation

**Primary Fix - Prevent Reminting of Burned IDs:**

Add state tracking to permanently mark burned IDs as unmintable:

```solidity
// In src/base/BaseNonfungibleToken.sol

mapping(uint256 => bool) public burnedIds;

function burn(uint256 id) external payable authorizedForNft(id) {
    burnedIds[id] = true;
    _burn(id);
}

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    require(!burnedIds[id], "ID previously burned");
    _mint(msg.sender, id);
}
```

**Alternative Fix - Verify Positions Before Burning:**

Override `burn()` in derived contracts to check position state:

```solidity  
// In src/base/BasePositions.sol

function burn(uint256 id) external payable override authorizedForNft(id) {
    // Verify no active positions exist
    // Note: This requires iterating known pools or maintaining a position registry
    require(!hasActivePositions(id), "Active positions exist");
    super.burn(id);
}
```

**Documentation Enhancement:**

At minimum, update the burn function documentation to explicitly warn:
- "WARNING: You must withdraw ALL liquidity from ALL positions before burning"
- "Burning with active positions results in permanent loss of funds"
- "Original minter can re-mint this ID and access positions"

**Recommendation Priority:** 
The primary fix (preventing reminting) is strongly preferred as it eliminates the vulnerability entirely without requiring users to verify complex position state across multiple pools.

## Notes

1. **Dual Contract Impact**: This vulnerability affects both `Positions.sol` and `Orders.sol` as both inherit from `BaseNonfungibleToken` with identical burn mechanisms and lack position/order validation. [9](#0-8) [10](#0-9) 

2. **Position Data Persistence**: The Core contract only clears position data when `liquidityNext == 0` during explicit withdrawal operations. [11](#0-10)  The burn operation never triggers this cleanup path.

3. **Design vs Implementation**: While the documentation explicitly states reminting is possible, it provides no security warnings about the implications. Even if reminting was an intentional design choice, the lack of safeguards against burning with active positions represents a critical implementation flaw that enables fund theft.

4. **Test Coverage Gap**: The existing test suite confirms reminting works as documented but does not test the security implications when positions contain liquidity from multiple owners. The test `test_burn_can_be_minted()` validates the reminting mechanism but not its misuse potential.

### Citations

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

**File:** src/libraries/CoreStorageLayout.sol (L100-114)
```text
    function poolPositionsSlot(PoolId poolId, address owner, PositionId positionId)
        internal
        pure
        returns (StorageSlot firstSlot)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, positionId)
            mstore(add(free, 0x20), poolId)
            mstore(add(free, 0x40), owner)
            mstore(0, keccak256(free, 0x60))
            mstore(32, 1)
            firstSlot := keccak256(0, 64)
        }
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

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** src/Positions.sol (L13-13)
```text
contract Positions is BasePositions {
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/Core.sol (L430-438)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }
```
