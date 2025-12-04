# Audit Report

## Title
NFT Burn/Re-mint Mechanism Allows Original Minter to Gain Unauthorized Access to Subsequent Owner's Position Liquidity

## Summary
The `burn()` function lacks validation to ensure associated positions are empty before burning the NFT. When combined with deterministic NFT ID generation based on the original minter's address and salt, this creates a critical vulnerability: after a subsequent NFT owner burns the token, the original minter can re-mint the identical NFT ID and gain unauthorized access to positions funded by that subsequent owner.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds. When Bob (subsequent owner) deposits liquidity into a position and later burns the NFT without fully withdrawing, Alice (original minter) can re-mint the same NFT ID and withdraw all of Bob's deposited liquidity. The impact is complete (100%) loss of the victim's funds with no recovery mechanism. This affects both the Positions and Orders contracts protocol-wide.

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol:133-135`, function `burn()`

**Intended Logic:**
The burn function is documented to "refund some gas after the NFT is no longer needed" with the explicit capability to recreate the same ID by reusing the salt. [1](#0-0) 

**Actual Logic:**
The burn function only verifies the caller is authorized for the NFT via the `authorizedForNft(id)` modifier, then immediately calls `_burn(id)`. No validation checks whether positions or orders associated with the NFT are empty. [2](#0-1) 

Position data persists in Core storage even after burning. The storage location is computed from `(poolId, Positions contract address, positionId)` where positionId is derived from the NFT ID as `bytes24(uint192(id))`. [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. **Alice mints NFT**: Alice calls `mint(salt)` generating a deterministic ID via `keccak256(minter, salt, chainid(), contract_address)`. [5](#0-4) [6](#0-5) 

2. **Alice transfers NFT to Bob**: Standard ERC721 transfer changes ownership to Bob.

3. **Bob deposits liquidity**: Bob calls `deposit()` which passes the `authorizedForNft(id)` check since he owns the NFT. [7](#0-6)  The liquidity is stored in Core under a positionId derived from the NFT ID.

4. **Bob burns the NFT**: Bob calls `burn(id)` which succeeds because he is the current owner. The NFT is destroyed but the position data in Core remains intact with Bob's liquidity. [2](#0-1) 

5. **Alice re-mints same ID**: Alice calls `mint(salt)` with her original salt. The deterministic `saltToId()` function generates the identical ID. Since the NFT no longer exists (Bob burned it), the mint succeeds.

6. **Alice withdraws Bob's liquidity**: Alice calls `withdraw()` which passes the `authorizedForNft(id)` check because she now owns the re-minted NFT. [8](#0-7)  The withdraw accesses the same position (same positionId derived from the NFT ID) and Alice extracts all liquidity including Bob's deposits.

**Security Property Broken:**
This violates the fundamental security invariant that users maintain exclusive control over their deposited liquidity. The NFT represents ownership of positions, yet burning followed by re-minting breaks this ownership model, allowing the original minter to regain unauthorized access to positions funded by subsequent owners.

## Impact Explanation

**Affected Assets:**
- All liquidity positions in Positions contract where NFT ownership has changed hands through transfers or marketplace sales
- All TWAMM orders in Orders contract (identical vulnerability pattern) [9](#0-8) [10](#0-9) 

**Damage Severity:**
- Complete (100%) loss of liquidity deposited by any owner after NFT transfer
- Original minter gains unauthorized access to all subsequent owners' deposits
- If Bob deposits $1M in liquidity and burns the NFT, Alice can steal the entire $1M

**User Impact:**
- NFT marketplace buyers who add liquidity then burn the NFT
- Users receiving NFTs as gifts/transfers who misunderstand the burn mechanism
- Any user following UI suggestions to burn "empty" or "unused" NFTs
- Protocol-wide impact across both Positions and Orders contracts

**Trigger Conditions:**
Victim must burn the NFT without fully withdrawing all liquidity first. While this requires user error, the error is highly plausible because the documentation mentions gas refunds but provides no warnings about withdrawal requirements, "no longer needed" is ambiguous, and malicious UIs could deliberately mislead users to burn NFTs prematurely.

## Likelihood Explanation

**Attacker Profile:**
Any user who has previously minted a Position or Order NFT and subsequently transferred or sold it to another party.

**Preconditions:**
1. Attacker mints NFT and records the salt value
2. Attacker transfers NFT to victim via sale, gift, or other mechanism
3. Victim deposits liquidity to the position
4. Victim burns NFT without fully withdrawing (requires user error, but plausible given ambiguous documentation)

**Execution Complexity:**
Trivial. Attacker simply calls `mint(originalSalt)` after detecting the burn event on-chain, then calls `withdraw()` to extract all liquidity. No special transaction ordering, front-running, or complex setup required.

**Economic Cost:**
Only gas fees (minimal). No capital lockup or other economic barriers.

**Frequency:**
Exploitable once per NFT that gets burned. With NFT trading markets for positions (a stated protocol goal), this attack vector could affect numerous users over time.

**Overall Likelihood:**
MEDIUM to HIGH - While requiring victim error (burning without withdrawing), the error is plausible in realistic scenarios (marketplace trading, ambiguous documentation, dust amounts remaining, malicious UI guidance). The trivial execution and high impact make this a serious threat.

## Recommendation

**Primary Fix - Prevent Re-minting of Burned IDs:**

Track burned NFT IDs permanently to prevent re-minting:

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

**Alternative Fix - Validate Position State Before Burning:**

Override `burn()` in BasePositions and Orders to verify all positions/orders are empty before allowing burn.

**Documentation Enhancement:**

At minimum, add explicit warnings in the burn function documentation:
- "WARNING: You must withdraw ALL liquidity from ALL positions before burning"
- "Burning with active positions results in permanent loss of funds"
- "Original minter can re-mint this ID and access remaining positions"

**Recommendation Priority:**
The primary fix (preventing re-minting of burned IDs) eliminates the vulnerability entirely and is strongly preferred over requiring users to manually verify complex position state across multiple pools.

## Notes

1. **Dual Contract Impact**: Both `Positions.sol` and `Orders.sol` inherit from `BaseNonfungibleToken` with identical burn mechanisms lacking position/order validation. [9](#0-8) [10](#0-9) 

2. **Position Data Persistence**: Core only clears position data when `liquidityNext == 0` during explicit withdrawal operations. [11](#0-10)  The burn operation never triggers this cleanup path.

3. **Test Coverage Gap**: The existing test confirms re-minting works but doesn't test security implications when positions contain liquidity from multiple sequential owners.

4. **Design Intent vs Security**: While documentation explicitly states re-minting is possible, it provides no security warnings about the implications when combined with transferable NFTs representing valuable positions. Even if intentional, the lack of safeguards represents a critical implementation flaw enabling fund theft.

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
