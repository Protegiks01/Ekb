After conducting a thorough technical validation through the strict Ekubo security framework, I must provide my assessment:

# Audit Report

## Title
NFT Burn/Re-mint Mechanism Enables Original Minter to Steal Subsequent Owner's Position Liquidity

## Summary
The `burn()` function lacks validation to ensure associated liquidity positions are empty before burning. Combined with deterministic NFT ID generation, this allows the original minter to re-mint the same NFT ID after transfer and burning, gaining unauthorized control over positions funded by subsequent owners. [1](#0-0) 

## Impact
**Severity**: High - Direct theft of user funds resulting in complete loss for victims

This vulnerability enables complete theft of liquidity from users who purchase or receive Position/Order NFTs and subsequently burn them. The attacker gains 100% of the victim's deposited liquidity with no recovery mechanism. This violates the core protocol invariant stated in the README that "All positions should be able to be withdrawn at any time."

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol:133-135`, function `burn()`

**Intended Logic:** Per documentation, burn() provides "gas refund after the NFT is no longer needed" with the ability to recreate the same ID by reusing the salt. [2](#0-1) 

**Actual Logic:** The burn function only verifies caller authorization but performs NO validation that associated positions are empty. Positions are stored in Core keyed by `(poolId, PositionsContractAddress, positionId)` where positionId derives from the NFT ID. [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. **Alice mints NFT**: Calls `mint(salt)` generating deterministic ID based on `keccak256(Alice, salt, chainid, contract)` [5](#0-4) [6](#0-5) 

2. **Alice deposits liquidity**: Position stored in Core with positionId derived from NFT ID [7](#0-6) [8](#0-7) 

3. **Alice transfers NFT to Bob**: Standard ERC721 transfer, Bob becomes owner

4. **Bob deposits additional liquidity**: Passes `authorizedForNft(id)` check and adds to SAME position in Core [9](#0-8) 

5. **Bob burns the NFT**: Only checks authorization, does NOT verify position is empty. ERC721 state cleared but Core position data remains unchanged

6. **Alice re-mints same ID**: Calls `mint(salt)` with original salt. Due to deterministic generation, gets identical ID. No check prevents re-minting burned IDs.

7. **Alice withdraws all liquidity**: Passes `authorizedForNft(id)` because Alice owns the re-minted NFT. Withdraws entire position including Bob's deposits. [10](#0-9) 

**Security Guarantee Broken:** After burning, Bob's position becomes permanently inaccessible to Bob (he cannot recreate the NFT as only Alice can use that minter+salt combination) but accessible to Alice, violating the documented invariant that "All positions should be able to be withdrawn at any time."

## Impact Explanation

**Affected Assets**: 
- All liquidity positions in Positions contract
- All TWAMM orders in Orders contract (same inheritance pattern) [11](#0-10) [12](#0-11) 

**Damage Severity**:
- Victim experiences 100% permanent loss of deposited liquidity
- Attacker gains unauthorized access to victim's full position value
- No recovery mechanism exists - victim cannot recreate the NFT ID (requires attacker's address)
- Scales linearly with number of NFT transfers and subsequent burns

**User Impact**: 
- NFT marketplace buyers purchasing position NFTs
- Users receiving NFTs through transfers/gifts
- Anyone who burns an NFT without being the original minter

**Trigger Conditions**: Victim must burn NFT while position contains liquidity deposited after transfer. Realistic as users may burn for gas refunds without realizing the risk.

## Likelihood Explanation

**Attacker Profile**: Original minter of any Position or Order NFT. No special privileges required.

**Preconditions**:
1. Attacker mints NFT with specific salt (records salt value)
2. Attacker transfers NFT to victim
3. Victim deposits liquidity
4. Victim burns NFT without full withdrawal

**Execution Complexity**: Trivial - Two function calls: `positions.mint(originalSalt)` then `positions.withdraw(id, ...)`

**Economic Cost**: Only gas fees (~0.01-0.05 ETH)

**Overall Likelihood**: MEDIUM-HIGH - Requires victim to burn with active position, but lack of warnings and reasonable user expectation that burning their own NFT is safe make this realistic.

## Recommendation

**Primary Fix - Prevent Re-minting Burned IDs:**
```solidity
// In src/base/BaseNonfungibleToken.sol
mapping(uint256 => bool) private burnedIds;

function burn(uint256 id) external payable authorizedForNft(id) {
    burnedIds[id] = true;
    _burn(id);
}

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    require(!burnedIds[id], "ID was previously burned");
    _mint(msg.sender, id);
}
```

**Alternative Fix - Validate Empty Positions:**
Add virtual `_beforeBurn` hook that child contracts implement to verify no active positions exist before allowing burn.

**Mitigation Notes**: 
- First solution prevents the core issue by making burned IDs non-reusable
- Documentation should clearly warn about security implications
- Consider UI warnings before burning operations

## Notes

**Additional Context:**
- Position data persists in Core storage after NFT burn because Core only clears positions when `liquidityNext == 0`, not when NFTs are burned [13](#0-12) 

- The deterministic ID generation is a deliberate design choice for gas efficiency, but the security implications when combined with position transfers and burns were not adequately addressed

- Current documentation mentions re-mint capability but does NOT warn users that the original minter can steal funds from subsequent owners who burn the NFT

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

**File:** src/Core.sol (L381-381)
```text
            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
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

**File:** src/libraries/CoreStorageLayout.sol (L100-113)
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

**File:** src/base/BasePositions.sol (L243-246)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
```

**File:** src/types/positionId.sol (L31-36)
```text
function createPositionId(bytes24 _salt, int32 _tickLower, int32 _tickUpper) pure returns (PositionId v) {
    assembly ("memory-safe") {
        // v = salt | (tickLower << 32) | tickUpper
        v := or(shl(64, shr(64, _salt)), or(shl(32, and(_tickLower, 0xFFFFFFFF)), and(_tickUpper, 0xFFFFFFFF)))
    }
}
```

**File:** src/Positions.sol (L13-13)
```text
contract Positions is BasePositions {
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```
