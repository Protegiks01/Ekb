# Audit Report

## Title
NFT Burn-and-Remint Vulnerability Allows Original Minter to Steal Liquidity from Secondary Holders

## Summary
The BasePositions contract's deterministic NFT ID generation, combined with the absence of liquidity checks in the burn function, creates a critical vulnerability. When a position NFT is transferred to a secondary holder who subsequently burns it, the original minter can recreate the identical NFT ID and withdraw the position's liquidity, effectively stealing the secondary holder's funds.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds. Secondary NFT holders can lose 100% of their deposited liquidity to the original minter. Any position NFT that has been transferred (through sale, gift, or other means) and subsequently burned without first withdrawing liquidity is vulnerable to this attack.

The vulnerability violates the critical protocol invariant: "All positions should be able to be withdrawn at any time." [1](#0-0)  After burning the NFT, the secondary holder permanently loses access to their liquidity, while only the original minter can access it by re-minting.

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol:133-134`, function `burn()`; `src/base/BasePositions.sol:120-133`, function `withdraw()`

**Intended Logic:**
The NFT system is designed to allow the original minter to recreate an NFT after burning it for gas refunds. [2](#0-1)  This design assumes the NFT remains with the original minter throughout its lifecycle.

**Actual Logic:**
The system fails to account for ERC721 NFT transferability creating an asymmetric access control vulnerability. NFT IDs are deterministically computed as `keccak256(minter, salt, chainid, contract)` [3](#0-2) , where the minter address is hardcoded into the ID generation. Position IDs derive from NFT IDs using the lower 192 bits as salt. [4](#0-3) 

When a secondary holder burns an NFT, the original minter can recreate the identical NFT ID because `mint(salt)` uses `msg.sender` (the caller's address) in the hash function. [5](#0-4)  Since the position ID is deterministically derived from the NFT ID, the original minter regains control over the position containing the secondary holder's liquidity.

**Exploitation Path:**

1. **Attacker mints with specific salt**: Alice calls `mintAndDepositWithSalt(salt_X, poolKey, tickLower, tickUpper, amount0, amount1, minLiquidity)` [6](#0-5) , creating NFT with ID = `keccak256(alice, salt_X, chainid, contract)` and depositing liquidity into the associated position.

2. **Transfer to victim**: Alice transfers the NFT to Bob via standard ERC721 transfer. Bob now owns the NFT and believes he has exclusive control over the position's liquidity.

3. **Victim burns NFT**: Bob calls `burn(id)` [7](#0-6) , which only verifies authorization via the `authorizedForNft(id)` modifier but does not check if the position has remaining liquidity. The NFT is destroyed, but the position in Core still contains Bob's liquidity.

4. **Attacker re-mints same ID**: Alice calls `mint(salt_X)` again. The `saltToId()` function generates the exact same ID because it uses Alice's address as the minter parameter. Since the NFT was burned, `_mint()` succeeds and Alice now owns a new NFT with the same ID.

5. **Attacker extracts liquidity**: Alice calls `withdraw(id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)` [8](#0-7) . The `authorizedForNft(id)` check passes because Alice owns the NFT. The position ID is recalculated identically [9](#0-8) , allowing Alice to withdraw Bob's liquidity.

**Security Property Broken:**
After Bob burns the NFT, he permanently loses access to his liquidity because he cannot recreate the NFT ID (his address in the hash would produce a different ID). Only Alice can access the position by re-minting, violating the protocol invariant that positions should be withdrawable at any time.

## Impact Explanation

**Affected Assets**: All liquidity positions where NFTs have been transferred to secondary holders who subsequently burn the NFT without withdrawing liquidity first.

**Damage Severity**:
- Secondary NFT holders lose 100% of their deposited liquidity
- Original minters can steal all funds from any position they originally created if the secondary holder burns the NFT
- Marketplace risk: Any position NFT sold on secondary markets can be exploited by the original minter if the buyer ever burns it

**User Impact**: Any user who receives a position NFT (via transfer, gift, or marketplace purchase) and burns it loses all their liquidity permanently. This particularly affects users who may burn NFTs for gas refunds as encouraged by the design comments, or who burn them by mistake.

## Likelihood Explanation

**Attacker Profile**: The original minter of any position NFT. This could be a malicious actor who intentionally mints positions to later exploit, or an opportunistic user who exploits mistakes by secondary holders.

**Preconditions**:
1. Attacker mints position NFT using `mintAndDepositWithSalt()` with a known salt
2. Attacker transfers/sells the NFT to a victim
3. Victim burns the NFT without first withdrawing liquidity
4. Position must have non-zero liquidity when burned

**Execution Complexity**: Simple - requires only standard function calls: initial minting/transfer, then re-minting after the victim burns. The attacker can monitor the mempool to immediately re-mint upon detecting a burn transaction.

**Economic Cost**: Only gas fees (minimal). No capital lockup or slippage costs.

**Frequency**: Exploitable once per transferred NFT that gets burned. The design explicitly encourages burning for gas refunds (per code comments), making this scenario more likely than it might initially appear.

**Overall Likelihood**: MEDIUM-HIGH - While it requires the victim to burn the NFT, the design explicitly encourages this behavior for gas refunds, and users may not understand the risk when transferring position NFTs.

## Recommendation

**Primary Fix:**
Override the `burn()` function in `BasePositions` to verify that all associated positions have zero liquidity before allowing the burn. Since a single NFT can be associated with multiple positions (different tick ranges in different pools), consider one of these approaches:

1. **Require explicit position specification**: Modify burn to accept pool and tick parameters, verify liquidity is zero for that specific position
2. **Implement safe burn pattern**: Create a `burnPosition()` function that first withdraws all liquidity, then burns the NFT
3. **Add transfer hooks**: Prevent transfers of NFTs with active positions, forcing users to withdraw before transferring

**Alternative Mitigations**:
- Add prominent warnings in documentation and UIs about the risks of burning transferred NFTs
- Consider implementing NFT versioning (include a counter in the position ID calculation) to prevent re-minting from accessing old positions
- Use non-deterministic NFT IDs (sequential counters) instead of deterministic salt-based IDs

## Proof of Concept

A valid PoC demonstrating the complete attack flow would:
- Deploy the Positions contract
- Alice mints and deposits liquidity with a specific salt
- Alice transfers the NFT to Bob
- Bob burns the NFT (NFT destroyed, position remains in Core)
- Alice re-mints using the same salt (recreates identical NFT ID)
- Alice successfully withdraws Bob's liquidity

This PoC would be implementable using the project's test infrastructure and would compile and run with `forge test`.

## Notes

This vulnerability is particularly critical because:

1. **Intentional design becomes exploitable**: The burn-and-remint feature for gas refunds is documented and tested (see `test_burn_can_be_minted()` in test suite), but the security implications for transferred NFTs were not considered.

2. **Asymmetric access control**: Only the original minter can recreate a specific NFT ID due to the minter address being part of the hash. Bob cannot protect himself by re-minting because his address would produce a different ID.

3. **Violates NFT ownership expectations**: Standard ERC721 behavior leads users to expect that owning an NFT grants exclusive control over associated assets. This vulnerability fundamentally breaks that assumption for Ekubo position NFTs.

4. **Systematic marketplace risk**: Creates an attack vector for any secondary market trading of position NFTs, as original minters retain the ability to reclaim positions after sale.

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

**File:** src/base/BaseNonfungibleToken.sol (L123-126)
```text
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
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

**File:** src/base/BasePositions.sol (L243-246)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
```

**File:** src/base/BasePositions.sol (L304-307)
```text
                PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                    -int128(liquidity)
```
