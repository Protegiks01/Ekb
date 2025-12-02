## Title
Approved Addresses Can Permanently Lock User Funds by Burning Position NFTs with Active Liquidity

## Summary
The `burn()` function in `BaseNonfungibleToken.sol` allows any approved address to destroy a Position NFT without verifying that the associated liquidity has been withdrawn. Once burned, all liquidity management functions become permanently inaccessible because they require NFT ownership verification. Since most users mint NFTs using pseudo-random salts that are never stored, the same NFT ID cannot be recreated to regain access, resulting in permanent fund loss. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol` (burn function at line 133) and `src/base/BasePositions.sol` (deposit/withdraw/collectFees functions requiring authorizedForNft modifier)

**Intended Logic:** The `burn()` function is designed to allow gas refunds by destroying NFTs that are no longer needed. The documentation states "the same ID can be recreated by the original minter by reusing the salt" [2](#0-1) , suggesting users can recover access to positions after burning.

**Actual Logic:** When `burn()` is called by an approved address while liquidity still exists in the position:

1. The NFT is destroyed via `_burn(id)` [1](#0-0) 
2. All liquidity management functions require `authorizedForNft(id)` [3](#0-2) 
3. The `authorizedForNft` modifier checks `_isApprovedOrOwner(msg.sender, id)` [4](#0-3) 
4. After burning, this check fails because the NFT no longer exists
5. Users cannot re-mint the same ID because the salt was pseudo-randomly generated and never stored [5](#0-4) 

**Exploitation Path:**

1. **User creates position:** Alice calls `mintAndDeposit()` to create a position with 1000 ETH of liquidity [6](#0-5) 
   - This internally calls `mint()` which generates a pseudo-random salt using `prevrandao()` and `gas()` [5](#0-4) 
   - The salt is used to generate a deterministic token ID but is never stored or emitted

2. **User grants approval:** Alice approves a marketplace contract (e.g., OpenSea) via `setApprovalForAll(marketplace, true)` for convenience in trading NFTs

3. **Malicious burn:** The marketplace contract (if malicious or compromised) calls `burn(id)` on Alice's Position NFT [1](#0-0) 
   - The burn succeeds because the marketplace is authorized via approval
   - No check exists to verify that liquidity has been withdrawn first

4. **Permanent fund lock:** Alice attempts to call `withdraw()` to recover her 1000 ETH but the transaction reverts with `NotUnauthorizedForToken` [4](#0-3) 
   - The `authorizedForNft(id)` modifier fails because the NFT no longer exists
   - Alice cannot re-mint the same NFT ID because she doesn't know the pseudo-random salt that was generated
   - The position's liquidity remains locked in the Core contract forever

**Security Property Broken:** This violates Critical Invariant #2: "Withdrawal Availability: All positions MUST be withdrawable at any time"

## Impact Explanation

- **Affected Assets**: All tokens in liquidity positions represented by burned NFTs. This includes both principal liquidity and accumulated trading fees in any token pair.

- **Damage Severity**: Complete and permanent loss of funds. An attacker with approval can burn all of a user's Position NFTs, locking 100% of their deposited liquidity forever. Unlike temporary locks or recoverable scenarios, this is an irreversible loss because:
  - The NFT cannot be recreated without the original pseudo-random salt
  - No alternative withdrawal mechanism exists
  - The liquidity remains in the Core contract but becomes permanently inaccessible

- **User Impact**: Any user who has granted approval to marketplace contracts, router contracts, or other third-party protocols is vulnerable. This affects users who:
  - Listed Position NFTs on marketplaces like OpenSea, Blur, or LooksRare
  - Approved aggregator contracts for NFT trading
  - Used router contracts that require NFT approvals
  - Granted approvals for any protocol integration

## Likelihood Explanation

- **Attacker Profile**: Any address with approval can exploit this. This includes:
  - Malicious marketplace contracts
  - Compromised router contracts
  - Phishing contracts that trick users into granting approvals
  - Legitimate contracts with bugs or unexpected behavior

- **Preconditions**: 
  - User must have minted a Position NFT using `mintAndDeposit()` or `mint()` (without explicit salt)
  - User must have deposited liquidity into the position
  - User must have granted approval to an external address via `approve()` or `setApprovalForAll()`
  - The approved address must call `burn(id)`

- **Execution Complexity**: Single transaction. The attacker simply calls `burn(id)` with the victim's token ID. No complex timing, state manipulation, or multi-step process required.

- **Frequency**: Can be exploited continuously. An attacker with approval can burn all Position NFTs owned by a user in a single multicall transaction, locking all their liquidity permanently.

## Recommendation

Add a liquidity check in the `burn()` function to prevent burning NFTs with active positions:

```solidity
// In src/base/BaseNonfungibleToken.sol, line 133:

// CURRENT (vulnerable):
function burn(uint256 id) external payable authorizedForNft(id) {
    _burn(id);
}

// FIXED:
function burn(uint256 id) external payable authorizedForNft(id) {
    // For Position NFTs, verify no liquidity exists before burning
    // This check should be implemented in the concrete contract (Positions.sol)
    // by overriding burn() and checking position liquidity
    _beforeBurn(id); // Hook for subclasses to implement checks
    _burn(id);
}
```

**Better solution - Override in Positions.sol:**

```solidity
// In src/Positions.sol, add:

/// @notice Burns a position NFT
/// @dev Overrides BaseNonfungibleToken.burn() to add safety check
/// @param id The token ID to burn
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Verify the NFT has no active liquidity in any pool
    // Note: This cannot check all possible (poolKey, tickLower, tickUpper) combinations
    // Users MUST withdraw all liquidity before burning
    // Alternative: Store active positions per NFT ID and verify they're all closed
    _burn(id);
}
```

**Recommended mitigation strategy:**

1. **Store active positions:** Maintain a mapping of NFT IDs to their active positions (poolKey, tickLower, tickUpper combinations)
2. **Check on burn:** Before burning, verify all positions associated with the NFT have zero liquidity
3. **Update on deposit/withdraw:** When liquidity is deposited, add to the active positions set. When fully withdrawn, remove from the set.
4. **Alternative:** Emit the salt in a Minted event so users can recover their NFT IDs if needed

## Proof of Concept

```solidity
// File: test/Exploit_BurnWithLiquidity.t.sol
// Run with: forge test --match-test test_BurnLocksLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import "../test/helpers/PositionsTestBase.sol";

contract Exploit_BurnWithLiquidity is PositionsTestBase {
    address alice = address(0x1);
    address maliciousMarketplace = address(0x2);
    
    function setUp() public {
        // Initialize protocol (use existing test base setup)
        super.setUp();
        
        // Fund Alice
        vm.deal(alice, 10 ether);
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
    }
    
    function test_BurnLocksLiquidity() public {
        vm.startPrank(alice);
        
        // SETUP: Alice creates a position with liquidity
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Alice mints and deposits liquidity (uses pseudo-random salt internally)
        (uint256 id, uint128 liquidityDeposited,,) = 
            positions.mintAndDeposit(poolKey, -100, 100, 100e18, 100e18, 0);
        
        // Verify Alice has liquidity
        (uint128 liquidity,,,,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertGt(liquidity, 0, "Alice should have liquidity");
        
        // Alice approves a marketplace for convenience
        positions.setApprovalForAll(maliciousMarketplace, true);
        vm.stopPrank();
        
        // EXPLOIT: Malicious marketplace burns Alice's NFT
        vm.prank(maliciousMarketplace);
        positions.burn(id);
        
        // VERIFY: Alice's funds are permanently locked
        vm.startPrank(alice);
        
        // Alice tries to withdraw but fails because NFT no longer exists
        vm.expectRevert();
        positions.withdraw(id, poolKey, -100, 100, liquidity);
        
        // Alice cannot re-mint the same ID because she doesn't know the salt
        // The pseudo-random salt was generated using prevrandao() and gas()
        // and was never stored or emitted
        
        // Verify liquidity still exists in Core but is inaccessible
        (uint128 remainingLiquidity,,,,) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(remainingLiquidity, liquidityDeposited, 
            "Liquidity remains in Core but is permanently inaccessible");
        
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **User trust assumption**: Users commonly grant approvals to legitimate marketplaces and routers for convenience, not expecting these contracts to destroy their NFTs
2. **No warning**: There's no indication in the UI or documentation that approving an address gives them the power to permanently lock all your funds
3. **Irreversible**: Unlike most DeFi vulnerabilities that can be mitigated or recovered from, this causes permanent and complete fund loss
4. **Scale**: A single malicious or compromised approved contract can drain all positions from all users who granted it approval

The fix requires either preventing burns when liquidity exists, or storing/emitting the salt so users can recreate their NFT IDs if needed. The current design's assumption that users will "remember" their pseudo-random salt is unrealistic and dangerous.

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
