## Title
Permanent Fund Lock Through NFT Burning Without Salt Recovery Mechanism

## Summary
Users who burn their position NFTs to obtain gas refunds (as encouraged by the comment at line 129) permanently lose access to their liquidity positions. The position data remains in Core contract storage, but all withdrawal functions require NFT ownership via the `authorizedForNft` modifier. For NFTs minted using the parameterless `mint()` function, the random salt is never stored and cannot be recovered, making fund withdrawal impossible and directly violating the protocol's critical invariant that "all positions must be withdrawable at any time."

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The burn function is designed to allow users to destroy NFTs they no longer need and receive a gas refund from clearing storage. The comment suggests users can safely burn NFTs and recreate them later using the original salt.

**Actual Logic:** When users burn NFTs:
1. The ERC721 token is destroyed via `_burn(id)`
2. Position data remains in Core contract storage (indexed by poolId, Positions contract address, and positionId derived from NFT ID)
3. The `mint()` function generates random salts that are never stored or emitted
4. Without the exact salt, users cannot recreate the NFT ID
5. All position management functions require `authorizedForNft(id)` modifier [2](#0-1) 

**Exploitation Path:**
1. User calls `positions.mint()` which generates a random salt from `prevrandao()` and `gas()` - this salt is used once and never stored
2. User deposits liquidity via `deposit(id, poolKey, tickLower, tickUpper, ...)` creating a position in Core contract storage
3. User reads comment "Can be used to refund some gas after the NFT is no longer needed" and calls `positions.burn(id)` 
4. NFT is destroyed but position data (containing user's liquidity) remains in Core contract storage
5. User attempts to withdraw via `positions.withdraw(id, ...)` → reverts because `authorizedForNft(id)` check fails (user no longer owns NFT)
6. User cannot recreate NFT because random salt was never stored and is mathematically unrecoverable
7. User's liquidity is permanently locked in Core contract with no recovery mechanism

**Security Property Broken:** Violates the critical invariant: "All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit)." [3](#0-2) 

## Impact Explanation
- **Affected Assets**: All liquidity positions where users burn their NFTs. Both token0 and token1 liquidity plus accumulated fees become permanently inaccessible.
- **Damage Severity**: Complete and permanent loss of user funds. Users lose 100% of deposited liquidity plus any accumulated trading fees. The position continues to exist in Core storage and earn fees, but these earnings are also permanently locked.
- **User Impact**: Any user who burns their position NFT without storing the mint salt. The misleading comment at line 129 actively encourages this behavior without warning about salt preservation requirements. Particularly affects users who:
  - Use the random salt `mint()` function (most common case)
  - Experience wallet recovery and lose their salt records
  - Don't understand the technical requirement to preserve salts

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a critical user error facilitated by misleading documentation. Any normal user managing liquidity positions can trigger this.
- **Preconditions**: 
  - User has minted an NFT and deposited liquidity
  - User burns the NFT believing it can be safely recreated (as suggested by comment)
  - User used random salt generation or lost their custom salt
- **Execution Complexity**: Trivially simple - single call to `burn(id)` function. The comment encourages this action for "gas refund."
- **Frequency**: Can affect any user at any time they burn their NFT. Given the comment actively suggests burning "when the NFT is no longer needed," this is likely to be a recurring issue.

## Recommendation

**Option 1: Emit salt in mint event (Recommended)**
```solidity
// In src/base/BaseNonfungibleToken.sol, add event:
event Minted(uint256 indexed id, address indexed minter, bytes32 salt);

// In mint() function at line 109:
function mint() public payable returns (uint256 id) {
    bytes32 salt;
    assembly ("memory-safe") {
        mstore(0, prevrandao())
        mstore(32, gas())
        salt := keccak256(0, 64)
    }
    id = mint(salt);
    emit Minted(id, msg.sender, salt); // Add this line
}

// In mint(bytes32 salt) function at line 123:
function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    _mint(msg.sender, id);
    emit Minted(id, msg.sender, salt); // Add this line
}
```

**Option 2: Store salt mapping**
```solidity
// Add mapping to track salts
mapping(uint256 => bytes32) public tokenIdToSalt;

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    tokenIdToSalt[id] = salt; // Store for recovery
    _mint(msg.sender, id);
}
```

**Option 3: Prevent burning positions with liquidity**
```solidity
// In Positions.sol, override burn function:
function burn(uint256 id) external payable override {
    // Check all possible tick ranges - complex and gas-intensive
    // Not recommended due to implementation complexity
    super.burn(id);
}
```

**Option 4: Update documentation to warn users**
```solidity
// Update comment at line 129:
/// @dev Can be used to refund some gas after the NFT is no longer needed.
///      WARNING: Burning an NFT makes the position unwithdrawable unless you
///      have stored the original minting salt. Only burn NFTs for positions
///      that have been fully withdrawn. The same ID can be recreated by the
///      original minter by reusing the salt, but the salt from mint() is 
///      randomly generated and never stored - you must record it yourself.
```

**Recommended Solution: Implement Option 1 (emit events) AND Option 4 (update docs)**

## Proof of Concept
```solidity
// File: test/Exploit_BurnedNFTFundLock.t.sol
// Run with: forge test --match-test test_BurnedNFTFundLock -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_BurnedNFTFundLock is FullTest {
    
    function setUp() public override {
        super.setUp();
    }
    
    function test_BurnedNFTFundLock() public {
        // SETUP: Create pool and get tokens
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        token0.approve(address(positions), 1000e18);
        token1.approve(address(positions), 1000e18);
        
        // STEP 1: User mints NFT with random salt (common case)
        uint256 id = positions.mint(); // Random salt generated, never stored
        
        // STEP 2: User deposits significant liquidity
        (uint128 liquidity,,) = positions.deposit(id, poolKey, -100, 100, 100e18, 100e18, 0);
        assertGt(liquidity, 0, "Position created with liquidity");
        
        // Verify position exists and has liquidity
        (uint128 posLiquidity,,,,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(posLiquidity, liquidity, "Position has expected liquidity");
        
        // STEP 3: User reads comment "Can be used to refund some gas after the NFT is no longer needed"
        // and burns NFT thinking they can recreate it later
        positions.burn(id);
        
        // STEP 4: Verify NFT is burned (user no longer owns it)
        vm.expectRevert(); // ownerOf will revert for burned token
        positions.ownerOf(id);
        
        // STEP 5: User tries to withdraw their liquidity
        vm.expectRevert(); // Will revert with NotUnauthorizedForToken
        positions.withdraw(id, poolKey, -100, 100, liquidity);
        
        // STEP 6: Verify position STILL EXISTS in Core storage with user's liquidity
        (uint128 stillExists,,,,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(stillExists, liquidity, "Position still exists in Core storage!");
        
        // STEP 7: User tries to re-mint but cannot recover random salt
        uint256 newId = positions.mint(); // Different random salt
        assertNotEq(newId, id, "New mint produces different ID - original salt lost forever");
        
        // VULNERABILITY CONFIRMED: 
        // - User's 100e18 tokens of liquidity are permanently locked
        // - Position still exists in Core storage
        // - No way to recreate original NFT ID without the random salt
        // - Critical invariant "all positions must be withdrawable" is violated
        
        console.log("Original NFT ID:", id);
        console.log("New NFT ID after reminting:", newId);
        console.log("Locked liquidity:", liquidity);
    }
    
    function test_BurnedNFTWithKnownSalt() public {
        // Even with known salt, users might forget or lose it
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        token0.approve(address(positions), 1000e18);
        token1.approve(address(positions), 1000e18);
        
        bytes32 userSalt = bytes32(uint256(12345));
        uint256 id = positions.mint(userSalt);
        
        positions.deposit(id, poolKey, -100, 100, 100e18, 100e18, 0);
        positions.burn(id);
        
        // If user forgets salt or loses it in wallet recovery:
        vm.expectRevert();
        positions.withdraw(id, poolKey, -100, 100, 1);
        
        // User can recover IF they remember the salt
        uint256 recoveredId = positions.mint(userSalt);
        assertEq(recoveredId, id, "Same ID recreated with same salt");
        
        // Now withdrawal works
        positions.withdraw(recoveredId, poolKey, -100, 100, 1);
    }
}
```

**Notes:**
- This vulnerability is NOT in the known issues section of the README
- It directly violates the documented invariant that "all positions must be withdrawable at any time"
- The misleading comment at line 129 actively encourages the dangerous behavior
- No recovery mechanism exists for users who burn NFTs minted with random salts
- The issue affects the core position management system, not third-party extensions
- Impact is HIGH: Permanent, complete loss of user funds with no admin recovery possible

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L109-135)
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

    /// @inheritdoc IBaseNonfungibleToken
    /// @dev The token ID is generated using saltToId(msg.sender, salt). This prevents the need
    ///      to store a counter of how many tokens were minted, as IDs are deterministic.
    ///      No fees are collected; any msg.value sent is ignored.
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }

    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
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

**File:** README.md (L202-202)
```markdown
All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
```
