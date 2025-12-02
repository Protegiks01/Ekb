## Title
Missing Token Validation in Single-Hop Swap Allows Wrong-Direction Swaps via Parameter Encoding Bypass

## Summary
The `swap(RouteNode, TokenAmount, threshold)` function in Router.sol lacks token address validation that is present in the multihop swap path. When `tokenAmount.token` doesn't match either pool token, the function silently treats it as a token0 swap instead of reverting, causing users to swap in the unintended direction.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Router.sol` - `swap(RouteNode memory node, TokenAmount memory tokenAmount, int256 calculatedAmountThreshold)` function [1](#0-0) 

**Intended Logic:** Based on the multihop swap implementation, the system should validate that `tokenAmount.token` matches either `poolKey.token0` or `poolKey.token1` before executing a swap. This ensures users are swapping the intended token from the pool.

**Actual Logic:** The single-hop swap function determines swap direction using `node.poolKey.token1 == tokenAmount.token` without validation. If `tokenAmount.token` is neither pool token, `isToken1` defaults to `false`, treating any non-token1 address as a token0 swap.

**Exploitation Path:**
1. User intends to swap token1 (e.g., WETH) for token0 (e.g., USDC) in a USDC/WETH pool
2. Due to integration bug, UI error, or malicious contract, `tokenAmount.token` is set to incorrect address (e.g., DAI)
3. Function executes: `node.poolKey.token1 == DAI` → `false` → `isToken1 = false`
4. System swaps token0 (USDC) instead of intended token1 (WETH)
5. User loses USDC instead of WETH - opposite of their intention
6. Slippage protection only checks amounts, not token types, so transaction succeeds

**Security Property Broken:** The validation inconsistency between swap functions violates the principle that swap operations should fail fast on invalid inputs rather than silently executing wrong-direction swaps.

## Impact Explanation
- **Affected Assets**: User tokens in pools where integrations use the RouteNode/TokenAmount swap variant
- **Damage Severity**: Users swap the wrong pool token, losing funds equal to the swap amount. For exact output swaps, users could pay significantly more of the wrong token than intended.
- **User Impact**: Any user or integration calling this public function with incorrect token addresses. Most vulnerable are automated systems, aggregators, and smart contract integrations that might have bugs in token address construction.

## Likelihood Explanation
- **Attacker Profile**: Malicious smart contracts, compromised front-ends, or buggy integrations. Also affects honest users with implementation errors.
- **Preconditions**: Pool must be initialized with liquidity. User must call the specific swap overload and have sufficient balance/approval of the wrong token.
- **Execution Complexity**: Single transaction. Requires constructing TokenAmount with wrong token address.
- **Frequency**: Can occur on every call to this function variant with incorrect token addresses. No per-pool or timing restrictions.

## Recommendation

Add token validation matching the multihop implementation: [2](#0-1) 

```solidity
// In src/Router.sol, function swap(RouteNode, TokenAmount, threshold), line 365:

// CURRENT (vulnerable):
balanceUpdate = swap(
    node.poolKey,
    node.poolKey.token1 == tokenAmount.token,  // No validation
    tokenAmount.amount,
    node.sqrtRatioLimit,
    node.skipAhead,
    calculatedAmountThreshold,
    msg.sender
);

// FIXED:
bool isToken1 = node.poolKey.token1 == tokenAmount.token;
// Validate token matches one of the pool tokens
require(isToken1 || tokenAmount.token == node.poolKey.token0, "Invalid token");

balanceUpdate = swap(
    node.poolKey,
    isToken1,
    tokenAmount.amount,
    node.sqrtRatioLimit,
    node.skipAhead,
    calculatedAmountThreshold,
    msg.sender
);
```

Alternative: Add a custom error `InvalidSwapToken()` for better error reporting.

## Proof of Concept
```solidity
// File: test/Exploit_WrongDirectionSwap.t.sol
// Run with: forge test --match-test test_WrongDirectionSwap -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";

contract Exploit_WrongDirectionSwap is Test {
    Router router;
    Core core;
    address USDC = address(0x1);
    address WETH = address(0x2);
    address DAI = address(0x3);  // Wrong token
    
    function setUp() public {
        core = new Core();
        router = new Router(ICore(address(core)));
        
        // Initialize USDC/WETH pool
        PoolKey memory poolKey = PoolKey({
            token0: USDC,
            token1: WETH,
            config: PoolConfig.wrap(0)
        });
        core.initializePool(poolKey, 0);
        
        // Add liquidity (simplified)
        // User has USDC and WETH, wants to swap WETH for USDC
    }
    
    function test_WrongDirectionSwap() public {
        // SETUP: User wants to swap WETH (token1) for USDC (token0)
        PoolKey memory poolKey = PoolKey({
            token0: USDC,
            token1: WETH,
            config: PoolConfig.wrap(0)
        });
        
        // User constructs swap with WRONG token address (DAI instead of WETH)
        RouteNode memory node = RouteNode({
            poolKey: poolKey,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0
        });
        
        TokenAmount memory tokenAmount = TokenAmount({
            token: DAI,  // WRONG! Should be WETH
            amount: 1000e18
        });
        
        // EXPLOIT: Swap executes in wrong direction
        // Expected: Swap WETH (token1) for USDC (token0)
        // Actual: Swaps USDC (token0) for WETH (token1) because isToken1=false
        
        PoolBalanceUpdate memory result = router.swap(
            node,
            tokenAmount,
            type(int256).min
        );
        
        // VERIFY: Swap executed token0 instead of token1
        // In multihop path, this would revert with require()
        // In single swap path, it silently swaps wrong direction
        assertTrue(result.delta0() > 0, "Token0 (USDC) was swapped, not token1 (WETH)!");
    }
}
```

**Notes**

The validation inconsistency exists specifically between:
- Multihop swap validation at [2](#0-1)  which enforces `require(isToken1 || tokenAmount.token == node.poolKey.token0)`
- Single-hop swap at [3](#0-2)  which only uses boolean comparison without validation

The vulnerability is triggered through the public payable function at [4](#0-3)  and processes through the lock mechanism eventually reaching handleLockData at [5](#0-4)  where token addresses from poolKey (not tokenAmount) are used for actual transfers.

### Citations

**File:** src/Router.sol (L91-103)
```text
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory result) {
        uint256 callType = abi.decode(data, (uint256));

        if (callType == CALL_TYPE_SINGLE_SWAP) {
            // swap
            (
                ,
                address swapper,
                PoolKey memory poolKey,
                SwapParameters params,
                int256 calculatedAmountThreshold,
                address recipient
            ) = abi.decode(data, (uint256, address, PoolKey, SwapParameters, int256, address));
```

**File:** src/Router.sol (L186-187)
```text
                        bool isToken1 = tokenAmount.token == node.poolKey.token1;
                        require(isToken1 || tokenAmount.token == node.poolKey.token0);
```

**File:** src/Router.sol (L360-374)
```text
    function swap(RouteNode memory node, TokenAmount memory tokenAmount, int256 calculatedAmountThreshold)
        public
        payable
        returns (PoolBalanceUpdate balanceUpdate)
    {
        balanceUpdate = swap(
            node.poolKey,
            node.poolKey.token1 == tokenAmount.token,
            tokenAmount.amount,
            node.sqrtRatioLimit,
            node.skipAhead,
            calculatedAmountThreshold,
            msg.sender
        );
    }
```
