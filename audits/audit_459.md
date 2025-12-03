## Title
Fee Calculation Mismatch Between View Function and Core Contract for Non-Full-Range Stableswap Pools

## Summary
The `getPositionFeesAndLiquidity()` view function in `BasePositions.sol` uses incorrect logic to determine fee calculation method for stableswap pools with non-zero amplification or center tick. It checks `isFullRange()` instead of `isStableswap()`, causing it to calculate fees differently than the Core contract's actual `collectFees()` implementation, misleading users about their accumulated fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (function `getPositionFeesAndLiquidity`, lines 64-66)

**Intended Logic:** The view function should mirror the Core contract's fee accrual logic to accurately display users' accumulated fees before they collect them.

**Actual Logic:** The view function uses `isFullRange()` to decide between global fees and fees inside tick boundaries, while the Core contract's `collectFees()` uses `isStableswap()`. For stableswap pools with amplification≠0 or centerTick≠0:
- `isStableswap()` returns TRUE (because bit 31 = 0)
- `isFullRange()` returns FALSE (because amplification≠0 or centerTick≠0)

This creates a logic mismatch where: [1](#0-0) 

The view function uses `isFullRange()` and calls `getPoolFeesPerLiquidityInside()` for non-full-range pools, but: [2](#0-1) 

The actual `collectFees()` uses `isStableswap()` and applies global fees for all stableswap pools.

**Exploitation Path:**
1. A stableswap pool is created with amplification=4 and centerTick=0 (common configuration for stable pairs)
2. User deposits liquidity and earns fees through swaps
3. User calls `getPositionFeesAndLiquidity()` to check their accumulated fees before collecting
4. The view function incorrectly calculates fees using `getPoolFeesPerLiquidityInside()` (concentrated pool logic) instead of global fees
5. When user actually calls `collectFees()`, they receive different amounts than displayed, violating user expectations

**Security Property Broken:** Violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." While this doesn't enable double-claiming, it breaks fee accounting accuracy by showing incorrect fee amounts to users.

## Impact Explanation
- **Affected Assets**: All user positions in non-full-range stableswap pools (i.e., stableswap pools with amplification≠0 or centerTick≠0)
- **Damage Severity**: Users receive incorrect fee information from the view function, which could be significantly different from actual collectible fees. This misinformation can lead to poor decision-making about when to collect fees, position management, or pool selection.
- **User Impact**: All liquidity providers in affected stableswap pools see incorrect fee data. This affects any UI, analytics dashboard, or automated strategy that relies on this view function.

## Likelihood Explanation
- **Attacker Profile**: This is not an exploitable vulnerability by attackers, but a logic bug affecting all users of non-full-range stableswap pools
- **Preconditions**: 
  - Pool must be a stableswap pool with amplification≠0 or centerTick≠0 (very common for stable pair pools)
  - Users attempt to query their fee balances using `getPositionFeesAndLiquidity()`
- **Execution Complexity**: Triggered automatically whenever the view function is called for affected pools
- **Frequency**: Affects every query to `getPositionFeesAndLiquidity()` for non-full-range stableswap pools

## Recommendation

The fix is to align the view function's logic with the Core contract's logic: [3](#0-2) 

The view function should check `isStableswap()` instead of `isFullRange()`:

```solidity
// In src/base/BasePositions.sol, function getPositionFeesAndLiquidity, lines 64-66:

// CURRENT (vulnerable):
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
    ? CORE.getPoolFeesPerLiquidity(poolId)
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);

// FIXED:
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isStableswap()
    ? CORE.getPoolFeesPerLiquidity(poolId)
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);
```

This change ensures the view function uses the same logic as `collectFees()`, providing users with accurate fee information.

## Proof of Concept

```solidity
// File: test/Exploit_FeeCalculationMismatch.t.sol
// Run with: forge test --match-test test_FeeCalculationMismatch -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {createStableswapPoolConfig} from "../src/types/poolConfig.sol";

contract Exploit_FeeCalculationMismatch is FullTest {
    function test_FeeCalculationMismatch() public {
        // SETUP: Create a stableswap pool with amplification=4, centerTick=0
        // This makes isStableswap()=true but isFullRange()=false
        PoolConfig config = createStableswapPoolConfig(1 << 63, 4, 0, address(0));
        PoolKey memory poolKey = createPool(address(token0), address(token1), 0, config);
        
        // Verify the configuration
        assertTrue(config.isStableswap(), "Pool should be stableswap");
        assertFalse(config.isFullRange(), "Pool should NOT be full-range");
        
        // Get the active liquidity tick range for stableswap
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        
        // Create a position and generate fees through swaps
        (uint256 id, ) = createPosition(poolKey, lower, upper, 1000 ether, 1000 ether);
        
        // Execute a swap to generate fees
        token0.approve(address(router), 100 ether);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100 ether}),
            type(int256).min
        );
        
        // EXPLOIT: Query fees using the view function
        (,,, uint128 viewFees0, uint128 viewFees1) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, lower, upper);
        
        // Collect actual fees
        (uint128 actualFees0, uint128 actualFees1) = 
            positions.collectFees(id, poolKey, lower, upper);
        
        // VERIFY: The view function shows different fees than actually collected
        // This demonstrates the mismatch between view logic and actual collection logic
        console.log("View function fees0:", viewFees0);
        console.log("Actual collected fees0:", actualFees0);
        console.log("View function fees1:", viewFees1);
        console.log("Actual collected fees1:", actualFees1);
        
        // The assertion will fail if there's a mismatch, proving the vulnerability
        assertEq(viewFees0, actualFees0, "Vulnerability confirmed: View fees0 != Actual fees0");
        assertEq(viewFees1, actualFees1, "Vulnerability confirmed: View fees1 != Actual fees1");
    }
}
```

**Notes:**
- This vulnerability affects the accuracy of fee information displayed to users, not the actual fee collection mechanism itself
- The Core contract's fee accrual logic is correct; only the view function is inconsistent
- The fix is straightforward: replace `isFullRange()` with `isStableswap()` to match the Core contract's logic
- This issue specifically impacts stableswap pools configured with non-zero amplification factors or non-zero center ticks, which are common configurations for stable pair pools like USDC/USDT

### Citations

**File:** src/base/BasePositions.sol (L64-66)
```text
        FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
            ? CORE.getPoolFeesPerLiquidity(poolId)
            : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);
```

**File:** src/Core.sol (L480-490)
```text
        if (poolKey.config.isStableswap()) {
            // Stableswap pools: use global fees per liquidity
            StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
            feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
            feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
        } else {
            // Concentrated pools: calculate fees per liquidity inside the position bounds
            feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                poolId, readPoolState(poolId).tick(), positionId.tickLower(), positionId.tickUpper()
            );
        }
```

**File:** src/types/poolConfig.sol (L68-73)
```text
function isStableswap(PoolConfig config) pure returns (bool r) {
    assembly ("memory-safe") {
        // = iff bit 31 is not set
        r := iszero(and(0x80000000, config))
    }
}
```
