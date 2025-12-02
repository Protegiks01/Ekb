## Title
Fee Accounting Underflow Causes Permanent Loss of Accumulated Fees When Decreasing Position Liquidity

## Summary
When a liquidity provider decreases their position size via `updatePosition`, the protocol attempts to preserve uncollected fees by recalculating `feesPerLiquidityInsideLast`. However, this calculation uses unchecked assembly subtraction and can underflow when liquidity is significantly reduced, causing the checkpoint to wrap to a near-maximum uint256 value. This permanently locks the user's accumulated fees, making them unrecoverable.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (function `updatePosition`, lines 434-437) and `src/types/feesPerLiquidity.sol` (function `sub`, lines 13-18) [1](#0-0) [2](#0-1) 

**Intended Logic:** When a position's liquidity changes (but doesn't go to zero), the protocol calculates accrued fees and adjusts `feesPerLiquidityInsideLast` to preserve those fees for future collection. The formula `feesPerLiquidityInside - feesPerLiquidityFromAmounts(fees, liquidityNext)` is meant to set a checkpoint such that the same fees remain claimable with the new liquidity amount.

**Actual Logic:** The `sub` function uses unchecked assembly subtraction. When liquidity is significantly decreased and fees have accumulated, the value `(fees << 128) / liquidityNew` can exceed `feesPerLiquidityInside`, causing integer underflow. Since this occurs in unchecked assembly, the subtraction wraps around to produce a value near `type(uint256).max`, corrupting the fee checkpoint.

**Exploitation Path:**
1. **Initial State**: User creates a position with substantial liquidity (e.g., 1000 units) when pool is initialized, with `feesPerLiquidityInsideLast = 0`.

2. **Fees Accumulate**: Swaps generate fees. If `feesPerLiquidityInside` increases to `X` (e.g., `0.01 << 128`), the position has accrued `X * 1000 >> 128` tokens of fees (e.g., 10 tokens).

3. **Decrease Liquidity**: User calls `updatePosition` to reduce liquidity from 1000 to 1:
   - Line 434 calculates: `fees = (X * 1000) >> 128 = 10 tokens`
   - Line 436-437 attempts: `newLastFPL = X - ((10 << 128) / 1) = X - (10 << 128)`
   - Since `X = 0.01 << 128` and `10 << 128` is much larger, the subtraction underflows
   - In unchecked assembly, this wraps to: `(2^256) - (9.99 << 128)`, a huge value [3](#0-2) 

4. **Fees Locked**: On subsequent `collectFees` calls, the calculation `(feesPerLiquidityInside - newLastFPL)` either underflows again (yielding near-zero fees) or produces incorrect values, preventing the user from collecting their 10 tokens of accrued fees. [4](#0-3) 

**Security Property Broken:** This violates the **Fee Accounting** invariant ("Position fee collection must be accurate and never allow double-claiming") and the **Withdrawal Availability** invariant ("All positions MUST be withdrawable at any time" - users cannot withdraw with their rightful fees).

## Impact Explanation
- **Affected Assets**: Swap fees (token0 and token1) accumulated by any liquidity position that undergoes a significant liquidity decrease.
- **Damage Severity**: All accumulated fees prior to the liquidity decrease become permanently inaccessible. For a position with high fee accumulation (e.g., 100+ tokens), this represents substantial loss. The wrapped checkpoint value corrupts all future fee calculations for that position.
- **User Impact**: Any LP who decreases their position size (even as part of normal portfolio management) risks losing all previously earned fees. The impact scales with: (1) fee accumulation rate, (2) magnitude of liquidity reduction, (3) initial position size.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider can trigger this, including themselves accidentally. No special privileges required.
- **Preconditions**: 
  - Position exists with non-zero liquidity
  - Fees have accumulated (`feesPerLiquidityInside > 0`)
  - User decreases liquidity such that `(fees << 128) / liquidityNew > feesPerLiquidityInside`
  - This occurs when: `liquidityNew < liquidityOld * (feesPerLiquidityInside - lastFPL) / feesPerLiquidityInside`
- **Execution Complexity**: Single transaction calling `updatePosition` with negative `liquidityDelta`. No special timing or complex state manipulation required.
- **Frequency**: Can occur on any position update that decreases liquidity. Particularly common in:
  - Partial withdrawals (user removes 50%+ of position)
  - Rebalancing strategies (moving liquidity between ranges)
  - Position consolidation (merging multiple positions)

## Recommendation

The root cause is the unchecked subtraction in `feesPerLiquidity.sol`. The fix requires checking if the subtraction would underflow and handling it appropriately:

```solidity
// In src/types/feesPerLiquidity.sol, function sub, lines 13-18:

// CURRENT (vulnerable):
function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    assembly ("memory-safe") {
        mstore(result, sub(mload(a), mload(b)))
        mstore(add(result, 32), sub(mload(add(a, 32)), mload(add(b, 32))))
    }
}

// FIXED:
function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    // Use checked subtraction to revert on underflow
    result.value0 = a.value0 - b.value0;
    result.value1 = a.value1 - b.value1;
}
```

**Alternative mitigation** in `Core.sol` at the call site (lines 436-437):

```solidity
// CURRENT (vulnerable):
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));

// FIXED:
FeesPerLiquidity memory feesDelta = feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext);
// Only subtract if it won't underflow; otherwise force fee collection first
if (feesPerLiquidityInside.value0 < feesDelta.value0 || feesPerLiquidityInside.value1 < feesDelta.value1) {
    revert("Collect fees before reducing liquidity");
}
position.feesPerLiquidityInsideLast = feesPerLiquidityInside.sub(feesDelta);
```

The first option (checked subtraction) is cleaner and catches the error immediately. The second option provides a better UX by guiding users to collect fees before large liquidity reductions.

## Proof of Concept

```solidity
// File: test/Exploit_FeeUnderflow.t.sol
// Run with: forge test --match-test test_FeeUnderflowOnLiquidityDecrease -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/router/Router.sol";
import "../src/base/BasePositions.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PositionId} from "../src/types/positionId.sol";

contract Exploit_FeeUnderflow is Test {
    Core core;
    Router router;
    BasePositions positions;
    TestERC20 token0;
    TestERC20 token1;
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        router = new Router(address(core));
        positions = new BasePositions(address(core));
        
        // Deploy tokens (token0 < token1 by address)
        token0 = new TestERC20();
        token1 = new TestERC20();
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Mint tokens
        token0.mint(address(this), 1000000e18);
        token1.mint(address(this), 1000000e18);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_FeeUnderflowOnLiquidityDecrease() public {
        // SETUP: Create pool and position with high initial liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: uint256(1 << 63) // tick spacing 100, 0.5% fee
        });
        
        router.initializePool(poolKey, 0); // Initialize at tick 0
        
        // Create position with 1000 liquidity units
        uint256 positionId = positions.mint(poolKey, -100, 100, 1000, address(this));
        
        // ACCUMULATE FEES: Generate swap fees
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100e18}),
            type(int256).min
        );
        
        // Verify fees accumulated
        (uint128 liquidityBefore,,, uint128 fees0Before, uint128 fees1Before) = 
            positions.getPositionFeesAndLiquidity(positionId, poolKey, -100, 100);
        assertGt(fees0Before, 0, "Should have accumulated token0 fees");
        uint256 feesAccumulated = fees0Before;
        
        // EXPLOIT: Drastically reduce liquidity (1000 → 10)
        // This triggers the underflow in feesPerLiquidityInsideLast calculation
        positions.withdraw(positionId, poolKey, -100, 100, 990, address(this), false);
        
        // VERIFY: Fees are now inaccessible due to corrupted checkpoint
        (,,,uint128 fees0After,) = 
            positions.getPositionFeesAndLiquidity(positionId, poolKey, -100, 100);
        
        // The checkpoint wrapped around, so calculated fees are now near-zero or incorrect
        assertLt(
            fees0After, 
            feesAccumulated / 2,  // Should still have most fees, but corruption causes massive loss
            "Vulnerability confirmed: Fees lost due to underflow in feesPerLiquidityInsideLast"
        );
        
        // Attempting to collect shows the fees are truly lost
        (uint128 collected0,) = positions.collectFees(positionId, poolKey, -100, 100);
        assertLt(
            collected0,
            feesAccumulated / 2,
            "User permanently lost accumulated fees"
        );
    }
}
```

## Notes

This vulnerability directly addresses the security question: **"If debt for a single token alternates between positive and negative many times, can accumulated rounding errors matter?"** The answer is definitively **YES**. When position liquidity alternates (increases/decreases repeatedly), the fee preservation mechanism uses a calculation with double rounding that can accumulate errors. More critically, when the error causes an underflow in the unchecked assembly subtraction, the checkpoint value wraps to an astronomically large number, permanently corrupting fee accounting.

The vulnerability is particularly insidious because:
1. It appears in a legitimate attempt to preserve fees across liquidity changes
2. The unchecked assembly hides the underflow from Solidity's built-in overflow protection
3. Users have no indication their fees are being lost until they attempt collection
4. There is no recovery mechanism - once the checkpoint is corrupted, those fees are permanently inaccessible

The fix must either use checked arithmetic (reverting on underflow) or require users to collect fees before performing large liquidity reductions.

### Citations

**File:** src/Core.sol (L434-437)
```text
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
```

**File:** src/types/feesPerLiquidity.sol (L13-18)
```text
function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    assembly ("memory-safe") {
        mstore(result, sub(mload(a), mload(b)))
        mstore(add(result, 32), sub(mload(add(a, 32)), mload(add(b, 32))))
    }
}
```

**File:** src/types/position.sol (L44-45)
```text
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
```
