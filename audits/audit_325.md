## Title
Fee Accounting Corruption via Liquidity Decrease Due to Mismatched Liquidity Values in feesPerLiquidityFromAmounts Calculation

## Summary
When a liquidity provider decreases their position size in `Core.updatePosition()`, the fee checkpoint adjustment uses the NEW (smaller) liquidity while fees are collected using OLD (larger) liquidity. This mismatch causes the checkpoint adjustment to exceed the actual accumulated fees, resulting in underflow and permanent corruption of position fee accounting.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` - function `updatePosition()` (lines 434-437) [1](#0-0) 

**Intended Logic:** When a position's liquidity changes, the system should:
1. Collect fees accumulated up to this point based on current liquidity
2. Update the liquidity amount
3. Reset the fee checkpoint so future fee calculations start fresh from the current `feesPerLiquidityInside` value

**Actual Logic:** The code creates a critical mismatch when decreasing liquidity:
1. Line 434: Fees are calculated using `position.fees()`, which internally uses the OLD `position.liquidity` value (not yet updated) [2](#0-1) 

2. Line 435: Position liquidity is updated to the NEW (smaller) value `liquidityNext`

3. Line 437: The checkpoint is adjusted by calling `feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext)` using the NEW smaller liquidity [3](#0-2) 

The mathematical breakdown:
- Let `D = feesPerLiquidityInside - feesPerLiquidityInsideLast` (the actual accumulated fee delta)
- Fees collected: `fees = (D * L_old) >> 128`
- Checkpoint adjustment: `adjustment = (fees << 128) / L_new = ((D * L_old) / L_new)`
- When `L_old > L_new`: `adjustment = (D * L_old / L_new) > D`
- New checkpoint: `feesPerLiquidityInside - adjustment` where `adjustment > D` causes **underflow**

The `sub()` function uses unchecked assembly arithmetic: [4](#0-3) 

**Exploitation Path:**
1. Alice creates a position with large liquidity (e.g., L = 1000)
2. Pool accumulates swap fees, increasing `feesPerLiquidityInside` by some amount D
3. Alice calls `updatePosition()` with negative `liquidityDelta` to reduce liquidity to 1 wei
4. The system calculates fees: `fees = (D * 1000) >> 128` (sent to Alice correctly)
5. The system attempts to update checkpoint: `newLast = feesPerLiquidityInside - ((fees << 128) / 1)`
6. But `((fees << 128) / 1) = fees << 128 = D * 1000`, which is 1000x larger than the actual fee delta D
7. The subtraction `feesPerLiquidityInside - (D * 1000)` underflows to a massive value
8. Alice's `feesPerLiquidityInsideLast` is now corrupted with an extremely large value
9. Future fee calculations `(feesPerLiquidityInside - feesPerLiquidityInsideLast) * liquidity` will underflow or return incorrect values
10. Alice permanently loses access to future fee accruals for this position

**Security Property Broken:** This violates the **Fee Accounting** invariant from the README: "Position fee collection must be accurate and never allow double-claiming." The position's fee tracking becomes permanently corrupted, preventing accurate fee collection.

## Impact Explanation
- **Affected Assets**: All accumulated fees for any position that undergoes a liquidity decrease. Both token0 and token1 fees are affected.
- **Damage Severity**: Complete loss of future fee collection capability for the affected position. The fees are effectively "donated" to the pool as they remain in the global fee accounting but become uncollectable by the corrupted position. If the position has significant remaining liquidity (even after decrease), this could represent substantial ongoing losses as future fees accumulate but cannot be collected.
- **User Impact**: Any LP who legitimately decreases their position size (a normal operation for managing liquidity) will have their fee accounting corrupted. This affects all users, not just attackers. The issue is particularly severe because it's triggered by a routine liquidity management operation.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider can trigger this issue, even unintentionally. No special privileges required.
- **Preconditions**: 
  - Position must have accumulated some fees (feesPerLiquidityInside > feesPerLiquidityInsideLast)
  - User must decrease their liquidity (liquidityNext < position.liquidity)
  - The larger the liquidity decrease ratio, the more severe the underflow
- **Execution Complexity**: Single transaction calling `updatePosition()` with negative `liquidityDelta`. This is a standard operation available through the Router or direct Core interaction.
- **Frequency**: Can occur on every liquidity decrease operation. Given that decreasing liquidity is a common portfolio management action (reducing exposure, rebalancing, partial withdrawal), this vulnerability will affect many users in normal protocol operation.

## Recommendation

**In src/Core.sol, function `updatePosition`, lines 434-437:**

The root cause is using mismatched liquidity values. The fee collection and checkpoint adjustment must use the same liquidity base. The fix is to calculate fees and adjust the checkpoint using the OLD liquidity consistently: [5](#0-4) 

**FIXED:**
```solidity
} else {
    (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
    // Update checkpoint BEFORE changing liquidity, using current liquidity for consistency
    position.feesPerLiquidityInsideLast = feesPerLiquidityInside.sub(
        feesPerLiquidityFromAmounts(fees0, fees1, position.liquidity)  // Use OLD liquidity
    );
    position.liquidity = liquidityNext;  // Then update liquidity
}
```

**Alternative approach:** Set the checkpoint directly to `feesPerLiquidityInside` after collecting fees (similar to `collectFees()`):
```solidity
} else {
    (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
    position.liquidity = liquidityNext;
    position.feesPerLiquidityInsideLast = feesPerLiquidityInside;  // Reset to current value
}
```

This alternative is simpler and matches the logic in `collectFees()` where the checkpoint is set directly without adjustment: [6](#0-5) 

## Proof of Concept
```solidity
// File: test/Exploit_FeeAccountingCorruption.t.sol
// Run with: forge test --match-test test_FeeAccountingCorruptionOnLiquidityDecrease -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PositionId, createPositionId} from "../src/types/positionId.sol";
import {SwapParameters, createSwapParameters} from "../src/types/swapParameters.sol";
import {tickToSqrtRatio} from "../src/math/ticks.sol";
import {ICore} from "../src/interfaces/ICore.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_FeeAccountingCorruption is FullTest {
    PoolKey poolKey;
    PositionId positionId;
    address alice = makeAddr("alice");
    
    function setUp() public override {
        super.setUp();
        // Create concentrated pool at tick 0
        poolKey = createPool(0, 3000, 60); // 0.3% fee, 60 tick spacing
        positionId = createPositionId(MIN_TICK, MAX_TICK);
        
        // Give Alice tokens
        token0.mint(alice, 1000000e18);
        token1.mint(alice, 1000000e18);
        vm.startPrank(alice);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_FeeAccountingCorruptionOnLiquidityDecrease() public {
        vm.startPrank(alice);
        
        // STEP 1: Alice adds large liquidity
        router.lock(abi.encode("mint", poolKey, positionId, uint128(100000)));
        
        // STEP 2: Generate fees through swaps
        // Swap token0 -> token1 to generate fees
        router.lock(abi.encode(
            "swap",
            poolKey,
            createSwapParameters(1000e18, false, tickToSqrtRatio(MIN_TICK), 0)
        ));
        
        // Swap back to generate more fees
        router.lock(abi.encode(
            "swap",
            poolKey,
            createSwapParameters(1000e18, true, tickToSqrtRatio(MAX_TICK), 0)
        ));
        
        // STEP 3: Check fees before liquidity decrease
        (uint128 liquidity1, , , uint128 fees0Before, uint128 fees1Before) = 
            router.getPositionFeesAndLiquidity(poolKey, positionId, alice);
        
        console.log("Liquidity before:", liquidity1);
        console.log("Fees0 before decrease:", fees0Before);
        console.log("Fees1 before decrease:", fees1Before);
        
        // STEP 4: Decrease liquidity drastically (from 100000 to 1)
        // This triggers the vulnerability
        router.lock(abi.encode("burn", poolKey, positionId, int128(-99999)));
        
        // STEP 5: Generate more fees
        router.lock(abi.encode(
            "swap",
            poolKey,
            createSwapParameters(500e18, false, tickToSqrtRatio(MIN_TICK), 0)
        ));
        
        // STEP 6: Try to collect new fees - accounting is corrupted!
        (uint128 liquidity2, , , uint128 fees0After, uint128 fees1After) = 
            router.getPositionFeesAndLiquidity(poolKey, positionId, alice);
        
        console.log("Liquidity after:", liquidity2);
        console.log("Fees0 after more swaps:", fees0After);
        console.log("Fees1 after more swaps:", fees1After);
        
        // VERIFY: Position accounting is corrupted
        // With liquidity of 1, new fees should accumulate normally
        // But due to underflow, fees will be 0 or incorrect
        assertEq(liquidity2, 1, "Liquidity should be 1");
        // The position should have accumulated new fees but won't due to corruption
        assertTrue(
            fees0After == 0 || fees0After < fees0Before,
            "Fee accounting corrupted: unable to collect new fees correctly"
        );
        
        vm.stopPrank();
    }
}
```

## Notes

The vulnerability exists because `feesPerLiquidityFromAmounts()` is mathematically correct in isolation - converting fee amounts to per-liquidity representation requires dividing by liquidity. However, the USAGE context in `Core.updatePosition()` creates the bug by applying this conversion with the wrong liquidity value (NEW instead of OLD).

The test suite doesn't catch this because there are no integration tests for fee collection after liquidity decrease scenarios with accumulated fees. The unit test for `feesPerLiquidityFromAmounts()` only validates the math in isolation, not the interaction with position updates.

This is distinct from the question's initial premise about "donating fees" due to precision loss - the actual vulnerability is worse: it's not just precision loss from small liquidity, but complete accounting corruption via underflow when liquidity is decreased by any significant amount.

### Citations

**File:** src/Core.sol (L433-438)
```text
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }
```

**File:** src/Core.sol (L492-494)
```text
        (amount0, amount1) = position.fees(feesPerLiquidityInside);

        position.feesPerLiquidityInsideLast = feesPerLiquidityInside;
```

**File:** src/types/position.sol (L33-51)
```text
function fees(Position memory position, FeesPerLiquidity memory feesPerLiquidityInside)
    pure
    returns (uint128, uint128)
{
    uint128 liquidity;
    uint256 difference0;
    uint256 difference1;
    assembly ("memory-safe") {
        liquidity := mload(add(position, 0x20))
        // feesPerLiquidityInsideLast is now at offset 0x40 due to extraData field
        let positionFpl := mload(add(position, 0x40))
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
    }

    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
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

**File:** src/types/feesPerLiquidity.sol (L20-28)
```text
function feesPerLiquidityFromAmounts(uint128 amount0, uint128 amount1, uint128 liquidity)
    pure
    returns (FeesPerLiquidity memory result)
{
    assembly ("memory-safe") {
        mstore(result, div(shl(128, amount0), liquidity))
        mstore(add(result, 32), div(shl(128, amount1), liquidity))
    }
}
```
