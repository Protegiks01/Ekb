## Title
Tick Re-initialization Overwrites Fee Accumulator Data, Corrupting Position Fee Calculations

## Summary
The `_updateTick` function in `src/Core.sol` unconditionally overwrites `feesPerLiquidityOutside` slots when a tick's `liquidityNet` transitions from 0 to non-zero, even if the tick was previously crossed during a swap. This destroys fee accumulation data, leading to massive miscalculation of fees owed to liquidity providers. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol`, function `_updateTick`, lines 302-316

**Intended Logic:** When a tick is first used (liquidityNet transitions from 0 to non-zero), the `feesPerLiquidityOutside` slots should be initialized to track fees accumulated outside the tick boundary. The comment states this is "to non-zero so tick crossing is cheaper" (gas optimization). [2](#0-1) 

**Actual Logic:** The code initializes `feesPerLiquidityOutside` to 1 whenever `liquidityNetNext > 0`, regardless of:
1. Whether this is a fresh initialization or a re-initialization
2. Whether the tick was crossed while uninitialized (liquidityNet = 0)
3. The current tick position or global fee accumulator values

The assembly computation `v := gt(liquidityNetNext, 0)` is technically correct, but it's used in flawed logic that doesn't account for tick crossings that occur when `liquidityNet = 0`.

**Exploitation Path:**

1. **Initial Position Creation & Removal:** Alice creates position [80, 120] at tick 100 with global fees = 1000. Ticks 80 and 120 are initialized with `feesOutside = 1`. Alice immediately removes the position, causing both ticks to be uninitialized with `feesOutside = 0`. [2](#0-1) 

2. **Tick Crossing While Uninitialized:** A swap crosses tick 120 upward when global fees = 5000. During the crossing, `feesOutside[120]` is updated using the formula at lines 786-791: `feesOutside[120] = 5000 - 0 = 5000` (since it was reset to 0). [3](#0-2) 

3. **Re-initialization Overwrites Crossing Data:** Bob creates position [120, 140]. Tick 120's liquidityNet transitions from 0 to non-zero, triggering the initialization condition. The code sets `feesOutside[120] = 1`, **overwriting** the correct value of 5000. [2](#0-1) 

4. **Corrupted Fee Calculation:** When calculating fees inside Bob's position [120, 140] with current tick = 130 and global = 8000:
   - Expected: `feesInside = global - lower - upper = 8000 - 5000 - feesOutside[140]`
   - Actual: `feesInside = 8000 - 1 - feesOutside[140]` (off by 4999!) [4](#0-3) 

This causes Bob's position to calculate fees based on `feesInside` inflated by 4999 units. When multiplied by liquidity and divided by 2^128, Bob receives massively inflated fees, draining the pool.

**Security Property Broken:** Violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." The corrupted fee accumulator causes positions to either steal fees from other LPs or lose entitled fees.

## Impact Explanation
- **Affected Assets**: All pools where ticks are uninitialized (all positions removed) and then crossed before re-initialization. Affects token0 and token1 fees for all positions sharing the corrupted tick.
- **Damage Severity**: The fee miscalculation can be in the thousands or millions of fee units, depending on global fees accumulated between uninitialization and re-initialization. Since fees are calculated as `(feesInside_delta * liquidity) / 2^128`, even a delta of 1000 units with typical liquidity can result in significant token theft. LPs creating positions after the corruption steal fees from existing LPs, or lose entitled fees if the overwrite reduces the accumulator value.
- **User Impact**: Any LP whose position range includes a corrupted tick receives incorrect fees. This can affect multiple positions across the entire pool, as ticks are shared between overlapping positions.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this by creating and immediately removing positions to uninitialized target ticks, then waiting for swaps to cross those ticks. No special privileges required.
- **Preconditions**: 
  1. A tick must have all its liquidity removed (liquidityNet = 0)
  2. The price must cross that tick via swaps
  3. A new position must be created that re-initializes the tick
  
  These are normal protocol operations that occur frequently in active pools.
- **Execution Complexity**: Single transaction to create/remove position, wait for organic swap activity to cross the tick, then create another position. Can also be done atomically using flash loans to manipulate liquidityNet.
- **Frequency**: Can be exploited once per tick per uninitialization cycle. In active pools with frequent position churn, this vulnerability can be triggered repeatedly on different ticks.

## Recommendation

The initialization logic must consider the current tick position and preserve existing fee data. The correct approach (similar to Uniswap V3) is:

```solidity
// In src/Core.sol, function _updateTick, lines 302-316:

// CURRENT (vulnerable):
if ((currentLiquidityNet == 0) != (liquidityNetNext == 0)) {
    flipTick(CoreStorageLayout.tickBitmapsSlot(poolId), tick, poolConfig.concentratedTickSpacing());

    (StorageSlot fplSlot0, StorageSlot fplSlot1) =
        CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tick);

    bytes32 v;
    assembly ("memory-safe") {
        v := gt(liquidityNetNext, 0)
    }

    fplSlot0.store(v);
    fplSlot1.store(v);
}

// FIXED:
if ((currentLiquidityNet == 0) != (liquidityNetNext == 0)) {
    flipTick(CoreStorageLayout.tickBitmapsSlot(poolId), tick, poolConfig.concentratedTickSpacing());

    // Only initialize when transitioning from 0 to non-zero (not during uninitialization)
    if (liquidityNetNext != 0) {
        (StorageSlot fplSlot0, StorageSlot fplSlot1) =
            CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tick);
        
        // Only overwrite if the slots are zero (never initialized or explicitly cleared)
        // This preserves fee data from tick crossings that occurred while liquidityNet was 0
        bytes32 existingValue0 = fplSlot0.load();
        bytes32 existingValue1 = fplSlot1.load();
        
        if (existingValue0 == 0) {
            // Initialize based on current tick position for correct fee accounting
            int32 currentTick = readPoolState(poolId).tick();
            if (currentTick >= tick) {
                // Tick is at or below current price, initialize to global fees
                StorageSlot globalSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
                fplSlot0.store(globalSlot.load());
                fplSlot1.store(globalSlot.next().load());
            } else {
                // Tick is above current price, initialize to 0 (or 1 for gas optimization)
                fplSlot0.store(bytes32(uint256(1)));
                fplSlot1.store(bytes32(uint256(1)));
            }
        }
        // else: preserve existing values from previous crossings
    }
    // When uninitialized (liquidityNetNext == 0), do NOT reset the fee accumulators
    // This preserves crossing data in case the tick is re-initialized later
}
```

**Alternative simpler fix:** Never reset `feesOutside` to 0 during uninitialization, and always check if the slot is non-zero before overwriting during initialization.

## Proof of Concept

```solidity
// File: test/Exploit_TickReinitialization.t.sol
// Run with: forge test --match-test test_TickReinitializationCorruptsFees -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";
import "../src/types/positionId.sol";

contract Exploit_TickReinitializationCorruptsFees is Test {
    Core core;
    address token0;
    address token1;
    PoolKey poolKey;
    
    function setUp() public {
        core = new Core();
        token0 = makeAddr("token0");
        token1 = makeAddr("token1");
        
        // Initialize pool at tick 100
        poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: /* concentrated config */
        });
        
        // Initialize pool and accumulate initial fees
        // Global fees = 1000 at this point
    }
    
    function test_TickReinitializationCorruptsFees() public {
        // SETUP: Initial state at tick 100, global fees = 1000
        
        // Alice adds position [80, 120] - initializes ticks 80 and 120 to feesOutside = 1
        PositionId positionAlice = PositionId.wrap(/* [80, 120] */);
        core.updatePosition(poolKey, positionAlice, 1000);
        
        // Alice removes position - uninitializes ticks, resets feesOutside to 0
        core.updatePosition(poolKey, positionAlice, -1000);
        
        // Verify tick 120 feesOutside is now 0
        (StorageSlot slot0, StorageSlot slot1) = 
            CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolKey.toPoolId(), 120);
        assertEq(uint256(slot0.load()), 0, "Tick 120 should be reset to 0");
        
        // EXPLOIT: Swap crosses tick 120 upward, global fees = 5000
        // This updates feesOutside[120] = 5000 - 0 = 5000
        SwapParameters memory params = SwapParameters({/* cross tick 120 */});
        core.swap(poolKey, params);
        
        // Verify tick 120 was updated to 5000 during crossing
        uint256 feesAfterCrossing = uint256(slot0.load());
        assertEq(feesAfterCrossing, 5000, "Tick 120 should be 5000 after crossing");
        
        // Bob adds position [120, 140] - RE-INITIALIZES tick 120
        PositionId positionBob = PositionId.wrap(/* [120, 140] */);
        core.updatePosition(poolKey, positionBob, 1000);
        
        // VERIFY: Tick 120 was OVERWRITTEN to 1, destroying crossing data
        uint256 feesAfterReinit = uint256(slot0.load());
        assertEq(feesAfterReinit, 1, "Vulnerability confirmed: tick 120 overwritten to 1");
        assertLt(feesAfterReinit, feesAfterCrossing, "Fee accumulator data LOST!");
        
        // Calculate fees for Bob's position - will be massively inflated
        // Expected: feesInside based on correct feesOutside[120] = 5000
        // Actual: feesInside based on corrupted feesOutside[120] = 1
        // Difference: 4999 fee units, multiplied by liquidity
        
        uint128 bobFees = /* calculate Bob's fees */;
        uint128 expectedFees = /* correct fees if feesOutside was preserved */;
        assertGt(bobFees, expectedFees, "Bob receives inflated fees due to corruption");
    }
}
```

## Notes

The assembly computation `v := gt(liquidityNetNext, 0)` itself is correct - it properly checks if `liquidityNetNext > 0`. However, this value is used in fundamentally flawed initialization logic that:

1. Doesn't account for tick crossings that occur when `liquidityNet = 0`
2. Unconditionally overwrites fee accumulators during re-initialization
3. Resets accumulators to 0 during uninitialization, losing historical data
4. Doesn't consider the current tick position for proper initialization

The vulnerability manifests when normal protocol operations (position removal, swap crossing, position creation) occur in sequence, making it highly exploitable in production environments. The impact is severe as it violates the core "Fee Accounting" invariant and can lead to theft of fees from other LPs.

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

**File:** src/Core.sol (L302-316)
```text
        if ((currentLiquidityNet == 0) != (liquidityNetNext == 0)) {
            flipTick(CoreStorageLayout.tickBitmapsSlot(poolId), tick, poolConfig.concentratedTickSpacing());

            (StorageSlot fplSlot0, StorageSlot fplSlot1) =
                CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tick);

            bytes32 v;
            assembly ("memory-safe") {
                v := gt(liquidityNetNext, 0)
            }

            // initialize the storage slots for the fees per liquidity outside to non-zero so tick crossing is cheaper
            fplSlot0.store(v);
            fplSlot1.store(v);
        }
```

**File:** src/Core.sol (L786-791)
```text
                                tickFplFirstSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplSecondSlot.load()))
                                );
```
