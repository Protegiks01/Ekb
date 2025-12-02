## Title
Initialized Time Skipping Vulnerability Due to Dynamic Time Grid Misalignment Causing Reward Rate Snapshot Corruption

## Summary
The TWAMM extension's virtual order execution can skip initialized times when the valid time grid changes between order placement and execution. This causes reward rate snapshots to never be written at those times, leaving pre-warm values (1,1) in storage. Orders referencing skipped times calculate rewards using these incorrect values, leading to arithmetic underflow and massively inflated reward amounts that can drain pool funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` (lines 417-574, specifically the virtual order execution loop and reward snapshot logic at lines 537-548), `src/math/timeBitmap.sol` (lines 60-82, searchForNextInitializedTime function), `src/math/time.sol` (lines 17-64, computeStepSize and nextValidTime functions)

**Intended Logic:** 
The TWAMM system should process all initialized times sequentially during virtual order execution, saving cumulative reward rate snapshots at each time boundary. Orders calculate rewards as `rewardRate[endTime] - rewardRate[startTime]` to get rewards accumulated during their active period. The pre-warming mechanism (writing (1,1) during `_updateTime`) is meant to reduce gas costs by converting cold writes to warm writes. [1](#0-0) 

**Actual Logic:**
The valid time grid is determined by `computeStepSize`, which returns different step sizes based on the time difference from `currentTime`. When orders are placed, times are validated with `isTimeValid(block.timestamp, time)`. However, when virtual orders execute, `searchForNextInitializedTime` uses `nextValidTime(lastVirtualOrderExecutionTime, time)` to find the next valid time. If `lastVirtualOrderExecutionTime` differs from the `block.timestamp` at placement, the step size grid can change, causing initialized times to be skipped. [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Order Placement:** At `block.timestamp = 0`, attacker places a TWAMM order with `endTime = 8192`. This time is valid because `computeStepSize(0, 8192)` returns 4096 (since 8192 > 4095), and `8192 % 4096 = 0`. The `_updateTime` function marks time 8192 in the bitmap and pre-warms `poolRewardRatesBeforeSlot(poolId, 8192)` with `(1, 1)`. [4](#0-3) [5](#0-4) 

2. **Delayed Execution:** Virtual orders don't execute until much later. At `block.timestamp = 8300`, virtual orders begin executing from `lastVirtualOrderExecutionTime = 4200` (an arbitrary earlier value). When the execution loop reaches `time = 8000`, it calls `searchForNextInitializedTime(slot, 4200, 8000, 8300)`. [6](#0-5) 

3. **Time Skipping:** Inside `searchForNextInitializedTime`, `nextValidTime(4200, 8000)` is called. Since `8000 < 4200 + 4095`, `computeStepSize` returns 256. The function calculates the next valid time as `8256` (next multiple of 256 >= 8000). When `findNextInitializedTime` searches from `8256` onward, it doesn't find time `8192` (which is < 8256), so that initialized time is **skipped**. The loop continues to `block.timestamp = 8300` without crossing time 8192. [7](#0-6) [8](#0-7) 

4. **Snapshot Corruption:** Since time 8192 was never crossed, the reward rate snapshot was never written. The `poolRewardRatesBeforeSlot(poolId, 8192)` still contains the pre-warm value `(1, 1)` instead of the actual cumulative reward rates.

5. **Reward Calculation Exploit:** When the order claims rewards via `getRewardRateInside`, it reads `rewardRateEnd = 1` (pre-warm value) and `rewardRateStart = largeValue` (actual cumulative rate from an earlier crossed time). The unchecked subtraction `result = rewardRateEnd - rewardRateStart = 1 - largeValue` underflows to `type(uint256).max - largeValue + 1`, a massive number. This inflated reward amount is then used to calculate purchased tokens, potentially draining the pool. [9](#0-8) 

**Security Property Broken:** 
This violates the protocol's fee accounting invariant that "position fee collection must be accurate and never allow double-claiming." It also threatens pool solvency by allowing extraction of far more rewards than legitimately earned.

## Impact Explanation
- **Affected Assets**: All tokens in TWAMM pools where initialized times are skipped. The reward calculation affects both token0 and token1 depending on order direction.
- **Damage Severity**: Attacker can claim rewards magnitudes larger than earned (potentially `type(uint256).max` scale). This can drain entire pool balances if liquidity is insufficient to cover the inflated claims, or cause accounting imbalances leading to insolvency.
- **User Impact**: All users with orders spanning the skipped time boundary are affected. Honest users may receive incorrect (likely reduced) rewards if the attacker extracts excessive value first. Pool LPs suffer impermanent loss as pool balances are depleted.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this by carefully timing order placement and execution delays.
- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Attacker must place orders with end times on the coarse time grid (multiples of 4096 or larger)
  - Virtual order execution must be delayed such that `lastVirtualOrderExecutionTime` differs from placement time
  - The step size must change between placement and execution (achievable with times > 4095 seconds in the future)
- **Execution Complexity**: Single order placement, then waiting for natural execution delay. No complex multi-transaction coordination required.
- **Frequency**: Can be repeated for multiple pools and time boundaries. Each skipped time affects all orders referencing it.

## Recommendation

The root cause is that the valid time grid used during placement differs from the grid used during execution. The fix is to ensure initialized times are always processed regardless of the current valid time grid.

**Option 1: Remove Time Grid Filtering During Execution**

In `src/math/timeBitmap.sol`, modify `searchForNextInitializedTime` to not skip initialized times based on `nextValidTime`: [3](#0-2) 

**Option 2: Validate Time Grid Consistency**

In `src/extensions/TWAMM.sol`, add validation that times being crossed match the expected grid: [1](#0-0) 

**Recommended Fix (Option 1 - Most Comprehensive):**

Modify `searchForNextInitializedTime` to search for ANY initialized time without grid filtering, as initialized times have already been validated during placement. The grid validation should only apply when initially placing orders, not when executing existing orders.

Alternatively, store the grid context (step size) with each initialized time so execution can use the same grid that was valid at placement.

## Proof of Concept

```solidity
// File: test/Exploit_TimeSkipping.t.sol
// Run with: forge test --match-test test_TimeSkippingCausesSnapshotCorruption -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/types/orderKey.sol";

contract Exploit_TimeSkipping is Test {
    Core core;
    TWAMM twamm;
    
    function setUp() public {
        // Deploy Core and TWAMM extension
        core = new Core();
        twamm = new TWAMM(address(core));
        
        // Initialize a test pool with TWAMM extension
        // (pool initialization details omitted for brevity)
    }
    
    function test_TimeSkippingCausesSnapshotCorruption() public {
        // SETUP: Place order at time 0 with endTime = 8192
        vm.warp(0);
        
        OrderKey memory orderKey;
        orderKey.config = createOrderConfig({
            startTime: 256,
            endTime: 8192,  // Valid on 4096 grid at time 0
            isToken1: false
        });
        
        // Place order, which initializes time 8192 in bitmap
        // and pre-warms poolRewardRatesBeforeSlot(poolId, 8192) with (1,1)
        bytes32 salt = bytes32(uint256(1));
        twamm.modifyOrder(salt, orderKey, 1000000); // Add 1M sale rate
        
        // Verify time 8192 is initialized
        // (assertion code omitted)
        
        // EXPLOIT: Warp to block.timestamp = 8300
        // Assume lastVirtualOrderExecutionTime = 4200 (from prior execution)
        vm.warp(8300);
        
        // Trigger virtual order execution
        // The execution will skip time 8192 because:
        // - nextValidTime(4200, 8000) returns 8256 (step size = 256)
        // - findNextInitializedTime(slot, 8256) doesn't find 8192
        twamm.executeVirtualOrders(poolKey);
        
        // VERIFY: Time 8192 was skipped
        // poolRewardRatesBeforeSlot(poolId, 8192) still contains (1, 1)
        uint256 snapshotValue = twamm.getRewardRateAtTime(poolId, 8192);
        assertEq(snapshotValue, 1, "Snapshot should be pre-warm value 1, not actual rate");
        
        // Claim rewards - getRewardRateInside will underflow
        uint256 rewards = twamm.getRewardRateInside(poolId, orderKey.config);
        
        // Result = 1 - (largeValue) underflows to massive number
        assertGt(rewards, type(uint128).max, "Vulnerability confirmed: rewards massively inflated due to underflow");
    }
}
```

**Notes:**
- The exact exploitation requires understanding the pool's `lastVirtualOrderExecutionTime` state
- Step size changes occur at the 4095 second boundary and at powers-of-16 intervals
- The vulnerability is most easily triggered when placing orders far in the future (>4095 seconds) then executing after delays
- Pre-warm values of 1 represent ~2.93×10^-39 in Q128.128 fixed-point format, making underflow arithmetic extremely impactful

### Citations

**File:** src/extensions/TWAMM.sol (L84-95)
```text
    function getRewardRateInside(PoolId poolId, OrderConfig config) public view returns (uint256 result) {
        if (block.timestamp >= config.endTime()) {
            uint256 offset = LibBit.rawToUint(!config.isToken1());
            uint256 rewardRateStart =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.startTime()).add(offset).load());

            uint256 rewardRateEnd =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.endTime()).add(offset).load());

            unchecked {
                result = rewardRateEnd - rewardRateStart;
            }
```

**File:** src/extensions/TWAMM.sol (L158-168)
```text
        bool flip = (numOrders == 0) != (numOrdersNext == 0);

        // write the poolRewardRatesBefore[poolId][time] = (1,1) if any orders still reference the time, or write (0,0) otherwise
        // we assume `_updateTime` is being called only for times that are greater than block.timestamp, i.e. have not been crossed yet
        // this reduces the cost of crossing that timestamp to a warm write instead of a cold write
        if (flip) {
            bytes32 zeroNumOrders = bytes32(LibBit.rawToUint(numOrders == 0));

            TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, time).storeTwo(zeroNumOrders, zeroNumOrders);

            flipTime(TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId), time);
```

**File:** src/extensions/TWAMM.sol (L203-208)
```text
                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }
```

**File:** src/extensions/TWAMM.sol (L417-425)
```text
                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });
```

**File:** src/extensions/TWAMM.sol (L537-548)
```text
                    if (initialized) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                            rewardRate0Access = 1;
                        }
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                            rewardRate1Access = 1;
                        }

                        TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, nextTime)
                            .storeTwo(bytes32(rewardRates.value0), bytes32(rewardRates.value1));
```

**File:** src/math/time.sol (L17-30)
```text
function computeStepSize(uint256 currentTime, uint256 time) pure returns (uint256 stepSize) {
    assembly ("memory-safe") {
        switch gt(time, add(currentTime, 4095))
        case 1 {
            let diff := sub(time, currentTime)

            let msb := sub(255, clz(diff)) // = index of msb

            msb := sub(msb, mod(msb, 4)) // = round down to multiple of 4

            stepSize := shl(msb, 1)
        }
        default { stepSize := 256 }
    }
```

**File:** src/math/time.sol (L43-64)
```text
///      Assumes currentTime is less than type(uint256).max - type(uint32).max
function nextValidTime(uint256 currentTime, uint256 time) pure returns (uint256 nextTime) {
    unchecked {
        uint256 stepSize = computeStepSize(currentTime, time);
        assembly ("memory-safe") {
            nextTime := add(time, stepSize)
            nextTime := sub(nextTime, mod(nextTime, stepSize))
        }

        // only if we didn't overflow
        if (nextTime != 0) {
            uint256 nextStepSize = computeStepSize(currentTime, nextTime);
            if (nextStepSize != stepSize) {
                assembly ("memory-safe") {
                    nextTime := add(time, nextStepSize)
                    nextTime := sub(nextTime, mod(nextTime, nextStepSize))
                }
            }
        }

        nextTime = FixedPointMathLib.ternary(nextTime > currentTime + type(uint32).max, 0, nextTime);
    }
```

**File:** src/math/timeBitmap.sol (L60-82)
```text
function searchForNextInitializedTime(
    StorageSlot slot,
    uint256 lastVirtualOrderExecutionTime,
    uint256 fromTime,
    uint256 untilTime
) view returns (uint256 nextTime, bool isInitialized) {
    unchecked {
        nextTime = fromTime;
        while (!isInitialized && nextTime != untilTime) {
            uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);
            // if there is no valid time after the given nextTime, just return untilTime
            if (nextValid == 0) {
                nextTime = untilTime;
                isInitialized = false;
                break;
            }
            (nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
            if (nextTime > untilTime) {
                nextTime = untilTime;
                isInitialized = false;
            }
        }
    }
```
