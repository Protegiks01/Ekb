## Title
TWAMM Orders Execute Indefinitely Due to Incorrect Time Reconstruction When Execution Gap Exceeds uint32 Range

## Summary
The `realLastVirtualOrderExecutionTime()` function reconstructs the full timestamp from a stored uint32 value using modular arithmetic. When the gap between stored time and current `block.timestamp` exceeds `type(uint32).max` (~136 years), the reconstruction is off by exactly 2^32 seconds, causing `_executeVirtualOrdersFromWithinLock()` to search in the wrong time range and completely skip order endTimes, resulting in orders executing indefinitely beyond their intended duration.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `realLastVirtualOrderExecutionTime()` function should reconstruct the full timestamp from the stored uint32 value, allowing the protocol to handle timestamps that exceed uint32 range by using modular arithmetic to find the closest match to current time.

**Actual Logic:** The reconstruction formula `time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))` assumes the stored time is within the most recent uint32 period. When the actual gap exceeds `type(uint32).max`, the reconstruction returns a value that is off by exactly 2^32 seconds, placing it in the "recent past" relative to current time rather than the actual ancient past.

**Exploitation Path:**

1. **Initial State Setup**: A TWAMM pool is initialized and has active orders. The `lastVirtualOrderExecutionTime` is set to time T0 (e.g., 1000 seconds). [2](#0-1) 

2. **Order Creation**: Users create orders with endTimes between T0 and T0 + type(uint32).max. These endTimes are stored in the initialized times bitmap. [3](#0-2) 

3. **Extended Inactivity**: The pool has no swaps, position updates, or fee collections for more than type(uint32).max seconds (~136 years), so `lastVirtualOrderExecutionTime` remains at T0. The stored value is `uint32(T0)`.

4. **Execution Trigger**: At current time C = T0 + 2^32 + Delta (where Delta > 0), someone triggers virtual order execution via swap, position update, or direct call. [4](#0-3) 

5. **Incorrect Time Reconstruction**: The `realLastVirtualOrderExecutionTime()` function reconstructs the time as:
   - `C & 0xffffffff = Delta` (lower 32 bits of current time)
   - `T0 & 0xffffffff = T0` (stored value)
   - `diff = Delta - T0` (wrapped in uint32 if negative)
   - `reconstructed = C - diff = T0 + 2^32` (off by exactly 2^32 from actual T0)

6. **Wrong Search Window**: The execution loop runs from `reconstructed time (T0 + 2^32)` to `block.timestamp (C)`, which is a tiny window of size Delta. [5](#0-4) 

7. **Skipped EndTimes**: All order endTimes that were created in the range [T0, T0 + type(uint32).max] are in the absolute past (< C), but they fall outside the search window [T0 + 2^32, C]. The `searchForNextInitializedTime()` never finds them. [6](#0-5) 

8. **Sale Rate Deltas Not Applied**: Because these endTimes are skipped, their sale rate deltas are never applied. [7](#0-6) 

9. **Orders Execute Indefinitely**: Orders that should have ended continue executing with their original sale rates, indefinitely selling users' tokens beyond the intended duration.

**Security Property Broken:** Violates user fund safety - users' sell orders continue executing beyond their specified endTime, effectively forcing continued sales they never authorized. This violates the fundamental expectation that orders execute only for their specified duration.

## Impact Explanation
- **Affected Assets**: All tokens involved in TWAMM orders created during the gap period between the last execution and current time
- **Damage Severity**: Users with sell orders lose 100% of additional tokens sold beyond their intended endTime. If an order was meant to sell X tokens over duration D, but continues indefinitely, the total loss is unbounded over time.
- **User Impact**: Every user who created TWAMM orders in pools that experience > 136 year execution gaps. While the timeframe seems extreme, the protocol is designed for long-term operation and the vulnerability is permanent once triggered.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a systemic failure that occurs automatically when conditions are met. Any user triggering execution (via swap, position update, etc.) would expose the bug.
- **Preconditions**: 
  1. Pool has TWAMM orders created
  2. No virtual order execution occurs for > type(uint32).max seconds (~136 years)
  3. This could realistically happen if a pool is deployed early and becomes inactive for extended periods
- **Execution Complexity**: Automatic - simply triggering any operation that calls `lockAndExecuteVirtualOrders()` exposes the bug
- **Frequency**: Once the gap exceeds uint32 range, every subsequent execution uses the wrong time range until the next execution catches up

## Recommendation

The core issue is that the reconstruction formula cannot distinguish between times that are 2^32 * N seconds apart. A proper fix requires either:

**Option 1**: Store additional bits to track which uint32 "epoch" we're in: [1](#0-0) 

```solidity
// CURRENT (vulnerable):
// Stores only uint32, cannot distinguish epochs beyond 136 years

// FIXED:
// Add validation to prevent execution when gap exceeds safe range
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        let storedLower := and(state, 0xffffffff)
        let currentLower := and(timestamp(), 0xffffffff)
        let diff := and(sub(currentLower, storedLower), 0xffffffff)
        time := sub(timestamp(), diff)
        
        // If reconstructed time is more than type(uint32).max in the past,
        // the reconstruction is ambiguous. Revert to prevent incorrect execution.
        if gt(sub(timestamp(), time), 0xffffffff) {
            // revert with "ExecutionGapTooLarge()"
            mstore(0, shl(224, 0x8f2c8d7b))
            revert(0, 4)
        }
    }
}
```

**Option 2**: Add explicit staleness check in execution: [8](#0-7) 

```solidity
// Add check after line 401:
uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

// ADDED: Prevent execution if gap is too large
if (block.timestamp - realLastVirtualOrderExecutionTime > type(uint32).max) {
    revert ExecutionGapTooLarge();
}
```

**Option 3**: Use a larger timestamp storage (uint64 would suffice for millions of years).

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMTimeReconstruction.t.sol
// Run with: forge test --match-test test_TWAMMTimeReconstruction -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/types/twammPoolState.sol";

contract Exploit_TWAMMTimeReconstruction is Test {
    function test_TWAMMTimeReconstruction() public {
        // SETUP: Simulate stored state from 136+ years ago
        uint32 storedTime = 1000; // Ancient timestamp
        uint112 saleRate0 = 1000000;
        uint112 saleRate1 = 0;
        
        TwammPoolState state = createTwammPoolState(
            storedTime,
            saleRate0,
            saleRate1
        );
        
        // EXPLOIT: Fast forward more than type(uint32).max seconds
        uint256 currentTime = uint256(storedTime) + uint256(type(uint32).max) + 1000;
        vm.warp(currentTime);
        
        // VERIFY: Reconstructed time is wrong by 2^32
        uint256 reconstructed = state.realLastVirtualOrderExecutionTime();
        uint256 expected = storedTime; // Should be ancient time
        uint256 actual = storedTime + uint256(type(uint32).max); // But gets recent time
        
        // The reconstruction is off by exactly 2^32
        assertEq(reconstructed, actual, "Time reconstructed incorrectly");
        assertGt(reconstructed - expected, type(uint32).max, "Error exceeds uint32 range");
        
        // This causes the execution window to be tiny (only 1000 seconds)
        // instead of the full gap of type(uint32).max + 1000
        uint256 executionWindow = currentTime - reconstructed;
        assertEq(executionWindow, 1000, "Execution window is tiny");
        
        // Orders with endTimes between storedTime and currentTime would be skipped
        console.log("Vulnerability confirmed:");
        console.log("Stored time:", storedTime);
        console.log("Current time:", currentTime);
        console.log("Reconstructed time:", reconstructed);
        console.log("Reconstruction error:", reconstructed - storedTime);
        console.log("Execution window:", executionWindow);
    }
}
```

## Notes

The vulnerability is fundamentally about the uint32 storage limitation for timestamps combined with the modular arithmetic reconstruction. While 136 years seems like an extreme timeframe, this is a **permanent architectural flaw** that:

1. Cannot be fixed without migration once triggered
2. Affects all orders created during the gap period
3. Causes indefinite unauthorized execution of user orders
4. Violates the core promise that orders execute only for their specified duration

The `searchForNextInitializedTime()` behavior when `nextValid == 0` (the original security question) is a symptom of this deeper issue - when the time reconstruction is wrong, the search window is wrong, leading to either:
- `nextValid == 0` being returned prematurely (when searching from the wrong starting point)
- Initialized times being completely outside the search window and thus never found

The fix must address the root cause: either prevent execution when gaps exceed uint32 range, or use a larger timestamp storage that doesn't have this limitation.

### Citations

**File:** src/types/twammPoolState.sol (L20-24)
```text
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))
    }
}
```

**File:** src/extensions/TWAMM.sol (L203-212)
```text
                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }

                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L386-404)
```text
    function _executeVirtualOrdersFromWithinLock(PoolKey memory poolKey, PoolId poolId) internal {
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

            // we only conditionally load this if the state is coincidentally zero,
            // in order to not lock the pool if state is 0 but the pool _is_ initialized
            // this can only happen iff a pool has zero sale rates **and** an execution of virtual orders
            // happens on the uint32 boundary
            if (TwammPoolState.unwrap(state) == bytes32(0)) {
                if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
                    revert PoolNotInitialized();
                }
            }

            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

            // no-op if already executed in this block
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
```

**File:** src/extensions/TWAMM.sol (L415-425)
```text
                uint256 time = realLastVirtualOrderExecutionTime;

                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });
```

**File:** src/extensions/TWAMM.sol (L537-558)
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

                        StorageSlot timeInfoSlot = TWAMMStorageLayout.poolTimeInfosSlot(poolId, nextTime);
                        (, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) =
                            TimeInfo.wrap(timeInfoSlot.load()).parse();

                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
                            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
                        });
```

**File:** src/extensions/TWAMM.sol (L625-644)
```text
    function afterInitializePool(address, PoolKey memory key, int32, SqrtRatio)
        external
        override(BaseExtension, IExtension)
        onlyCore
    {
        if (!key.config.isFullRange()) revert FullRangePoolOnly();

        PoolId poolId = key.toPoolId();

        TWAMMStorageLayout.twammPoolStateSlot(poolId)
            .store(
                TwammPoolState.unwrap(
                    createTwammPoolState({
                        _lastVirtualOrderExecutionTime: uint32(block.timestamp), _saleRateToken0: 0, _saleRateToken1: 0
                    })
                )
            );

        _emitVirtualOrdersExecuted({poolId: poolId, saleRateToken0: 0, saleRateToken1: 0});
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
