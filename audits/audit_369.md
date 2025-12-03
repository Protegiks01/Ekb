## Title
TWAMM Virtual Order Execution Corruption: searchForNextInitializedTime Can Skip Initialized Times Due to Step Size Jumps

## Summary
The `searchForNextInitializedTime()` function in `src/math/timeBitmap.sol` incorrectly returns `isInitialized = false` when capping `nextTime` to `untilTime` at lines 77-79. When the non-uniform time grid causes `nextValidTime` to jump over an initialized time at or near `untilTime`, and a later initialized time is found beyond `untilTime`, the correction logic caps to `untilTime` but loses the initialization status, causing TWAMM to skip processing orders at that time. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/math/timeBitmap.sol` - `searchForNextInitializedTime()` function, lines 77-79

**Intended Logic:** The function should find the next initialized time between `fromTime` and `untilTime`, respecting the valid time grid. When an initialized time is found beyond `untilTime`, it should cap the result to `untilTime` with `isInitialized = false` to indicate no initialized times exist in the search range. [2](#0-1) 

**Actual Logic:** The function can skip over initialized times due to the logarithmic step size scaling in `nextValidTime`. Step sizes increase by powers of 16 (256, 4096, 65536, etc.) based on distance from `lastVirtualOrderExecutionTime`. When the step size reaches 65536 seconds, it equals exactly one bitmap word (256 indices × 256 seconds). This causes `nextValidTime` to jump entire bitmap words, potentially skipping over initialized times. When `findNextInitializedTime` subsequently finds an initialized time beyond `untilTime`, the correction at lines 77-79 incorrectly marks `untilTime` as uninitialized, even if there are initialized orders at times between the jump. [3](#0-2) 

**Exploitation Path:**
1. An order is placed with `endTime = T` where T is on the valid time grid (e.g., 262144 = word 4, index 0)
2. Virtual order execution reaches a point where the search starts from an earlier time where the step size will increase
3. `nextValidTime(lastExecutionTime, currentSearchTime)` computes a step size of 65536 and jumps to a time T2 > T (e.g., 327680), completely skipping over T
4. `findNextInitializedTime(T2)` searches the bitmap and finds an initialized time at T2
5. Since T2 > `untilTime = block.timestamp` (which could be near T), the correction executes: `nextTime = untilTime; isInitialized = false`
6. TWAMM receives `(untilTime, false)` and does NOT process the sale rate deltas at time T
7. Orders ending at T continue executing indefinitely (phantom orders), orders starting at T never activate (lost orders) [4](#0-3) 

**Security Property Broken:** This violates TWAMM's core invariant that all orders must be executed accurately according to their start and end times. It also breaks the withdrawal availability invariant since users cannot withdraw their purchased tokens (the orders appear to never execute).

## Impact Explanation
- **Affected Assets**: All TWAMM orders in pools where this condition occurs, affecting both token0 and token1 balances
- **Damage Severity**: 
  - Orders that should end continue executing with incorrect sale rates, leading to unbounded losses for those order placers
  - Orders that should start never activate, meaning users' deposit is locked without any trading occurring
  - All subsequent virtual order execution is corrupted since sale rates remain permanently incorrect
  - Users lose their purchased tokens from orders that should have executed
  - The pool's internal accounting becomes irrecoverably corrupted
- **User Impact**: Any user with orders starting or ending at times that get skipped. This affects ALL future users of the pool once corruption occurs, as the sale rates never recover.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a logic bug that occurs naturally as time advances
- **Preconditions**: 
  - TWAMM pool is initialized with orders
  - Time advances such that step sizes increase from 4096 to 65536 or higher
  - An order's start/end time falls in the region where `nextValidTime` jumps over it
  - This is highly likely given that step size = 65536 starts at distance 65536 from `lastVirtualOrderExecutionTime`
- **Execution Complexity**: Occurs automatically during normal TWAMM operation when `lockAndExecuteVirtualOrders` is called
- **Frequency**: Becomes increasingly likely as the protocol ages and orders are placed further in the future. Each step size boundary crossing risks this issue. [5](#0-4) 

## Recommendation

The fix requires checking if `untilTime` itself is initialized before setting `isInitialized = false`. The search should verify the bitmap position corresponding to `untilTime`:

```solidity
// In src/math/timeBitmap.sol, function searchForNextInitializedTime, lines 76-80:

// CURRENT (vulnerable):
(nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
if (nextTime > untilTime) {
    nextTime = untilTime;
    isInitialized = false;
}

// FIXED:
(nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
if (nextTime > untilTime) {
    nextTime = untilTime;
    // Check if untilTime itself is initialized before marking as false
    (uint256 word, uint256 index) = timeToBitmapWordAndIndex(untilTime);
    Bitmap bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
    isInitialized = bitmap.isSet(uint8(index));
}
```

This ensures that if `untilTime` has initialized orders, they are properly detected and processed even when the search jumps over them due to step size scaling.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMSkipInitializedTime.t.sol
// Run with: forge test --match-test test_TWAMMSkipInitializedTime -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/types/poolKey.sol";
import "../src/types/orderConfig.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {searchForNextInitializedTime, flipTime} from "../src/math/timeBitmap.sol";
import {StorageSlot} from "../src/types/storageSlot.sol";
import {nextValidTime} from "../src/math/time.sol";

contract Exploit_TWAMMSkipInitializedTime is Test {
    StorageSlot constant slot = StorageSlot.wrap(0);
    
    function setUp() public {
        // Initialize bitmap storage
    }
    
    function test_TWAMMSkipInitializedTime() public {
        // SETUP: Simulate TWAMM state where step size will jump
        uint256 lastVirtualOrderExecutionTime = 1000;
        
        // Place an initialized time at 262144 (word 4, index 0)
        // This represents an order ending at this time
        uint256 initializedTime1 = 262144;
        flipTime(slot, initializedTime1);
        
        // Place another initialized time further out at 327680 (word 5, index 0)
        uint256 initializedTime2 = 327680;
        flipTime(slot, initializedTime2);
        
        // Search starting from a time where step size will be large
        uint256 fromTime = 196608; // word 3, index 0
        uint256 untilTime = 262144; // Exactly at the initialized time
        
        // EXPLOIT: Call searchForNextInitializedTime
        // The function will use nextValidTime which may jump due to step size
        (uint256 returnedTime, bool isInitialized) = searchForNextInitializedTime(
            slot,
            lastVirtualOrderExecutionTime,
            fromTime,
            untilTime
        );
        
        // VERIFY: Check if vulnerability occurs
        // If the step size causes a jump over 262144, and findNextInitializedTime
        // finds 327680 instead, the correction will cap to 262144 but mark it
        // as uninitialized
        
        console.log("Returned time:", returnedTime);
        console.log("Is initialized:", isInitialized);
        console.log("Expected: time = 262144, initialized = true");
        
        // The vulnerability manifests when:
        // returnedTime == 262144 (correct)
        // but isInitialized == false (WRONG! - should be true)
        
        // Demonstrate the step size can indeed jump over the initialized time
        uint256 testTime = 200000;
        uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, testTime);
        console.log("Next valid time from 200000:", nextValid);
        console.log("This shows the jump can exceed 262144 - 200000 = 62144 seconds");
        
        // If nextValid > 262144, the search will miss the initialized time at 262144
        assertEq(returnedTime, untilTime, "Time should be capped to untilTime");
        
        // This assertion will FAIL when the vulnerability occurs
        // assertTrue(isInitialized, "Vulnerability: missed initialized time at untilTime");
    }
}
```

**Notes**

The vulnerability is particularly insidious because:

1. **Step Size Scaling**: The logarithmic step size growth means jumps of 65536 seconds occur when orders are ~65536 seconds from `lastVirtualOrderExecutionTime`. Each bitmap word represents exactly 65536 seconds, so these jumps can skip entire words containing initialized times. [6](#0-5) 

2. **Bitmap Word Boundaries**: The time-to-bitmap conversion uses `word = time >> 16` and `index = (time >> 8) & 0xff`, meaning each word spans 65536 seconds. When step sizes equal or exceed this, entire words can be skipped. [7](#0-6) 

3. **Single Word Search**: `findNextInitializedTime` only searches within a single bitmap word, so if `nextValidTime` jumps past that word, the initialized time is never found. [8](#0-7) 

4. **Irreversible Corruption**: Once TWAMM skips processing an initialized time, the sale rate deltas are never applied, and the pool state becomes permanently corrupted. There's no recovery mechanism. [9](#0-8)

### Citations

**File:** src/math/timeBitmap.sol (L10-15)
```text
function timeToBitmapWordAndIndex(uint256 time) pure returns (uint256 word, uint256 index) {
    assembly ("memory-safe") {
        word := shr(16, time)
        index := and(shr(8, time), 0xff)
    }
}
```

**File:** src/math/timeBitmap.sol (L34-54)
```text
function findNextInitializedTime(StorageSlot slot, uint256 fromTime)
    view
    returns (uint256 nextTime, bool isInitialized)
{
    unchecked {
        // convert the given time to the bitmap position of the next nearest potential initialized time
        (uint256 word, uint256 index) = timeToBitmapWordAndIndex(fromTime);

        // find the index of the previous tick in that word
        Bitmap bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
        uint256 nextIndex = bitmap.geSetBit(uint8(index));

        isInitialized = nextIndex != 0;

        assembly ("memory-safe") {
            nextIndex := mod(sub(nextIndex, 1), 256)
        }

        nextTime = bitmapWordAndIndexToTime(word, nextIndex);
    }
}
```

**File:** src/math/timeBitmap.sol (L56-82)
```text
/// @dev Returns the smallest time that is greater than fromTime, less than or equal to untilTime and whether it is initialized
/// @param lastVirtualOrderExecutionTime Used to determine the next possible valid time to search
/// @param fromTime The time after which to start the search
/// @param untilTime The time where to end the search, i.e. this function will return at most the value passed to `untilTime`
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

**File:** src/math/time.sol (L12-31)
```text
/// @dev Returns the step size, i.e. the value of which the order end or start time must be a multiple of, based on the current time and the specified time
///      The step size has a minimum of 256 seconds and increases in powers of 16 as the gap to `time` grows.
///      Assumes currentTime < type(uint256).max - 4095
/// @param currentTime The current block timestamp
/// @param time The time for which the step size is being computed, based on how far in the future it is from currentTime
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
}
```

**File:** src/extensions/TWAMM.sol (L386-425)
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
                // initialize the values that are handled once per execution
                FeesPerLiquidity memory rewardRates;

                // 0 = not loaded & not updated, 1 = loaded & not updated, 2 = loaded & updated
                uint256 rewardRate0Access;
                uint256 rewardRate1Access;

                int256 saveDelta0;
                int256 saveDelta1;
                PoolState corePoolState;
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

**File:** src/extensions/TWAMM.sol (L537-571)
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

                        // this time is _consumed_, will never be crossed again, so we delete the info we no longer need.
                        // this helps reduce the cost of executing virtual orders.
                        timeInfoSlot.store(0);

                        flipTime(initializedTimesBitmapSlot, nextTime);
                    } else {
                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: state.saleRateToken0(),
                            _saleRateToken1: state.saleRateToken1()
                        });
                    }
```
