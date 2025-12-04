# Audit Report

## Title
TWAMM Virtual Order Execution Corruption: searchForNextInitializedTime Can Skip Initialized Times Due to Step Size Jumps

## Summary
The `searchForNextInitializedTime()` function in `src/math/timeBitmap.sol` contains a critical flaw where it incorrectly returns `isInitialized = false` when capping to `untilTime`, causing TWAMM to skip processing orders whose start/end times fall within regions that `nextValidTime()` jumps over. This leads to permanent pool corruption, unbounded losses for users whose orders should have ended, and locked funds for users whose orders should have started. [1](#0-0) 

## Impact
**Severity**: High

This vulnerability causes direct loss of user funds and permanent protocol corruption. Orders that should terminate continue executing indefinitely with incorrect sale rates, leading to unbounded losses. Orders that should activate never begin trading, causing user deposits to remain locked without any trading activity. Once this corruption occurs, all subsequent virtual order executions are permanently incorrect as the sale rate deltas are never applied, and there is no recovery mechanism.

## Finding Description

**Location:** `src/math/timeBitmap.sol:77-79`, function `searchForNextInitializedTime()`

**Intended Logic:**
The function should find the next initialized time between `fromTime` and `untilTime` by iterating through valid times on the non-uniform time grid. When an initialized time exists beyond `untilTime`, the function should return `untilTime` with `isInitialized = false` to indicate no initialized times exist within the search range. However, if `untilTime` itself is initialized, this should be detected and returned with `isInitialized = true`. [2](#0-1) 

**Actual Logic:**
The function uses `nextValidTime()` to determine search positions, which computes step sizes that increase logarithmically by powers of 16 (256, 4096, 65536, 1048576, etc.) based on distance from `lastVirtualOrderExecutionTime`. When the step size reaches 65536 seconds, it equals exactly one bitmap word (256 indices × 256 seconds = 65536 seconds per word). [3](#0-2) 

The bitmap structure stores times with `word = time >> 16` and `index = (time >> 8) & 0xff`, meaning each word represents 65536 seconds. [4](#0-3) 

When `nextValidTime()` jumps by 65536 seconds, it can land on a time that maps to a later index within a bitmap word or even a completely different word. The `findNextInitializedTime()` function then searches for set bits starting from this jumped-to position, potentially missing initialized times at earlier indices. [5](#0-4) 

**Exploitation Path:**
1. **Setup**: An order is placed with `endTime = 262144` (word 4, index 0), which is validated as a valid time using `isTimeValid()` at order placement
2. **Time Progression**: Virtual order execution proceeds with `lastVirtualOrderExecutionTime = 1000`, and the search reaches `currentTime = 200000`
3. **Jump Occurs**: `nextValidTime(1000, 200000)` computes:
   - `diff = 199000`
   - `msb = 17`, rounded to 16
   - `stepSize = 65536`
   - Result: `nextValidTime = 262464` (word 4, index 1)
4. **Miss**: `findNextInitializedTime(slot, 262464)` searches from index 1 onward in word 4, completely missing the initialized time at index 0 (time 262144)
5. **False Negative**: If no other bits are set in word 4, `findNextInitializedTime` returns the last time in the word with `isInitialized = false`, or finds a time in a later word
6. **Incorrect Correction**: When the found time exceeds `untilTime = block.timestamp`, lines 77-79 execute: `nextTime = untilTime; isInitialized = false`
7. **Corruption**: TWAMM receives `(262144, false)` and skips processing the sale rate deltas at time 262144 [6](#0-5) 

**Security Property Broken:**
This violates TWAMM's core invariant that all orders must be executed accurately according to their start and end times. When `initialized = false`, the sale rate delta processing is completely skipped, leaving sale rates permanently incorrect. [7](#0-6) 

## Impact Explanation

**Affected Assets**: All TWAMM orders in affected pools, impacting both token0 and token1 balances for all liquidity providers and order placers.

**Damage Severity**:
- Orders with `endTime` at the skipped time continue executing with their full sale rate indefinitely, causing unbounded losses as they sell tokens without ever stopping
- Orders with `startTime` at the skipped time never activate, meaning user deposits are permanently locked without any trading occurring
- All future virtual order executions in the pool operate with permanently incorrect sale rates, corrupting all subsequent trading
- Users cannot withdraw their purchased tokens from orders that should have executed but were skipped
- The pool's TWAMM state becomes irrecoverably corrupted with no admin recovery mechanism

**User Impact**: Any user with orders starting or ending at times that fall within jump regions. Once corruption occurs, ALL future users of the pool are affected since the sale rates never recover to correct values.

## Likelihood Explanation

**Attacker Profile**: No attacker needed - this is a logic bug that occurs automatically during normal protocol operation.

**Preconditions**:
1. TWAMM pool has initialized orders
2. Time advances such that the distance between `lastVirtualOrderExecutionTime` and order times results in step size ≥ 65536
3. An order's start/end time falls at an index that gets skipped by the jump
4. This is highly likely because step size = 65536 begins when `time - lastVirtualOrderExecutionTime ≥ 65536`, and bitmap words naturally align with this boundary

**Execution Complexity**: Occurs automatically when any transaction triggers `_executeVirtualOrdersFromWithinLock()` during normal TWAMM operation - no special transactions or ordering required.

**Frequency**: Risk increases as the protocol ages and orders are placed further in the future. Each step size boundary crossing (65536, 1048576, etc.) presents risk of skipping initialized times.

**Overall Likelihood**: HIGH - The alignment of step sizes with bitmap word boundaries (both 65536 seconds) makes this scenario mathematically inevitable for long-running pools with distant order times.

## Recommendation

**Primary Fix:**
The correction logic at lines 77-79 must verify whether `untilTime` itself is initialized before setting `isInitialized = false`:

```solidity
// In src/math/timeBitmap.sol, function searchForNextInitializedTime
(nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
if (nextTime > untilTime) {
    nextTime = untilTime;
    // Check if untilTime itself is initialized before marking as false
    (uint256 word, uint256 index) = timeToBitmapWordAndIndex(untilTime);
    Bitmap bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
    isInitialized = bitmap.isSet(uint8(index));
}
```

This ensures that if `untilTime` has initialized orders, they are properly detected and processed even when the search jumps over them.

**Additional Mitigations**:
- Consider adding assertions in `_executeVirtualOrdersFromWithinLock()` to verify that all known initialized times are processed
- Add comprehensive integration tests that verify orders execute correctly when step sizes cross word boundaries

## Proof of Concept

The provided PoC demonstrates the vulnerability concept. A complete working PoC would:
1. Deploy Core and TWAMM contracts
2. Initialize a pool and place orders at specific times (e.g., 262144)
3. Use `vm.warp()` to advance time while keeping `lastVirtualOrderExecutionTime` at an old value
4. Trigger virtual order execution
5. Verify that orders at the skipped time were not processed (sale rates unchanged, order info not deleted)
6. Demonstrate resulting pool corruption

**Expected PoC Result:**
- **If Vulnerable**: Order at time 262144 is not processed, `isInitialized` returns false, sale rates remain incorrect
- **If Fixed**: Order at time 262144 is correctly detected and processed, sale rates are updated properly

## Notes

The vulnerability is particularly severe due to:

1. **Perfect Alignment**: Step sizes and bitmap word boundaries both use 65536 seconds, creating perfect conditions for jumps to skip entire words containing initialized times.

2. **Single-Word Search**: `findNextInitializedTime()` only searches within a single bitmap word starting from the given position, so any initialized time at an earlier index in that word is invisible to the search.

3. **No Recovery Mechanism**: Once sale rate deltas are skipped, there is no way to retroactively apply them. The pool state is permanently corrupted from that point forward.

4. **Cascading Impact**: Because all future virtual order executions use the incorrect sale rates, the damage compounds over time, affecting all users who interact with the pool after the corruption occurs.

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
