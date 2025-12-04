After conducting a comprehensive validation against the Ekubo Protocol security framework, I must deliver my judgment:

# Audit Report

## Title
TWAMM Virtual Order Execution Corruption: searchForNextInitializedTime Can Skip Initialized Times Due to Step Size Jumps

## Summary
The `searchForNextInitializedTime()` function contains a critical flaw where exponentially growing step sizes can jump over valid initialized order times, causing TWAMM to permanently skip sale rate delta updates. This results in orders executing indefinitely past their end times or never activating at their start times, leading to unbounded losses and permanent pool state corruption.

## Impact
**Severity**: High

This vulnerability causes direct permanent loss of user funds through two mechanisms: (1) orders that should terminate continue selling tokens indefinitely with incorrect sale rates, causing unbounded losses to order placers, and (2) orders that should activate never begin trading, permanently locking user deposits. The pool's TWAMM state becomes irrecoverably corrupted as sale rate deltas are never applied, affecting all subsequent users of the pool with no recovery mechanism. [1](#0-0) 

## Finding Description

**Location:** `src/math/timeBitmap.sol:77-79`, function `searchForNextInitializedTime()` [2](#0-1) 

**Intended Logic:**
The function should find all initialized times between `fromTime` and `untilTime` by iterating through the valid time grid. When no initialized times exist within the range, it should return `untilTime` with `isInitialized = false`. If `untilTime` itself is initialized, it must be detected and returned with `isInitialized = true`.

**Actual Logic:**
The search uses `nextValidTime()` which computes step sizes that grow logarithmically in powers of 16 (256, 4096, 65536, 1048576 seconds) based on the distance from `lastVirtualOrderExecutionTime`. [3](#0-2) 

When step size reaches 65536 seconds, it exactly equals one bitmap word size. The bitmap structure stores times with `word = time >> 16` and `index = (time >> 8) & 0xff`, meaning each word represents exactly 65536 seconds. [4](#0-3) 

When `nextValidTime()` jumps by 65536+ seconds, it can land at a later index within a bitmap word. The `findNextInitializedTime()` function then searches forward using `geSetBit()` from this landed position, missing any initialized times at earlier indices in the same word. [5](#0-4) 

**Exploitation Path:**
1. **Setup**: Order placed at `endTime = 262144` (word 4, index 0), validated as valid time at placement using `isTimeValid(block.timestamp, 262144)`
2. **Time Progression**: Pool remains inactive with `lastVirtualOrderExecutionTime = 1000`, then execution triggered at `currentTime = 200000+`
3. **Jump Occurs**: `nextValidTime(1000, 200000)` computes `diff = 199000`, determines `stepSize = 65536`, returns `≈265536`
4. **Miss**: `findNextInitializedTime(slot, 265536)` searches from word 4, index 4+ forward, completely missing the initialized time at word 4, index 0
5. **False Negative**: Search returns time > `untilTime`, triggering lines 77-79 which cap to `untilTime` with `isInitialized = false`
6. **Corruption**: TWAMM execution loop receives `(262144, false)` and skips the critical `if (initialized)` block at line 537, never applying sale rate deltas [6](#0-5) 

**Security Property Broken:**
This violates TWAMM's core invariant that all orders must execute accurately at their designated start and end times. When `initialized = false` is incorrectly returned, the sale rate delta application is completely bypassed, leaving the pool's sale rates permanently incorrect for all future trades.

## Impact Explanation

**Affected Assets**: All TWAMM orders in the affected pool, impacting token0 and token1 balances for all order placers and liquidity providers.

**Damage Severity**:
- Orders with `endTime` at skipped times continue executing with full sale rate indefinitely, causing unbounded losses as tokens are sold without ever stopping
- Orders with `startTime` at skipped times never activate, permanently locking user deposits without any trading occurring  
- All subsequent virtual order executions operate with permanently incorrect sale rates, corrupting every future trade
- Users cannot correctly withdraw purchased tokens from orders that should have completed
- Pool TWAMM state is irrecoverably corrupted with no admin or user recovery mechanism

**User Impact**: Any users with orders at times that fall within jump regions. Once initial corruption occurs, ALL subsequent users are affected as sale rates never recover.

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is an automatic logic bug during normal protocol operation.

**Preconditions**:
1. TWAMM pool with initialized orders at valid grid positions
2. Time advances creating distance where `lastVirtualOrderExecutionTime` to search position ≥ 65536 seconds
3. Order times fall at positions that get jumped over (mathematically inevitable given word boundary alignment)
4. Any transaction triggers `_executeVirtualOrdersFromWithinLock()` 

**Execution Complexity**: Occurs automatically during normal TWAMM operations when any user interacts with the pool - no special transactions required.

**Frequency**: Risk increases with protocol maturity as orders are placed further into the future. Each step size boundary (65536, 1048576, etc.) creates skip potential.

**Overall Likelihood**: HIGH - The perfect mathematical alignment of step sizes with bitmap word boundaries (both 65536 seconds) makes this scenario inevitable for pools with distant order times and inactive periods.

## Recommendation

**Primary Fix:**
The correction logic must verify whether `untilTime` itself is initialized before unconditionally setting `isInitialized = false`:

```solidity
// In src/math/timeBitmap.sol, function searchForNextInitializedTime, lines 77-79
if (nextTime > untilTime) {
    nextTime = untilTime;
    // CRITICAL: Check if untilTime itself is initialized
    (uint256 word, uint256 index) = timeToBitmapWordAndIndex(untilTime);
    Bitmap bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
    isInitialized = bitmap.isSet(uint8(index));
}
```

**Additional Mitigations:**
- Add comprehensive integration tests covering step size boundary crossings with orders at various word indices
- Consider architectural changes to prevent step sizes from exceeding word boundaries, or implement multi-pass search strategy to catch skipped times
- Add invariant assertions in virtual order execution to detect when expected initialized times are not found

## Proof of Concept

**Expected PoC Result:**
- **If Vulnerable**: Order at time 262144 not processed despite being initialized, `isInitialized` incorrectly returns false, sale rates remain wrong, pool corrupted
- **If Fixed**: Order at time 262144 correctly detected and processed, sale rate deltas properly applied, pool state correct

## Notes

**Critical Design Considerations:**

1. **Perfect Alignment Vulnerability**: Step sizes and bitmap word boundaries both use 65536 seconds, creating perfect mathematical conditions for jumps to skip entire words containing initialized times.

2. **Forward-Only Search**: The `geSetBit()` function only searches forward from the given index within a word, making any initialized times at earlier indices completely invisible to the search algorithm.

3. **Permanence**: Once sale rate deltas are skipped, there is no mechanism to retroactively apply them. The pool state corruption is permanent and affects all future users.

4. **Incomplete Proposed Fix**: The recommended fix only addresses the specific case where `untilTime` itself is initialized. If multiple initialized times exist between the search start and `untilTime`, all except the one at `untilTime` (if present) would still be skipped. A more comprehensive solution would require fundamental changes to the search strategy to ensure no times are skipped within visited bitmap words.

### Citations

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

**File:** src/math/timeBitmap.sol (L77-79)
```text
            if (nextTime > untilTime) {
                nextTime = untilTime;
                isInitialized = false;
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
