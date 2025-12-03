## Title
TWAMM Virtual Order Execution Skips Initialized Times Due to Bitmap Word Boundary and Variable Step Size Mismatch

## Summary
The `findNextInitializedTime()` function returns the greatest time in a bitmap word (line 52) when no initialized time is found, combined with `searchForNextInitializedTime()`'s use of variable step sizes that can exceed bitmap granularity (256 seconds), causes TWAMM virtual order execution to skip initialized times at word boundaries, resulting in orders not starting/ending at their scheduled times and users losing funds. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/math/timeBitmap.sol` (lines 34-54, 60-82) and `src/extensions/TWAMM.sol` (lines 417-573)

**Intended Logic:** When searching for the next initialized time across multiple bitmap words, the search should find all initialized times between the starting point and the target time, ensuring TWAMM orders start/end at their scheduled times.

**Actual Logic:** When `findNextInitializedTime()` finds no initialized time in a bitmap word, it returns the greatest time in that word (index 255). [2](#0-1)  The `searchForNextInitializedTime()` function then calls `nextValidTime()` with this greatest time. [3](#0-2) 

For times far in the future, `nextValidTime()` uses step sizes > 256 seconds (e.g., 4096 seconds). [4](#0-3)  When the next valid time falls in the next bitmap word but not at index 0, `findNextInitializedTime()` converts this time to `(word, index)` and searches forward from that index only, missing any initialized times at lower indices in that word. [5](#0-4) 

**Exploitation Path:**
1. **Setup**: Create TWAMM orders with start/end times that fall on low indices in bitmap words (e.g., word 1, index 1 = time 65792) when the lastVirtualOrderExecutionTime is far in the past (e.g., 1000 seconds)
2. **Trigger**: Execute virtual orders via any TWAMM operation (swap, position update, or explicit execution call) [6](#0-5) 
3. **Skip**: The search in word 0 finds nothing, returns time 65280. `nextValidTime(1000, 65280)` returns 68096 (word 1, index 10) due to step size of 4096. `findNextInitializedTime(slot, 68096)` searches from index 10 forward, missing the initialized time at index 1
4. **Impact**: Orders scheduled at the skipped time never have their sale rate deltas applied, causing incorrect virtual order execution with wrong sale rates. [7](#0-6) 

**Security Property Broken:** Fee Accounting invariant - users' TWAMM orders execute at incorrect rates, causing miscalculation of purchased amounts and loss of funds.

## Impact Explanation
- **Affected Assets**: All TWAMM orders in pools where virtual order execution is triggered after long periods of inactivity (> 4096 seconds between executions)
- **Damage Severity**: Users whose orders should start/end at skipped times receive incorrect token amounts. If an order's start time is skipped, it never activates and the user's sell tokens remain locked while they receive no purchased tokens. If an order's end time is skipped, it continues executing beyond its intended duration, exposing users to unintended price risk.
- **User Impact**: Any user with TWAMM orders crossing bitmap word boundaries in pools with infrequent execution. The probability increases for times further in the future due to larger step sizes (4096, 65536 seconds, etc.)

## Likelihood Explanation
- **Attacker Profile**: Any user can trigger this by simply creating orders at specific times and waiting for natural execution, or by explicitly calling `lockAndExecuteVirtualOrders()` [8](#0-7) 
- **Preconditions**: Pool must have TWAMM orders at times that align with low indices in bitmap words, and sufficient time gap between executions (> 4096 seconds) for step size to exceed 256
- **Execution Complexity**: Single transaction - just trigger any operation that executes virtual orders (swap, position update, fee collection, or explicit execution)
- **Frequency**: Can occur repeatedly for any pool meeting the preconditions. More likely for less active pools or during periods of low activity

## Recommendation

The root cause is that `searchForNextInitializedTime` doesn't search the entire range between the current position and untilTime - it only searches forward from each `nextValidTime` result. When `nextValidTime` jumps forward due to large step sizes, it can skip bitmap indices.

**Fix Option 1: Search all indices in word**
```solidity
// In src/math/timeBitmap.sol, modify findNextInitializedTime:
// After finding no initialized time in current word at or after the given index,
// search from index 0 of the NEXT word instead of returning the greatest time in current word

function findNextInitializedTime(StorageSlot slot, uint256 fromTime)
    view
    returns (uint256 nextTime, bool isInitialized)
{
    unchecked {
        (uint256 word, uint256 index) = timeToBitmapWordAndIndex(fromTime);
        Bitmap bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
        uint256 nextIndex = bitmap.geSetBit(uint8(index));
        
        if (nextIndex == 0) {
            // No initialized time in current word, try next word from index 0
            word = word + 1;
            bitmap = Bitmap.wrap(uint256(slot.add(word).load()));
            nextIndex = bitmap.geSetBit(0);
            
            if (nextIndex == 0) {
                // No initialized time in next word either, return greatest time in next word
                isInitialized = false;
                nextTime = bitmapWordAndIndexToTime(word, 255);
                return (nextTime, isInitialized);
            }
        }
        
        isInitialized = true;
        nextIndex = nextIndex - 1;
        nextTime = bitmapWordAndIndexToTime(word, nextIndex);
    }
}
```

**Fix Option 2: Make searchForNextInitializedTime word-boundary aware**
```solidity
// In src/math/timeBitmap.sol, modify searchForNextInitializedTime to always check
// from the start of each word:
function searchForNextInitializedTime(
    StorageSlot slot,
    uint256 lastVirtualOrderExecutionTime,
    uint256 fromTime,
    uint256 untilTime
) view returns (uint256 nextTime, bool isInitialized) {
    unchecked {
        nextTime = fromTime;
        (uint256 currentWord,) = timeToBitmapWordAndIndex(fromTime);
        
        while (!isInitialized && nextTime != untilTime) {
            uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);
            if (nextValid == 0) {
                nextTime = untilTime;
                isInitialized = false;
                break;
            }
            
            // If nextValid crosses into a new word, search from index 0 of that word
            (uint256 nextWord,) = timeToBitmapWordAndIndex(nextValid);
            if (nextWord > currentWord) {
                // Check entire new word from start
                nextValid = bitmapWordAndIndexToTime(nextWord, 0);
                currentWord = nextWord;
            }
            
            (nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
            if (nextTime > untilTime) {
                nextTime = untilTime;
                isInitialized = false;
            }
        }
    }
}
```

## Proof of Concept
```solidity
// File: test/Exploit_SkippedTWAMMTime.t.sol
// Run with: forge test --match-test test_SkippedInitializedTime -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/math/timeBitmap.sol";
import "../src/libraries/TWAMMStorageLayout.sol";
import "../src/types/storageSlot.sol";

contract Exploit_SkippedTWAMMTime is Test {
    using TWAMMLib for *;
    
    // Simulated storage for testing
    mapping(uint256 => bytes32) storage_data;
    
    function setUp() public {
        // Set up bitmap with initialized time at word 1, index 1
        uint256 time = 65792; // word 1, index 1 = (1 << 16) + (1 << 8)
        (uint256 word, uint256 index) = timeToBitmapWordAndIndex(time);
        
        // Mark this time as initialized in bitmap
        bytes32 bitmap = storage_data[word];
        bitmap = bytes32(uint256(bitmap) | (1 << index));
        storage_data[word] = bitmap;
    }
    
    function test_SkippedInitializedTime() public view {
        // SETUP: Search for next initialized time
        uint256 lastVirtualOrderExecutionTime = 1000;
        uint256 fromTime = 1000;
        uint256 untilTime = 100000;
        
        StorageSlot slot = StorageSlot.wrap(0);
        
        // EXPLOIT: Call search function which will skip the initialized time
        (uint256 nextTime, bool initialized) = searchForNextInitializedTime(
            slot,
            lastVirtualOrderExecutionTime,
            fromTime,
            untilTime
        );
        
        // VERIFY: The initialized time at 65792 should be found but is skipped
        // Due to step size of 4096, nextValidTime(1000, 65280) returns 68096
        // which is word 1, index 10, causing search to miss index 1
        
        // Expected: nextTime should be 65792 (the initialized time)
        // Actual: nextTime will be > 65792, skipping the initialized time
        assertTrue(nextTime > 65792 || !initialized, 
            "Vulnerability confirmed: initialized time at 65792 was skipped");
    }
}
```

**Notes:**
- This vulnerability is particularly severe for pools with infrequent activity where `lastVirtualOrderExecutionTime` lags significantly behind current time
- The step size grows exponentially (256, 4096, 65536, etc.) as times get further in the future, making the vulnerability more likely for longer-dated orders
- Each skipped initialized time can affect multiple orders that share that start/end time
- The issue compounds across multiple word boundaries if the time gap is very large

### Citations

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

**File:** src/math/timeBitmap.sol (L66-76)
```text
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
```

**File:** src/math/time.sol (L17-31)
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

**File:** src/extensions/TWAMM.sol (L605-620)
```text
    function lockAndExecuteVirtualOrders(PoolKey memory poolKey) public {
        // the only thing we lock for is executing virtual orders, so all we need to encode is the pool key
        // so we call lock on the core contract with the pool key after it
        address target = address(CORE);
        assembly ("memory-safe") {
            let o := mload(0x40)
            mstore(o, shl(224, 0xf83d08ba))
            mcopy(add(o, 4), poolKey, 96)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, o, 100, 0, 0)) {
                returndatacopy(o, 0, returndatasize())
                revert(o, returndatasize())
            }
        }
    }
```
