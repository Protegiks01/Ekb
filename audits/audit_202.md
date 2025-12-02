# NoVulnerability found for this question.

After conducting a comprehensive analysis of the `logicalIndexToStorageIndex` function and its usage throughout the Oracle extension, I found **no exploitable vulnerability** related to incorrect index calculation or wrong snapshot access.

## Analysis Summary

The `logicalIndexToStorageIndex` function implements a mathematically correct circular buffer index mapping using the formula `(index + 1 + logicalIndex) % count`. [1](#0-0) 

**Key Safety Mechanisms Verified:**

1. **Assumption Enforcement**: The function assumes `index < count` and `logicalIndex < count`. These invariants are strictly maintained by the circular buffer logic where `index = (index + 1) % count` ensures index never exceeds count. [2](#0-1) 

2. **Count Initialization**: Count is initialized to 1 (never 0) when a pool is first created, preventing division by zero in the modulo operation. [3](#0-2) 

3. **Bounds Checking at Call Sites**: All call sites in `searchRangeForPrevious` maintain `mid < count` through binary search bounds, and the function properly reverts if no valid snapshot exists. [4](#0-3) 

4. **Safe Extrapolation Logic**: When accessing the next snapshot in `extrapolateSnapshotInternal`, the code only calls `logicalIndexToStorageIndex(c.index(), c.count(), logicalIndex + 1)` in the else branch where `logicalIndex < c.count() - 1` is guaranteed, ensuring `logicalIndex + 1 < count`. [5](#0-4) 

5. **Zero Count Handling**: The `OracleLib.getEarliestSnapshotTimestamp` function explicitly checks for `count == 0` and returns a sentinel value, preventing invalid access. [6](#0-5) 

6. **Test Coverage**: The test suite includes `test_snapshots_circularWriteAtCapacity` which verifies correct behavior when the circular buffer wraps around and overwrites old snapshots. [7](#0-6) 

**Notes:**
- The circular buffer implementation is standard and correct
- No integer overflow is possible (sum is at most 2×count+1, well within uint256 range)
- State consistency is maintained through atomic Solidity execution
- All edge cases (wraparound, capacity expansion, empty buffer) are properly handled

### Citations

**File:** src/extensions/Oracle.sol (L46-51)
```text
function logicalIndexToStorageIndex(uint256 index, uint256 count, uint256 logicalIndex) pure returns (uint256) {
    // We assume index < count and logicalIndex < count
    unchecked {
        return (index + 1 + logicalIndex) % count;
    }
}
```

**File:** src/extensions/Oracle.sol (L128-135)
```text
            uint32 count = c.count();
            uint32 capacity = c.capacity();

            bool isLastIndex = index == count - 1;
            bool incrementCount = isLastIndex && capacity > count;

            if (incrementCount) count++;
            index = (index + 1) % count;
```

**File:** src/extensions/Oracle.sol (L170-175)
```text
        c = createCounts({
            _index: 0,
            _count: 1,
            _capacity: uint32(FixedPointMathLib.max(1, c.capacity())),
            _lastTimestamp: lastTimestamp
        });
```

**File:** src/extensions/Oracle.sol (L265-277)
```text
            while (left < right) {
                uint256 mid = (left + right + 1) >> 1;
                uint256 storageIndex = logicalIndexToStorageIndex(c.index(), c.count(), mid);
                Snapshot midSnapshot;
                assembly ("memory-safe") {
                    midSnapshot := sload(or(shl(32, token), storageIndex))
                }
                if (current - midSnapshot.timestamp() >= targetDiff) {
                    left = mid;
                } else {
                    right = mid - 1;
                }
            }
```

**File:** src/extensions/Oracle.sol (L327-340)
```text
                if (logicalIndex == c.count() - 1) {
                    // Use current pool state.
                    PoolId poolId = getPoolKey(token).toPoolId();
                    PoolState state = CORE.poolState(poolId);

                    tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
                    secondsPerLiquidityCumulative += uint160(
                        FixedPointMathLib.rawDiv(
                            uint256(timePassed) << 128, FixedPointMathLib.max(1, state.liquidity())
                        )
                    );
                } else {
                    // Use the next snapshot.
                    uint256 logicalIndexNext = logicalIndexToStorageIndex(c.index(), c.count(), logicalIndex + 1);
```

**File:** src/libraries/OracleLib.sol (L38-41)
```text
            if (c.count() == 0) {
                // if there are no snapshots, return a timestamp that will never be considered valid
                return type(uint256).max;
            }
```

**File:** test/extensions/Oracle.t.sol (L444-475)
```text
    function test_snapshots_circularWriteAtCapacity(uint256 startTime) public {
        startTime = bound(startTime, 0, type(uint256).max - type(uint32).max);
        vm.warp(startTime);

        PoolKey memory pk = createOraclePool(address(token1), 2000);
        // writes 0
        advanceTime(2);
        movePrice(pk, -500);
        oracle.expandCapacity(address(token1), 3);
        // writes 1
        advanceTime(3);
        movePrice(pk, 700);
        // writes 2
        advanceTime(6);
        movePrice(pk, -5000);
        // writes 0
        advanceTime(4);
        movePrice(pk, 0);

        Counts c = oracle.counts(address(token1));
        assertEq(c.index(), 0, "index");
        assertEq(c.count(), 3, "count");
        assertEq(c.capacity(), 3, "capacity");
        assertEq(c.lastTimestamp(), uint32(startTime + 2 + 3 + 6 + 4));

        Snapshot snapshot = oracle.snapshots(address(token1), 0);
        unchecked {
            assertEq(snapshot.timestamp(), uint32(startTime) + 4 + 6 + 3 + 2);
        }
        assertEq(snapshot.secondsPerLiquidityCumulative(), uint256(4 + 6 + 3 + 2) << 128);
        assertEq(snapshot.tickCumulative(), (2000 * 2) + (-500 * 3) + (700 * 6) + (-5000 * 4));
    }
```
