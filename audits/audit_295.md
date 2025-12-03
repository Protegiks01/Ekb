# NoVulnerability found for this question.

After thorough investigation of the `IOracle.extrapolateSnapshot` function and all related code paths, I found that the implementation correctly handles the case where a pool has no observations.

## Analysis Summary

**Key Protection Mechanism:**

When `extrapolateSnapshot` is called on a token with no observations, the function flow is:

1. Reads `Counts c` from storage at line 374 [1](#0-0) 

2. Calls `searchRangeForPrevious(c, token, atTime, 0, c.count())` at line 376 [2](#0-1) 

3. The `searchRangeForPrevious` function immediately checks if the range is empty at line 256: `if (logicalMin >= logicalMaxExclusive)` which becomes `if (0 >= 0)` when `count = 0` [3](#0-2) 

4. **Reverts with `NoPreviousSnapshotExists(token, time)` before any storage reads occur**

**Additional Safeguards:**

- Pool initialization via `beforeInitializePool` always creates the first snapshot with `count = 1`, so even pools with no swaps have at least one observation [4](#0-3) 

- The `OracleLib.getEarliestSnapshotTimestamp` helper function returns `type(uint256).max` when `count = 0`, which dependent protocols like `PriceFetcher` use to validate data availability before calling `extrapolateSnapshot` [5](#0-4) 

- Test coverage confirms the revert behavior when querying before the earliest available snapshot [6](#0-5) 

**Storage Slot 0 Analysis:**

The Oracle uses custom storage with snapshots at `(token << 32) | i`. For slot 0 to be accessed, `token` would need to be `address(0)`. However, Oracle pools have `token0 = NATIVE_TOKEN_ADDRESS = address(0)` [7](#0-6)  and Oracle stores data keyed by `token1` (not `token0`), which must be non-zero per pool ordering rules.

**Conclusion:**

The function design prevents accessing uninitialized storage through proper validation that occurs before any storage reads when no observations exist. The security concern outlined in the question does not materialize into an exploitable vulnerability.

### Citations

**File:** src/extensions/Oracle.sol (L170-186)
```text
        c = createCounts({
            _index: 0,
            _count: 1,
            _capacity: uint32(FixedPointMathLib.max(1, c.capacity())),
            _lastTimestamp: lastTimestamp
        });

        Snapshot snapshot =
            createSnapshot({_timestamp: lastTimestamp, _secondsPerLiquidityCumulative: 0, _tickCumulative: 0});

        assembly ("memory-safe") {
            sstore(token, c)
            sstore(shl(32, token), snapshot)
        }

        _emitSnapshotEvent(token, snapshot);
    }
```

**File:** src/extensions/Oracle.sol (L256-258)
```text
            if (logicalMin >= logicalMaxExclusive) {
                revert NoPreviousSnapshotExists(token, time);
            }
```

**File:** src/extensions/Oracle.sol (L372-375)
```text
        Counts c;
        assembly ("memory-safe") {
            c := sload(token)
        }
```

**File:** src/extensions/Oracle.sol (L376-376)
```text
        (uint256 logicalIndex, Snapshot snapshot) = searchRangeForPrevious(c, token, atTime, 0, c.count());
```

**File:** src/libraries/OracleLib.sol (L38-41)
```text
            if (c.count() == 0) {
                // if there are no snapshots, return a timestamp that will never be considered valid
                return type(uint256).max;
            }
```

**File:** test/extensions/Oracle.t.sol (L499-510)
```text
        vm.expectRevert(abi.encodeWithSelector(IOracle.NoPreviousSnapshotExists.selector, address(token1), startTime));
        oracle.extrapolateSnapshot(address(token1), startTime);

        vm.expectRevert(
            abi.encodeWithSelector(IOracle.NoPreviousSnapshotExists.selector, address(token1), startTime + 2)
        );
        oracle.extrapolateSnapshot(address(token1), startTime + 2);

        vm.expectRevert(
            abi.encodeWithSelector(IOracle.NoPreviousSnapshotExists.selector, address(token1), startTime + 4)
        );
        oracle.extrapolateSnapshot(address(token1), startTime + 4);
```

**File:** src/math/constants.sol (L26-26)
```text
address constant NATIVE_TOKEN_ADDRESS = address(0);
```
