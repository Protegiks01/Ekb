## Title
uint32 Timestamp Wraparound Bypasses Boundary Check in findPreviousSnapshot Leading to Invalid Oracle Data

## Summary
The `searchRangeForPrevious` function in `Oracle.sol` uses uint32 arithmetic to compare timestamps in an `unchecked` block. When snapshots are older than 2^32 seconds (~136 years) relative to the current block timestamp, uint32 wraparound causes the final boundary check to incorrectly pass, allowing the function to return snapshot data at index 0 even when the requested time is chronologically before the first snapshot exists. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/extensions/Oracle.sol` - `searchRangeForPrevious` function (lines 248-288), called by `findPreviousSnapshot` (lines 291-304) [2](#0-1) 

**Intended Logic:** The function should find the snapshot with the greatest timestamp ≤ the given time parameter. If no such snapshot exists (i.e., the requested time is before the first snapshot), it should revert with `NoPreviousSnapshotExists`. [3](#0-2) 

The code documents an assumption: "We make the assumption that all snapshots for the token were written within (2**32 - 1) seconds of the current block timestamp" [4](#0-3) 

**Actual Logic:** When this assumption is violated (snapshots older than 2^32 seconds exist), the uint32 arithmetic in the unchecked block causes wraparound: [5](#0-4) 

The final boundary check at line 283 fails to catch invalid queries due to uint32 modular arithmetic: [6](#0-5) 

**Exploitation Path:**

1. **Setup**: Pool initialized near uint32 overflow boundary (e.g., `block.timestamp = 2^32 - 100 = 4,294,967,196`). First snapshot created with `uint32 timestamp = 4,294,967,196`.

2. **Time Advances**: Current time moves past uint32 wraparound: `block.timestamp = 2^32 + 500 = 4,294,967,796` (uint32 = 500).

3. **Invalid Query**: Attacker (or any user/contract) calls `findPreviousSnapshot(token, 200)` - requesting data from timestamp 200 (early 1970s), which is chronologically BEFORE the first snapshot at time ~4.29 billion.

4. **Bypass**: 
   - Line 296 check passes: `200 <= 4,294,967,796` ✓
   - Line 260-261: `current = 500`, `targetDiff = 500 - 200 = 300`
   - Line 272 binary search: `current - snapshot.timestamp()` = `500 - 4,294,967,196` wraps to `600` in uint32, `600 >= 300` ✓
   - Line 283 boundary check: `600 < 300` = FALSE, does not revert
   - Function returns snapshot at index 0 with invalid data for the requested time

5. **Impact**: Downstream contracts like `ERC7726` that consume this oracle data will compute incorrect TWAPs, leading to price manipulation. [7](#0-6) 

**Security Property Broken:** The oracle's guarantee that queries before the first snapshot timestamp should revert is violated, allowing invalid historical data to be returned.

## Impact Explanation

- **Affected Assets**: All tokens with oracle pools that have existed across the uint32 boundary (post year 2106), and any protocols consuming this oracle data for pricing, liquidations, or trading decisions.

- **Damage Severity**: Users of oracle data (DEX aggregators, lending protocols, derivative contracts) receive incorrect TWAP values when querying historical prices. This can lead to:
  - Mispriced trades in protocols using Ekubo price feeds
  - Incorrect liquidation thresholds if oracle data is used for collateral valuation
  - Manipulated price references for derivative contracts

- **User Impact**: Any protocol or user querying oracle data for timestamps that fall before the first snapshot but after uint32 wraparound will receive invalid data instead of a revert, potentially making incorrect financial decisions based on this data.

## Likelihood Explanation

- **Attacker Profile**: Any user, contract, or protocol integrating with Ekubo Oracle. No special privileges required - this is a view function accessible to anyone.

- **Preconditions**: 
  1. Current `block.timestamp` must have crossed the uint32 boundary (after Feb 7, 2106)
  2. Oracle pool must have snapshots from before the uint32 overflow
  3. Query must be for a time that appears "recent" in uint32 space but is actually chronologically before the first snapshot

- **Execution Complexity**: Single view function call - extremely simple to trigger once preconditions are met.

- **Frequency**: While the precondition requires time after year 2106, the vulnerability is **permanent** once that threshold is crossed. Every query for early timestamps will incorrectly return data instead of reverting. Given Ethereum's long-term viability goals, this is a real concern for protocol longevity.

## Recommendation

Replace the uint32 modular arithmetic approach with proper timestamp reconstruction that matches `OracleLib.getEarliestSnapshotTimestamp`'s approach: [8](#0-7) 

The fix should reconstruct full uint256 timestamps before comparison:

```solidity
// In src/extensions/Oracle.sol, function searchRangeForPrevious, lines 260-286:

// CURRENT (vulnerable):
// Uses uint32 arithmetic that breaks with old snapshots
uint32 current = uint32(block.timestamp);
uint32 targetDiff = current - uint32(time);
// ... binary search using targetDiff ...
if (current - snapshot.timestamp() < targetDiff) {
    revert NoPreviousSnapshotExists(token, time);
}

// FIXED:
// Reconstruct full timestamp for first snapshot to validate it's not too old
Snapshot firstSnapshot;
uint256 firstStorageIndex = logicalIndexToStorageIndex(c.index(), c.count(), 0);
assembly ("memory-safe") {
    firstSnapshot := sload(or(shl(32, token), firstStorageIndex))
}
// Reconstruct full timestamp: block.timestamp - (uint32(block.timestamp) - snapshot.timestamp())
uint256 firstFullTimestamp = block.timestamp - (uint32(block.timestamp) - firstSnapshot.timestamp());

// Validate the requested time is not before the first snapshot
if (time < firstFullTimestamp) {
    revert NoPreviousSnapshotExists(token, time);
}

// Now safe to use uint32 arithmetic since we know snapshots are within valid range
uint32 current = uint32(block.timestamp);
uint32 targetDiff = current - uint32(time);
// ... rest of binary search ...
```

Alternative: Add explicit validation that no snapshot is older than 2^32 seconds during snapshot insertion, or document this as a known limitation with appropriate access controls on old pools.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32TimestampWraparound.t.sol
// Run with: forge test --match-test test_Uint32TimestampWraparound -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/Oracle.sol";
import "../src/interfaces/extensions/IOracle.sol";
import "./extensions/Oracle.t.sol";

contract Exploit_Uint32TimestampWraparound is BaseOracleTest {
    function test_Uint32TimestampWraparound() public {
        // SETUP: Create pool near uint32 boundary
        uint256 initTime = uint256(type(uint32).max) - 100; // Near uint32 max
        vm.warp(initTime);
        
        address token = address(token1);
        oracle.expandCapacity(token, 10);
        PoolKey memory poolKey = createOraclePool(token, 693147);
        updateOraclePoolLiquidity(token, 100_000);
        
        // First snapshot created at time ~4,294,967,196 (uint32 = type(uint32).max - 100)
        
        // TIME PASSES: Cross uint32 boundary
        uint256 currentTime = uint256(type(uint32).max) + 500; // After wraparound
        vm.warp(currentTime);
        
        // EXPLOIT: Query for time 200 (early 1970s) - chronologically BEFORE first snapshot
        uint256 attackTime = 200;
        
        // Expected behavior: Should revert with NoPreviousSnapshotExists
        // Actual behavior: Returns snapshot at index 0 due to uint32 wraparound
        
        // This should revert but doesn't due to the vulnerability
        (uint256 count, uint256 logicalIndex, Snapshot snapshot) = 
            oracle.findPreviousSnapshot(token, attackTime);
        
        // VERIFY: Function incorrectly returned data instead of reverting
        assertEq(logicalIndex, 0, "Vulnerability confirmed: returned index 0");
        assertEq(snapshot.timestamp(), uint32(initTime), "Returned first snapshot");
        
        // The query time (200) is chronologically before the first snapshot (initTime),
        // but uint32 arithmetic made it appear valid. This violates the oracle's guarantee.
        assertTrue(attackTime < initTime, "Attack time is before first snapshot");
        console.log("Vulnerability: Query for time %s returned snapshot from time %s", attackTime, initTime);
    }
}
```

## Notes

This vulnerability demonstrates a critical edge case in timestamp handling for long-lived protocols. While the precondition requires operation past year 2106, Ethereum and Ekubo are designed for indefinite operation. The test suite explicitly avoids this scenario by bounding timestamps: [9](#0-8) 

The `OracleLib` correctly handles timestamp reconstruction but `searchRangeForPrevious` does not use the same approach, creating an inconsistency in how the protocol handles old snapshots. This is a boundary condition vulnerability that violates the documented behavior of the `NoPreviousSnapshotExists` error condition.

### Citations

**File:** src/extensions/Oracle.sol (L240-240)
```text
    ///      We make the assumption that all snapshots for the token were written within (2**32 - 1) seconds of the current block timestamp
```

**File:** src/extensions/Oracle.sol (L248-288)
```text
    function searchRangeForPrevious(
        Counts c,
        address token,
        uint256 time,
        uint256 logicalMin,
        uint256 logicalMaxExclusive
    ) private view returns (uint256 logicalIndex, Snapshot snapshot) {
        unchecked {
            if (logicalMin >= logicalMaxExclusive) {
                revert NoPreviousSnapshotExists(token, time);
            }

            uint32 current = uint32(block.timestamp);
            uint32 targetDiff = current - uint32(time);

            uint256 left = logicalMin;
            uint256 right = logicalMaxExclusive - 1;
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

            uint256 resultIndex = logicalIndexToStorageIndex(c.index(), c.count(), left);
            assembly ("memory-safe") {
                snapshot := sload(or(shl(32, token), resultIndex))
            }
            if (current - snapshot.timestamp() < targetDiff) {
                revert NoPreviousSnapshotExists(token, time);
            }
            return (left, snapshot);
        }
    }
```

**File:** src/extensions/Oracle.sol (L291-304)
```text
    function findPreviousSnapshot(address token, uint256 time)
        public
        view
        returns (uint256 count, uint256 logicalIndex, Snapshot snapshot)
    {
        if (time > block.timestamp) revert FutureTime();

        Counts c;
        assembly ("memory-safe") {
            c := sload(token)
        }
        count = c.count();
        (logicalIndex, snapshot) = searchRangeForPrevious(c, token, time, 0, count);
    }
```

**File:** src/interfaces/extensions/IOracle.sol (L52-61)
```text
    /// @notice Finds the snapshot with the greatest timestamp ≤ the given time
    /// @param token The token address
    /// @param time The target timestamp
    /// @return count The total number of snapshots for the token
    /// @return logicalIndex The logical index of the found snapshot
    /// @return snapshot The snapshot data
    function findPreviousSnapshot(address token, uint256 time)
        external
        view
        returns (uint256 count, uint256 logicalIndex, Snapshot snapshot);
```

**File:** src/lens/ERC7726.sol (L35-60)
```text
/// @title Ekubo ERC-7726 Oracle Implementation
/// @notice Implements the ERC-7726 standard oracle interface using time-weighted average prices from Ekubo Protocol
/// @dev This contract provides manipulation-resistant price quotes by leveraging Ekubo's Oracle extension
///      which records price and liquidity data into accumulators. The oracle supports direct queries for
///      tokens paired with ETH, and cross-pair calculations for other token pairs.
/// @author Ekubo Protocol
contract ERC7726 is IERC7726 {
    /// @notice Thrown when an invalid TWAP duration is provided
    error InvalidTwapDuration();

    /// @notice The Ekubo Oracle extension contract used for price data
    IOracle public immutable ORACLE;

    /// @notice The address of the token to represent ETH, or NATIVE_TOKEN_ADDRESS if ETH is the native token on the chain
    address public immutable ETH_PROXY_TOKEN;

    /// @notice The ERC-20 token used as a proxy to represent USD in price calculations
    address public immutable USD_PROXY_TOKEN;

    /// @notice The ERC-20 token used as a proxy to represent BTC in price calculations
    /// @dev Since the oracle only tracks token pairs with ETH, we use a BTC-pegged token (e.g., WBTC) as a proxy
    address public immutable BTC_PROXY_TOKEN;

    /// @notice The time window in seconds over which to calculate time-weighted average prices
    /// @dev Longer durations provide more manipulation resistance but less price responsiveness
    uint32 public immutable TWAP_DURATION;
```

**File:** src/libraries/OracleLib.sol (L33-46)
```text
    function getEarliestSnapshotTimestamp(IOracle oracle, address token) internal view returns (uint256) {
        unchecked {
            if (token == NATIVE_TOKEN_ADDRESS) return 0;

            Counts c = counts(oracle, token);
            if (c.count() == 0) {
                // if there are no snapshots, return a timestamp that will never be considered valid
                return type(uint256).max;
            }

            Snapshot snapshot = snapshots(oracle, token, logicalIndexToStorageIndex(c.index(), c.count(), 0));
            return block.timestamp - (uint32(block.timestamp) - snapshot.timestamp());
        }
    }
```

**File:** test/extensions/Oracle.t.sol (L590-591)
```text
    function test_findPreviousSnapshot(uint256 startTime) public {
        startTime = bound(startTime, 5, type(uint256).max - type(uint32).max);
```
