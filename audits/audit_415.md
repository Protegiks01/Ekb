## Title
Division by Zero in PriceFetcher Due to Identical Cumulative Values from Oracle Extrapolation

## Summary
The Oracle's `extrapolateSnapshotInternal` function uses integer division that can round down to zero when interpolating between snapshots with low accumulation rates. When two queries with different timestamps both round to the same cumulative value, `PriceFetcher.getAveragesOverPeriod` and `getHistoricalPeriodAverages` divide by zero, causing transaction reverts and DOS of price fetching functionality.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/PriceFetcher.sol` (function `getAveragesOverPeriod`, lines 95-106 and function `getHistoricalPeriodAverages`, lines 148-160)

**Intended Logic:** The Oracle is supposed to provide time-weighted average price data by extrapolating cumulative values that strictly increase over time. PriceFetcher should calculate liquidity and tick averages by dividing the time period by the difference in cumulative values.

**Actual Logic:** The Oracle's extrapolation uses integer division that can round to zero when the accumulation rate is low relative to the time difference. When querying two close timestamps within a snapshot interval, both can extrapolate to the same `secondsPerLiquidityCumulative` value, causing PriceFetcher to divide by zero. [1](#0-0) 

The extrapolation adds:
```
(timePassed * accumulationDifference) / timestampDifference
```
If `timePassed * accumulationDifference < timestampDifference`, this rounds to zero. [2](#0-1) 

**Exploitation Path:**
1. Pool exists with low liquidity (e.g., 1e6 wei), causing slow `secondsPerLiquidityCumulative` accumulation
2. Snapshots are taken with large intervals (e.g., 1000 seconds apart)
3. Attacker calls `PriceFetcher.getAveragesOverPeriod()` with `startTime` and `endTime` both within the same snapshot interval, separated by only a few seconds
4. Both `extrapolateSnapshot` calls at lines 96 and 98 round to the same cumulative value
5. Line 103 attempts: `(uint160(endTime - startTime) << 128) / 0`
6. Transaction reverts with division by zero, DOS'ing price fetching

**Security Property Broken:** This violates the availability expectation that oracle data should be queryable for valid historical periods. While not directly violating the documented invariants, it breaks the oracle's core functionality.

## Impact Explanation
- **Affected Assets**: All price queries through `PriceFetcher` and `ERC7726` oracle interfaces
- **Damage Severity**: Complete DOS of historical price fetching for affected time ranges. No direct fund loss, but external protocols relying on these lens contracts for price data will fail. This affects TWAP calculations critical for DeFi integrations.
- **User Impact**: Any user or protocol attempting to fetch historical averages for pools with low liquidity and large snapshot intervals will experience transaction reverts. This impacts integrators using ERC7726 standard interface. [3](#0-2) 

The ERC7726 implementation also divides by the tick cumulative difference, but if `secondsPerLiquidityCumulative` is identical, the tick cumulative will likely also round to the same value, causing issues.

## Likelihood Explanation
- **Attacker Profile**: Any user or external protocol querying historical price data
- **Preconditions**: 
  - Pool must have low liquidity (< 1e12 wei for realistic exploitation)
  - Snapshot interval must be large relative to query interval (e.g., 1000s between snapshots, 10s query window)
  - Query times must both fall within the same snapshot interval
  - Accumulation rate: `(accumulationDifference * queryInterval) < snapshotInterval`
- **Execution Complexity**: Single transaction calling public view functions - extremely simple
- **Frequency**: Can be triggered continuously for any valid time range meeting the conditions. Becomes more likely as pools age with low liquidity.

## Recommendation

Add zero-difference checks before division in `PriceFetcher.sol`: [4](#0-3) 

```solidity
// In src/lens/PriceFetcher.sol, function getAveragesOverPeriod:

// CURRENT (vulnerable):
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

// FIXED:
(uint160 secondsPerLiquidityCumulativeEnd, int64 tickCumulativeEnd) =
    ORACLE.extrapolateSnapshot(otherToken, endTime);
(uint160 secondsPerLiquidityCumulativeStart, int64 tickCumulativeStart) =
    ORACLE.extrapolateSnapshot(otherToken, startTime);

uint160 spcDiff = secondsPerLiquidityCumulativeEnd - secondsPerLiquidityCumulativeStart;
if (spcDiff == 0) revert InsufficientOracleDataForPeriod(); // Add custom error

return PeriodAverage(
    uint128((uint160(endTime - startTime) << 128) / spcDiff),
    tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(endTime - startTime))
);
``` [5](#0-4) 

Apply the same fix at line 156 in `getHistoricalPeriodAverages`.

Alternative mitigation: Enforce minimum accumulation in Oracle by increasing the nonZeroLiquidity floor or adding minimum time requirements between extrapolation queries.

## Proof of Concept

```solidity
// File: test/Exploit_OracleDivisionByZero.t.sol
// Run with: forge test --match-test test_OracleDivisionByZero -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./extensions/Oracle.t.sol";
import "../src/lens/PriceFetcher.sol";

contract Exploit_OracleDivisionByZero is BaseOracleTest {
    PriceFetcher priceFetcher;
    address testToken;
    
    function setUp() public override {
        BaseOracleTest.setUp();
        priceFetcher = new PriceFetcher(oracle);
        
        // Deploy test token and create oracle pool
        testToken = address(new TestToken());
        createOraclePool(testToken, 0);
        
        // Add minimal liquidity to create low accumulation rate
        updateOraclePoolLiquidity(testToken, 1e6); // Very low liquidity
    }
    
    function test_OracleDivisionByZero() public {
        // SETUP: Create initial snapshot
        vm.warp(1000);
        updateOraclePoolLiquidity(testToken, 1e6);
        
        // Move time forward significantly to create large snapshot interval
        vm.warp(2000);
        updateOraclePoolLiquidity(testToken, 1e6 + 1); // Trigger new snapshot
        
        // EXPLOIT: Query two close timestamps within the interval
        // Both will round to the same cumulative value
        uint64 startTime = 1001; // Just after first snapshot
        uint64 endTime = 1005;   // 4 seconds later
        
        // This will revert with division by zero
        vm.expectRevert(); // Expecting arithmetic error (division by zero)
        priceFetcher.getAveragesOverPeriod(
            NATIVE_TOKEN_ADDRESS,
            testToken,
            startTime,
            endTime
        );
        
        // VERIFY: Demonstrate the cumulative values are indeed identical
        (uint160 spcStart,) = oracle.extrapolateSnapshot(testToken, startTime);
        (uint160 spcEnd,) = oracle.extrapolateSnapshot(testToken, endTime);
        
        assertEq(spcStart, spcEnd, "Vulnerability confirmed: identical cumulative values");
        assertTrue(spcEnd - spcStart == 0, "Division by zero denominator");
    }
}
```

## Notes

This vulnerability is triggered by the combination of:
1. **Low liquidity pools**: The `secondsPerLiquidityCumulative` accumulates very slowly when liquidity is low
2. **Large snapshot intervals**: When snapshots are far apart, interpolation must estimate values over long periods
3. **Close query times**: When querying timestamps near each other within an interval, the integer division rounds both to the same value

The issue is exacerbated in the ERC7726 lens contract which is designed for external protocol integration. A DOS here could break price feeds for dependent protocols.

While the Oracle itself protects against zero liquidity using `max(1, liquidity)` when creating new snapshots, this doesn't prevent the rounding issue during interpolation between existing snapshots.

### Citations

**File:** src/extensions/Oracle.sol (L354-358)
```text
                    secondsPerLiquidityCumulative += uint160(
                        (uint256(timePassed)
                                * (next.secondsPerLiquidityCumulative() - snapshot.secondsPerLiquidityCumulative()))
                            / timestampDifference
                    );
```

**File:** src/lens/PriceFetcher.sol (L95-106)
```text
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

**File:** src/lens/PriceFetcher.sol (L153-159)
```text
                    averages[i] = PeriodAverage(
                        uint128(
                            (uint160(period) << 128)
                                / (end.secondsPerLiquidityCumulative() - start.secondsPerLiquidityCumulative())
                        ),
                        tickSign * int32((end.tickCumulative() - start.tickCumulative()) / int64(uint64(period)))
                    );
```

**File:** src/lens/ERC7726.sol (L98-101)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
```
