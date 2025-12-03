## Title
PeriodAverage Struct Cannot Hold Maximum Valid Liquidity Values Without Overflow

## Summary
The `PeriodAverage` struct in `PriceFetcher.sol` uses a `uint128` field to store calculated time-weighted average liquidity, but the liquidity calculation can produce values exceeding `type(uint128).max` when pool liquidity is at or near its maximum. This causes an overflow to 0, returning incorrect liquidity data to users and downstream contracts.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `PeriodAverage` struct is designed to hold time-weighted average liquidity and tick values for any valid pool state. The liquidity calculation should accurately reflect the harmonic mean of liquidity over a time period by dividing the time period (left-shifted by 128 bits) by the change in `secondsPerLiquidityCumulative`.

**Actual Logic:** When pool liquidity approaches `type(uint128).max`, the calculation produces a result that exceeds `uint128.max` due to precision loss in integer division. Specifically: [2](#0-1) 

The formula `(time << 128) / delta` can yield values greater than `type(uint128).max` when the denominator (delta of `secondsPerLiquidityCumulative`) is very small due to high liquidity.

**Exploitation Path:**
1. A full-range Oracle pool accumulates liquidity approaching `type(uint128).max` over time through normal user deposits
2. The Oracle extension records snapshots with `secondsPerLiquidityCumulative` accumulating as [3](#0-2) 
3. Any user or contract calls `getAveragesOverPeriod()` for a time period where liquidity was at maximum
4. The calculation overflows: if `L = type(uint128).max` and `T = 1`, then `delta = floor(2^128 / (2^128 - 1)) = 1`, and `calculated = 2^128 / 1 = 2^128`, which exceeds `type(uint128).max` and wraps to 0

**Security Property Broken:** Data integrity - the PriceFetcher is expected to provide accurate historical liquidity data for use in pricing, risk management, and trading decisions. Returning 0 instead of the actual high liquidity value violates this expectation.

## Impact Explanation
- **Affected Assets**: Any protocol or user relying on `PriceFetcher` to obtain accurate time-weighted average liquidity data for Oracle pools
- **Damage Severity**: Users receive incorrect liquidity data (0 or very small values instead of ~`type(uint128).max`), which could lead to:
  - Incorrect price impact calculations
  - Failed liquidity checks in downstream contracts
  - Misinformed trading decisions
  - Potential exploit opportunities if other contracts make security decisions based on reported liquidity
- **User Impact**: All users and contracts querying historical liquidity data for high-liquidity Oracle pools will receive corrupted data

## Likelihood Explanation
- **Attacker Profile**: Not directly exploitable by attackers; this is a data integrity issue that manifests when pools naturally accumulate very high liquidity
- **Preconditions**: 
  - Oracle pool must have liquidity at or very close to `type(uint128).max` (340,282,366,920,938,463,463,374,607,431,768,211,455)
  - Time period queried must be short enough that `secondsPerLiquidityCumulative` delta is minimal
- **Execution Complexity**: No active exploitation required; issue triggers automatically when querying data for high-liquidity periods
- **Frequency**: Unlikely in practice as reaching such extreme liquidity values is rare, but theoretically possible for popular, long-lived pools

## Recommendation

The root cause is that the division result can exceed the target type's capacity. The fix should use a larger type for intermediate calculations and validate the result before downcasting:

```solidity
// In src/lens/PriceFetcher.sol, function getAveragesOverPeriod, around line 100-106:

// CURRENT (vulnerable):
return PeriodAverage(
    uint128(
        (uint160(endTime - startTime) << 128)
            / (secondsPerLiquidityCumulativeEnd - secondsPerLiquidityCumulativeStart)
    ),
    tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(endTime - startTime))
);

// FIXED:
uint256 liquidityCalculated = (uint256(endTime - startTime) << 128)
    / (secondsPerLiquidityCumulativeEnd - secondsPerLiquidityCumulativeStart);
// Cap at uint128.max to prevent overflow while preserving maximum valid value
uint128 liquiditySafe = liquidityCalculated > type(uint128).max 
    ? type(uint128).max 
    : uint128(liquidityCalculated);

return PeriodAverage(
    liquiditySafe,
    tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(endTime - startTime))
);
```

Apply the same fix to lines 153-159 in `getHistoricalPeriodAverages()`.

## Proof of Concept

```solidity
// File: test/Exploit_LiquidityOverflow.t.sol
// Run with: forge test --match-test test_PeriodAverageLiquidityOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/lens/PriceFetcher.sol";
import "../src/extensions/Oracle.sol";
import "./extensions/Oracle.t.sol";

contract Exploit_LiquidityOverflow is BaseOracleTest {
    PriceFetcher pf;
    
    function setUp() public override {
        BaseOracleTest.setUp();
        pf = new PriceFetcher(oracle);
    }
    
    function test_PeriodAverageLiquidityOverflow() public {
        // SETUP: Create Oracle pool with maximum possible liquidity
        address token = address(token0);
        createOraclePool(token, 0);
        oracle.expandCapacity(token, 10);
        
        // Set liquidity to type(uint128).max
        uint128 maxLiquidity = type(uint128).max;
        updateOraclePoolLiquidity(token, maxLiquidity);
        
        uint64 startTime = uint64(block.timestamp);
        
        // Advance time by 1 second to create a period
        advanceTime(1);
        
        uint64 endTime = uint64(block.timestamp);
        
        // EXPLOIT: Query average over the period
        PriceFetcher.PeriodAverage memory avg = pf.getAveragesOverPeriod(
            token,
            NATIVE_TOKEN_ADDRESS,
            startTime,
            endTime
        );
        
        // VERIFY: The returned liquidity is 0 due to overflow, not the expected max value
        console.log("Expected liquidity (approx):", maxLiquidity);
        console.log("Actual returned liquidity:", avg.liquidity);
        
        // The vulnerability: returned liquidity is 0 instead of ~type(uint128).max
        assertTrue(avg.liquidity < maxLiquidity / 2, "Liquidity should have overflowed to near 0");
        assertLt(avg.liquidity, 100, "Vulnerability confirmed: liquidity overflowed");
    }
}
```

## Notes

The vulnerability specifically affects the calculation at [2](#0-1)  and the similar calculation at [4](#0-3) . 

The issue stems from the mathematical relationship where `secondsPerLiquidityCumulative` accumulates as the reciprocal of liquidity over time [5](#0-4) . When liquidity is at maximum, the accumulation rate is minimal, causing the delta to be very small and the inverse calculation to overflow.

While the likelihood of pools reaching such extreme liquidity values is low in practice, the issue represents a clear violation of data integrity that could have cascading effects on any systems relying on accurate historical liquidity data from the Oracle extension.

### Citations

**File:** src/lens/PriceFetcher.sol (L68-73)
```text
    struct PeriodAverage {
        /// @notice Time-weighted average liquidity for the period
        uint128 liquidity;
        /// @notice Time-weighted average tick for the period
        int32 tick;
    }
```

**File:** src/lens/PriceFetcher.sol (L100-106)
```text
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

**File:** src/extensions/Oracle.sol (L121-126)
```text
            Snapshot snapshot = createSnapshot({
                _timestamp: uint32(block.timestamp),
                _secondsPerLiquidityCumulative: last.secondsPerLiquidityCumulative()
                    + uint160(FixedPointMathLib.rawDiv(uint256(timePassed) << 128, nonZeroLiquidity)),
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });
```
