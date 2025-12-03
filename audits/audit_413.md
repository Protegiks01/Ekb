## Title
Oracle Price Query DoS When Paired Token Lacks Snapshot Data

## Summary
The Ekubo Oracle system fails to gracefully handle cross-pair price queries when one token has oracle data but the paired token doesn't. Functions in `ERC7726.sol` and `PriceFetcher.sol` revert with `NoPreviousSnapshotExists` instead of checking data availability first, causing Denial of Service for external integrations attempting to query prices for token pairs where one token lacks historical snapshots.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- `src/lens/ERC7726.sol` (function `getAverageTick`, lines 91-112)
- `src/lens/PriceFetcher.sol` (function `getAveragesOverPeriod`, lines 82-119)
- `src/lens/PriceFetcher.sol` (function `getHistoricalPeriodAverages`, lines 129-184)

**Intended Logic:** 
The Oracle extension is designed to provide time-weighted average prices for token pairs. For pairs not directly tracked (both tokens paired with native token separately), the system should compute cross-pair prices using the native token as an intermediary. The documentation states the Oracle "enables a separate contract to compute a manipulation resistant average price." [1](#0-0) 

**Actual Logic:** 
When computing cross-pair prices, the system recursively calls itself to fetch oracle data for both tokens paired with the native token. However, it doesn't verify that oracle data exists before attempting to extrapolate snapshots. If one token lacks snapshots, the call chain reverts.

**Exploitation Path:**

1. **Setup**: TokenA has an oracle pool initialized with snapshots, TokenB does not (either no pool exists or pool exists but no snapshots have been recorded)

2. **Trigger**: External protocol calls `ERC7726.getQuote(amount, tokenA, tokenB)` where neither token is the native token [2](#0-1) 

3. **Recursive Call**: The function calls `getAverageTick(tokenA, tokenB)` which attempts to fetch oracle data for both tokens: [3](#0-2) 

4. **Revert**: When `extrapolateSnapshot(tokenB, timestamp)` is called in the Oracle contract, it invokes `searchRangeForPrevious` with `c.count() == 0`, causing the function to revert: [4](#0-3) 

**Security Property Broken:** 
This violates the **Extension Isolation** principle. The Oracle extension should not cause complete failure of price queries when data is partially available. External integrations expect oracle systems to either return valid data or indicate unavailability gracefully, not revert unexpectedly.

## Impact Explanation

- **Affected Assets**: No direct asset loss, but affects all external protocols integrating with the Ekubo price oracle system
- **Damage Severity**: 
  - ERC-7726 standard implementation becomes unreliable for cross-pair queries
  - DeFi protocols using PriceFetcher for price feeds experience unexpected transaction failures
  - Automated systems (arbitrage bots, liquidation engines) that rely on these price feeds will fail
  - Users cannot obtain price quotes for token pairs where one token lacks oracle history
- **User Impact**: Any user or protocol attempting to query prices for token pairs where one token has oracle data but the other doesn't will experience transaction reverts. This affects:
  - DEX aggregators integrating Ekubo prices
  - Lending protocols using Ekubo for price feeds
  - Portfolio trackers and analytics tools
  - Any smart contract calling `getQuote()` or `getAveragesOverPeriod()`

## Likelihood Explanation

- **Attacker Profile**: Not an intentional attack - this is a design flaw triggerable by any user or protocol attempting legitimate price queries
- **Preconditions**: 
  - TokenA must have oracle data (pool initialized with native token, snapshots recorded)
  - TokenB must lack oracle data (either no pool exists or count == 0)
  - Query involves both tokens in a cross-pair calculation
- **Execution Complexity**: Single view function call - extremely easy to trigger
- **Frequency**: Continuous - affects all cross-pair queries where one token lacks data. New tokens added to the system will commonly lack oracle history initially, making this a frequent occurrence

## Recommendation

Add data availability checks before attempting to extrapolate snapshots, similar to how `getAvailableHistoricalPeriodAverages` handles this: [5](#0-4) 

```solidity
// In src/lens/ERC7726.sol, function getAverageTick, before line 98:

// CURRENT (vulnerable):
function getAverageTick(address baseToken, address quoteToken) private view returns (int32 tick) {
    unchecked {
        bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
        if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
            (int32 tickSign, address otherToken) =
                baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

            (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
            // ... reverts if otherToken has no snapshots

// FIXED:
function getAverageTick(address baseToken, address quoteToken) private view returns (int32 tick) {
    unchecked {
        bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
        if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
            (int32 tickSign, address otherToken) =
                baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

            // Check if sufficient oracle data exists
            uint32 maxPeriod = OracleLib.getMaximumObservationPeriod(ORACLE, otherToken);
            if (maxPeriod < TWAP_DURATION) {
                revert InsufficientOracleData(otherToken, maxPeriod, TWAP_DURATION);
            }

            (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
            // ... now safe to proceed
```

Similarly for `PriceFetcher.sol`:

```solidity
// In src/lens/PriceFetcher.sol, function getAveragesOverPeriod, after line 87:

// CURRENT (vulnerable):
if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
    (int32 tickSign, address otherToken) =
        baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

    (uint160 secondsPerLiquidityCumulativeEnd, int64 tickCumulativeEnd) =
        ORACLE.extrapolateSnapshot(otherToken, endTime);
    // ... reverts if otherToken has no data

// FIXED:
if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
    (int32 tickSign, address otherToken) =
        baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

    // Check data availability using OracleLib
    uint256 earliestTime = OracleLib.getEarliestSnapshotTimestamp(ORACLE, otherToken);
    if (earliestTime >= startTime) {
        revert InsufficientHistoricalData(otherToken, earliestTime, startTime);
    }

    (uint160 secondsPerLiquidityCumulativeEnd, int64 tickCumulativeEnd) =
        ORACLE.extrapolateSnapshot(otherToken, endTime);
    // ... now safe
```

## Proof of Concept

```solidity
// File: test/Exploit_OracleDoS.t.sol
// Run with: forge test --match-test test_OracleDoS_MissingTokenData -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../test/extensions/Oracle.t.sol";
import {ERC7726} from "../src/lens/ERC7726.sol";
import {PriceFetcher} from "../src/lens/PriceFetcher.sol";
import {TestToken} from "../test/TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {IOracle} from "../src/interfaces/extensions/IOracle.sol";

contract Exploit_OracleDoS is BaseOracleTest {
    ERC7726 internal erc;
    PriceFetcher internal fetcher;
    TestToken internal tokenA; // Has oracle data
    TestToken internal tokenB; // NO oracle data
    
    function setUp() public override {
        BaseOracleTest.setUp();
        
        // Create two tokens
        tokenA = new TestToken(address(this));
        tokenB = new TestToken(address(this));
        
        // Deploy lens contracts
        erc = new ERC7726(oracle, address(0), address(0), NATIVE_TOKEN_ADDRESS, 60);
        fetcher = new PriceFetcher(oracle);
        
        // Initialize oracle pool for tokenA and create snapshots
        oracle.expandCapacity(address(tokenA), 10);
        createOraclePool(address(tokenA), 0);
        updateOraclePoolLiquidity(address(tokenA), 100_000);
        
        // Advance time to create oracle history
        advanceTime(120);
        
        // TokenB: NO pool initialization, NO snapshots
        // This simulates a newly listed token or one without oracle tracking
    }
    
    function test_OracleDoS_ERC7726_CrossPair() public {
        // SETUP: tokenA has oracle data, tokenB does not
        // Both tokens are NOT the native token
        
        // EXPLOIT: Try to get price quote for tokenA/tokenB cross-pair
        // This should revert with NoPreviousSnapshotExists
        vm.expectRevert(
            abi.encodeWithSelector(
                IOracle.NoPreviousSnapshotExists.selector,
                address(tokenB),
                block.timestamp - 60
            )
        );
        erc.getQuote(1e18, address(tokenA), address(tokenB));
        
        // VERIFY: The function reverts instead of handling gracefully
        // External integrations expecting ERC-7726 compliance will break
    }
    
    function test_OracleDoS_PriceFetcher_CrossPair() public {
        // EXPLOIT: Try to get TWAP for tokenA/tokenB cross-pair
        uint64 startTime = uint64(block.timestamp - 60);
        uint64 endTime = uint64(block.timestamp);
        
        vm.expectRevert(
            abi.encodeWithSelector(
                IOracle.NoPreviousSnapshotExists.selector,
                address(tokenB),
                startTime
            )
        );
        fetcher.getAveragesOverPeriod(address(tokenA), address(tokenB), startTime, endTime);
        
        // VERIFY: Price fetching fails completely even though tokenA has valid data
    }
    
    function test_OracleDoS_HistoricalAverages() public {
        // EXPLOIT: Try to get historical averages
        vm.expectRevert();
        fetcher.getHistoricalPeriodAverages(
            address(tokenA), 
            address(tokenB), 
            uint64(block.timestamp),
            2,
            30
        );
        
        // VERIFY: Historical data fetching is also blocked
    }
    
    function test_SafeFunction_getAvailableHistoricalPeriodAverages() public {
        // NOTE: This function DOES handle the case correctly
        // It checks data availability and returns empty array
        (uint64 startTime, PriceFetcher.PeriodAverage[] memory averages) = 
            fetcher.getAvailableHistoricalPeriodAverages(
                address(tokenA),
                address(tokenB),
                uint64(block.timestamp),
                2,
                30
            );
        
        // Returns empty array instead of reverting
        assertEq(averages.length, 0, "Should return empty array for missing data");
        
        // This demonstrates the correct pattern that other functions should follow
    }
}
```

## Notes

The vulnerability demonstrates a **lack of defensive programming** in oracle data access. While `getAvailableHistoricalPeriodAverages` correctly implements data availability checks using `OracleLib.getEarliestSnapshotTimestamp()`, other critical functions like `ERC7726.getQuote()` and `PriceFetcher.getAveragesOverPeriod()` do not perform these checks. [6](#0-5) 

The `OracleLib.getEarliestSnapshotTimestamp()` function returns `type(uint256).max` when no snapshots exist (count == 0), which allows callers to detect unavailable data. However, directly calling `ORACLE.extrapolateSnapshot()` bypasses this check and causes `searchRangeForPrevious` to revert when `logicalMin >= logicalMaxExclusive` (both 0 when count is 0). [7](#0-6) 

This is particularly problematic for the ERC-7726 standard implementation, as the standard is intended to provide a unified oracle interface across DeFi protocols. Unexpected reverts break composability and make the implementation unreliable for external integrations.

### Citations

**File:** src/extensions/Oracle.sol (L55-55)
```text
/// @notice Records price and liquidity into accumulators enabling a separate contract to compute a manipulation resistant average price and liquidity
```

**File:** src/extensions/Oracle.sol (L256-258)
```text
            if (logicalMin >= logicalMaxExclusive) {
                revert NoPreviousSnapshotExists(token, time);
            }
```

**File:** src/extensions/Oracle.sol (L365-379)
```text
    function extrapolateSnapshot(address token, uint256 atTime)
        public
        view
        returns (uint160 secondsPerLiquidityCumulative, int64 tickCumulative)
    {
        if (atTime > block.timestamp) revert FutureTime();

        Counts c;
        assembly ("memory-safe") {
            c := sload(token)
        }
        (uint256 logicalIndex, Snapshot snapshot) = searchRangeForPrevious(c, token, atTime, 0, c.count());
        (secondsPerLiquidityCumulative, tickCumulative) =
            extrapolateSnapshotInternal(c, token, atTime, logicalIndex, snapshot);
    }
```

**File:** src/lens/ERC7726.sol (L91-112)
```text
    function getAverageTick(address baseToken, address quoteToken) private view returns (int32 tick) {
        unchecked {
            bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
            if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
                (int32 tickSign, address otherToken) =
                    baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
            } else {
                int32 baseTick = getAverageTick(NATIVE_TOKEN_ADDRESS, baseToken);
                int32 quoteTick = getAverageTick(NATIVE_TOKEN_ADDRESS, quoteToken);

                return
                    int32(
                        FixedPointMathLib.min(MAX_TICK, FixedPointMathLib.max(MIN_TICK, int256(quoteTick - baseTick)))
                    );
            }
        }
    }
```

**File:** src/lens/ERC7726.sol (L138-154)
```text
    function getQuote(uint256 baseAmount, address base, address quote) external view returns (uint256 quoteAmount) {
        address normalizedBase = normalizeAddress(base);
        address normalizedQuote = normalizeAddress(quote);

        // Short-circuit same-token quotes to avoid unnecessary oracle calls and math
        if (normalizedBase == normalizedQuote) {
            return baseAmount;
        }

        int32 tick = getAverageTick({baseToken: normalizedBase, quoteToken: normalizedQuote});

        uint256 sqrtRatio = tickToSqrtRatio(tick).toFixed();

        uint256 ratio = FixedPointMathLib.fullMulDivN(sqrtRatio, sqrtRatio, 128);

        quoteAmount = FixedPointMathLib.fullMulDivN(baseAmount, ratio, 128);
    }
```

**File:** src/lens/PriceFetcher.sol (L202-209)
```text
        uint256 earliestObservationTime = FixedPointMathLib.max(
            ORACLE.getEarliestSnapshotTimestamp(baseToken), ORACLE.getEarliestSnapshotTimestamp(quoteToken)
        );

        // no observations available for the period, return an empty array
        if (earliestObservationTime >= endTime) {
            return (endTime, new PeriodAverage[](0));
        }
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
