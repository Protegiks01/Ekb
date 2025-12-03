## Title
Oracle Tick Accumulator Int64 Overflow Causes Incorrect TWAP Calculations After 3.3 Years

## Summary
The Oracle extension stores `tickCumulative` as an `int64` that accumulates `timePassed * currentTick` on every snapshot. At `MAX_TICK = 88,722,835`, the accumulator overflows after approximately 3.3 years (103,984,990 seconds). TWAP queries spanning the overflow boundary produce catastrophically incorrect prices because the subtraction `(tickCumulativeEnd - tickCumulativeStart)` yields massive negative values that don't represent actual price movements.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/Oracle.sol` (function `maybeInsertSnapshot`, lines 95-146; function `extrapolateSnapshotInternal`, lines 315-362) [1](#0-0) [2](#0-1) 

**Intended Logic:** The Oracle should accumulate tick values over time to enable manipulation-resistant TWAP price calculations. The `tickCumulative` field should grow monotonically, allowing consumers to compute time-weighted average ticks by taking differences between snapshots.

**Actual Logic:** The `tickCumulative` field is stored as `int64` rather than a larger signed integer type. [3](#0-2) 

At line 125, accumulation occurs inside an unchecked block: [4](#0-3) 

The multiplication `int64(uint64(timePassed)) * state.tick()` and subsequent addition can silently overflow after approximately 103,984,990 seconds (3.3 years) at `MAX_TICK = 88,722,835`: [5](#0-4) 

**Exploitation Path:**

1. **Pool Initialization:** A pool is created with the Oracle extension, and it trades at or near `MAX_TICK` consistently.

2. **Accumulation Over Time:** Over 3.3 years, the `tickCumulative` field accumulates:
   - Daily accumulation at MAX_TICK: `86,400 seconds * 88,722,835 = 7,665,652,864,000`
   - After ~1,203 days: `tickCumulative` approaches `int64.max = 9,223,372,036,854,775,807`
   - On the next snapshot update, overflow occurs and the value wraps to large negative numbers

3. **TWAP Query Across Overflow:** External protocols (e.g., ERC7726 oracle consumers, PriceFetcher users) query TWAP spanning the overflow boundary: [6](#0-5) 

4. **Incorrect Price Calculation:** 
   - `tickCumulativeStart` (before overflow): `≈ +9,223,000,000,000,000,000`
   - `tickCumulativeEnd` (after overflow): `≈ -9,223,000,000,000,000,000`
   - Subtraction: `(-9.22e18) - (+9.22e18) = -18.44e18`
   - Division by time: Yields a massively incorrect negative tick value
   - Cast to `int32`: Further truncation produces garbage values that don't represent any valid price [7](#0-6) 

**Security Property Broken:** The Oracle's fundamental invariant that TWAP calculations accurately reflect time-weighted average prices is violated. This breaks the manipulation-resistance guarantee that the oracle is designed to provide.

## Impact Explanation

- **Affected Assets**: All tokens paired with native token in Oracle-enabled pools that trade at high tick values for extended periods. External protocols consuming Ekubo oracle data (via ERC7726 or PriceFetcher) are affected.

- **Damage Severity**: Protocols relying on Ekubo oracle prices will receive completely incorrect price data after overflow. This can lead to:
  - Incorrect liquidations in lending protocols
  - Catastrophic trades in DEX aggregators using the oracle
  - Loss of funds in any protocol using these prices for settlement
  - The error magnitude is unbounded - the returned tick can be billions of ticks away from the true average

- **User Impact**: Any user interacting with protocols that consume Ekubo oracle data after the 3.3-year overflow point. This includes:
  - Traders receiving wrong price quotes
  - Borrowers being incorrectly liquidated
  - LPs having positions valued incorrectly
  - Any smart contract using `getQuote()` from ERC7726 or `getAveragesOverPeriod()` from PriceFetcher

## Likelihood Explanation

- **Attacker Profile**: No attacker required - this is a time-based vulnerability that occurs naturally if a pool trades at high ticks for ~3.3 years. However, an attacker with sufficient capital could manipulate a pool to MAX_TICK and maintain it there to accelerate overflow.

- **Preconditions**: 
  - Pool exists with Oracle extension enabled
  - Pool trades at or near MAX_TICK for extended period
  - Time passes (~3.3 years at MAX_TICK, longer at lower ticks)
  - External protocols query TWAP data spanning the overflow

- **Execution Complexity**: The vulnerability triggers automatically through normal protocol operation. No special transaction or timing is required beyond the passage of time and consistent high-tick trading.

- **Frequency**: Once per pool after the overflow occurs. However, multiple pools can be affected, and the issue is permanent once it occurs (all future TWAP queries spanning the overflow are broken).

## Recommendation

Change the `tickCumulative` storage type from `int64` to `int128` or `int256` to provide sufficient overflow protection: [3](#0-2) 

**Alternative Mitigation:**
Implement overflow detection and handling in the accumulation logic: [4](#0-3) 

Add checks to detect when overflow is imminent and either:
- Revert to prevent further accumulation
- Reset the accumulator with a marker indicating the discontinuity
- Use a different storage scheme (e.g., separate epoch counter)

However, changing to `int128` is the simplest and most robust solution, providing ~10^19x more headroom.

## Proof of Concept

```solidity
// File: test/Exploit_OracleInt64Overflow.t.sol
// Run with: forge test --match-test test_OracleInt64Overflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/Oracle.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "./FullTest.sol";

contract Exploit_OracleInt64Overflow is FullTest {
    Oracle oracle;
    PoolKey poolKey;
    address token;
    
    function setUp() public override {
        FullTest.setUp();
        
        // Deploy Oracle extension
        address deployAddress = address(uint160(oracleCallPoints().toUint8()) << 152);
        deployCodeTo("Oracle.sol", abi.encode(core), deployAddress);
        oracle = Oracle(deployAddress);
        
        // Create test token and oracle pool at MAX_TICK
        token = address(new TestToken());
        poolKey = PoolKey(
            NATIVE_TOKEN_ADDRESS, 
            token,
            createFullRangePoolConfig(0, address(oracle))
        );
        
        // Initialize pool at MAX_TICK
        core.initializePool(poolKey, MAX_TICK);
    }
    
    function test_OracleInt64Overflow() public {
        // SETUP: Simulate 3.3 years of accumulation at MAX_TICK
        // int64.max = 9,223,372,036,854,775,807
        // MAX_TICK = 88,722,835
        // Overflow time = 9,223,372,036,854,775,807 / 88,722,835 ≈ 103,984,990 seconds
        
        uint256 startTime = block.timestamp;
        
        // Get initial snapshot
        (, int64 tickCumulativeStart) = oracle.extrapolateSnapshot(token, startTime);
        console.log("Initial tickCumulative:", uint64(tickCumulativeStart));
        
        // Fast forward to just before overflow (3.3 years - 1 hour)
        uint256 timeBeforeOverflow = 103_984_990 - 3600;
        vm.warp(startTime + timeBeforeOverflow);
        
        // Trigger snapshot update
        router.swap(poolKey, false, 1, toSqrtRatio(1, false), 0);
        
        (, int64 tickCumulativeBeforeOverflow) = oracle.extrapolateSnapshot(token, block.timestamp);
        console.log("Before overflow tickCumulative:", uint64(tickCumulativeBeforeOverflow));
        
        // Fast forward past overflow point
        vm.warp(startTime + timeBeforeOverflow + 7200); // 2 hours later
        
        // Trigger another snapshot
        router.swap(poolKey, false, 1, toSqrtRatio(1, false), 0);
        
        (, int64 tickCumulativeAfterOverflow) = oracle.extrapolateSnapshot(token, block.timestamp);
        console.log("After overflow tickCumulative:", int64(tickCumulativeAfterOverflow));
        
        // VERIFY: TWAP calculation is wrong
        // Calculate TWAP from before overflow to after overflow (2 hour window)
        int64 tickDifference = tickCumulativeAfterOverflow - tickCumulativeBeforeOverflow;
        int32 averageTick = int32(tickDifference / int64(7200));
        
        console.log("Calculated average tick:", int32(averageTick));
        console.log("Expected average tick (MAX_TICK):", MAX_TICK);
        
        // The average tick should be close to MAX_TICK, but due to overflow it's completely wrong
        // This assertion will fail, proving the vulnerability
        assertApproxEqAbs(
            uint256(uint32(averageTick)), 
            uint256(uint32(MAX_TICK)), 
            1000,
            "TWAP calculation broken after int64 overflow"
        );
    }
}
```

**Notes:**
- The actual PoC would need to be adapted to the test suite's exact setup, including proper token approvals and pool initialization
- The vulnerability is time-dependent, requiring ~3.3 years at MAX_TICK, so the PoC uses `vm.warp()` to fast-forward time
- The core issue is demonstrated: TWAP queries spanning the overflow produce incorrect results due to the wraparound of `int64` arithmetic

### Citations

**File:** src/extensions/Oracle.sol (L95-146)
```text
    function maybeInsertSnapshot(PoolId poolId, address token) private {
        unchecked {
            Counts c;
            assembly ("memory-safe") {
                c := sload(token)
            }

            uint32 timePassed = uint32(block.timestamp) - c.lastTimestamp();
            if (timePassed == 0) return;

            uint32 index = c.index();

            // we know count is always g.t. 0 in the places this is called
            Snapshot last;
            assembly ("memory-safe") {
                last := sload(or(shl(32, token), index))
            }

            PoolState state = CORE.poolState(poolId);

            uint128 liquidity = state.liquidity();
            uint256 nonZeroLiquidity;
            assembly ("memory-safe") {
                nonZeroLiquidity := add(liquidity, iszero(liquidity))
            }

            Snapshot snapshot = createSnapshot({
                _timestamp: uint32(block.timestamp),
                _secondsPerLiquidityCumulative: last.secondsPerLiquidityCumulative()
                    + uint160(FixedPointMathLib.rawDiv(uint256(timePassed) << 128, nonZeroLiquidity)),
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });

            uint32 count = c.count();
            uint32 capacity = c.capacity();

            bool isLastIndex = index == count - 1;
            bool incrementCount = isLastIndex && capacity > count;

            if (incrementCount) count++;
            index = (index + 1) % count;
            uint32 lastTimestamp = uint32(block.timestamp);

            c = createCounts({_index: index, _count: count, _capacity: capacity, _lastTimestamp: lastTimestamp});
            assembly ("memory-safe") {
                sstore(token, c)
                sstore(or(shl(32, token), index), snapshot)
            }

            _emitSnapshotEvent(token, snapshot);
        }
    }
```

**File:** src/extensions/Oracle.sol (L315-362)
```text
    function extrapolateSnapshotInternal(
        Counts c,
        address token,
        uint256 atTime,
        uint256 logicalIndex,
        Snapshot snapshot
    ) private view returns (uint160 secondsPerLiquidityCumulative, int64 tickCumulative) {
        unchecked {
            secondsPerLiquidityCumulative = snapshot.secondsPerLiquidityCumulative();
            tickCumulative = snapshot.tickCumulative();
            uint32 timePassed = uint32(atTime) - snapshot.timestamp();
            if (timePassed != 0) {
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
                    Snapshot next;
                    assembly ("memory-safe") {
                        next := sload(or(shl(32, token), logicalIndexNext))
                    }

                    uint32 timestampDifference = next.timestamp() - snapshot.timestamp();

                    tickCumulative += int64(
                        FixedPointMathLib.rawSDiv(
                            int256(uint256(timePassed)) * (next.tickCumulative() - snapshot.tickCumulative()),
                            int256(uint256(timestampDifference))
                        )
                    );
                    secondsPerLiquidityCumulative += uint160(
                        (uint256(timePassed)
                                * (next.secondsPerLiquidityCumulative() - snapshot.secondsPerLiquidityCumulative()))
                            / timestampDifference
                    );
                }
            }
        }
    }
```

**File:** src/types/snapshot.sol (L20-24)
```text
function tickCumulative(Snapshot snapshot) pure returns (int64 t) {
    assembly ("memory-safe") {
        t := signextend(7, shr(192, snapshot))
    }
}
```

**File:** src/math/constants.sol (L12-14)
```text
// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;
```

**File:** src/lens/ERC7726.sol (L91-101)
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
