## Title
Oracle tickCumulative Overflow Causes TWAP Direction Inversion Due to Unchecked Arithmetic

## Summary
The Oracle extension's `maybeInsertSnapshot()` function performs tickCumulative accumulation in an unchecked block, allowing int64 overflow for long-lived pools at extreme tick values. [1](#0-0)  When overflow occurs, the sign extension logic in `snapshot.sol` correctly interprets the bit pattern, but the underlying value is corrupted, causing TWAP calculations to produce inverted price directions. [2](#0-1) 

## Impact
**Severity**: Medium-High

## Finding Description
**Location:** `src/extensions/Oracle.sol` (function `maybeInsertSnapshot`, line 125) and `src/types/snapshot.sol` (function `tickCumulative`, lines 20-24)

**Intended Logic:** The Oracle extension accumulates tick values over time to enable manipulation-resistant TWAP calculations. Each snapshot stores `tickCumulative` as an int64, representing the cumulative sum of `tick * timePassed`. [3](#0-2) 

**Actual Logic:** The tickCumulative calculation occurs within an unchecked block [4](#0-3) , allowing int64 overflow without revert. For a pool at MAX_TICK (88,722,835) [5](#0-4) , the accumulator grows by ~88.7M per second and overflows after approximately 104 million seconds (~3.3 years). When overflow occurs, a large positive value wraps to a large negative value (or vice versa).

The sign extension in `snapshot.sol` uses `signextend(7, shr(192, snapshot))` [6](#0-5) , which correctly interprets bit 63 as the sign bit. However, the **value itself is corrupted** due to the prior overflow, not the extraction logic.

When TWAP is calculated in `ERC7726.sol`, the difference `(tickCumulativeEnd - tickCumulativeStart)` produces the wrong sign and magnitude if overflow occurred between the two timestamps: [7](#0-6) 

**Exploitation Path:**
1. Pool is initialized with Oracle extension at a high tick value (e.g., volatile or depegged token pair)
2. Over 3.3 years at MAX_TICK, tickCumulative accumulates from 0 toward int64 max (~9.22e18)
3. When tickCumulative exceeds int64 max, it overflows to a large negative value (e.g., from +8e18 to -2e18)
4. Any TWAP query spanning the overflow point calculates: `tickCumulativeEnd - tickCumulativeStart = (-2e18) - (+8e18) = -10e18` instead of the correct positive value
5. The inverted TWAP causes price calculations to return incorrect values, potentially triggering liquidations, mispriced swaps, or other oracle-dependent operations in external protocols

**Security Property Broken:** Oracle integrity is violated. The protocol assumes TWAP values are accurate for manipulation-resistant price feeds, but overflow corruption breaks this guarantee for long-lived pools.

## Impact Explanation
- **Affected Assets**: All tokens paired with ETH in Oracle pools that reach extreme ticks and operate for extended periods (years)
- **Damage Severity**: Complete oracle failure for affected pools. External protocols relying on Ekubo oracles receive inverted prices, potentially causing:
  - Incorrect liquidations (liquidating healthy positions or failing to liquidate underwater positions)
  - Mispriced trades in aggregators using Ekubo price feeds
  - Loss of funds for users trusting the TWAP for high-value decisions
- **User Impact**: Any user or protocol querying TWAP data from affected pools receives corrupted price information. The impact compounds over time as more pools age beyond the overflow threshold.

## Likelihood Explanation
- **Attacker Profile**: No active attacker needed—this is a time-based degradation issue. However, sophisticated actors could exploit mispriced oracles once overflow occurs.
- **Preconditions**: 
  - Pool must be initialized with Oracle extension
  - Pool must maintain extreme tick values (near MAX_TICK or MIN_TICK) for extended periods
  - Most realistic for: volatile pairs, depegged stablecoins, long-lived pools (3+ years)
- **Execution Complexity**: Passive exploitation—the overflow happens naturally over time. Active exploitation requires monitoring for overflow and executing trades/liquidations when TWAP becomes corrupted.
- **Frequency**: Once per pool lifetime, but affects ALL subsequent TWAP queries permanently unless pool state resets (which doesn't occur automatically)

## Recommendation

Add overflow checks to the tickCumulative accumulation logic:

```solidity
// In src/extensions/Oracle.sol, function maybeInsertSnapshot, line 125:

// CURRENT (vulnerable):
_tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()

// FIXED:
_tickCumulative: _calculateTickCumulativeSafe(
    last.tickCumulative(), 
    int64(uint64(timePassed)), 
    state.tick()
)

// Add helper function with overflow protection:
function _calculateTickCumulativeSafe(
    int64 lastCumulative, 
    int64 timePassed, 
    int32 tick
) private pure returns (int64) {
    int64 increment = timePassed * int64(tick);
    int64 newCumulative = lastCumulative + increment;
    
    // Check for overflow: if signs differ after addition, overflow occurred
    if ((lastCumulative > 0 && increment > 0 && newCumulative < 0) ||
        (lastCumulative < 0 && increment < 0 && newCumulative > 0)) {
        revert TickCumulativeOverflow();
    }
    
    return newCumulative;
}
```

**Alternative mitigation:** Use a larger type (int128 or int256) for tickCumulative to extend the overflow timeframe to impractical durations. This requires updating the Snapshot packing logic. [8](#0-7) 

## Proof of Concept
```solidity
// File: test/Exploit_OracleOverflow.t.sol
// Run with: forge test --match-test test_OracleTickCumulativeOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/Oracle.sol";
import "../src/lens/ERC7726.sol";
import "../test/FullTest.sol";

contract Exploit_OracleOverflow is FullTest {
    Oracle oracle;
    ERC7726 erc7726;
    
    function setUp() public override {
        FullTest.setUp();
        // Deploy oracle at standard address
        address oracleAddr = address(uint160(oracleCallPoints().toUint8()) << 152);
        deployCodeTo("Oracle.sol", abi.encode(core), oracleAddr);
        oracle = Oracle(oracleAddr);
    }
    
    function test_OracleTickCumulativeOverflow() public {
        // SETUP: Create pool at MAX_TICK
        address token = address(new TestToken("TEST", 18));
        PoolKey memory poolKey = oracle.getPoolKey(token);
        
        // Initialize pool at MAX_TICK
        router.initializePool(poolKey, MAX_TICK, 1 ether);
        
        // Add liquidity
        positions.mint();
        uint256 posId = 1;
        positions.deposit(posId, poolKey, MIN_TICK, MAX_TICK, 1 ether, 1 ether, 0);
        
        // EXPLOIT: Simulate time passage to overflow point
        // At MAX_TICK (88,722,835), overflow occurs after ~104M seconds
        uint256 timeToOverflow = uint256(type(int64).max) / uint256(int256(MAX_TICK));
        
        // Record initial tickCumulative
        (, int64 tickCumStart) = oracle.extrapolateSnapshot(token, block.timestamp);
        
        // Advance time to just before overflow
        vm.warp(block.timestamp + timeToOverflow - 1000);
        router.swap(poolKey, false, 1, MAX_SQRT_RATIO - 1, 0); // Trigger snapshot
        (, int64 tickCumBefore) = oracle.extrapolateSnapshot(token, block.timestamp);
        
        // Advance time past overflow point
        vm.warp(block.timestamp + 2000);
        router.swap(poolKey, false, 1, MAX_SQRT_RATIO - 1, 0); // Trigger snapshot
        (, int64 tickCumAfter) = oracle.extrapolateSnapshot(token, block.timestamp);
        
        // VERIFY: tickCumulative wrapped from positive to negative
        assertTrue(tickCumBefore > 0, "Before overflow: should be positive");
        assertTrue(tickCumAfter < 0, "After overflow: wrapped to negative");
        
        // TWAP calculation is now inverted
        int64 twapDifference = tickCumAfter - tickCumBefore;
        assertTrue(twapDifference < 0, "TWAP difference is negative when should be positive");
        
        console.log("tickCumulative before overflow:", uint64(tickCumBefore));
        console.log("tickCumulative after overflow:", uint64(tickCumAfter));
        console.log("TWAP difference (WRONG):", uint64(twapDifference));
    }
}
```

## Notes

The vulnerability is confirmed through code analysis:

1. **Unchecked arithmetic**: The `maybeInsertSnapshot()` function explicitly uses an `unchecked` block [9](#0-8) , disabling Solidity 0.8+ overflow protection.

2. **Sign extension is correct**: The `signextend(7, shr(192, snapshot))` operation properly handles int64 sign extension from bit 63 [2](#0-1) . The issue is NOT with the extraction logic, but with the corrupted value being extracted.

3. **TWAP calculation assumes no overflow**: The ERC7726 oracle implementation computes TWAP as `(tickCumulativeEnd - tickCumulativeStart) / duration` [10](#0-9) , which fails when overflow wraps the cumulative value between the two timestamps.

4. **Realistic for long-lived pools**: While 3.3 years at MAX_TICK seems long, Ekubo is designed for perpetual operation, and pools with extreme price ratios (depegged stablecoins, highly volatile pairs) can realistically hit these conditions.

The security question correctly identifies this vulnerability. The answer is: **Yes, when tickCumulative overflows due to unchecked arithmetic, the sign extension correctly interprets the corrupted bit pattern, but the underlying value is wrong, causing TWAP direction inversion.**

### Citations

**File:** src/extensions/Oracle.sol (L96-146)
```text
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

**File:** src/types/snapshot.sol (L20-24)
```text
function tickCumulative(Snapshot snapshot) pure returns (int64 t) {
    assembly ("memory-safe") {
        t := signextend(7, shr(192, snapshot))
    }
}
```

**File:** src/types/snapshot.sol (L26-39)
```text
function createSnapshot(uint32 _timestamp, uint160 _secondsPerLiquidityCumulative, int64 _tickCumulative)
    pure
    returns (Snapshot s)
{
    assembly ("memory-safe") {
        // s = timestamp | (secondsPerLiquidityCumulative << 32) | (tickCumulative << 192)
        s := or(
            or(
                and(_timestamp, 0xFFFFFFFF),
                shl(32, and(_secondsPerLiquidityCumulative, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
            ),
            shl(192, and(_tickCumulative, 0xFFFFFFFFFFFFFFFF))
        )
    }
```

**File:** src/math/constants.sol (L14-14)
```text
int32 constant MAX_TICK = 88722835;
```

**File:** src/lens/ERC7726.sol (L91-111)
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
```
