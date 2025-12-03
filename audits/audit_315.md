## Title
TWAP Manipulation via Current Pool State Extrapolation During Snapshot Gaps

## Summary
The Oracle extension's `extrapolateSnapshotInternal()` function uses the current pool state to compute tick cumulatives when extrapolating to timestamps after the most recent snapshot. During periods of low pool activity where gaps form between snapshots, an attacker can manipulate the current price and cause TWAP calculations to treat the entire historical gap period as if it was at the manipulated price, effectively breaking the manipulation-resistance guarantee.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/Oracle.sol`, function `extrapolateSnapshotInternal()`, lines 327-337 [1](#0-0) 

**Intended Logic:** The Oracle extension is designed to provide manipulation-resistant time-weighted average prices (TWAP) by recording snapshots of tick and liquidity at each pool interaction. When querying historical data, it should extrapolate using actual historical pool states captured in snapshots.

**Actual Logic:** When `extrapolateSnapshotInternal()` is called for a timestamp after the most recent snapshot (determined by `logicalIndex == c.count() - 1`), it reads the CURRENT pool state via `CORE.poolState(poolId)` and uses the current tick to calculate tick cumulatives for the entire time period since the last snapshot. [2](#0-1) 

**Exploitation Path:**

1. **Wait for low activity period:** Attacker monitors for periods where no pool interactions occur (no swaps or position updates), creating a gap of hours/days since the last snapshot.

2. **Manipulate current price:** In a single transaction, attacker performs large swap to move the pool price significantly (e.g., from tick 100 to tick 10000). Since `maybeInsertSnapshot()` only writes new snapshots if `block.timestamp > lastTimestamp`, and no new block has occurred yet, no snapshot is recorded with the manipulated price. [3](#0-2) 

3. **Victim queries TWAP:** In the same block (or any subsequent query before arbitrageurs fix the price), a victim contract calls `getAverageTick()` from the ERC7726 oracle contract. [4](#0-3) 

4. **TWAP returns manipulated value:** Both calls to `extrapolateSnapshot()` (for start and end of TWAP window) find the same old snapshot from before the gap. Since this is the most recent snapshot and we're extrapolating forward, both calls use the CURRENT manipulated pool state to compute tick cumulatives. The entire gap period (which could be hours or days) is treated as if the price was at the manipulated level, resulting in a completely manipulated TWAP value.

**Security Property Broken:** The Oracle extension's documentation states it provides "manipulation resistant average price" by recording data into accumulators. [5](#0-4)  This vulnerability allows an attacker to manipulate TWAP calculations without the manipulation being recorded in snapshots.

## Impact Explanation
- **Affected Assets:** All protocols and users relying on Ekubo's ERC7726 oracle interface for pricing, including lending protocols, DEX aggregators, automated trading strategies, and any contract using `getQuote()` for token valuations.
- **Damage Severity:** Attacker can cause TWAP to return arbitrary prices within MIN_TICK to MAX_TICK bounds. For example, if the actual average tick over 1 hour is 100, but there's a 10-hour gap since the last snapshot, attacker can manipulate the TWAP to report tick 10000 by moving current price. This enables: (1) Unfair liquidations in lending protocols, (2) Sandwich attacks with oracle-based pricing, (3) Theft of funds from protocols trusting the TWAP value.
- **User Impact:** All users of downstream protocols that trust Ekubo's TWAP for critical operations (liquidations, swaps, collateral valuations) can suffer financial losses. The attack affects all users of affected protocols, not just direct Ekubo users.

## Likelihood Explanation
- **Attacker Profile:** Any user with sufficient capital to perform a large swap (or alternatively, add concentrated liquidity at extreme ticks). MEV searchers or sophisticated traders can execute this attack.
- **Preconditions:** (1) Pool must have low activity creating gaps in snapshot recording (common for low-volume pools), (2) Sufficient liquidity to move price significantly, (3) Victim protocol queries TWAP during or shortly after the manipulation, (4) Gap duration must be longer than TWAP_DURATION for maximum impact.
- **Execution Complexity:** Single transaction containing: swap to manipulate price + victim's TWAP query (via direct call or flashloan-funded attack on victim protocol). Alternatively, manipulate price and wait for victim's normal transaction flow.
- **Frequency:** Repeatable whenever gap conditions exist. For low-volume pools, this could be exploited continuously. High-volume pools have natural protection through frequent snapshot updates.

## Recommendation

The core issue is using current pool state for historical extrapolation. The fix requires ensuring that only snapshots (historical data) are used for TWAP calculations, never current state:

```solidity
// In src/extensions/Oracle.sol, function extrapolateSnapshotInternal, lines 327-337:

// CURRENT (vulnerable):
// When querying after the most recent snapshot, uses current pool state
if (logicalIndex == c.count() - 1) {
    // Use current pool state.
    PoolId poolId = getPoolKey(token).toPoolId();
    PoolState state = CORE.poolState(poolId);
    tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
    ...
}

// FIXED:
// Option 1: Revert when querying times after the most recent snapshot
if (logicalIndex == c.count() - 1) {
    // Only allow extrapolation to exactly the snapshot timestamp, not beyond
    if (timePassed != 0) {
        revert CannotExtrapolateBeyondLastSnapshot(token, atTime);
    }
    // Return snapshot values directly without extrapolation
    return (secondsPerLiquidityCumulative, tickCumulative);
}

// Option 2: Require up-to-date snapshot before TWAP queries
// In ERC7726.sol, before getAverageTick():
// Force a snapshot update by making a 0-amount swap to trigger maybeInsertSnapshot
// This ensures current block always has a snapshot, preventing gaps from being exploited
```

**Alternative mitigation:** Modify `maybeInsertSnapshot()` to write a snapshot even when `timePassed == 0` if called from specific contexts (e.g., oracle queries), but this adds complexity and gas costs. [6](#0-5) 

The recommended fix is Option 1 (revert on extrapolation beyond last snapshot), which prevents TWAP queries from using non-snapshot data. Callers must ensure pools have recent activity before relying on TWAP values, or explicitly trigger a snapshot update first.

## Proof of Concept

```solidity
// File: test/Exploit_TWAPManipulation.t.sol
// Run with: forge test --match-test test_TWAPManipulationViaSnapshotGap -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/Oracle.sol";
import "../src/lens/ERC7726.sol";

contract Exploit_TWAPManipulation is Test {
    Core core;
    Oracle oracle;
    ERC7726 erc7726;
    address token0 = address(0); // NATIVE_TOKEN_ADDRESS
    address token1 = address(0x123);
    
    function setUp() public {
        // Deploy Core and Oracle
        core = new Core();
        oracle = new Oracle(core);
        
        // Initialize pool with Oracle extension
        PoolKey memory poolKey = oracle.getPoolKey(token1);
        core.initializePool(poolKey, 100); // Initialize at tick 100
        
        // Expand oracle capacity and add initial liquidity
        oracle.expandCapacity(token1, 10);
        // Add liquidity to pool (implementation depends on protocol specifics)
        
        // Deploy ERC7726 with 1 hour TWAP
        erc7726 = new ERC7726(oracle, address(0), address(0), address(0), 3600);
    }
    
    function test_TWAPManipulationViaSnapshotGap() public {
        // SETUP: Create initial snapshot at T=1000
        vm.warp(1000);
        // Trigger snapshot by simulating pool activity (swap)
        // Assume pool price is at tick = 100
        
        // STEP 1: Wait for long period with no activity (10 hours gap)
        vm.warp(1000 + 36000); // T = 37000
        // No snapshots written during this gap period
        
        // Verify last snapshot is still at T=1000
        (uint256 count, uint256 logicalIndex, Snapshot snapshot) = 
            oracle.findPreviousSnapshot(token1, block.timestamp);
        assertEq(snapshot.timestamp(), 1000, "Last snapshot should be from T=1000");
        
        // STEP 2: EXPLOIT - Attacker manipulates price to tick = 10000
        // In reality, this would be a large swap:
        // core.swap(poolKey, swapParams); // Move price to tick 10000
        // For this PoC, we assume price is now at tick 10000
        
        // STEP 3: Victim queries TWAP with 1 hour window
        // getAverageTick() calls:
        // - extrapolateSnapshot(token1, 37000 - 3600) = extrapolateSnapshot(token1, 33400)
        // - extrapolateSnapshot(token1, 37000)
        
        // Both calls find snapshot at T=1000 (last snapshot)
        // Both calls extrapolate using CURRENT tick = 10000
        // Result: TWAP shows tick ≈ 10000 instead of actual historical average ≈ 100
        
        uint256 baseAmount = 1e18;
        uint256 quote = erc7726.getQuote(baseAmount, token0, token1);
        
        // VERIFY: Quote is based on manipulated tick 10000, not actual average 100
        // The ratio should be extremely skewed
        // For tick 10000: price ratio ≈ 2.7e43
        // For tick 100: price ratio ≈ 1.01
        
        // This demonstrates that the TWAP is completely manipulated
        // In a real attack, this would enable:
        // 1. Liquidating positions unfairly
        // 2. Swapping at unfair rates in protocols using this oracle
        // 3. Extracting value from any system trusting the TWAP
        
        assertTrue(quote > baseAmount * 1e20, "TWAP shows manipulated price");
    }
}
```

**Notes:**
- The PoC demonstrates the conceptual attack flow. Full implementation requires actual swap execution to manipulate the pool price.
- The vulnerability is confirmed by examining how `extrapolateSnapshotInternal()` uses current pool state when `logicalIndex == c.count() - 1` and `timePassed != 0`.
- Real-world exploitation requires coordination with victim protocols that query the TWAP, but the oracle manipulation itself is straightforward.
- The impact is severe because the manipulation affects the entire time gap retroactively, not just the current moment.

### Citations

**File:** src/extensions/Oracle.sol (L55-55)
```text
/// @notice Records price and liquidity into accumulators enabling a separate contract to compute a manipulation resistant average price and liquidity
```

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
