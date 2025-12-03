## Title
Oracle Extrapolation Uses Current Pool State Enabling TWAP Manipulation via Stale Snapshot Exploitation

## Summary
The Oracle extension's `extrapolateSnapshotInternal` function reads the current pool state via `CORE.poolState(poolId)` when extrapolating from the most recent snapshot. [1](#0-0)  This allows attackers to manipulate the pool price after a snapshot is written, causing all subsequent TWAP calculations to include the manipulated price until the next snapshot is recorded, enabling single-block or multi-block TWAP manipulation attacks on dependent lending protocols.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/Oracle.sol` - `extrapolateSnapshotInternal()` function (lines 315-362) and `maybeInsertSnapshot()` function (lines 95-146)

**Intended Logic:** The Oracle extension is designed to provide manipulation-resistant time-weighted average prices (TWAP) by recording price snapshots at each pool interaction. [2](#0-1)  When calculating TWAP, the system should use historical snapshot data to prevent single-block price manipulation.

**Actual Logic:** When `extrapolateSnapshotInternal` needs to extrapolate from the most recent snapshot to a future timestamp, it reads the **current** pool state directly from storage to calculate the extrapolated cumulative values. [1](#0-0)  However, this current pool state can reflect a manipulated price that was set **after** the snapshot was written.

**Exploitation Path:**
1. **Snapshot Capture (Before Swap):** When a swap occurs, the `beforeSwap` hook calls `maybeInsertSnapshot`, which reads the current pool state and writes a snapshot with `timestamp = block.timestamp`. [3](#0-2)  The snapshot captures the tick value at line 125 via `state.tick()` BEFORE the swap executes. [4](#0-3) 

2. **Price Manipulation (Swap Executes):** The swap then executes in Core.sol, updating the pool state to a new manipulated tick. [5](#0-4)  The `beforeSwap` hook runs at line 528, then pool state is updated during swap execution starting at line 532.

3. **Stale Snapshot Persistence:** Within the same block, `maybeInsertSnapshot` will not write a new snapshot because `timePassed = block.timestamp - c.lastTimestamp() = 0`. [6](#0-5) 

4. **TWAP Calculation Reads Manipulated State:** In a subsequent block, when a lending protocol calculates TWAP using `extrapolateSnapshot(token, block.timestamp)`, it finds the snapshot from step 1 (most recent, `logicalIndex == c.count() - 1`) and extrapolates using `CORE.poolState(poolId).tick()`, which returns the **manipulated** tick from step 2. [7](#0-6)  The manipulated tick is then multiplied by the time elapsed since the snapshot.

**Security Property Broken:** The Oracle is intended to provide manipulation-resistant TWAP data. By exploiting the timing gap between snapshot writes and pool state updates, attackers can cause the TWAP to incorporate manipulated prices, violating the core security assumption of time-weighted averaging.

## Impact Explanation
- **Affected Assets:** All lending protocols, options protocols, or other DeFi applications that rely on the Ekubo Oracle's TWAP for price feeds are vulnerable. The ERC7726 implementation specifically calculates TWAP by calling `extrapolateSnapshot` twice. [8](#0-7) 

- **Damage Severity:** Attackers can manipulate TWAP values to trigger bad liquidations in lending protocols, execute unfavorable trades in options protocols, or extract value through price oracle manipulation. If the oracle pool has low trading volume (infrequent snapshots), the manipulation can persist for extended periods (minutes to hours), allowing the attacker to execute complex multi-step attacks. For example, manipulating a 30-minute TWAP by 10% for just 1 minute would result in a ~0.33% TWAP deviation, which compounds if the manipulation persists.

- **User Impact:** All users of protocols depending on this oracle for collateral valuation, liquidation thresholds, or pricing data are at risk. Borrowers can face unfair liquidations; lenders face bad debt accumulation; traders receive incorrect pricing.

## Likelihood Explanation
- **Attacker Profile:** Any user with capital sufficient to execute a large swap can perform this attack. No special privileges required.

- **Preconditions:** 
  - Oracle pool must exist and be initialized with the target token
  - Sufficient liquidity must be present to execute price-moving swaps
  - A lending protocol or other price consumer must be actively querying the oracle
  - Pool must have low enough trading volume that snapshots aren't written every block

- **Execution Complexity:** Single transaction to manipulate price (via swap), then the manipulation persists automatically until the next snapshot write. The attacker doesn't need to maintain the position or execute complex strategies. The vulnerability exists in the protocol logic itself.

- **Frequency:** Can be exploited continuously. Each swap creates an opportunity window where the manipulated price affects all TWAP calculations until the next interaction. In low-volume pools, this window can extend for multiple blocks or even minutes.

## Recommendation

**Fix Option 1: Use Only Snapshot Data for Extrapolation**
Modify `extrapolateSnapshotInternal` to never read current pool state when extrapolating. Instead, only allow queries for timestamps where complete snapshot data exists, or return the most recent snapshot value without extrapolation: [9](#0-8) 

```solidity
// In src/extensions/Oracle.sol, function extrapolateSnapshotInternal:

// CURRENT (vulnerable):
if (logicalIndex == c.count() - 1) {
    // Use current pool state.
    PoolId poolId = getPoolKey(token).toPoolId();
    PoolState state = CORE.poolState(poolId);
    
    tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
    // ... rest of extrapolation using current state
}

// FIXED - Option 1: Disallow future extrapolation
if (logicalIndex == c.count() - 1 && timePassed != 0) {
    // Cannot extrapolate beyond the most recent snapshot
    // Consumers must ensure a fresh snapshot exists before querying
    revert CannotExtrapolateBeyondLastSnapshot(token, atTime);
}
// For timePassed == 0, return the snapshot values directly (no change needed)
```

**Fix Option 2: Write Snapshot After Swap**
Add an `afterSwap` hook to write a snapshot with post-swap prices, ensuring the TWAP always reflects actual historical prices: [10](#0-9) 

```solidity
// In src/extensions/Oracle.sol, update oracleCallPoints:

// CURRENT:
function oracleCallPoints() pure returns (CallPoints memory) {
    return CallPoints({
        beforeInitializePool: true,
        afterInitializePool: false,
        beforeUpdatePosition: true,
        afterUpdatePosition: false,
        beforeSwap: true,
        afterSwap: false,  // <-- VULNERABLE
        // ...
    });
}

// FIXED:
function oracleCallPoints() pure returns (CallPoints memory) {
    return CallPoints({
        beforeInitializePool: true,
        afterInitializePool: false,
        beforeUpdatePosition: true,
        afterUpdatePosition: false,
        beforeSwap: true,
        afterSwap: true,  // <-- Write snapshot after swap to capture post-swap price
        // ...
    });
}

// Add afterSwap implementation:
function afterSwap(Locker, PoolKey memory poolKey, SwapParameters params, PoolState stateAfter)
    external
    override(BaseExtension, IExtension)
    onlyCore
{
    if (params.amount() != 0) {
        // Write a snapshot capturing the post-swap state
        maybeInsertSnapshot(poolKey.toPoolId(), poolKey.token1);
    }
}
```

**Recommended Approach:** Implement Fix Option 1 (reject extrapolation beyond last snapshot) as it provides the strongest guarantee against manipulation. Protocol consumers should call a permissionless function to update the oracle before querying TWAP, ensuring fresh data. This places the responsibility on the consumer to maintain oracle freshness rather than relying on potentially stale extrapolations.

## Proof of Concept

```solidity
// File: test/Exploit_OracleTWAPManipulation.t.sol
// Run with: forge test --match-test test_OracleTWAPManipulation -vvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "./extensions/Oracle.t.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {TestToken} from "./TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {OracleLib} from "../src/libraries/OracleLib.sol";

contract Exploit_OracleTWAPManipulation is BaseOracleTest {
    using CoreLib for *;
    using OracleLib for *;

    TestToken token;
    PoolKey poolKey;

    function setUp() public override {
        BaseOracleTest.setUp();
        
        // Create token and oracle pool
        token = new TestToken();
        poolKey = createOraclePool(address(token), 0);
        
        // Add liquidity to enable swaps
        updateOraclePoolLiquidity(address(token), 1000000 ether);
    }

    function test_OracleTWAPManipulation() public {
        // SETUP: Establish baseline with initial snapshot
        vm.warp(1000);
        movePrice(poolKey, 100); // Move to tick 100, writes snapshot at timestamp 1000
        
        int64 tickCumulativeBefore = 0;
        (, tickCumulativeBefore) = oracle.extrapolateSnapshot(address(token), block.timestamp);
        
        // EXPLOIT STEP 1: In same block, manipulate price after snapshot was written
        // The snapshot was written by movePrice at tick 100 BEFORE the final swap
        // Now manipulate to tick 10000 (massive price change) in SAME BLOCK
        movePrice(poolKey, 10000);
        
        // EXPLOIT STEP 2: Advance time and query TWAP (simulating lending protocol)
        vm.warp(1012); // 12 seconds later
        
        // When lending protocol calculates TWAP ending at current time:
        (, int64 tickCumulativeAfter) = oracle.extrapolateSnapshot(address(token), block.timestamp);
        
        // VERIFY: The TWAP includes the manipulated tick
        // Expected: tickCumulativeBefore + (manipulated_tick * time_elapsed)
        // The extrapolation uses CURRENT pool state (tick 10000), not snapshot state (tick 100)
        int64 expectedIfUsingManipulatedPrice = tickCumulativeBefore + int64(10000) * 12;
        int64 expectedIfUsingSnapshotPrice = tickCumulativeBefore + int64(100) * 12;
        
        // Vulnerability confirmed: extrapolated cumulative uses manipulated price
        assertEq(
            tickCumulativeAfter,
            expectedIfUsingManipulatedPrice,
            "VULN: Extrapolation used manipulated pool state instead of snapshot data"
        );
        
        // This should NOT be equal if the oracle was secure:
        assert(tickCumulativeAfter != expectedIfUsingSnapshotPrice);
        
        // IMPACT DEMONSTRATION:
        // For a 30-minute TWAP, this 12-second manipulation would cause:
        // deviation = (10000 - 100) * 12 / 1800 = ~66 tick points of manipulation
        // This can trigger false liquidations or enable arbitrage attacks
        uint256 manipulationWindow = 12;
        uint256 twapDuration = 1800; // 30 minutes
        int256 tickDeviation = (int256(10000) - int256(100)) * int256(manipulationWindow) / int256(twapDuration);
        
        emit log_named_int("Tick deviation in 30min TWAP", tickDeviation);
        assert(tickDeviation > 0); // Confirms TWAP manipulation occurred
    }
}
```

**Notes:**
- The vulnerability stems from the fundamental design choice to use current pool state for extrapolation rather than pure historical snapshot data
- The issue affects the core TWAP calculation mechanism documented as "manipulation resistant" [2](#0-1) 
- Low-volume oracle pools are especially vulnerable as snapshots are written infrequently, extending the manipulation window
- The attack requires no special setup beyond normal pool interaction and can be executed by any user with swap capital
- This vulnerability is NOT listed in the known issues section of the README [11](#0-10)

### Citations

**File:** src/extensions/Oracle.sol (L22-36)
```text
/// @notice Returns the call points configuration for the Oracle extension
/// @dev Specifies which hooks the Oracle needs to capture price and liquidity data
/// @return The call points configuration for Oracle functionality
function oracleCallPoints() pure returns (CallPoints memory) {
    return CallPoints({
        beforeInitializePool: true,
        afterInitializePool: false,
        beforeUpdatePosition: true,
        afterUpdatePosition: false,
        beforeSwap: true,
        afterSwap: false,
        beforeCollectFees: false,
        afterCollectFees: false
    });
}
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

**File:** src/interfaces/extensions/IOracle.sol (L11-12)
```text
/// @notice Interface for the Ekubo Oracle Extension
/// @dev Records price and liquidity into accumulators enabling a separate contract to compute a manipulation resistant average price and liquidity
```

**File:** src/Core.sol (L528-542)
```text
            IExtension(config.extension()).maybeCallBeforeSwap(locker, poolKey, params);

            PoolId poolId = poolKey.toPoolId();

            PoolState stateAfter = readPoolState(poolId);

            if (!stateAfter.isInitialized()) revert PoolNotInitialized();

            int256 amountRemaining = params.amount();

            PoolBalanceUpdate balanceUpdate;

            // 0 swap amount or sqrt ratio limit == sqrt ratio is no-op
            if (amountRemaining != 0 && stateAfter.sqrtRatio() != sqrtRatioLimit) {
                (SqrtRatio sqrtRatio, int32 tick, uint128 liquidity) = stateAfter.parse();
```

**File:** src/lens/ERC7726.sol (L98-101)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
```

**File:** README.md (L30-63)
```markdown
## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### Compiler Vulnerabilities

Any vulnerabilities that pertain to the experimental nature of the `0.8.31` pre-release candidate and the project's toolkits are considered out-of-scope for the purposes of this contest.

### Non-Standard EIP-20 Assets

Tokens that have non-standard behavior e.g. allow for arbitrary calls may not be used safely in the system.

Token balances are only expected to change due to calls to `transfer` or `transferFrom`.

Any issues related to non-standard tokens should only affect the pools that use the token, i.e. those pools can never become insolvent in the other token due to non-standard behavior in one token.

### Extension Freezing Power

The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital.

Third-party extensions, however, can freeze a pool and lock deposited user capital. This is considered an acceptable risk.

### TWAMM Guarantees

TWAMM order execution quality is dependent on the liquidity in the pool and orders on the other side of the pool. 

If any of the following conditions are true:

- Liquidity in the pool is low
- The other side has not placed orders
- Blocks are not produced for a period of time

The user may receive a bad price from the TWAMM. This is a known risk; the TWAMM order execution price is not guaranteed.

```
