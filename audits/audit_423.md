## Title
Single-Block TWAP Manipulation via Current Pool State in Oracle Extrapolation

## Summary
The `Oracle.extrapolateSnapshotInternal()` function uses the current pool state (`CORE.poolState(poolId)`) when extrapolating from the most recent snapshot, allowing attackers to manipulate TWAP calculations through flash loans or large swaps within the same transaction. This affects price oracles like ERC7726 that rely on manipulation-resistant time-weighted average prices.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The Oracle extension is documented to provide "manipulation resistant average price and liquidity" by recording historical snapshots. [2](#0-1)  When extrapolating cumulative values to a specific timestamp, the function should use historical data that cannot be manipulated within a single transaction.

**Actual Logic:** When `extrapolateSnapshotInternal()` determines that it's extrapolating from the most recent snapshot (`logicalIndex == c.count() - 1`), it reads the **current** pool state directly from storage to calculate tick cumulative values. [3](#0-2)  This current state can be temporarily manipulated by an attacker via flash loans or large swaps within the same transaction, before the oracle query is executed.

**Exploitation Path:**
1. **Initial State**: The most recent oracle snapshot was created 1 hour ago at tick=100. Pool currently has normal liquidity and fair tick=100.

2. **Attacker Transaction Begins**: Attacker takes a flash loan and executes a large swap that moves the pool's current tick from 100 to 200. No new snapshot is created yet because the swap's `beforeSwap` hook [4](#0-3)  would create a snapshot with the pre-swap tick, and subsequent swaps in the same block don't create additional snapshots. [5](#0-4) 

3. **Victim Oracle Query**: Within the same transaction (via callback or subsequent call), a victim contract (e.g., ERC7726) queries the oracle to calculate a 30-minute TWAP by calling `extrapolateSnapshot(token, block.timestamp - 30 minutes)`. [6](#0-5) 

4. **Vulnerable Extrapolation**: The function finds the snapshot from 1 hour ago and needs to extrapolate forward 30 minutes. Since `logicalIndex == c.count() - 1` (most recent snapshot), it calls `CORE.poolState(poolId)` which returns the manipulated tick=200. [7](#0-6)  The extrapolation calculation uses this manipulated tick to compute cumulative values for the 30-minute gap, resulting in a manipulated TWAP.

5. **Profit and Cleanup**: The victim's contract makes decisions based on the manipulated TWAP (e.g., incorrect price quotes in ERC7726). Attacker reverses the swap, repays the flash loan, and profits from the manipulation.

**Security Property Broken:** The oracle's documented guarantee of providing "manipulation resistant average price" is violated. The function reads mutable state that can be manipulated within the same transaction, breaking the fundamental security property of time-weighted average price oracles.

## Impact Explanation
- **Affected Assets**: All contracts relying on the Oracle for TWAP calculations, including ERC7726 (price quotes) and PriceFetcher (period averages). Any protocol using these oracles for pricing, lending ratios, liquidations, or trading decisions is at risk.

- **Damage Severity**: An attacker can artificially inflate or deflate reported prices by up to the maximum price movement achievable with available liquidity and flash loan capital. For protocols making financial decisions based on these prices, this could result in:
  - Incorrect swap quotes allowing arbitrage
  - Unfair liquidations in lending protocols
  - Manipulation of any price-dependent mechanisms
  - The severity depends on the time gap between snapshots and the liquidity available for manipulation

- **User Impact**: Any user or protocol consuming oracle data during or after an attack transaction receives manipulated prices. The impact multiplies if the oracle is used for critical decisions like collateralization ratios, swap pricing, or reward calculations.

## Likelihood Explanation
- **Attacker Profile**: Any user with access to flash loans can execute this attack. MEV searchers and sophisticated traders are the most likely attackers, as they can bundle transactions atomically.

- **Preconditions**: 
  - A time gap must exist between the most recent snapshot and the query time
  - Pool must have liquidity that can be manipulated (lower liquidity = easier manipulation)
  - Victim must query the oracle within the attacker's transaction
  - This is particularly exploitable when snapshot frequency is low or when querying historical timestamps

- **Execution Complexity**: Single transaction attack. Attacker can use flash loans from any DEX, execute swaps to manipulate the tick, trigger victim contract calls (via callbacks or reentrancy), and reverse the swaps—all atomically.

- **Frequency**: Can be exploited repeatedly, potentially every block, as long as the preconditions exist. The attack is most profitable when oracle update frequency is low or when large financial decisions depend on the oracle reading.

## Recommendation

**Option 1 (Recommended)**: Enforce a maximum staleness threshold and revert if extrapolating beyond it:

```solidity
// In src/extensions/Oracle.sol, function extrapolateSnapshotInternal, around line 326:

// Add a maximum extrapolation duration (e.g., 5 minutes)
uint32 constant MAX_EXTRAPOLATION_DURATION = 300;

function extrapolateSnapshotInternal(...) private view returns (...) {
    unchecked {
        secondsPerLiquidityCumulative = snapshot.secondsPerLiquidityCumulative();
        tickCumulative = snapshot.tickCumulative();
        uint32 timePassed = uint32(atTime) - snapshot.timestamp();
        if (timePassed != 0) {
            if (logicalIndex == c.count() - 1) {
                // Prevent manipulation by reverting if snapshot is too stale
                if (timePassed > MAX_EXTRAPOLATION_DURATION) {
                    revert SnapshotTooStale(token, timePassed);
                }
                // Use current pool state only for very recent extrapolations
                ...
            }
        }
    }
}
```

**Option 2**: Always use the next snapshot for interpolation, never current state:

```solidity
// Remove the branch that uses current pool state entirely
// Always require two snapshots to bracket the target time
// This ensures historical data only, preventing any manipulation
```

**Option 3**: Create a snapshot at the beginning of any oracle query:

```solidity
// In extrapolateSnapshot, before searching for previous snapshot:
// Force a snapshot update if timestamp has changed
maybeInsertSnapshot(poolId, token);
// Then proceed with extrapolation using only historical data
```

## Proof of Concept

```solidity
// File: test/Exploit_OracleTWAPManipulation.t.sol
// Run with: forge test --match-test test_OracleTWAPManipulation -vvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "./extensions/Oracle.t.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {TestToken} from "./TestToken.sol";
import {IOracle} from "../src/interfaces/extensions/IOracle.sol";

contract Exploit_OracleTWAPManipulation is BaseOracleTest {
    TestToken token;
    PoolKey poolKey;
    uint32 constant TWAP_DURATION = 1800; // 30 minutes
    
    function setUp() public override {
        BaseOracleTest.setUp();
        
        // Deploy token and create oracle pool
        token = new TestToken();
        poolKey = createOraclePool(address(token), 0);
        
        // Add liquidity
        updateOraclePoolLiquidity(address(token), 1e18);
        
        // Create initial snapshot by moving time forward
        vm.warp(block.timestamp + 1);
        movePrice(poolKey, 100);
        
        // Move time forward significantly to create gap
        vm.warp(block.timestamp + 3600); // 1 hour later
    }
    
    function test_OracleTWAPManipulation() public {
        // SETUP: Record fair TWAP before manipulation
        uint256 timestampBefore = block.timestamp - TWAP_DURATION;
        (, int64 tickCumBefore) = oracle.extrapolateSnapshot(address(token), timestampBefore);
        (, int64 tickCumEndBefore) = oracle.extrapolateSnapshot(address(token), block.timestamp);
        int32 fairTWAP = int32((tickCumEndBefore - tickCumBefore) / int64(uint64(TWAP_DURATION)));
        
        // EXPLOIT: Flash loan attack - manipulate tick
        // Move price dramatically (simulating large swap)
        movePrice(poolKey, 500); // Move from ~100 to 500
        
        // Query oracle while price is manipulated
        (, int64 tickCumStartManip) = oracle.extrapolateSnapshot(address(token), timestampBefore);
        (, int64 tickCumEndManip) = oracle.extrapolateSnapshot(address(token), block.timestamp);
        int32 manipulatedTWAP = int32((tickCumEndManip - tickCumStartManip) / int64(uint64(TWAP_DURATION)));
        
        // VERIFY: TWAP is significantly manipulated
        int32 manipulation = manipulatedTWAP - fairTWAP;
        
        // The manipulation should be substantial (>100 ticks difference)
        assertGt(manipulation, 100, "TWAP was successfully manipulated");
        
        // This demonstrates single-block TWAP manipulation
        // In a real attack, attacker would:
        // 1. Take flash loan
        // 2. Swap to manipulate tick
        // 3. Victim queries oracle (or attacker calls victim contract)
        // 4. Victim makes decision based on manipulated TWAP
        // 5. Attacker reverses swap and repays flash loan
    }
}
```

**Notes:**
- The vulnerability stems from the design decision to use current pool state when extrapolating from the most recent snapshot, which was likely intended for efficiency but creates a manipulation vector.
- The issue is particularly severe when snapshot frequency is low (e.g., during periods of low activity) or when consumers query historical timestamps that require extrapolation.
- While the `beforeSwap` hook creates snapshots before swaps, an attacker can still manipulate the state that subsequent oracle queries within the same transaction will read.
- The fix requires balancing manipulation resistance against the need for recent price data—the recommended approach is to enforce staleness limits and fail-safe to historical interpolation only.

### Citations

**File:** src/extensions/Oracle.sol (L102-103)
```text
            uint32 timePassed = uint32(block.timestamp) - c.lastTimestamp();
            if (timePassed == 0) return;
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

**File:** src/interfaces/extensions/IOracle.sol (L12-12)
```text
/// @dev Records price and liquidity into accumulators enabling a separate contract to compute a manipulation resistant average price and liquidity
```

**File:** src/lens/ERC7726.sol (L98-99)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);
```
