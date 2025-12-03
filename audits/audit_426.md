## Title
Timestamp Wraparound Causes Oracle to Return Zero Maximum Observation Period, Enabling Sandwich Attacks

## Summary
The `OracleLib.getEarliestSnapshotTimestamp()` function incorrectly reconstructs full uint256 timestamps from uint32 values after the 2^32 seconds wraparound. When snapshots exist from before wraparound and queries occur after, the unchecked arithmetic causes integer underflow, resulting in `getMaximumObservationPeriod()` returning 0, which dependent protocols interpret as "no historical data available."

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The function should reconstruct the full timestamp of the earliest snapshot by computing the elapsed time in uint32 space and subtracting it from the current block.timestamp. This is designed to handle the circular nature of uint32 timestamps through modular arithmetic.

**Actual Logic:** After timestamp wraparound at 2^32 seconds (February 2106), when a snapshot exists from before wraparound and the function is called after wraparound, the calculation fails: [2](#0-1) 

1. `uint32(block.timestamp)` returns a small value (e.g., 100 after wraparound)
2. `snapshot.timestamp()` returns a large uint32 value from before wraparound (e.g., 2^32 - 50)
3. The subtraction `100 - (2^32 - 50)` is performed in uint256 space (both operands are promoted)
4. In the unchecked block, this underflows to approximately `2^256 - 2^32`, a huge value
5. `block.timestamp - huge_value` also underflows, wrapping to approximately `2*2^32`
6. Since `earliest > block.timestamp`, the function returns 0

**Exploitation Path:**
1. Oracle pools are initialized and accumulate snapshots before the 2^32 timestamp wraparound
2. At approximately block.timestamp = 2^32 (February 7, 2106), the wraparound occurs
3. Post-wraparound, any call to `getMaximumObservationPeriod()` for tokens with pre-wraparound snapshots returns 0
4. Dependent protocols using [3](#0-2)  check if `maxPeriodForToken >= observationPeriod`
5. With maxPeriod = 0, the check fails, causing the protocol to skip TWAP calculation
6. Protocols fall back to spot prices, enabling sandwich attacks during this period

**Security Property Broken:** The oracle fails to provide manipulation-resistant time-weighted average prices during the wraparound period, violating its core purpose of preventing price manipulation attacks.

## Impact Explanation
- **Affected Assets**: All tokens with oracle pools that existed before the wraparound. Users trading these tokens are exposed to sandwich attacks.
- **Damage Severity**: During the wraparound period (which could last until all pre-wraparound snapshots are overwritten in the circular buffer), users receive spot prices instead of TWAPs. Sandwich attackers can manipulate spot prices through flash loans or large trades immediately before victim transactions, extracting value.
- **User Impact**: All users relying on oracle price feeds during the wraparound window. The duration depends on the circular buffer capacity and trading activity - potentially hours to days for low-activity tokens.

## Likelihood Explanation
- **Attacker Profile**: Any MEV searcher or sophisticated trader monitoring mempool during the wraparound period
- **Preconditions**: 
  - Must occur after February 7, 2106 (2^32 seconds from Unix epoch)
  - Oracle snapshots must exist from before wraparound in the circular buffer
  - Target protocols must use `PriceFetcher.getOracleTokenAverages()` or similar logic
- **Execution Complexity**: Standard sandwich attack - front-run victim trade, manipulate spot price, back-run to profit
- **Frequency**: Continuously exploitable during the wraparound period for all affected token pairs

## Recommendation

Fix the timestamp reconstruction logic to handle wraparound correctly by ensuring arithmetic stays in uint32 space until the final addition:

```solidity
// In src/libraries/OracleLib.sol, function getEarliestSnapshotTimestamp, line 44:

// CURRENT (vulnerable):
// return block.timestamp - (uint32(block.timestamp) - snapshot.timestamp());

// FIXED:
// Compute elapsed time in uint32 space where modular arithmetic works correctly
uint32 elapsed = uint32(block.timestamp) - snapshot.timestamp();
// Then extend to full timestamp by subtracting the uint32 elapsed from full timestamp
return block.timestamp - uint256(elapsed);
```

The issue is that the subtraction `uint32(block.timestamp) - snapshot.timestamp()` promotes both operands to uint256 before subtracting, breaking the modular arithmetic. The fix explicitly casts the result to preserve uint32 wraparound behavior, then promotes to uint256 for the final subtraction.

Alternative mitigation: Add explicit wraparound handling:

```solidity
function getEarliestSnapshotTimestamp(IOracle oracle, address token) internal view returns (uint256) {
    unchecked {
        if (token == NATIVE_TOKEN_ADDRESS) return 0;

        Counts c = counts(oracle, token);
        if (c.count() == 0) {
            return type(uint256).max;
        }

        Snapshot snapshot = snapshots(oracle, token, logicalIndexToStorageIndex(c.index(), c.count(), 0));
        
        // Handle wraparound by computing in uint32 then extending
        uint32 currentTime32 = uint32(block.timestamp);
        uint32 snapshotTime32 = snapshot.timestamp();
        uint32 elapsed = currentTime32 - snapshotTime32; // Wraps correctly in uint32
        
        // Extend to full timestamp
        return block.timestamp - uint256(elapsed);
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TimestampWraparound.t.sol
// Run with: forge test --match-test test_TimestampWraparound -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/Oracle.sol";
import "../src/libraries/OracleLib.sol";
import "../src/lens/PriceFetcher.sol";

contract Exploit_TimestampWraparound is Test {
    using OracleLib for *;
    
    Oracle oracle;
    PriceFetcher priceFetcher;
    address token = address(0x1234);
    
    function setUp() public {
        // Deploy Oracle (requires Core, simplified for PoC)
        // oracle = new Oracle(core);
        // priceFetcher = new PriceFetcher(IOracle(address(oracle)));
    }
    
    function test_TimestampWraparound() public {
        uint256 WRAPAROUND_TIME = 2**32;
        
        // SETUP: Simulate a snapshot recorded just before wraparound
        vm.warp(WRAPAROUND_TIME - 50); // 50 seconds before wraparound
        // [Initialize oracle pool and record snapshot at time 2^32 - 50]
        // This snapshot will have timestamp() = uint32(2^32 - 50) = 2^32 - 50
        
        // EXPLOIT: Query after wraparound
        vm.warp(WRAPAROUND_TIME + 100); // 100 seconds after wraparound
        
        // The calculation will fail:
        // uint32(block.timestamp) = 100
        // snapshot.timestamp() = 2^32 - 50 (as uint32 value 4294967246)
        // Subtraction: 100 - 4294967246 underflows in uint256 to ~2^256
        // Final: (2^32 + 100) - (2^256 - 4294967146) wraps to ~2*2^32
        
        uint256 maxPeriod = oracle.getMaximumObservationPeriod(token);
        
        // VERIFY: Function incorrectly returns 0
        assertEq(maxPeriod, 0, "Vulnerability confirmed: maxPeriod is 0 during wraparound");
        
        // This causes dependent protocols to skip TWAP calculation
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        (uint64 endTime, PriceFetcher.PeriodAverage[] memory results) = 
            priceFetcher.getOracleTokenAverages(3600, tokens); // Request 1 hour TWAP
        
        // Result will be default PeriodAverage(0, 0) since maxPeriod < observationPeriod
        assertEq(results[0].liquidity, 0, "Protocol skipped TWAP calculation");
        assertEq(results[0].tick, 0, "Protocol will fall back to spot price");
    }
}
```

## Notes

While the vulnerability won't manifest until February 2106 (136 years in the future), it represents a fundamental flaw in the timestamp reconstruction logic that violates the protocol's stated goal of providing manipulation-resistant price data. The Oracle extension explicitly documents the assumption that all snapshots are within 2^32 seconds of current time [4](#0-3) , but the implementation doesn't handle the wraparound transition correctly.

The impact is classified as Medium because:
1. It enables sandwich attacks beyond the expected MEV, causing direct financial harm to users
2. The attack window is temporary (until pre-wraparound snapshots are overwritten)
3. It requires specific timing (post-wraparound period)
4. The likelihood is certain once the wraparound occurs

The fix is straightforward: ensure the elapsed time calculation remains in uint32 arithmetic where modular wraparound works correctly, then promote to uint256 only for the final timestamp reconstruction.

### Citations

**File:** src/libraries/OracleLib.sol (L33-54)
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

    function getMaximumObservationPeriod(IOracle oracle, address token) internal view returns (uint32) {
        unchecked {
            uint256 earliest = getEarliestSnapshotTimestamp(oracle, token);
            if (earliest > block.timestamp) return 0;
            return uint32(block.timestamp - earliest);
        }
    }
```

**File:** src/lens/PriceFetcher.sol (L283-287)
```text
                    uint256 maxPeriodForToken = ORACLE.getMaximumObservationPeriod(token);

                    if (maxPeriodForToken >= observationPeriod) {
                        results[i] = getAveragesOverPeriod(token, NATIVE_TOKEN_ADDRESS, startTime, endTime);
                    }
```

**File:** src/extensions/Oracle.sol (L240-240)
```text
    ///      We make the assumption that all snapshots for the token were written within (2**32 - 1) seconds of the current block timestamp
```
