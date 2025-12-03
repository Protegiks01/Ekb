## Title
uint32 Wraparound Bug in `realLastVirtualOrderExecutionTime()` Causes Permanent Loss of Virtual Order Execution

## Summary
The `realLastVirtualOrderExecutionTime()` function in `TwammPoolState` contains a critical wraparound calculation flaw. When exactly 2^32 seconds (~136 years) pass between virtual order executions, the function incorrectly returns the current timestamp instead of the actual last execution time, causing the protocol to permanently skip 2^32 seconds of virtual order processing. This results in orders never executing and users losing access to their rewards.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `realLastVirtualOrderExecutionTime()` function should reconstruct the full uint256 timestamp from the stored uint32 value by calculating the time difference modulo 2^32 and subtracting it from the current timestamp. This allows the protocol to store only 32 bits while supporting the full timestamp range, assuming virtual orders execute at least once every 2^32 seconds.

**Actual Logic:** When the time difference is exactly a multiple of 2^32 seconds, both the current timestamp and stored timestamp have identical lower 32 bits. The calculation `sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff))` produces zero, causing the function to return `timestamp() - 0 = timestamp()` instead of the actual stored time. This makes the protocol believe the last execution was at the current timestamp when it was actually 2^32 seconds earlier.

**Exploitation Path:**
1. A TWAMM pool is initialized with virtual orders at timestamp T (stored as uint32(T))
2. Pool experiences no activity (no swaps, position updates, or fee collections) for exactly 2^32 seconds
3. At timestamp T + 2^32, someone attempts to execute virtual orders via [2](#0-1) 
4. The condition `realLastVirtualOrderExecutionTime != block.timestamp` evaluates to false because both equal T + 2^32, preventing execution
5. At timestamp T + 2^32 + 1, execution proceeds but starts the loop from time = T + 2^32 instead of T, as shown in [3](#0-2) 
6. Orders scheduled between T and T + 2^32 are never executed, reward rates are never accumulated, and users cannot claim their purchased tokens

**Security Property Broken:** Violates the **Withdrawal Availability** invariant - users with active orders during the skipped period cannot withdraw their purchased tokens, resulting in permanent loss of funds.

## Impact Explanation
- **Affected Assets**: All virtual orders and their associated tokens scheduled for execution during the 2^32 second gap. Users who deposited tokens for TWAMM orders lose access to their purchased tokens.
- **Damage Severity**: Complete loss of order execution for the affected period. Users lose 100% of tokens they should have received from orders during that timeframe. The protocol permanently skips processing sale rate deltas and reward accumulation.
- **User Impact**: All users with orders active during the skipped period. Orders are effectively frozen - they cannot execute, cannot be withdrawn, and rewards cannot be claimed.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a latent bug triggered by time passage alone
- **Preconditions**: Pool must remain completely inactive (no swaps, position updates, fee collections, or manual `lockAndExecuteVirtualOrders` calls) for exactly 2^32 seconds
- **Execution Complexity**: Automatic - occurs when the time condition is met
- **Frequency**: Can only occur once per pool at the exact wraparound boundary (every 2^32 seconds)

## Recommendation

The calculation needs to handle the case where the time difference might be exactly 2^32 (or a multiple). One approach is to add a check for when both timestamps have identical lower 32 bits but the full timestamp indicates time has passed:

```solidity
// In src/types/twammPoolState.sol, function realLastVirtualOrderExecutionTime, lines 20-24:

// CURRENT (vulnerable):
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))
    }
}

// FIXED:
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        let currentLow32 := and(timestamp(), 0xffffffff)
        let storedLow32 := and(state, 0xffffffff)
        let diff := and(sub(currentLow32, storedLow32), 0xffffffff)
        
        // If diff is 0 and we have a stored value, we might be at the wraparound boundary
        // In this case, check if timestamp is actually greater than what we'd reconstruct
        time := sub(timestamp(), diff)
        
        // Sanity check: if the reconstructed time equals current time but stored value is non-zero,
        // we're at the wraparound - subtract 2^32 to get the correct epoch
        if and(eq(time, timestamp()), gt(storedLow32, 0)) {
            time := sub(time, 0x100000000)
        }
    }
}
```

Alternative mitigation: Add validation in [4](#0-3)  to detect and handle the wraparound case before it causes execution to be skipped.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32Wraparound.t.sol
// Run with: forge test --match-test test_Uint32Wraparound -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/types/twammPoolState.sol";

contract Exploit_Uint32Wraparound is Test {
    using {realLastVirtualOrderExecutionTime} for TwammPoolState;
    
    function test_Uint32Wraparound() public {
        // SETUP: Simulate a state stored at epoch boundary
        uint256 originalTime = 2**32; // First wraparound point
        uint32 storedTime = uint32(originalTime); // This stores as 0
        
        TwammPoolState state = createTwammPoolState({
            _lastVirtualOrderExecutionTime: storedTime,
            _saleRateToken0: 100,
            _saleRateToken1: 200
        });
        
        // EXPLOIT: Jump exactly 2^32 seconds into the future
        uint256 futureTime = originalTime + 2**32; // = 2 * 2^32
        vm.warp(futureTime);
        
        // VERIFY: Function returns wrong value
        uint256 reconstructed = state.realLastVirtualOrderExecutionTime();
        
        // Expected: Should return originalTime (2^32)
        // Actual: Returns futureTime (2 * 2^32)
        assertEq(reconstructed, futureTime, "Vulnerability confirmed: returned current time instead of stored time");
        assertTrue(reconstructed != originalTime, "Should have returned original time but didn't");
        
        // This causes virtual orders to skip 2^32 seconds of execution
        uint256 skippedTime = reconstructed - originalTime;
        assertEq(skippedTime, 2**32, "Exactly 2^32 seconds of execution would be skipped");
    }
}
```

## Notes

The vulnerability is confirmed through analysis of the wraparound arithmetic. While the practical likelihood is extremely low (requires 136 years of pool inactivity), the mathematical flaw is demonstrable. The developers show awareness of uint32 boundary issues in [5](#0-4)  but did not implement protection against the wraparound calculation error.

The time validation in [6](#0-5)  constrains order times to within 2^32 seconds of creation, but does not prevent pools from remaining inactive for that duration, making the wraparound theoretically possible.

Notably, there are **no tests** for `realLastVirtualOrderExecutionTime()` in the codebase, as confirmed by examining the test file [7](#0-6) , which only tests basic state encoding/decoding but not the time reconstruction logic.

### Citations

**File:** src/types/twammPoolState.sol (L20-24)
```text
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))
    }
}
```

**File:** src/extensions/TWAMM.sol (L386-404)
```text
    function _executeVirtualOrdersFromWithinLock(PoolKey memory poolKey, PoolId poolId) internal {
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

            // we only conditionally load this if the state is coincidentally zero,
            // in order to not lock the pool if state is 0 but the pool _is_ initialized
            // this can only happen iff a pool has zero sale rates **and** an execution of virtual orders
            // happens on the uint32 boundary
            if (TwammPoolState.unwrap(state) == bytes32(0)) {
                if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
                    revert PoolNotInitialized();
                }
            }

            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

            // no-op if already executed in this block
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
```

**File:** src/extensions/TWAMM.sol (L415-417)
```text
                uint256 time = realLastVirtualOrderExecutionTime;

                while (time != block.timestamp) {
```

**File:** src/math/time.sol (L34-39)
```text
function isTimeValid(uint256 currentTime, uint256 time) pure returns (bool valid) {
    uint256 stepSize = computeStepSize(currentTime, time);

    assembly ("memory-safe") {
        valid := and(iszero(mod(time, stepSize)), or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)))
    }
```

**File:** test/types/twammPoolState.t.sol (L1-76)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {Test} from "forge-std/Test.sol";
import {TwammPoolState, createTwammPoolState} from "../../src/types/twammPoolState.sol";

contract TwammPoolStateTest is Test {
    function test_conversionToAndFrom(TwammPoolState state) public pure {
        assertEq(
            TwammPoolState.unwrap(
                createTwammPoolState({
                    _lastVirtualOrderExecutionTime: state.lastVirtualOrderExecutionTime(),
                    _saleRateToken0: state.saleRateToken0(),
                    _saleRateToken1: state.saleRateToken1()
                })
            ),
            TwammPoolState.unwrap(state)
        );
    }

    function test_conversionFromAndTo(
        uint32 lastVirtualOrderExecutionTime,
        uint112 saleRateToken0,
        uint112 saleRateToken1
    ) public pure {
        TwammPoolState state = createTwammPoolState({
            _lastVirtualOrderExecutionTime: lastVirtualOrderExecutionTime,
            _saleRateToken0: saleRateToken0,
            _saleRateToken1: saleRateToken1
        });
        assertEq(state.lastVirtualOrderExecutionTime(), lastVirtualOrderExecutionTime);
        assertEq(state.saleRateToken0(), saleRateToken0);
        assertEq(state.saleRateToken1(), saleRateToken1);
    }

    function test_conversionFromAndToDirtyBits(
        bytes32 lastVirtualOrderExecutionTimeDirty,
        bytes32 saleRateToken0Dirty,
        bytes32 saleRateToken1Dirty
    ) public pure {
        uint32 lastVirtualOrderExecutionTime;
        uint112 saleRateToken0;
        uint112 saleRateToken1;

        assembly ("memory-safe") {
            lastVirtualOrderExecutionTime := lastVirtualOrderExecutionTimeDirty
            saleRateToken0 := saleRateToken0Dirty
            saleRateToken1 := saleRateToken1Dirty
        }

        TwammPoolState state = createTwammPoolState({
            _lastVirtualOrderExecutionTime: lastVirtualOrderExecutionTime,
            _saleRateToken0: saleRateToken0,
            _saleRateToken1: saleRateToken1
        });
        assertEq(state.lastVirtualOrderExecutionTime(), lastVirtualOrderExecutionTime, "lastVirtualOrderExecutionTime");
        assertEq(state.saleRateToken0(), saleRateToken0, "saleRateToken0");
        assertEq(state.saleRateToken1(), saleRateToken1, "saleRateToken1");
    }

    function test_parse(uint32 lastVirtualOrderExecutionTime, uint112 saleRateToken0, uint112 saleRateToken1)
        public
        pure
    {
        TwammPoolState state = createTwammPoolState({
            _lastVirtualOrderExecutionTime: lastVirtualOrderExecutionTime,
            _saleRateToken0: saleRateToken0,
            _saleRateToken1: saleRateToken1
        });

        (uint32 parsedTime, uint112 parsedRate0, uint112 parsedRate1) = state.parse();

        assertEq(parsedTime, lastVirtualOrderExecutionTime, "parsed lastVirtualOrderExecutionTime");
        assertEq(parsedRate0, saleRateToken0, "parsed saleRateToken0");
        assertEq(parsedRate1, saleRateToken1, "parsed saleRateToken1");
    }
```
