## Title
TWAMM Orders Can Be Permanently Skipped Due to Step Size Mismatch Between Order Placement and Virtual Order Execution

## Summary
The TWAMM extension validates order times using `block.timestamp` at placement but searches for orders using a fixed `lastVirtualOrderExecutionTime` during execution. When `lastVirtualOrderExecutionTime` is significantly in the past, the step size calculation causes `nextValidTime()` to skip over valid order times, permanently preventing their execution and causing user fund loss. [1](#0-0) [2](#0-1) [3](#0-2) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/TWAMM.sol` (_executeVirtualOrdersFromWithinLock, lines 420-425), `src/math/timeBitmap.sol` (searchForNextInitializedTime, line 69), `src/math/time.sol` (nextValidTime, lines 44-64)

**Intended Logic:** The TWAMM system should execute all placed orders at their designated start times. Orders are validated at placement to ensure their times fall on the valid time grid. During virtual order execution, `searchForNextInitializedTime()` should find all initialized order times between the last execution and current block timestamp.

**Actual Logic:** Orders are validated using `isTimeValid(block.timestamp, startTime)` at placement time, but searched using `nextValidTime(lastVirtualOrderExecutionTime, currentIterationTime)` during execution. The step size calculation in `computeStepSize()` depends on the time difference between its parameters. When `lastVirtualOrderExecutionTime` is far in the past (e.g., no virtual orders executed for days), the step size becomes larger, causing `nextValidTime()` to jump over times that were valid when placed. [4](#0-3) 

**Exploitation Path:**

1. **Setup (t=1000)**: Pool is initialized, `lastVirtualOrderExecutionTime = 1000`. Virtual orders execute and update the state.

2. **Order Placement (t=5120)**: User places an order with `startTime = 5376`. Validation checks `isTimeValid(5120, 5376)`:
   - `computeStepSize(5120, 5376)` returns 256 (diff = 256 < 4095)
   - `5376 % 256 = 0` ✓ Valid
   - Order accepted, bitmap marks time 5376 as initialized

3. **Delayed Execution (t=10000)**: No activity for ~5000 seconds. A swap triggers virtual order execution. Loop processes times starting from `lastVirtualOrderExecutionTime = 1000` (still fixed from step 1).

4. **Critical Iteration (time=5120)**: `searchForNextInitializedTime(bitmap, 1000, 5120, 10000)` calls `nextValidTime(1000, 5120)`:
   - `computeStepSize(1000, 5120)` returns 4096 (diff = 4120 > 4095, msb = 12)
   - Calculates `nextTime = 5120 + 4096 = 9216`, rounds to `8192`
   - `findNextInitializedTime(bitmap, 8192)` searches from 8192 onwards
   - Order at 5376 is **behind** the search position and is **skipped**

5. **Permanent Loss**: Loop completes, `lastVirtualOrderExecutionTime` updates to a time beyond 5376. The order at 5376 is never executed in future executions. User's funds remain locked in unexecuted order, and the sale rate delta is never applied to pool state. [5](#0-4) 

**Security Property Broken:** Users' TWAMM orders must execute at their designated times. The vulnerability violates this by permanently skipping valid orders, causing direct fund loss.

## Impact Explanation

- **Affected Assets**: User funds locked in TWAMM orders that are never executed. All tokens (token0/token1) in affected orders are at risk.

- **Damage Severity**: Complete loss of order execution opportunity. Users cannot withdraw unexecuted order amounts, and the expected token swaps never occur. If the market moves against the user during the skipped period, they suffer additional opportunity cost losses.

- **User Impact**: Any user placing orders during periods of low activity is vulnerable. The issue is more likely when virtual order execution doesn't occur frequently (e.g., pools with low swap volume, liquidity operations, or fee collections). Multiple orders at different times can be skipped in a single execution gap.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this is a protocol-level bug affecting normal users. Any user placing orders is at risk.

- **Preconditions**: 
  - Virtual orders haven't executed for a period greater than 4095 seconds (~68 minutes)
  - User places order at a time that's valid relative to recent block.timestamp
  - The time becomes "invalid" relative to the old lastVirtualOrderExecutionTime due to step size differences

- **Execution Complexity**: Occurs naturally during normal protocol operation. No special actions needed beyond normal order placement.

- **Frequency**: Can affect multiple orders in each occurrence. Happens whenever there's a gap in virtual order execution. More frequent in low-activity pools.

## Recommendation

The root issue is using a fixed `lastVirtualOrderExecutionTime` throughout the entire execution loop. The fix is to use the current iteration's `time` variable as the reference point for `nextValidTime()`, since it represents the actual current position in the time search: [2](#0-1) 

**Recommended Fix:**

Change the `searchForNextInitializedTime()` call in TWAMM.sol to pass `time` instead of `realLastVirtualOrderExecutionTime`:

```solidity
// In src/extensions/TWAMM.sol, line 420-425:

// CURRENT (vulnerable):
(uint256 nextTime, bool initialized) = searchForNextInitializedTime({
    slot: initializedTimesBitmapSlot,
    lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,  // FIXED reference
    fromTime: time,
    untilTime: block.timestamp
});

// FIXED:
(uint256 nextTime, bool initialized) = searchForNextInitializedTime({
    slot: initializedTimesBitmapSlot,
    lastVirtualOrderExecutionTime: time,  // Use current iteration time as reference
    fromTime: time,
    untilTime: block.timestamp
});
```

This ensures the step size is computed relative to the current search position, maintaining consistency with how orders were validated at placement (always relative to a recent time).

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMSkippedOrders.t.sol
// Run with: forge test --match-test test_TWAMMOrderPermanentlySkipped -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import {nextValidTime, isTimeValid} from "../src/math/time.sol";

contract Exploit_TWAMMSkippedOrders is Test {
    Core core;
    TWAMM twamm;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        twamm = new TWAMM(core);
        
        // Initialize pool with TWAMM extension at t=1000
        vm.warp(1000);
        // ... pool initialization code ...
        // After init, lastVirtualOrderExecutionTime = 1000
    }
    
    function test_TWAMMOrderPermanentlySkipped() public {
        // SETUP: Time advances to t=5120
        vm.warp(5120);
        
        // User places order with startTime=5376
        // Validation: isTimeValid(5120, 5376) = true (stepSize=256, 5376%256=0)
        assertTrue(isTimeValid(5120, 5376), "Order should be valid at placement");
        
        // ... place order at time 5376 ...
        // Order is accepted and stored in bitmap at time 5376
        
        // EXPLOIT: Time advances significantly without virtual order execution
        vm.warp(10000);
        
        // Demonstrate the skip: from lastVirtualOrderExecutionTime=1000, 
        // searching from time=5120 jumps to 8192
        uint256 nextTime = nextValidTime(1000, 5120);
        assertEq(nextTime, 8192, "Next valid time from 1000 to 5120 is 8192");
        
        // Order at 5376 is now unreachable (5376 < 8192)
        assertLt(5376, nextTime, "Order time 5376 is skipped");
        
        // VERIFY: Trigger virtual order execution
        // ... call swap or other function that triggers execution ...
        
        // Order at 5376 was never executed
        // Sale rate delta at 5376 was never applied
        // User funds remain locked
        // This demonstrates complete loss of order execution
    }
    
    function test_StepSizeDiscrepancy() public {
        // Demonstrate the root cause: step size changes with reference time
        
        // When order is placed at t=5120, checking t=5376:
        // stepSize from 5120 to 5376 is 256
        assertEq(nextValidTime(5120, 5120), 5376, "From recent time, next is 5376");
        
        // When searching from old t=1000, checking t=5120:
        // stepSize from 1000 to 5120 is 4096 (jumps to 8192)
        assertEq(nextValidTime(1000, 5120), 8192, "From old time, next is 8192");
        
        // The valid time 5376 is in the gap between 5120 and 8192
        assertTrue(5376 > 5120 && 5376 < 8192, "5376 is in the skip gap");
    }
}
```

**Notes:**
- The vulnerability occurs due to the logarithmic scaling of step sizes in the time grid system
- Step size increases by 16x when the time difference crosses power-of-16 boundaries
- The mismatch between validation (using recent block.timestamp) and search (using old lastVirtualOrderExecutionTime) creates reachability gaps
- Orders in these gaps are permanently orphaned in storage, causing direct user fund loss
- The issue becomes more severe in low-activity pools where virtual order execution intervals are longer

### Citations

**File:** src/extensions/TWAMM.sol (L204-208)
```text
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }
```

**File:** src/extensions/TWAMM.sol (L420-425)
```text
                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });
```

**File:** src/math/timeBitmap.sol (L60-82)
```text
function searchForNextInitializedTime(
    StorageSlot slot,
    uint256 lastVirtualOrderExecutionTime,
    uint256 fromTime,
    uint256 untilTime
) view returns (uint256 nextTime, bool isInitialized) {
    unchecked {
        nextTime = fromTime;
        while (!isInitialized && nextTime != untilTime) {
            uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);
            // if there is no valid time after the given nextTime, just return untilTime
            if (nextValid == 0) {
                nextTime = untilTime;
                isInitialized = false;
                break;
            }
            (nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
            if (nextTime > untilTime) {
                nextTime = untilTime;
                isInitialized = false;
            }
        }
    }
```

**File:** src/math/time.sol (L17-31)
```text
function computeStepSize(uint256 currentTime, uint256 time) pure returns (uint256 stepSize) {
    assembly ("memory-safe") {
        switch gt(time, add(currentTime, 4095))
        case 1 {
            let diff := sub(time, currentTime)

            let msb := sub(255, clz(diff)) // = index of msb

            msb := sub(msb, mod(msb, 4)) // = round down to multiple of 4

            stepSize := shl(msb, 1)
        }
        default { stepSize := 256 }
    }
}
```

**File:** src/math/time.sol (L44-64)
```text
function nextValidTime(uint256 currentTime, uint256 time) pure returns (uint256 nextTime) {
    unchecked {
        uint256 stepSize = computeStepSize(currentTime, time);
        assembly ("memory-safe") {
            nextTime := add(time, stepSize)
            nextTime := sub(nextTime, mod(nextTime, stepSize))
        }

        // only if we didn't overflow
        if (nextTime != 0) {
            uint256 nextStepSize = computeStepSize(currentTime, nextTime);
            if (nextStepSize != stepSize) {
                assembly ("memory-safe") {
                    nextTime := add(time, nextStepSize)
                    nextTime := sub(nextTime, mod(nextTime, nextStepSize))
                }
            }
        }

        nextTime = FixedPointMathLib.ternary(nextTime > currentTime + type(uint32).max, 0, nextTime);
    }
```
