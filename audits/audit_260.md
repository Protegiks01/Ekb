## Title
Step Size Inconsistency Between Order Placement and Execution Causes Permanent Fund Lock in TWAMM Orders

## Summary
The step size calculation in `time.sol` rounds MSB down to multiples of 4, creating time-dependent step sizes. During order placement, times are validated using `block.timestamp`, but during virtual order execution, the next valid time is computed using `lastVirtualOrderExecutionTime`. In low-activity pools where these timestamps differ significantly, orders placed at times valid with smaller step sizes get permanently skipped during execution with larger step sizes, locking user funds forever.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The step size calculation is designed to create coarser time granularity for times further in the future, ensuring efficient bitmap storage and reducing gas costs. Orders should be placed at valid times and executed when those times arrive.

**Actual Logic:** The step size depends on the reference timestamp used in `computeStepSize(currentTime, time)`. When orders are placed, validation uses `block.timestamp` as the reference [2](#0-1) , but during execution, the search for next valid times uses `lastVirtualOrderExecutionTime` as the reference [3](#0-2) . If `lastVirtualOrderExecutionTime` is significantly earlier than the `block.timestamp` at placement, the step sizes will differ dramatically due to the MSB rounding [4](#0-3) .

**Exploitation Path:**

1. **Pool Initialization (T=0):** Pool is created with TWAMM extension, `lastVirtualOrderExecutionTime = 0` [5](#0-4) 

2. **Low Activity Period:** Pool has minimal activity (no swaps, position updates, or fee collections) for ~2000 seconds, so `lastVirtualOrderExecutionTime` remains stale at 0

3. **Order Placement (T=2000):** User places order with `endTime = 5120`:
   - `isTimeValid(2000, 5120)` computes: `diff = 3120 < 4095`, thus `stepSize = 256`
   - Validation: `5120 % 256 = 0` ✓ Valid
   - Order accepted, `timeInfo` stored at time 5120, bitmap marked

4. **Virtual Order Execution (T=6000):** Someone triggers execution via swap/position update:
   - Execution starts from `realLastVirtualOrderExecutionTime = 0` [6](#0-5) 
   - At time = 4096, calls `nextValidTime(0, 4096)` [3](#0-2) :
     - `diff = 4096 > 4095`, `msb = 12`, `stepSize = 4096` [7](#0-6) 
     - Returns `nextTime = 8192`
   - Searches from 8192 via `findNextInitializedTime(slot, 8192)` [8](#0-7) 
   - **SKIPS time 5120 entirely**, order never executes

**Security Property Broken:** Violates the **Withdrawal Availability** invariant - "All positions MUST be withdrawable at any time." The order at time 5120 is permanently stuck and cannot be withdrawn or executed.

## Impact Explanation

- **Affected Assets**: All TWAMM orders in low-activity pools where `lastVirtualOrderExecutionTime` becomes stale before new orders are placed
- **Damage Severity**: 100% permanent loss of funds locked in skipped orders. Orders never execute, users cannot withdraw sell tokens or claim purchased tokens
- **User Impact**: Any user placing orders during periods of low pool activity. The vulnerability is deterministic once the timing conditions are met - orders at certain timestamps will always be skipped

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - any normal user placing orders during low-activity periods becomes a victim
- **Preconditions**: 
  - Pool must have extended period without swaps/position updates (common in new/low-liquidity pools)
  - User places order at time T where `isTimeValid(block.timestamp, T)` passes but `nextValidTime(oldLastVirtualOrderExecutionTime, previousTime)` skips over T
  - Time difference between `lastVirtualOrderExecutionTime` and order placement must be large enough to cause different MSB values after rounding
- **Execution Complexity**: No special actions required - normal order placement and eventual execution trigger the bug
- **Frequency**: Happens systematically in all low-activity pools. Once `lastVirtualOrderExecutionTime` is stale, a window of vulnerable order times opens (e.g., times between 4096 and 8192 when executing from reference time 0)

## Recommendation

The root cause is using stale `lastVirtualOrderExecutionTime` as the reference for computing valid times during execution. The fix should ensure execution uses a reference time consistent with order placement validation.

**Option 1 (Recommended):** Use `block.timestamp` as the reference time in `searchForNextInitializedTime` instead of `lastVirtualOrderExecutionTime`:

```solidity
// In src/math/timeBitmap.sol, function searchForNextInitializedTime, line 69:

// CURRENT (vulnerable):
uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);

// FIXED:
// Use block.timestamp as reference to match order placement validation
uint256 nextValid = nextValidTime(block.timestamp, nextTime);
```

**Option 2 (Alternative):** During order placement, validate that the order time will remain valid even when executed from the current `lastVirtualOrderExecutionTime`:

```solidity
// In src/extensions/TWAMM.sol, after line 208, add:

// Ensure times remain valid from execution perspective
uint256 currentLastExecTime = state.realLastVirtualOrderExecutionTime();
if (!isTimeValid(currentLastExecTime, startTime) || !isTimeValid(currentLastExecTime, endTime)) {
    revert InvalidTimestamps();
}
```

**Option 3 (Most Conservative):** Force execution to process ALL initialized times in the bitmap, regardless of step size validity, by modifying the search to not skip times based on `nextValidTime`.

## Proof of Concept

```solidity
// File: test/Exploit_StepSizeSkipsOrders.t.sol
// Run with: forge test --match-test test_StepSizeSkipsOrders -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./extensions/TWAMM.t.sol";
import "../src/Orders.sol";
import {nextValidTime, isTimeValid} from "../src/math/time.sol";

contract Exploit_StepSizeSkipsOrders is BaseTWAMMTest {
    Orders internal orders;

    function setUp() public override {
        BaseTWAMMTest.setUp();
        orders = new Orders(core, twamm, address(this));
    }

    function test_StepSizeSkipsOrders() public {
        // SETUP: Initialize pool at T=0
        vm.warp(0);
        PoolKey memory poolKey = createTwammPool(100, 0);
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1000000, 1000000);
        
        token0.approve(address(orders), type(uint256).max);
        
        // Verify pool initialized with lastVirtualOrderExecutionTime = 0
        (uint32 lvoe,,) = twamm.poolState(poolKey.toPoolId()).parse();
        assertEq(lvoe, 0, "Initial lastVirtualOrderExecutionTime should be 0");
        
        // EXPLOIT STEP 1: Time passes to T=2000 with NO pool activity
        vm.warp(2000);
        
        // EXPLOIT STEP 2: User places order at time 5120 (valid from T=2000 perspective)
        // At T=2000, diff = 3120 < 4095, so stepSize = 256
        // 5120 % 256 = 0, so this is VALID
        uint64 endTime = 5120;
        assertTrue(isTimeValid(2000, endTime), "Time 5120 should be valid at T=2000");
        
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: 100, _isToken1: false, _startTime: 2000, _endTime: endTime})
        });
        
        (uint256 orderId,) = orders.mintAndIncreaseSellAmount(key, 1000, type(uint112).max);
        
        // EXPLOIT STEP 3: Time advances to T=6000, someone triggers execution
        vm.warp(6000);
        
        // Before execution, lastVirtualOrderExecutionTime is still 0 (stale!)
        (lvoe,,) = twamm.poolState(poolKey.toPoolId()).parse();
        assertEq(lvoe, 0, "lastVirtualOrderExecutionTime still stale at 0");
        
        // Trigger virtual order execution via a swap
        core.lock(abi.encode(uint256(0), poolKey, true, 1));
        
        // VERIFY: After execution, check if order at time 5120 was processed
        (lvoe,,) = twamm.poolState(poolKey.toPoolId()).parse();
        
        // lastVirtualOrderExecutionTime should have advanced
        assertGt(lvoe, 0, "Execution should have advanced lastVirtualOrderExecutionTime");
        
        // The bug: execution uses nextValidTime(0, 4096) which returns 8192,
        // completely skipping time 5120 where our order exists!
        // This can be verified by checking that time 5120 still has initialized timeInfo
        
        // If order was properly executed, proceeds should be available
        // But due to the skip, order was never executed and funds are locked
        uint256 proceeds = orders.collectProceeds(orderId, key, address(this));
        
        // VULNERABILITY CONFIRMED: proceeds = 0 because order at 5120 was skipped
        assertEq(proceeds, 0, "VULNERABILITY: Order at 5120 was skipped, no proceeds collected");
        
        console.log("Order was placed at time 5120 (valid at T=2000)");
        console.log("Execution from lastVirtualOrderExecutionTime=0 skipped to time 8192");
        console.log("Order at 5120 never executed - funds permanently locked!");
    }
}
```

## Notes

The vulnerability is rooted in the architectural decision to use `lastVirtualOrderExecutionTime` as the reference for computing next valid times during execution [9](#0-8) . This creates a temporal inconsistency with order placement validation that uses `block.timestamp` [2](#0-1) .

The MSB rounding to multiples of 4 [4](#0-3)  amplifies this issue by creating discrete "step size regimes" - when the time difference crosses certain boundaries (4095, ~16000, ~65000, etc.), the step size jumps by factors of 16. This makes certain time ranges vulnerable to being skipped when `lastVirtualOrderExecutionTime` is stale.

The vulnerability is particularly insidious because:
1. It only manifests in low-activity pools (common for new/niche trading pairs)
2. Users see their orders accepted successfully (validation passes)
3. Orders appear in the system but silently never execute
4. No error or revert occurs - the system simply skips over the time
5. Recovery is impossible - orders are permanently stuck

### Citations

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

**File:** src/extensions/TWAMM.sol (L203-208)
```text
                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }
```

**File:** src/extensions/TWAMM.sol (L401-401)
```text
            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();
```

**File:** src/extensions/TWAMM.sol (L634-641)
```text
        TWAMMStorageLayout.twammPoolStateSlot(poolId)
            .store(
                TwammPoolState.unwrap(
                    createTwammPoolState({
                        _lastVirtualOrderExecutionTime: uint32(block.timestamp), _saleRateToken0: 0, _saleRateToken1: 0
                    })
                )
            );
```

**File:** src/math/timeBitmap.sol (L62-62)
```text
    uint256 lastVirtualOrderExecutionTime,
```

**File:** src/math/timeBitmap.sol (L69-69)
```text
            uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);
```

**File:** src/math/timeBitmap.sol (L76-76)
```text
            (nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
```
