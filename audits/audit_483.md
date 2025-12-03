## Title
Revenue Buyback Order Extension Logic Broken by Maximum lastOrderDuration Value

## Summary
The `RevenueBuybacks.roll()` function's order extension condition can become permanently satisfied when `lastOrderDuration` approaches `type(uint32).max`, preventing the creation of properly configured new orders and causing orders to be created with incorrect far-future endTimes due to uint32 underflow arithmetic.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (function `roll()`, lines 105-131) [1](#0-0) 

**Intended Logic:** The order extension condition is designed to reuse an existing order's endTime when:
1. The fee hasn't changed
2. Time remaining is at least the minimum duration
3. Time remaining doesn't exceed the last order duration

When an order ends, `timeRemaining` should underflow to a value greater than `lastOrderDuration`, causing the condition to fail and triggering creation of a new order with fresh parameters. [2](#0-1) 

**Actual Logic:** When `targetOrderDuration` is configured close to `type(uint32).max`, the resulting `lastOrderDuration` also approaches `type(uint32).max`. After the order ends:

1. `timeRemaining = state.lastEndTime() - uint32(block.timestamp)` underflows to a large uint32 value
2. The condition `timeRemaining <= state.lastOrderDuration()` remains TRUE even after underflow, since any uint32 value is ≤ `type(uint32).max`
3. The system incorrectly enters the "reuse" branch (line 114) instead of creating a new order
4. `endTime = uint64(block.timestamp + timeRemaining)` uses the underflowed `timeRemaining`, producing a far-future timestamp
5. The state update in lines 119-130 never executes, so `lastOrderDuration` remains at its maximum value permanently [3](#0-2) 

**Exploitation Path:**
1. Owner configures a token with `targetOrderDuration` close to `type(uint32).max` (e.g., `type(uint32).max - 10000`)
2. First `roll()` call creates an order where `lastOrderDuration ≈ type(uint32).max` is stored
3. Order eventually ends (block.timestamp > lastEndTime)
4. Subsequent `roll()` calls calculate `timeRemaining` via underflow: `lastEndTime - uint32(block.timestamp)`, resulting in a large value
5. Since `timeRemaining ≤ type(uint32).max` is always true, the extension condition passes
6. `endTime = block.timestamp + (underflowed timeRemaining)` creates orders with incorrect, far-future endTimes (potentially 100+ years in the future)
7. The state never updates to create properly configured new orders based on `targetOrderDuration` [4](#0-3) 

**Security Property Broken:** The protocol's revenue buyback mechanism fails to create orders with the owner-configured `targetOrderDuration`, violating the intended economic design where order durations should be controlled and predictable.

## Impact Explanation
- **Affected Assets**: All revenue tokens configured with `targetOrderDuration` values that result in `lastOrderDuration ≈ type(uint32).max`
- **Damage Severity**: Orders are created with incorrect durations extending decades or centuries into the future instead of the intended duration. This completely breaks the economic model of gradual revenue buybacks over controlled timeframes. Revenue remains locked in extremely long-duration orders that cannot execute as intended.
- **User Impact**: The protocol owner loses control over buyback timing and strategy. Revenue that should be gradually bought back over days/weeks/months instead gets locked in orders spanning 100+ years. This effectively freezes protocol revenue indefinitely.

## Likelihood Explanation
- **Attacker Profile**: The protocol owner can trigger this by misconfiguring `targetOrderDuration`, though they may not realize the consequence. No external attacker required - this is a design flaw.
- **Preconditions**: Token must be configured with `targetOrderDuration` such that the actual order duration approaches `type(uint32).max` (e.g., values greater than `type(uint32).max - 268435456` due to step size rounding)
- **Execution Complexity**: Single misconfiguration, then automatic on every `roll()` call
- **Frequency**: Permanent once triggered - all subsequent orders for that token will have incorrect durations

## Recommendation

**Fix Option 1: Add maximum bound validation in configure()**
```solidity
// In src/RevenueBuybacks.sol, function configure(), after line 151:

function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
    external
    onlyOwner
{
    if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
    if (minOrderDuration == 0 && targetOrderDuration != 0) {
        revert MinOrderDurationMustBeGreaterThanZero();
    }
    
    // ADD THIS CHECK:
    // Prevent targetOrderDuration values that could cause lastOrderDuration to approach uint32.max
    // Due to step size rounding, durations >= type(uint32).max - 268435456 are problematic
    if (targetOrderDuration > type(uint32).max - 268435456) {
        revert TargetOrderDurationTooLarge();
    }
    
    // ... rest of function
}
```

**Fix Option 2: Fix the extension condition logic**
```solidity
// In src/RevenueBuybacks.sol, function roll(), replace lines 109-112:

// CURRENT (vulnerable):
if (
    state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
        && timeRemaining <= state.lastOrderDuration()
) {

// FIXED - Check if order has actually ended first:
// If lastEndTime is in the past, block.timestamp > lastEndTime, so the cast will not underflow
bool orderStillActive = uint32(block.timestamp) < state.lastEndTime();
if (
    orderStillActive && state.fee() == state.lastFee() 
    && timeRemaining >= state.minOrderDuration()
    && timeRemaining <= state.lastOrderDuration()
) {
```

**Recommended approach**: Implement **both** fixes for defense in depth.

## Proof of Concept
```solidity
// File: test/Exploit_MaxDurationBrick.t.sol
// Run with: forge test --match-test test_MaxDurationBrick -vvv

pragma solidity ^0.8.31;

import "./RevenueBuybacks.t.sol";

contract Exploit_MaxDurationBrick is RevenueBuybacksTest {
    function test_MaxDurationBrick() public {
        uint64 poolFee = uint64((uint256(1) << 64) / 100);
        
        // Owner configures with targetOrderDuration close to uint32.max
        // This will result in lastOrderDuration approaching uint32.max
        uint32 targetOrderDuration = type(uint32).max - 100000; // ~136 years
        uint32 minOrderDuration = 1000;
        
        rb.configure({
            token: address(token0),
            targetOrderDuration: targetOrderDuration,
            minOrderDuration: minOrderDuration,
            fee: poolFee
        });
        
        // Setup pool with liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: poolFee})
        });
        
        positions.maybeInitializePool(poolKey, 0);
        token0.approve(address(positions), 1e18);
        buybacksToken.approve(address(positions), 1e18);
        positions.mintAndDeposit(poolKey, MIN_TICK, MAX_TICK, 1e18, 1e18, 0);
        
        rb.approveMax(address(token0));
        donate(address(token0), 1e18);
        
        // First roll - creates order with large lastOrderDuration
        (uint64 endTime1, ) = rb.roll(address(token0));
        uint256 firstOrderStartTime = block.timestamp;
        
        BuybacksState state1 = rb.state(address(token0));
        uint32 lastOrderDuration1 = state1.lastOrderDuration();
        uint32 lastEndTime1 = state1.lastEndTime();
        
        // Verify lastOrderDuration is very large
        assertGt(lastOrderDuration1, type(uint32).max / 2, "lastOrderDuration should be huge");
        
        // Warp to after the order theoretically ends
        // Note: the actual endTime might be far in future, but lastEndTime is uint32
        vm.warp(firstOrderStartTime + lastOrderDuration1 + 1000);
        
        donate(address(token0), 1e18);
        
        // Second roll - SHOULD create NEW order, but BUG causes reuse with wrong endTime
        uint256 secondRollTime = block.timestamp;
        (uint64 endTime2, ) = rb.roll(address(token0));
        
        // Check that state was NOT updated (this is the bug!)
        BuybacksState state2 = rb.state(address(token0));
        uint32 lastOrderDuration2 = state2.lastOrderDuration();
        uint32 lastEndTime2 = state2.lastEndTime();
        
        // BUG: lastOrderDuration should have been updated to targetOrderDuration, but wasn't
        assertEq(lastOrderDuration2, lastOrderDuration1, "BUG: lastOrderDuration not updated");
        assertEq(lastEndTime2, lastEndTime1, "BUG: lastEndTime not updated");
        
        // BUG: endTime2 is calculated with underflowed arithmetic
        // It should be ~targetOrderDuration in the future, but it's way off
        uint64 expectedEndTime = uint64(secondRollTime + targetOrderDuration);
        
        // The actual endTime will be far different due to underflow
        // endTime = block.timestamp + (underflowed timeRemaining)
        uint64 gap = endTime2 > expectedEndTime ? endTime2 - expectedEndTime : expectedEndTime - endTime2;
        
        // Gap should be massive (billions of seconds difference)
        assertGt(gap, type(uint32).max / 4, "BUG: endTime calculated incorrectly due to underflow");
        
        // Third roll - same issue persists
        vm.warp(block.timestamp + 10000);
        donate(address(token0), 1e18);
        (uint64 endTime3, ) = rb.roll(address(token0));
        
        BuybacksState state3 = rb.state(address(token0));
        
        // State STILL not updated
        assertEq(state3.lastOrderDuration(), lastOrderDuration1, "BUG persists: state never updates");
    }
}
```

## Notes

The vulnerability stems from the interaction between uint32 arithmetic underflow and the boundary condition `timeRemaining <= state.lastOrderDuration()`. When `lastOrderDuration` approaches the maximum uint32 value, this condition becomes nearly impossible to fail after an underflow occurs, permanently locking the system into the "reuse" code path.

The step size calculation in `computeStepSize()` uses logarithmic scaling, where durations near `type(uint32).max` have step sizes of ~268 million seconds (8.5 years). This means any `targetOrderDuration` configured above approximately `type(uint32).max - 268435456` can trigger this vulnerability after rounding. [5](#0-4) 

The protocol appears to have anticipated normal underflow scenarios in the comment at lines 107-108, but failed to account for the edge case where `lastOrderDuration` itself is at the maximum boundary, making the protective underflow check ineffective.

### Citations

**File:** src/RevenueBuybacks.sol (L105-131)
```text
            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
            // if the fee changed, or the amount of time exceeds the min order duration
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
                // handles overflow
                endTime = uint64(block.timestamp + timeRemaining);
            } else {
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));

                state = createBuybacksState({
                    _targetOrderDuration: state.targetOrderDuration(),
                    _minOrderDuration: state.minOrderDuration(),
                    _fee: state.fee(),
                    _lastEndTime: uint32(endTime),
                    _lastOrderDuration: uint32(endTime - block.timestamp),
                    _lastFee: state.fee()
                });

                assembly ("memory-safe") {
                    sstore(token, state)
                }
            }
```

**File:** src/types/buybacksState.sol (L41-45)
```text
function lastOrderDuration(BuybacksState state) pure returns (uint32 duration) {
    assembly ("memory-safe") {
        duration := and(shr(160, state), 0xFFFFFFFF)
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

**File:** src/math/time.sol (L42-64)
```text
/// @dev Returns the next valid time if there is one, or wraps around to the time 0 if there is not
///      Assumes currentTime is less than type(uint256).max - type(uint32).max
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
