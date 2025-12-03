## Title
State Corruption in RevenueBuybacks.roll() When minOrderDuration Equals type(uint32).max Allows Creation of Far-Future Orders Without State Update

## Summary
The `roll()` function in `RevenueBuybacks.sol` contains a critical edge case where intentional uint32 underflow can bypass proper state management when `minOrderDuration` is set to `type(uint32).max`. [1](#0-0)  When an order ends and `roll()` is called exactly one second later, the underflow value equals `type(uint32).max`, passing the reuse condition but creating a new order with a far-future endTime (~136 years) while leaving the state pointing to the expired order's endTime.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` - `roll()` function (lines 105-137)

**Intended Logic:** The comment at lines 107-108 states that when timeRemaining underflows (order has ended), it will be "greater than min order duration, but also greater than last order duration, so it will not be re-used." [2](#0-1)  The reuse logic at lines 109-114 should only extend existing active orders, not create new orders with different endTimes.

**Actual Logic:** When `minOrderDuration = type(uint32).max` and `lastOrderDuration = type(uint32).max`, the underflow edge case breaks the intended behavior. At exactly `block.timestamp = lastEndTime + 1`, the calculation `timeRemaining = state.lastEndTime() - uint32(block.timestamp)` produces `-1` in uint32 arithmetic, which wraps to `type(uint32).max`. [3](#0-2) 

This passes all reuse conditions [4](#0-3) :
- `timeRemaining >= state.minOrderDuration()` → `type(uint32).max >= type(uint32).max` ✓
- `timeRemaining <= state.lastOrderDuration()` → `type(uint32).max <= type(uint32).max` ✓

The code then sets `endTime = uint64(block.timestamp + timeRemaining)` [5](#0-4) , creating an order ending ~136 years in the future. Critically, the state update at lines 119-130 is SKIPPED because the reuse path was taken, leaving `state.lastEndTime` pointing to the old expired timestamp.

**Exploitation Path:**
1. Owner configures token with `minOrderDuration = type(uint32).max` and `targetOrderDuration = type(uint32).max` [6](#0-5) 
2. First `roll()` creates an order with duration = `type(uint32).max`, storing this endTime in state
3. Order eventually ends (or any subsequent order ends with `lastOrderDuration = type(uint32).max`)
4. Attacker monitors blockchain and calls `roll()` at exactly `block.timestamp = lastEndTime + 1`
5. Underflow produces `timeRemaining = type(uint32).max`, passing reuse conditions
6. New order created with `endTime = block.timestamp + type(uint32).max` via `increaseSellAmount` [7](#0-6) 
7. State remains with old `lastEndTime`, creating permanent inconsistency
8. Future `roll()` calls use stale `lastEndTime`, breaking order management logic

**Security Property Broken:** This violates state consistency invariants and can lead to fund lock scenarios where orders cannot be properly managed or collected.

## Impact Explanation
- **Affected Assets**: All revenue tokens configured with `minOrderDuration = type(uint32).max`, specifically the TWAMM order funds and buyback proceeds
- **Damage Severity**: Funds added to the far-future order become effectively locked for ~136 years (4,294,967,295 seconds). The state corruption prevents proper order tracking - subsequent `roll()` calls will create additional orders instead of managing the existing one, fragmenting revenue streams and reducing capital efficiency
- **User Impact**: The protocol owner loses ability to efficiently manage revenue buybacks. The buyback NFT (NFT_ID) accumulates multiple concurrent orders with different endTimes, making it impossible to collect proceeds predictably

## Likelihood Explanation
- **Attacker Profile**: Any address can call `roll()` as it's a public function. The "attacker" could even be a well-intentioned caller or automated bot
- **Preconditions**: 
  1. Owner must configure `minOrderDuration = type(uint32).max` (this is within validation bounds since `minOrderDuration <= targetOrderDuration` is enforced) [8](#0-7) 
  2. A previous order must have `lastOrderDuration = type(uint32).max`
  3. Caller must execute `roll()` at exactly the block where `block.timestamp = lastEndTime + 1`
- **Execution Complexity**: Medium - requires precise timing (1-second window), but MEV bots and automated systems can easily target specific block timestamps
- **Frequency**: Once per order end cycle when conditions align. While the timing window is narrow (1 second), the misconfiguration enables the vulnerability indefinitely

## Recommendation

Add an upper bound validation for `minOrderDuration` in the `configure()` function to prevent it from reaching values that break the underflow safety assumption:

```solidity
// In src/RevenueBuybacks.sol, function configure(), after line 151:

// CURRENT (vulnerable):
// No upper bound check on minOrderDuration beyond targetOrderDuration

// FIXED:
function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
    external
    onlyOwner
{
    if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
    if (minOrderDuration == 0 && targetOrderDuration != 0) {
        revert MinOrderDurationMustBeGreaterThanZero();
    }
    
    // NEW: Prevent minOrderDuration from reaching type(uint32).max
    // This ensures underflow values are always greater than minOrderDuration
    if (minOrderDuration >= type(uint32).max - 1) {
        revert MinOrderDurationTooLarge();
    }
    
    // ... rest of function
}
```

Alternative mitigation: Add explicit checks in `roll()` to detect when an order has truly ended:

```solidity
// In src/RevenueBuybacks.sol, function roll(), around line 105:

// Check if the last order has actually ended before allowing reuse
if (uint32(block.timestamp) > state.lastEndTime()) {
    // Order has ended, force creation of new order
    // (skip to line 116 logic)
} else if (
    state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
        && timeRemaining <= state.lastOrderDuration()
) {
    // Safe to reuse
    endTime = uint64(block.timestamp + timeRemaining);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_MinOrderDurationUnderflow.t.sol
// Run with: forge test --match-test test_MinOrderDurationUnderflowExploit -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./RevenueBuybacks.t.sol";

contract Exploit_MinOrderDurationUnderflow is RevenueBuybacksTest {
    function test_MinOrderDurationUnderflowExploit() public {
        // SETUP: Configure with type(uint32).max durations
        uint32 maxDuration = type(uint32).max;
        uint64 poolFee = uint64((uint256(1) << 64) / 100);
        
        rb.configure({
            token: address(token0),
            targetOrderDuration: maxDuration,
            minOrderDuration: maxDuration,
            fee: poolFee
        });
        
        // Initialize pool and add liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: poolFee})
        });
        positions.maybeInitializePool(poolKey, 0);
        token0.approve(address(positions), 10e18);
        buybacksToken.approve(address(positions), 10e18);
        positions.mintAndDeposit(poolKey, MIN_TICK, MAX_TICK, 10e18, 10e18, 0);
        rb.approveMax(address(token0));
        
        // Create first order
        donate(address(token0), 1e18);
        (uint64 endTime1,) = rb.roll(address(token0));
        uint32 lastEndTime1 = rb.state(address(token0)).lastEndTime();
        
        // EXPLOIT: Warp to exactly 1 second after order ends
        vm.warp(lastEndTime1 + 1);
        donate(address(token0), 1e18);
        
        // Call roll() - underflow triggers, creates far-future order
        (uint64 endTime2,) = rb.roll(address(token0));
        uint32 lastEndTime2 = rb.state(address(token0)).lastEndTime();
        
        // VERIFY: State corruption
        // endTime2 should be far in the future (block.timestamp + type(uint32).max)
        assertEq(endTime2, uint64(lastEndTime1 + 1) + uint64(type(uint32).max), 
            "New order has far-future endTime");
        
        // But state was NOT updated - still points to old endTime
        assertEq(lastEndTime2, lastEndTime1, 
            "State corruption: lastEndTime not updated despite new order creation");
        
        // This proves the vulnerability: new order created but state remains stale
        assertTrue(endTime2 > lastEndTime2 + type(uint32).max / 2, 
            "Vulnerability confirmed: massive gap between actual order and tracked state");
    }
}
```

**Notes:**
- The vulnerability requires `minOrderDuration = type(uint32).max`, which while unusual, is within the validated bounds per the `configure()` function's checks
- The timing window (exactly 1 second after order end) is narrow but exploitable by sophisticated actors monitoring chain state
- The test suite currently bounds `minOrderDuration` to `type(uint16).max` in fuzzing tests [9](#0-8) , which explains why this edge case was not caught
- While this requires owner misconfiguration to set such extreme values, the resulting state corruption and fund lock represent a genuine vulnerability that violates state consistency guarantees

### Citations

**File:** src/RevenueBuybacks.sol (L105-114)
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
```

**File:** src/RevenueBuybacks.sol (L134-136)
```text
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
```

**File:** src/RevenueBuybacks.sol (L147-153)
```text
    function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
        external
        onlyOwner
    {
        if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
        if (minOrderDuration == 0 && targetOrderDuration != 0) {
            revert MinOrderDurationMustBeGreaterThanZero();
```

**File:** test/RevenueBuybacks.t.sol (L217-218)
```text
        targetOrderDuration = uint32(bound(targetOrderDuration, 1, type(uint16).max));
        minOrderDuration = uint32(bound(minOrderDuration, 1, targetOrderDuration));
```
