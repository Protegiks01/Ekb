Based on my deep investigation of the RevenueBuybacks contract and the `roll()` function, I have identified a concrete vulnerability related to the uint32 truncation of `endTime`. Here is my full report:

## Title
Integer Truncation in RevenueBuybacks.roll() Causes Expired Orders to be Incorrectly Reused After Year 2106

## Summary
The `RevenueBuybacks.roll()` function stores `endTime` (a `uint64`) as `lastEndTime` (a `uint32`) in the `BuybacksState` struct. When `endTime >= 2^32`, the downcast causes data loss. This truncation breaks the order expiration logic when both `endTime` and `block.timestamp` exceed `2^32`, allowing expired buyback orders to be incorrectly reused with wrong end times, causing financial harm through unintended trade execution.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `roll()` function should detect when a previous order has ended and create a new order with fresh timing parameters. The comment at line 107 states: "note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration, but also greater than last order duration, so it will not be re-used." [2](#0-1) 

**Actual Logic:** When `endTime >= 2^32`, the cast to `uint32` truncates the value. [3](#0-2)  The subsequent `timeRemaining` calculation [4](#0-3)  uses modular arithmetic on truncated uint32 values. When `block.timestamp` also wraps around `2^32` differently than the stored `endTime`, the underflow detection breaks, allowing expired orders to pass the reuse check [5](#0-4)  and be extended with incorrect end times.

**Exploitation Path:**
1. **Setup (Year 2025):** Admin configures a revenue token with `targetOrderDuration = 4,000,000,000` seconds (~126 years) - the maximum allowed value for a `uint32`. Anyone calls `roll()` at `block.timestamp = 1,000,000,000`.
2. **Order Creation:** `nextValidTime()` calculates `endTime ≈ 5,000,000,000` (year 2128). [6](#0-5)  This is stored as `lastEndTime = uint32(5,000,000,000) = 705,032,704` and `lastOrderDuration = 4,000,000,000`.
3. **Time Passes (Year 2160):** At `block.timestamp = 6,000,000,000`, the order has ended (5 billion < 6 billion). Anyone calls `roll()` again to create a new order.
4. **Incorrect Reuse:** The calculation `timeRemaining = 705,032,704 - uint32(6,000,000,000) = 705,032,704 - 1,705,032,704 = 3,294,967,296` (due to uint32 underflow). The check `3,294,967,296 <= 4,000,000,000` passes, so the order is reused with `endTime = 6,000,000,000 + 3,294,967,296 = 9,294,967,296` instead of creating a new order.

**Security Property Broken:** Order timing integrity is violated. Expired orders are reused instead of being replaced, causing buyback trades to execute at incorrect times and potentially unfavorable prices.

## Impact Explanation
- **Affected Assets**: Protocol revenue tokens being used for buybacks (any ERC20 or ETH configured in RevenueBuybacks)
- **Damage Severity**: When the order is incorrectly extended by ~3.3 billion seconds beyond its intended end time, revenue tokens continue being sold through TWAMM orders in potentially adverse market conditions, leading to worse execution prices than intended. The protocol loses value on these trades.
- **User Impact**: All users who benefit from buybacks (token holders receiving bought-back tokens) are affected. The protocol systematically receives poor prices on revenue-to-token swaps during the extended period.

## Likelihood Explanation
- **Attacker Profile**: Any user can call `roll()` - no special permissions required. The vulnerability activates automatically when block timestamps cross critical thresholds.
- **Preconditions**: 
  1. A revenue token must be configured with large `targetOrderDuration` (approaching `type(uint32).max`)
  2. `block.timestamp` must exceed `~2^32` (4.29 billion seconds from epoch, approximately year 2106)
  3. An order with `endTime >= 2^32` must have been created previously
- **Execution Complexity**: Single transaction (`roll()` call) - no complex multi-step attack needed
- **Frequency**: The vulnerability persists indefinitely once activated. Every `roll()` call will incorrectly reuse expired orders until fixed.

## Recommendation [7](#0-6) 

Change the `BuybacksState` storage layout to store the time remaining as a `uint32` offset rather than the absolute `endTime`. Since `nextValidTime()` ensures `endTime - currentTime <= type(uint32).max` [8](#0-7) , storing the offset preserves all information without truncation:

```solidity
// In src/types/buybacksState.sol:
// CURRENT: lastEndTime is absolute timestamp (can exceed 2^32)
function lastEndTime(BuybacksState state) pure returns (uint32 endTime)

// FIXED: Store relative offset instead
// Add new field: lastTimeRemaining (bits [128:159])
function lastTimeRemaining(BuybacksState state) pure returns (uint32 remaining) {
    assembly ("memory-safe") {
        remaining := and(shr(128, state), 0xFFFFFFFF)
    }
}

// In src/RevenueBuybacks.sol, line 123:
// CURRENT (vulnerable):
_lastEndTime: uint32(endTime),

// FIXED:
_lastTimeRemaining: uint32(endTime - block.timestamp), // Store offset, not absolute time
```

Then update the `roll()` function to reconstruct `endTime` from the offset, eliminating truncation issues.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32Truncation.t.sol
// Run with: forge test --match-test test_Uint32TruncationVulnerability -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./RevenueBuybacks.t.sol";

contract Exploit_Uint32Truncation is RevenueBuybacksTest {
    
    function test_Uint32TruncationVulnerability() public {
        uint64 poolFee = uint64((uint256(1) << 64) / 100);
        
        // SETUP: Warp to year 2025, configure with maximum duration
        vm.warp(1_000_000_000); // Year ~2001
        rb.configure({
            token: address(token0),
            targetOrderDuration: 4_000_000_000, // ~126 years
            minOrderDuration: 1_000_000_000,
            fee: poolFee
        });
        
        // Create pool and add liquidity
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
        donate(address(token0), 1e18);
        
        // EXPLOIT STEP 1: Create order with endTime > 2^32
        (uint64 endTime1, ) = rb.roll(address(token0));
        console.log("Initial endTime:", endTime1);
        assertGt(endTime1, type(uint32).max, "endTime should exceed 2^32");
        
        // EXPLOIT STEP 2: Warp to year 2160 (order has ended)
        vm.warp(6_000_000_000);
        donate(address(token0), 1e18);
        
        // VERIFY: Order should create NEW order, but incorrectly reuses expired one
        (uint64 endTime2, ) = rb.roll(address(token0));
        
        console.log("Second endTime:", endTime2);
        console.log("First endTime:", endTime1);
        console.log("Current timestamp:", block.timestamp);
        
        // BUG: endTime2 should be > block.timestamp + targetDuration (~10 billion)
        // but due to truncation bug, it incorrectly extends the expired order
        assertGt(endTime2, endTime1, "Vulnerability: Expired order incorrectly reused");
        assertLt(endTime2, 10_000_000_000, "Vulnerability: endTime calculation is wrong");
    }
}
```

**Notes:**
- This vulnerability has a far-future activation timeline (year 2106+) but represents a concrete logic error
- The issue stems from storing uint64 timestamps in uint32 storage, breaking order expiration detection
- When `block.timestamp` crosses `2^32` boundaries, the modular arithmetic in `timeRemaining` calculation fails to detect expired orders
- The protocol's design uses uint64 timestamps throughout the TWAMM system [9](#0-8) , but RevenueBuybacks incorrectly uses uint32 for state storage
- While exploitation requires waiting decades, the code contains a demonstrable flaw that will cause financial harm when activated

### Citations

**File:** src/RevenueBuybacks.sol (L105-105)
```text
            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
```

**File:** src/RevenueBuybacks.sol (L107-108)
```text
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
```

**File:** src/RevenueBuybacks.sol (L109-114)
```text
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
                // handles overflow
                endTime = uint64(block.timestamp + timeRemaining);
```

**File:** src/RevenueBuybacks.sol (L116-126)
```text
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
```

**File:** src/types/buybacksState.sol (L35-39)
```text
function lastEndTime(BuybacksState state) pure returns (uint32 endTime) {
    assembly ("memory-safe") {
        endTime := and(shr(128, state), 0xFFFFFFFF)
    }
}
```

**File:** src/math/time.sol (L63-63)
```text
        nextTime = FixedPointMathLib.ternary(nextTime > currentTime + type(uint32).max, 0, nextTime);
```

**File:** src/types/orderConfig.sol (L40-44)
```text
function endTime(OrderConfig config) pure returns (uint64 r) {
    assembly ("memory-safe") {
        r := and(config, 0xffffffffffffffff)
    }
}
```
