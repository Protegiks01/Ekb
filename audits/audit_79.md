## Title
uint32 Truncation in RevenueBuybacks.roll() Causes Permanent Loss of Order Proceeds

## Summary
The `roll()` function in `RevenueBuybacks.sol` calculates a uint64 `endTime` for TWAMM orders but truncates it to uint32 when storing as `lastEndTime`. This truncation causes subsequent `roll()` calls to create new orders with different `endTime` values instead of extending the existing order, permanently locking the proceeds from the original order since the `collect()` function requires the exact `endTime` to retrieve proceeds.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `roll()` function should track the `endTime` of created orders to enable proceed collection and order extension logic. The stored `lastEndTime` should accurately reflect the actual order's `endTime`.

**Actual Logic:** The function stores `endTime` as uint32 in `lastEndTime` despite `endTime` being calculated as uint64. When `endTime` exceeds `type(uint32).max` (approximately year 2106 or when using large duration configurations), the value is silently truncated. Subsequent calls use this corrupted value to calculate new endTimes, creating different orders instead of tracking the original.

**Exploitation Path:**
1. Owner configures RevenueBuybacks with `targetOrderDuration` that results in `endTime > type(uint32).max` when added to current timestamp
2. First `roll()` call executes: [2](#0-1) 
3. The calculated uint64 `endTime` is truncated to uint32: [3](#0-2) 
4. Order is created via `increaseSellAmount` with the full uint64 `endTime`: [4](#0-3) 
5. On subsequent `roll()` calls, `timeRemaining` is calculated using the truncated `lastEndTime`: [5](#0-4) 
6. This produces a different `endTime`, creating a new order with a different `OrderId`: [6](#0-5) 
7. The `collect()` function cannot retrieve proceeds from the original order because it requires the exact `endTime`: [7](#0-6) 

**Security Property Broken:** Violates the **Solvency** and **Withdrawal Availability** invariants. Protocol fees allocated to buyback orders become permanently locked, and users cannot withdraw proceeds from completed orders.

## Impact Explanation
- **Affected Assets**: All protocol fees allocated to revenue buybacks for tokens configured with large durations or when `block.timestamp` approaches/exceeds uint32 limits
- **Damage Severity**: Complete loss of funds spent on the orphaned order. If the order executes with significant liquidity, the purchased tokens cannot be collected, resulting in permanent loss equal to the full order value
- **User Impact**: Protocol revenue is permanently lost. Since RevenueBuybacks is typically funded by protocol fees meant for buybacks, this affects the entire protocol's revenue model and token holders who should benefit from buybacks

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a logic bug that occurs through normal operation
- **Preconditions**: 
  - Owner configures token with `targetOrderDuration` such that `block.timestamp + targetOrderDuration > type(uint32).max`
  - Or `block.timestamp` itself exceeds uint32 range (February 2106)
  - Protocol fees are available for buyback
- **Execution Complexity**: Triggered automatically through normal `withdrawAndRoll()` calls: [8](#0-7) 
- **Frequency**: Occurs on every `roll()` call after the first one when preconditions are met

## Recommendation

**Fix the truncation by storing endTime as uint64:** [9](#0-8) 

Change `lastEndTime` from uint32 to uint64 in the BuybacksState structure. This requires adjusting the bit layout:

```solidity
// CURRENT (vulnerable):
// Bits 128-159: lastEndTime (uint32)
// Bits 160-191: lastOrderDuration (uint32)

// FIXED:
// Bits 128-191: lastEndTime (uint64)
// Bits 192-223: lastOrderDuration (uint32) - shifted up
```

Update the packing/unpacking logic in [10](#0-9)  accordingly.

**Alternative mitigation**: Add validation to prevent configurations that would cause truncation:

```solidity
// In RevenueBuybacks.configure():
if (block.timestamp + targetOrderDuration > type(uint32).max) {
    revert OrderDurationExceedsUint32();
}
```

However, this doesn't address the year 2106 problem when `block.timestamp` itself exceeds uint32.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32Truncation.t.sol
// Run with: forge test --match-test test_EndTimeTruncationLocksProceeds -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {BaseOrdersTest} from "./Orders.t.sol";
import {RevenueBuybacks} from "../src/RevenueBuybacks.sol";

contract Exploit_Uint32Truncation is BaseOrdersTest {
    RevenueBuybacks rb;
    
    function setUp() public override {
        BaseOrdersTest.setUp();
        rb = new RevenueBuybacks(address(this), orders, address(token1));
        
        // Warp to a time where truncation will occur
        vm.warp(2**32 + 1000); // Year 2106+
    }
    
    function test_EndTimeTruncationLocksProceeds() public {
        // Configure with duration that causes endTime > uint32.max
        uint32 targetDuration = 2**31; // ~68 years
        rb.configure(address(token0), targetDuration, 1000, 1000);
        rb.approveMax(address(token0));
        
        // Donate tokens for first order
        token0.transfer(address(rb), 1000 ether);
        
        // First roll() creates order with truncated lastEndTime
        (uint64 endTime1, ) = rb.roll(address(token0));
        
        // Donate more tokens and call roll() again
        vm.warp(block.timestamp + 100);
        token0.transfer(address(rb), 1000 ether);
        
        // Second roll() calculates different endTime due to truncation
        (uint64 endTime2, ) = rb.roll(address(token0));
        
        // Verify endTimes differ (proves different orders created)
        assertNotEq(endTime1, endTime2, "EndTimes should differ due to truncation");
        
        // Original order proceeds cannot be collected
        // because collect() requires exact endTime which is lost
        vm.expectRevert();
        rb.collect(address(token0), 1000, endTime1);
    }
}
```

**Notes**
- The vulnerability becomes immediately exploitable when `block.timestamp > type(uint32).max` (February 7, 2106)
- Before year 2106, it can be triggered by owner misconfiguration with excessively large `targetOrderDuration` values
- The `lastOrderDuration` field at line 124 also suffers from uint32 truncation when `endTime - block.timestamp > type(uint32).max`
- The storage layout in `BuybacksState` was designed to pack multiple fields into bytes32, but failed to account for the uint64 `endTime` values used throughout the protocol
- This affects the core revenue mechanism of the protocol, making it a critical infrastructure bug

### Citations

**File:** src/RevenueBuybacks.sol (L76-77)
```text
    function collect(address token, uint64 fee, uint64 endTime) external returns (uint128 proceeds) {
        proceeds = ORDERS.collectProceeds(NFT_ID, _createOrderKey(token, fee, 0, endTime), owner());
```

**File:** src/RevenueBuybacks.sol (L105-105)
```text
            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
```

**File:** src/RevenueBuybacks.sol (L116-117)
```text
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));
```

**File:** src/RevenueBuybacks.sol (L119-126)
```text
                state = createBuybacksState({
                    _targetOrderDuration: state.targetOrderDuration(),
                    _minOrderDuration: state.minOrderDuration(),
                    _fee: state.fee(),
                    _lastEndTime: uint32(endTime),
                    _lastOrderDuration: uint32(endTime - block.timestamp),
                    _lastFee: state.fee()
                });
```

**File:** src/RevenueBuybacks.sol (L134-136)
```text
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
```

**File:** src/types/orderKey.sol (L44-47)
```text
function toOrderId(OrderKey memory orderKey) pure returns (OrderId id) {
    assembly ("memory-safe") {
        id := keccak256(orderKey, 96)
    }
```

**File:** src/PositionsOwner.sol (L73-75)
```text
        // Call roll for both tokens
        BUYBACKS.roll(token0);
        BUYBACKS.roll(token1);
```

**File:** src/types/buybacksState.sol (L35-39)
```text
function lastEndTime(BuybacksState state) pure returns (uint32 endTime) {
    assembly ("memory-safe") {
        endTime := and(shr(128, state), 0xFFFFFFFF)
    }
}
```

**File:** src/types/buybacksState.sol (L78-97)
```text
function createBuybacksState(
    uint32 _targetOrderDuration,
    uint32 _minOrderDuration,
    uint64 _fee,
    uint32 _lastEndTime,
    uint32 _lastOrderDuration,
    uint64 _lastFee
) pure returns (BuybacksState state) {
    assembly ("memory-safe") {
        state := or(
            or(
                or(and(_targetOrderDuration, 0xFFFFFFFF), shl(32, and(_minOrderDuration, 0xFFFFFFFF))),
                shl(64, and(_fee, 0xFFFFFFFFFFFFFFFF))
            ),
            or(
                or(shl(128, and(_lastEndTime, 0xFFFFFFFF)), shl(160, and(_lastOrderDuration, 0xFFFFFFFF))),
                shl(192, _lastFee)
            )
        )
    }
```
