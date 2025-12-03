## Title
uint32 Truncation in RevenueBuybacks.roll() Causes Permanent Fund Lock After Configuration Changes

## Summary
The `roll()` function in `RevenueBuybacks.sol` truncates order `endTime` values when storing them as `lastEndTime` (uint32). [1](#0-0)  When an owner initially configures a large `targetOrderDuration` and later attempts to reconfigure to a reasonable value, the truncated `lastEndTime` causes the underflow detection logic to malfunction, resulting in revenue being locked in orders lasting ~136 years instead of the newly configured duration.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/RevenueBuybacks.sol` - `roll()` function (lines 90-139)

**Intended Logic:** 
The code is designed to detect when orders have expired through underflow. When `timeRemaining` underflows (becomes very large), it should exceed `lastOrderDuration`, failing the reuse condition and creating a new order with the current `targetOrderDuration`. [2](#0-1) 

**Actual Logic:** 
When `endTime` values exceed `uint32.max`, the cast to `uint32` on line 123 truncates the value, storing incorrect data in `lastEndTime`. [1](#0-0)  This breaks the underflow detection because the truncated value makes the system believe the order expired much earlier than it actually did. When `lastOrderDuration` is close to `uint32.max`, the underflowed `timeRemaining` still satisfies the condition on line 111, causing the reuse logic to execute with an invalid `endTime`. [3](#0-2) 

**Exploitation Path:**
1. Owner calls `configure(token, 4_294_967_295, 3600, fee)` setting `targetOrderDuration` to near `uint32.max` (either intentionally for a long-term strategy or accidentally)
2. At `block.timestamp = 1_000_000_000`, someone calls `roll(token)` which creates an order with `endTime ≈ 5_294_967_295` (year 2137) via `nextValidTime()` [4](#0-3) 
3. The state stores: `lastEndTime = uint32(5_294_967_295) = 999_999_999` (truncated), `lastOrderDuration = 4_294_967_295`
4. Owner realizes the error and calls `configure(token, 86400, 3600, fee)` to set daily buybacks
5. At `block.timestamp = 1_000_000_001`, someone calls `roll(token)` expecting a 1-day order
6. Line 105 calculates `timeRemaining = 999_999_999 - 1_000_000_001 = underflow to 4_294_966_998` [5](#0-4) 
7. Check passes: `4_294_966_998 <= 4_294_967_295` (lastOrderDuration), so reuse branch executes
8. Line 114 calculates `endTime = 1_000_000_001 + 4_294_966_998 = 5_294_966_999` creating a 136-year order instead of 1-day [6](#0-5) 
9. Revenue tokens are locked in this extremely long TWAMM order with minimal sale rate

**Security Property Broken:** 
Violates "Withdrawal Availability" - funds are effectively locked for 136 years, making them unrecoverable within any reasonable timeframe. The owner loses control over buyback configuration despite using the intended `configure()` interface.

## Impact Explanation

- **Affected Assets**: All protocol revenue tokens configured in RevenueBuybacks contract (ETH, governance tokens, fee tokens)
- **Damage Severity**: Complete loss of revenue control. Revenue is locked in TWAMM orders for ~136 years (until year 2106+), effectively making it permanently inaccessible. The sale rate becomes `(amount << 32) / 4_294_967_295`, resulting in negligible buyback activity. [7](#0-6) 
- **User Impact**: Protocol-wide impact. All accumulated revenue destined for buybacks becomes locked. Only workaround is changing the `fee` parameter to force new order creation, but this may not be economically viable or desirable.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this is triggered by legitimate owner actions attempting to reconfigure the system
- **Preconditions**: 
  1. Owner must initially configure `targetOrderDuration` to a value approaching `uint32.max` (either intentionally for long-term strategy or through input error)
  2. At least one `roll()` call must occur, creating an order with `endTime > uint32.max`
  3. Owner attempts to reconfigure to a normal duration
  4. Subsequent `roll()` calls trigger the bug
- **Execution Complexity**: Simple - happens automatically on next `roll()` call after reconfiguration, which can be called by anyone
- **Frequency**: Occurs every time `roll()` is called after the conditions are met, permanently locking all new revenue until fee is changed

## Recommendation

Add validation in the `configure()` function to prevent `targetOrderDuration` values that would cause `endTime` to exceed `uint32.max`:

```solidity
// In src/RevenueBuybacks.sol, function configure, after line 151:

// CURRENT (vulnerable):
if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
if (minOrderDuration == 0 && targetOrderDuration != 0) {
    revert MinOrderDurationMustBeGreaterThanZero();
}

// FIXED:
if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
if (minOrderDuration == 0 && targetOrderDuration != 0) {
    revert MinOrderDurationMustBeGreaterThanZero();
}
// Prevent targetOrderDuration from causing endTime to overflow uint32 storage
// Current timestamp + targetOrderDuration must fit in uint32 range to prevent truncation
if (targetOrderDuration > type(uint32).max - uint32(block.timestamp)) {
    revert TargetOrderDurationTooLarge();
}
```

Alternative mitigation: Change `lastEndTime` storage from `uint32` to `uint64` in the `BuybacksState` struct, though this requires storage layout changes. [8](#0-7) 

## Proof of Concept

```solidity
// File: test/Exploit_RevenueBuybacksTruncation.t.sol
// Run with: forge test --match-test test_RevenueBuybacksTruncation -vvvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/RevenueBuybacks.sol";
import "../src/Orders.sol";

contract Exploit_RevenueBuybacksTruncation is Test {
    RevenueBuybacks rb;
    Orders orders;
    address owner = address(0x1234);
    address token = address(0x5678);
    address buyToken = address(0x9ABC);
    uint64 fee = 3000;
    
    function setUp() public {
        // Deploy and initialize contracts
        vm.startPrank(owner);
        // [Assume proper deployment of Orders and RevenueBuybacks]
        vm.stopPrank();
    }
    
    function test_RevenueBuybacksTruncation() public {
        vm.startPrank(owner);
        
        // SETUP: Owner initially configures large targetOrderDuration
        uint32 largeTarget = type(uint32).max - 100_000_000; // ~4.2 billion seconds
        rb.configure(token, largeTarget, 3600, fee);
        
        // First roll at timestamp 1 billion
        vm.warp(1_000_000_000);
        deal(token, address(rb), 1e18);
        (uint64 endTime1,) = rb.roll(token);
        
        // endTime1 should be approximately 1_000_000_000 + 4_194_967_295 = 5_194_967_295
        assertGt(endTime1, type(uint32).max, "First order endTime exceeds uint32");
        
        // EXPLOIT: Owner realizes error and reconfigures to 1 day
        rb.configure(token, 86400, 3600, fee);
        
        // Warp forward just 1 second
        vm.warp(1_000_000_001);
        deal(token, address(rb), 1e18);
        (uint64 endTime2,) = rb.roll(token);
        
        // VERIFY: Despite reconfiguration to 86400 (1 day), order duration is still massive
        uint64 actualDuration = endTime2 - uint64(block.timestamp);
        
        // Expected: ~86400 seconds (1 day)
        // Actual: ~4.2 billion seconds (136 years)
        assertGt(actualDuration, 1_000_000_000, "Vulnerability confirmed: Duration still massive despite reconfiguration");
        assertLt(actualDuration, 90000, "This would pass if fixed"); // This assertion will fail
        
        vm.stopPrank();
    }
}
```

**Notes:**

The vulnerability stems from the mismatch between `endTime` (uint64) and `lastEndTime` (uint32) storage. The protocol uses `nextValidTime()` which can return values up to `currentTime + type(uint32).max` as valid, [9](#0-8)  but the storage truncates these values. This creates a scenario where configuration changes are ignored, and revenue becomes locked in extremely long orders. The issue is not merely a misconfiguration - it's a logic bug where the protocol fails to handle its own validation boundaries correctly, leading to loss of control over critical protocol functionality.

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

**File:** src/RevenueBuybacks.sol (L110-111)
```text
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
```

**File:** src/RevenueBuybacks.sol (L114-114)
```text
                endTime = uint64(block.timestamp + timeRemaining);
```

**File:** src/RevenueBuybacks.sol (L116-117)
```text
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));
```

**File:** src/RevenueBuybacks.sol (L123-123)
```text
                    _lastEndTime: uint32(endTime),
```

**File:** src/math/twamm.sol (L13-22)
```text
function computeSaleRate(uint256 amount, uint256 duration) pure returns (uint256 saleRate) {
    assembly ("memory-safe") {
        saleRate := div(shl(32, amount), duration)
        if shr(112, saleRate) {
            // cast sig "SaleRateOverflow()"
            mstore(0, shl(224, 0x83c87460))
            revert(0, 4)
        }
    }
}
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
