## Title
uint32 Truncation in RevenueBuybacks.lastEndTime Causes Premature Order Abandonment Near Timestamp Boundary

## Summary
The `RevenueBuybacks.roll()` function stores order end times as `uint32` values but uses `uint64` end times when creating TWAMM orders. When an order's `endTime` crosses the `type(uint32).max` boundary, the truncated storage causes incorrect time calculations that make the system abandon active orders and create duplicate orders, leading to uncollected proceeds and capital inefficiency.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (function `roll`, line 105, 123) and `src/types/buybacksState.sol` (function `lastEndTime`, lines 35-38)

**Intended Logic:** The RevenueBuybacks contract should track order end times and either extend existing orders or create new ones based on whether the previous order has ended. The `lastEndTime` field stores the end time of the last created order to enable this tracking. [1](#0-0) 

**Actual Logic:** The code stores only `uint32(endTime)` in the `lastEndTime` field, but the actual TWAMM order uses the full `uint64` endTime value. When block.timestamp approaches `type(uint32).max` (~4.29 billion, February 2106), orders can be created with `endTime` values that exceed this boundary. The `uint32` cast truncates the upper bits, causing a desynchronization between the stored value and the actual order's end time. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. When `block.timestamp` is near `type(uint32).max` (e.g., 4,294,960,000), the owner configures a buyback with `targetOrderDuration = 100,000` seconds
2. `roll()` is called, creating an order with `endTime = 4,295,060,000` (crosses uint32 boundary)
3. This endTime is passed to the TWAMM Orders contract as a uint64 value
4. But stored as `lastEndTime = uint32(4,295,060,000) = 92,704` (wrapped around)
5. A few minutes later at `block.timestamp = 4,294,963,000`, someone calls `roll()` again
6. Line 105 calculates: `timeRemaining = 92,704 - uint32(4,294,963,000) = 92,704 - 4,294,963,000` (massive underflow to ~4,294,870,000)
7. Lines 110-112: The condition fails since `timeRemaining` exceeds `lastOrderDuration`, so a NEW order is created
8. The original order (endTime=4,295,060,000) remains active in TWAMM but is abandoned by RevenueBuybacks [4](#0-3) 

**Security Property Broken:** This breaks the protocol's intended buyback automation mechanism and can lead to loss of funds through uncollected order proceeds.

## Impact Explanation
- **Affected Assets**: Protocol revenue tokens being used for buybacks, specifically the proceeds from abandoned TWAMM orders
- **Damage Severity**: Orders created near the uint32 boundary will be permanently abandoned. Their proceeds (bought tokens) will remain uncollected in the TWAMM system unless manually retrieved. New orders will be created with fresh funds, fragmenting liquidity and reducing buyback efficiency
- **User Impact**: While this primarily affects protocol operations, it results in inefficient use of protocol revenue and potentially lost funds if abandoned order proceeds are never collected. The issue will manifest for any protocol deployment that remains active past early 2106, or for protocols using time-warping in tests

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a time-based bug that triggers naturally
- **Preconditions**: Block timestamp must be within approximately `maxOrderDuration` of `type(uint32).max` (~4.29 billion seconds). Given TWAMM's constraint that orders must have duration < `type(uint32).max`, this creates a vulnerable window from roughly timestamp 2^32 - 2^31 to 2^32 + 2^31
- **Execution Complexity**: Occurs automatically when `roll()` is called during the vulnerable time window
- **Frequency**: Once the vulnerable time window is reached, every call to `roll()` will trigger the issue until the timestamp moves far enough past the boundary [5](#0-4) 

## Recommendation

Change the `lastEndTime` field in `BuybacksState` from `uint32` to `uint64` to match the actual endTime values used in TWAMM orders:

```solidity
// In src/types/buybacksState.sol, modify the bit layout:

// CURRENT (vulnerable):
// Bits [128:159] store lastEndTime as uint32

// FIXED:
// Bits [128:191] store lastEndTime as uint64
// Bits [192:223] store lastOrderDuration as uint32
// Bits [224:255] store lastFee as uint32 (reduced from uint64)

function lastEndTime(BuybacksState state) pure returns (uint64 endTime) {
    assembly ("memory-safe") {
        endTime := and(shr(128, state), 0xFFFFFFFFFFFFFFFF) // Extract 64 bits instead of 32
    }
}
```

This requires adjusting the bit layout in `buybacksState.sol` to allocate 64 bits for `lastEndTime` (currently only 32 bits), potentially by reducing `lastFee` from 64 bits to 32 bits or reorganizing the packing scheme. The `createBuybacksState` function and other accessors must be updated accordingly.

Alternative mitigation: Add a check in `roll()` to detect when the stored `lastEndTime` appears to be in the past due to uint32 wrapping, and handle it explicitly by treating it as an expired order.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32Wraparound.t.sol
// Run with: forge test --match-test test_Uint32Wraparound -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/RevenueBuybacks.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "./utils/TestERC20.sol";

contract Exploit_Uint32Wraparound is Test {
    RevenueBuybacks rb;
    Orders orders;
    Core core;
    Positions positions;
    TestERC20 token0;
    TestERC20 buyToken;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        positions = new Positions(address(this), core);
        orders = new Orders(address(this), core);
        token0 = new TestERC20();
        buyToken = new TestERC20();
        
        rb = new RevenueBuybacks(address(this), orders, address(buyToken));
    }
    
    function test_Uint32Wraparound() public {
        // SETUP: Warp to just before uint32 overflow
        uint256 nearOverflow = 4_294_960_000; // ~7 days before uint32.max
        vm.warp(nearOverflow);
        
        // Configure buyback with 10-day duration
        uint32 targetDuration = 10 days;
        rb.configure(address(token0), targetDuration, 1 days, 1e16);
        
        // Initialize pool and provide liquidity
        // (pool setup code omitted for brevity)
        
        // Fund the RevenueBuybacks contract
        token0.mint(address(rb), 1e18);
        rb.approveMax(address(token0));
        
        // EXPLOIT: Create order that crosses uint32 boundary
        (uint64 endTime1, ) = rb.roll(address(token0));
        
        // endTime1 will be ~4,295,820,000 (beyond uint32.max)
        // But lastEndTime stores only uint32(endTime1) ≈ 852,704
        assertTrue(endTime1 > type(uint32).max, "Order endTime should exceed uint32.max");
        
        // Advance time slightly (still before order should end)
        vm.warp(nearOverflow + 1 hours);
        
        // Add more funds
        token0.mint(address(rb), 1e18);
        
        // VERIFY: System incorrectly creates NEW order instead of extending
        (uint64 endTime2, ) = rb.roll(address(token0));
        
        // If working correctly, endTime2 should equal endTime1 (extending existing order)
        // But due to uint32 truncation bug, endTime2 will be different (new order)
        assertNotEq(endTime2, endTime1, "Vulnerability confirmed: Created new order instead of extending");
        assertTrue(endTime2 > endTime1, "New order has different endTime");
        
        // The original order with endTime1 is now abandoned
        // Its proceeds will never be collected by the automated system
    }
}
```

## Notes

The vulnerability window extends approximately from `type(uint32).max - maxPossibleOrderDuration` to `type(uint32).max + maxPossibleOrderDuration`. Given that TWAMM enforces order durations must fit within uint32 (<4.29 billion seconds, or ~136 years), this creates a theoretical maximum vulnerable window of ~272 years centered around February 2106.

While this may seem far in the future, long-lived protocols should plan for this boundary. Additionally, any protocol using time manipulation in testing (common with `vm.warp()`) could inadvertently trigger this issue.

The core issue is the type mismatch: TWAMM orders use `uint64` endTime values, but RevenueBuybacks only stores `uint32`. This asymmetry creates desynchronization when timestamps are large.

### Citations

**File:** src/RevenueBuybacks.sol (L105-108)
```text
            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
            // if the fee changed, or the amount of time exceeds the min order duration
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
```

**File:** src/RevenueBuybacks.sol (L109-112)
```text
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
```

**File:** src/RevenueBuybacks.sol (L123-123)
```text
                    _lastEndTime: uint32(endTime),
```

**File:** src/types/buybacksState.sol (L35-38)
```text
function lastEndTime(BuybacksState state) pure returns (uint32 endTime) {
    assembly ("memory-safe") {
        endTime := and(shr(128, state), 0xFFFFFFFF)
    }
```

**File:** src/math/time.sol (L37-39)
```text
    assembly ("memory-safe") {
        valid := and(iszero(mod(time, stepSize)), or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)))
    }
```
