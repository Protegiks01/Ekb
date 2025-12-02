## Title
Zero Sentinel Value from `nextValidTime` Confused with Unix Epoch Causes Revenue Lock in Extreme Duration Buybacks

## Summary
The `nextValidTime` function returns 0 as a sentinel value to indicate no valid time exists, but `RevenueBuybacks.roll()` directly uses this 0 as an order `endTime` without validation. When the contract is configured with large `targetOrderDuration` values and called with zero balance, state corruption occurs leading to subsequent orders being created with incorrect end times ~82 years in the future, locking protocol revenue for decades.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (function `roll`, lines 90-139) and `src/math/time.sol` (function `nextValidTime`, lines 44-64) [1](#0-0) [2](#0-1) 

**Intended Logic:** The `nextValidTime` function is intended to return the next valid time on the TWAMM time grid, and returns 0 as a sentinel value when no valid time exists (i.e., when the computed next time exceeds `currentTime + type(uint32).max`). The `RevenueBuybacks.roll()` function should calculate a valid order end time based on the configured `targetOrderDuration`.

**Actual Logic:** When `targetOrderDuration` is configured close to `type(uint32).max`, `nextValidTime` returns 0 because the computed next valid time exceeds the uint32 range limit. The `roll()` function directly casts this 0 to `uint64` and uses it as `endTime` without checking if it's the sentinel value. When `amountToSpend = 0`, no order creation is attempted (bypassing validation), so the transaction succeeds with state storing `lastEndTime = 0` and `lastOrderDuration = uint32(0 - block.timestamp)` (which underflows to ~2.6 billion seconds). Subsequent calls reuse this corrupted state, creating orders with end times approximately 82 years in the future. [3](#0-2) [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. Owner configures a revenue token with `targetOrderDuration = type(uint32).max - 1000` (or similar large value close to max uint32)
2. Someone calls `roll(token)` when contract has 0 balance (before revenue accumulates). `nextValidTime(block.timestamp, block.timestamp + 4294966295)` computes a next valid time beyond the uint32 range and returns 0
3. State is stored with `lastEndTime = uint32(0) = 0` and `lastOrderDuration = uint32(0 - block.timestamp)` which underflows. Since `amountToSpend = 0`, no order creation happens and transaction succeeds
4. After revenue accumulates, `roll(token)` is called again. `timeRemaining = 0 - uint32(block.timestamp)` underflows to ~2.6B seconds. The reuse path executes: `endTime = uint64(block.timestamp + timeRemaining)` ≈ timestamp for year 2106. Order is created with this far-future end time, locking all accumulated revenue for ~82 years [6](#0-5) 

**Security Property Broken:** This violates the intended economic behavior of the RevenueBuybacks system and creates a temporary fund lock (though technically recoverable via `decreaseSaleRate`, it requires owner intervention and understanding of the issue).

## Impact Explanation
- **Affected Assets**: Protocol revenue tokens configured in RevenueBuybacks with large `targetOrderDuration` values
- **Damage Severity**: All accumulated revenue for the affected token is locked in a TWAMM order with an end time ~82 years in the future (e.g., year 2106 if triggered in 2025). While technically recoverable by calling `decreaseSaleRate` to cancel the order, this requires owner awareness and action
- **User Impact**: The protocol loses the ability to execute revenue buybacks at intended intervals. Revenue accumulates but remains locked in an incorrectly-configured order for decades, preventing the buyback mechanism from functioning as designed

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by normal usage after owner misconfiguration
- **Preconditions**: 
  1. Owner configures a token with `targetOrderDuration` close to `type(uint32).max` (lacks upper bound validation)
  2. First `roll()` call occurs when contract balance is 0
  3. Revenue accumulates and second `roll()` call is made
- **Execution Complexity**: Simple - just requires calling the public `roll()` function twice under the described conditions
- **Frequency**: Once per misconfigured token until owner reconfigures or cancels the order

## Recommendation [7](#0-6) 

```solidity
// In src/RevenueBuybacks.sol, function roll(), lines 115-131:

// CURRENT (vulnerable):
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

// FIXED:
} else {
    endTime =
        uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));
    
    // Check if nextValidTime returned the sentinel value 0 (no valid time exists)
    if (endTime == 0) {
        revert InvalidOrderDuration(); // New error type needed
    }

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

**Alternative mitigation:** Add validation in the `configure()` function to reject `targetOrderDuration` values that would cause `nextValidTime` to return 0: [8](#0-7) 

```solidity
// In src/RevenueBuybacks.sol, function configure(), add after line 153:

// Add maximum duration check to prevent nextValidTime from returning 0
// The maximum safe duration is approximately type(uint32).max - some buffer for step size
uint256 maxSafeDuration = type(uint32).max - (1 << 28); // Subtract max step size
if (targetOrderDuration > maxSafeDuration) {
    revert TargetOrderDurationTooLarge();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_RevenueBuybacksZeroEndTime.t.sol
// Run with: forge test --match-test test_RevenueBuybacksZeroEndTime -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/RevenueBuybacks.sol";
import "../src/Orders.sol";
import "../src/Core.sol";

contract Exploit_RevenueBuybacksZeroEndTime is Test {
    RevenueBuybacks buybacks;
    Orders orders;
    Core core;
    address token;
    address buyToken;
    
    function setUp() public {
        // Deploy contracts (simplified - actual setup would need full initialization)
        core = new Core();
        orders = new Orders(core);
        buyToken = address(0x1234); // Example buy token
        buybacks = new RevenueBuybacks(address(this), orders, buyToken);
        token = address(0x5678); // Example revenue token
    }
    
    function test_RevenueBuybacksZeroEndTime() public {
        // SETUP: Configure token with large targetOrderDuration
        uint32 largeTarget = type(uint32).max - 1000;
        buybacks.configure(token, largeTarget, 1 days, 500);
        
        // Set timestamp to a realistic value
        vm.warp(1700000000); // May 2023
        
        // EXPLOIT STEP 1: Call roll() with 0 balance
        // This stores lastEndTime = 0 due to nextValidTime returning 0
        (uint64 endTime1, ) = buybacks.roll(token);
        
        // VERIFY: endTime is 0 (the sentinel value confused with timestamp 0)
        assertEq(endTime1, 0, "First roll should produce endTime = 0");
        
        // EXPLOIT STEP 2: Simulate revenue accumulation
        deal(token, address(buybacks), 1000 ether);
        
        // Call roll() again - this will create an order with incorrect end time
        (uint64 endTime2, ) = buybacks.roll(token);
        
        // VERIFY: endTime is approximately 82 years in the future
        // Expected: ~4294967296 (year 2106)
        // Actual block.timestamp: 1700000000
        // timeRemaining underflow: type(uint32).max - 1700000000 + 1 ≈ 2594967296
        uint256 expectedEndTime = block.timestamp + (type(uint32).max - uint32(block.timestamp) + 1);
        
        assertApproxEqAbs(
            endTime2, 
            expectedEndTime, 
            1000, 
            "Second roll should produce endTime ~82 years in future due to underflow"
        );
        
        // Verify the order duration is incorrect (~82 years instead of ~136 years)
        uint256 actualDuration = endTime2 - block.timestamp;
        assertTrue(
            actualDuration > 365 days * 80 && actualDuration < 365 days * 85,
            "Order duration should be ~82 years, locking revenue for decades"
        );
    }
}
```

## Notes

The vulnerability stems from a semantic confusion between two meanings of 0:
1. **Sentinel value**: `nextValidTime` returns 0 to mean "no valid time exists in the allowed range"
2. **Unix epoch**: 0 as an actual timestamp representing January 1, 1970

The `RevenueBuybacks` contract treats the returned 0 as a valid timestamp without distinguishing it from the sentinel value. While direct order creation with `endTime = 0` would fail validation in `Orders.sol`, the vulnerability manifests when `amountToSpend = 0` bypasses order creation, allowing corrupted state to persist. The comment at line 107-108 acknowledges underflow behavior but doesn't account for the scenario where both `lastEndTime` and `lastOrderDuration` underflow to matching values, enabling the reuse path with incorrect calculations. [9](#0-8)

### Citations

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

**File:** src/RevenueBuybacks.sol (L90-139)
```text
    function roll(address token) public returns (uint64 endTime, uint112 saleRate) {
        unchecked {
            BuybacksState state;
            assembly ("memory-safe") {
                state := sload(token)
            }

            if (!state.isConfigured()) {
                revert TokenNotConfigured(token);
            }

            // minOrderDuration == 0 indicates the token is not configured
            bool isEth = token == NATIVE_TOKEN_ADDRESS;
            uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

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

            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
            }
        }
    }
```

**File:** src/RevenueBuybacks.sol (L141-173)
```text
    /// @notice Configures buyback parameters for a revenue token (only callable by owner)
    /// @dev Sets the timing and fee parameters for automated buyback order creation
    /// @param token The revenue token to configure
    /// @param targetOrderDuration The target duration for new orders (in seconds)
    /// @param minOrderDuration The minimum duration threshold for creating new orders (in seconds)
    /// @param fee The fee tier for the buyback pool
    function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
        external
        onlyOwner
    {
        if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
        if (minOrderDuration == 0 && targetOrderDuration != 0) {
            revert MinOrderDurationMustBeGreaterThanZero();
        }

        BuybacksState state;
        assembly ("memory-safe") {
            state := sload(token)
        }
        state = createBuybacksState({
            _targetOrderDuration: targetOrderDuration,
            _minOrderDuration: minOrderDuration,
            _fee: fee,
            _lastEndTime: state.lastEndTime(),
            _lastOrderDuration: state.lastOrderDuration(),
            _lastFee: state.lastFee()
        });
        assembly ("memory-safe") {
            sstore(token, state)
        }

        emit Configured(token, state);
    }
```
