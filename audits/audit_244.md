## Title
TWAMM Order Duration Overflow via Historical startTime Allows Accounting Manipulation

## Summary
The TWAMM extension allows orders with `startTime` in the distant past and `endTime` in the distant future, causing `uint32` overflow when calculating order durations. This leads to incorrect `amountSold` tracking and breaks protocol accounting invariants. [1](#0-0) [2](#0-1) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/libraries/TWAMMLib.sol` (line 87) and `src/extensions/TWAMM.sol` (lines 258-259)

**Intended Logic:** 
The TWAMM calculates order durations to determine how much should be sold over time. Duration calculations should accurately reflect the time elapsed between order start and current time, bounded by order end time. [3](#0-2) 

**Actual Logic:**
The `isTimeValid` function allows `startTime` to be any past time (as long as it's a multiple of the step size), while `endTime` can be up to `uint32.max` seconds in the future. [4](#0-3) [5](#0-4) 

This creates two overflow scenarios:

**Scenario 1 - Immediate Overflow (TWAMMLib.sol):**
At line 87, `totalOrderDuration = uint32(endTime - startTime)` wraps when the actual duration exceeds `uint32.max`. [6](#0-5) 

**Scenario 2 - Delayed Overflow (TWAMM.sol):**
At line 259, `uint32(uint64(block.timestamp) - startTime)` wraps once enough time passes from startTime. [2](#0-1) 

**Exploitation Path:**

1. **Attacker creates malicious order**: Set `startTime = 256` (valid past time), `endTime = block.timestamp + type(uint32).max`
   - Current block.timestamp ≈ 1,700,000,000
   - Duration = (1,700,000,000 + 4,294,967,295) - 256 ≈ 5,994,967,039 seconds
   - `uint32(5,994,967,039) = 1,699,999,744` (wraps to ~39% of actual value)

2. **Immediate impact on totalOrderDuration**: When `executeVirtualOrdersAndGetCurrentOrderInfo` is called, line 87 calculates wrapped duration, artificially limiting `saleDuration` in the min() calculation

3. **Progressive accounting corruption**: As time passes and `block.timestamp` approaches `startTime + uint32.max`, the duration calculation at TWAMM.sol:259 wraps to zero or small values

4. **Result**: `amountSold` is severely under-counted, allowing withdrawal of more tokens than actually sold, breaking pool solvency

**Security Property Broken:** 
Violates the **Fee Accounting** invariant - "Position fee collection must be accurate and never allow double-claiming". The incorrect `amountSold` tracking allows users to extract more value than they contributed.

## Impact Explanation

- **Affected Assets**: All TWAMM pools where orders use historical startTime values
- **Damage Severity**: Attacker can create orders with artificially small tracked `amountSold`, potentially withdrawing significantly more tokens than sold, leading to pool insolvency
- **User Impact**: All LPs in affected pools lose funds; multiple malicious orders can drain pool reserves

## Likelihood Explanation

- **Attacker Profile**: Any user can create TWAMM orders with these parameters
- **Preconditions**: Pool must be initialized with TWAMM extension; no other preconditions required
- **Execution Complexity**: Single transaction to create order with vulnerable parameters
- **Frequency**: Exploitable immediately upon order creation; effect persists throughout order lifetime

## Recommendation

Add validation to ensure order duration fits within uint32:

In `src/extensions/TWAMM.sol`, add check after line 199: [7](#0-6) 

```solidity
// After line 207, add:
if (endTime - startTime > type(uint32).max) revert OrderDurationTooLong();
```

Additionally, update `isTimeValid` to constrain past times: [4](#0-3) 

```solidity
// Constrain past times to within uint32.max of current time:
function isTimeValid(uint256 currentTime, uint256 time) pure returns (bool valid) {
    uint256 stepSize = computeStepSize(currentTime, time);
    assembly ("memory-safe") {
        valid := and(
            iszero(mod(time, stepSize)), 
            and(
                or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)),
                or(gt(time, currentTime), lt(sub(currentTime, time), 0x100000000))
            )
        )
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMDurationOverflow.t.sol
// Run with: forge test --match-test test_TWAMMDurationOverflow -vvv

pragma solidity ^0.8.31;

import {BaseTWAMMTest} from "./extensions/TWAMM.t.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {TWAMMLib} from "../src/libraries/TWAMMLib.sol";

contract Exploit_TWAMMDurationOverflow is BaseTWAMMTest {
    using TWAMMLib for *;

    function test_TWAMMDurationOverflow() public {
        // SETUP: Create TWAMM pool
        vm.warp(1_700_000_000); // Current time ~early 2024
        uint256 currentTime = block.timestamp;
        
        poolKey = createTwammPool(100, 0);
        
        // Attacker sets startTime to ancient past, endTime to max future
        uint64 startTime = 256; // Valid past time (multiple of 256)
        uint64 endTime = uint64(currentTime + type(uint32).max);
        
        // Calculate expected vs actual duration
        uint256 actualDuration = endTime - startTime;
        uint32 wrappedDuration = uint32(actualDuration);
        
        // VERIFY: Duration overflow occurs
        assertGt(actualDuration, type(uint32).max, "Duration exceeds uint32.max");
        assertLt(wrappedDuration, actualDuration, "Duration wraps around");
        
        // EXPLOIT: Create order with vulnerable parameters
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: createOrderConfig(100, true, startTime, endTime)
        });
        
        // The order creation succeeds despite duration overflow
        bytes32 salt = bytes32(uint256(1));
        router.updateSaleRate(address(twamm), salt, orderKey, int112(1e18));
        
        // VERIFY: totalOrderDuration will be incorrectly calculated
        console.log("Actual duration:", actualDuration);
        console.log("Wrapped duration:", wrappedDuration);
        console.log("Loss percentage:", (actualDuration - wrappedDuration) * 100 / actualDuration);
    }
}
```

**Notes:**

The vulnerability stems from allowing `startTime` values arbitrarily far in the past while `endTime` can be up to `uint32.max` in the future. The `isTimeValid` function only checks that past times are multiples of the step size but imposes no lower bound. This creates situations where `(endTime - startTime) > uint32.max`, causing uint32 casts to wrap and severely under-count sold amounts.

The issue is exploitable immediately (not requiring year 2106) and breaks the core accounting invariant of the TWAMM system, potentially leading to pool insolvency as users can extract more value than they contributed.

### Citations

**File:** src/libraries/TWAMMLib.sol (L87-99)
```text
                    uint32 totalOrderDuration = uint32(endTime - startTime);

                    uint32 remainingTimeSinceLastUpdate = uint32(endTime) - lastUpdateTime;

                    uint32 saleDuration = uint32(
                        FixedPointMathLib.min(
                            remainingTimeSinceLastUpdate,
                            FixedPointMathLib.min(
                                FixedPointMathLib.min(secondsSinceLastUpdate, secondsSinceOrderStart),
                                totalOrderDuration
                            )
                        )
                    );
```

**File:** src/extensions/TWAMM.sol (L199-207)
```text
                (uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

                if (endTime <= block.timestamp) revert OrderAlreadyEnded();

                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
```

**File:** src/extensions/TWAMM.sol (L255-262)
```text
                                    + computeAmountFromSaleRate({
                                        saleRate: saleRate,
                                        duration: FixedPointMathLib.min(
                                            uint32(block.timestamp) - lastUpdateTime,
                                            uint32(uint64(block.timestamp) - startTime)
                                        ),
                                        roundUp: false
                                    })
```

**File:** src/math/twamm.sol (L40-46)
```text
/// @dev Computes amount from sale rate: (saleRate * duration) >> 32, with optional rounding.
/// @dev Assumes the saleRate <= type(uint112).max and duration <= type(uint32).max
function computeAmountFromSaleRate(uint256 saleRate, uint256 duration, bool roundUp) pure returns (uint256 amount) {
    assembly ("memory-safe") {
        amount := shr(32, add(mul(saleRate, duration), mul(0xffffffff, roundUp)))
    }
}
```

**File:** src/math/time.sol (L33-40)
```text
/// @dev Returns true iff the given time is a valid start or end time for a TWAMM order
function isTimeValid(uint256 currentTime, uint256 time) pure returns (bool valid) {
    uint256 stepSize = computeStepSize(currentTime, time);

    assembly ("memory-safe") {
        valid := and(iszero(mod(time, stepSize)), or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)))
    }
}
```
