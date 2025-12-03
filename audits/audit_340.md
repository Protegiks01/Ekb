## Title
TWAMM Pool Sale Rate Saturation Causes Permanent Order Update DOS

## Summary
The TWAMM extension's `addSaleRateDelta()` function can revert with `SaleRateDeltaOverflow` when the pool's cumulative sale rate approaches `type(uint112).max`, even when adding valid deltas that pass individual constraints. This occurs because the constraint `MAX_ABS_VALUE_SALE_RATE_DELTA` applies to deltas at each time boundary, not to the pool's total sale rate, allowing legitimate accumulation to saturate the uint112 storage.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** The TWAMM system constrains sale rate deltas at time boundaries to `MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / 91` to prevent overflow. With at most 91 valid future times, the design assumes cumulative sale rates remain within uint112 bounds.

**Actual Logic:** The constraint validation occurs in `_addConstrainSaleRateDelta()` when updating time boundary deltas, but does NOT validate whether the pool's current total sale rate will overflow when the delta is applied during order updates. Multiple orders starting at different times can each contribute deltas up to the limit, causing the pool's current rate to legitimately approach `type(uint112).max`. When this occurs, `addSaleRateDelta()` reverts on line 32 when attempting to apply any positive delta to the pool state. [3](#0-2) 

**Exploitation Path:**
1. Multiple users create orders with start times at different valid future times (T1, T2, ..., T91), each with sale rate deltas approaching `MAX_ABS_VALUE_SALE_RATE_DELTA`
2. As each time Ti is crossed during `_executeVirtualOrdersFromWithinLock()`, the pool's `saleRateToken0` or `saleRateToken1` increases by the time delta [4](#0-3) 
3. After sufficient times are crossed, the pool's sale rate reaches near `type(uint112).max` (e.g., 91 * MAX_ABS_VALUE_SALE_RATE_DELTA ≈ type(uint112).max)
4. Any subsequent attempt to increase an order's sale rate or create a new order reverts in `addSaleRateDelta()` because `rate + saleRateDelta > type(uint112).max` [5](#0-4) 

**Security Property Broken:** This violates the implicit expectation that users can update their orders when all inputs are individually valid. The invariant test acknowledges `SaleRateDeltaOverflow` as expected during fuzzing, indicating awareness of this limitation: [6](#0-5) 

## Impact Explanation
- **Affected Assets**: All TWAMM orders in the affected pool
- **Damage Severity**: Users cannot increase existing orders or create new orders until sufficient orders end to reduce the pool's sale rate. No funds are lost, but operations are blocked.
- **User Impact**: All users attempting to interact with the saturated pool, potentially lasting until orders expire (up to type(uint32).max seconds)

## Likelihood Explanation
- **Attacker Profile**: Any users (no malicious intent required) - occurs naturally with high order volume
- **Preconditions**: Pool must have multiple active orders with high sale rates across many time boundaries
- **Execution Complexity**: No attack needed - emerges from normal protocol usage
- **Frequency**: Rare but permanent once reached; resolves only when orders expire

## Recommendation

Add validation before applying deltas to the current pool state:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, lines 281-293:

// CURRENT (vulnerable):
// No check before addSaleRateDelta() application to pool state

// FIXED:
if (isToken1) {
    // Validate before applying to prevent revert
    uint256 newRate = uint256(rate1) + uint256(saleRateDelta);
    if (saleRateDelta > 0 && newRate > type(uint112).max) {
        revert PoolSaleRateCapacityExceeded();
    }
    currentState = createTwammPoolState({
        _lastVirtualOrderExecutionTime: lastTime,
        _saleRateToken0: rate0,
        _saleRateToken1: uint112(newRate)
    });
} else {
    uint256 newRate = uint256(rate0) + uint256(saleRateDelta);
    if (saleRateDelta > 0 && newRate > type(uint112).max) {
        revert PoolSaleRateCapacityExceeded();
    }
    currentState = createTwammPoolState({
        _lastVirtualOrderExecutionTime: lastTime,
        _saleRateToken0: uint112(newRate),
        _saleRateToken1: rate1
    });
}
```

Alternative: Document this as expected behavior and adjust `MAX_ABS_VALUE_SALE_RATE_DELTA` to include headroom for concurrent active orders.

## Proof of Concept

```solidity
// File: test/Exploit_SaleRateSaturation.t.sol
// Run with: forge test --match-test test_SaleRateSaturation -vvv

pragma solidity ^0.8.31;

import {BaseOrdersTest} from "./Orders.t.sol";
import {OrderKey} from "../src/interfaces/extensions/ITWAMM.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {nextValidTime} from "../src/math/time.sol";
import {MAX_ABS_VALUE_SALE_RATE_DELTA} from "../src/math/time.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_SaleRateSaturation is BaseOrdersTest {
    function test_SaleRateSaturation() public {
        // SETUP: Create pool with liquidity
        uint64 fee = 0;
        PoolKey memory poolKey = createTwammPool(fee, 0);
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1e30, 1e30);
        
        token0.approve(address(orders), type(uint256).max);
        
        uint64 currentTime = uint64(block.timestamp);
        uint64 commonEndTime = uint64(nextValidTime(currentTime, currentTime + 365 days));
        
        // Create multiple orders at different start times to saturate pool sale rate
        uint256 numOrders = 85; // Near the 91 limit
        uint256 amountPerOrder = 1e24; // Large amount to create high sale rate
        
        for (uint256 i = 0; i < numOrders; i++) {
            uint64 startTime = uint64(nextValidTime(currentTime, currentTime + (i * 256)));
            
            OrderKey memory key = OrderKey({
                token0: poolKey.token0,
                token1: poolKey.token1,
                config: createOrderConfig({
                    _fee: fee,
                    _isToken1: false,
                    _startTime: startTime,
                    _endTime: commonEndTime
                })
            });
            
            // Create order with high sale rate
            orders.mintAndIncreaseSellAmount(key, amountPerOrder, type(uint112).max);
        }
        
        // EXPLOIT: Warp time forward so all orders become active
        vm.warp(commonEndTime - 1 days);
        
        // Execute virtual orders to activate all orders
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // Try to create one more order or increase an existing one
        uint64 newStartTime = uint64(nextValidTime(block.timestamp, block.timestamp));
        uint64 newEndTime = uint64(nextValidTime(block.timestamp, newStartTime + 256));
        
        OrderKey memory newKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: false,
                _startTime: newStartTime,
                _endTime: newEndTime
            })
        });
        
        // VERIFY: This should revert with SaleRateDeltaOverflow
        vm.expectRevert(bytes4(0xc902643d)); // SaleRateDeltaOverflow selector
        orders.mintAndIncreaseSellAmount(newKey, 1000, type(uint112).max);
        
        // Vulnerability confirmed: legitimate order creation blocked due to pool saturation
    }
}
```

## Notes

This vulnerability emerges from the design decision to constrain deltas per time boundary rather than total pool capacity. While the invariant test acknowledges this can occur, it's not documented as a known limitation in the README. The issue is **temporary** (resolves when orders expire) but can persist for extended periods (up to ~136 years if orders span the full uint32 time range), effectively creating a permanent DOS for the pool's practical lifetime.

The constraint system was designed assuming 91 concurrent time boundaries, but doesn't account for the cumulative effect when all those boundaries are crossed and orders become simultaneously active in the pool state.

### Citations

**File:** src/extensions/TWAMM.sol (L118-132)
```text
    function _addConstrainSaleRateDelta(int112 saleRateDelta, int256 saleRateDeltaChange)
        internal
        pure
        returns (int112 saleRateDeltaNext)
    {
        int256 result = int256(saleRateDelta) + saleRateDeltaChange;

        // checked addition, no overflow of int112 type
        if (FixedPointMathLib.abs(result) > MAX_ABS_VALUE_SALE_RATE_DELTA) {
            revert MaxSaleRateDeltaPerTime();
        }

        // we know cast is safe because abs(result) is less than MAX_ABS_VALUE_SALE_RATE_DELTA which fits in a int112
        saleRateDeltaNext = int112(result);
    }
```

**File:** src/extensions/TWAMM.sol (L281-293)
```text
                    if (isToken1) {
                        currentState = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: lastTime,
                            _saleRateToken0: rate0,
                            _saleRateToken1: uint112(addSaleRateDelta(rate1, saleRateDelta))
                        });
                    } else {
                        currentState = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: lastTime,
                            _saleRateToken0: uint112(addSaleRateDelta(rate0, saleRateDelta)),
                            _saleRateToken1: rate1
                        });
                    }
```

**File:** src/extensions/TWAMM.sol (L554-558)
```text
                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
                            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
                        });
```

**File:** src/math/twamm.sol (L28-38)
```text
function addSaleRateDelta(uint256 saleRate, int256 saleRateDelta) pure returns (uint256 result) {
    assembly ("memory-safe") {
        result := add(saleRate, saleRateDelta)
        // if any of the upper bits are non-zero, revert
        if shr(112, result) {
            // cast sig "SaleRateDeltaOverflow()"
            mstore(0, shl(224, 0xc902643d))
            revert(0, 4)
        }
    }
}
```

**File:** test/TWAMMInvariantTest.t.sol (L271-274)
```text
            // 0xc902643d == SaleRateDeltaOverflow()
            if (
                sig != SaleRateOverflow.selector && sig != ITWAMM.MaxSaleRateDeltaPerTime.selector
                    && sig != SafeCastLib.Overflow.selector && sig != 0xc902643d
```
