# Audit Report

## Title
Immediate Orders Bypass MAX_ABS_VALUE_SALE_RATE_DELTA Constraint Enabling Permanent Pool DOS

## Summary
The TWAMM extension's `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint is designed to prevent overflow by limiting sale rate deltas at each time boundary to `type(uint112).max / 91`. However, immediate orders (startTime ≤ block.timestamp) bypass this constraint when updating the current pool state, allowing an attacker to accumulate the current sale rate to `type(uint112).max` through 91 separate orders. This causes permanent pool DOS when any future time boundary with a positive delta needs to be crossed.

## Impact
**Severity**: High

**Affected Assets**: All liquidity positions in the TWAMM pool, all pending TWAMM orders, and all tokens locked in those positions.

**Damage Severity**: 
- Complete and permanent freeze of the pool
- Users cannot withdraw liquidity, collect fees, cancel orders, or perform swaps
- Funds remain locked until the attacker cancels their orders (which may never happen)
- Violates the explicit requirement that in-scope extensions must not freeze pools [1](#0-0) 

**User Impact**: All users with positions or orders in the affected pool are impacted. The attack affects the entire pool, not just the attacker's positions.

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, function `handleForwardData()`, lines 274-299

**Intended Logic:** 
The `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint is defined as `type(uint112).max / 91` to ensure that even with 91 time boundaries each having maximum deltas, the cumulative sale rate cannot overflow `type(uint112).max`. [2](#0-1) 

The constraint is enforced via `_addConstrainSaleRateDelta` which validates that `abs(result) <= MAX_ABS_VALUE_SALE_RATE_DELTA` and reverts otherwise. [3](#0-2) 

**Actual Logic:**
Future orders correctly enforce the constraint by calling `_updateTime` for both start and end times [4](#0-3) , which internally uses `_addConstrainSaleRateDelta` at lines 172-174.

However, immediate orders (block.timestamp ≥ startTime) bypass the constraint for the current sale rate. They update the current state using `addSaleRateDelta` directly [5](#0-4) , which only checks if the result exceeds `type(uint112).max`, NOT `MAX_ABS_VALUE_SALE_RATE_DELTA`. [6](#0-5) 

**Exploitation Path:**

1. **Attacker creates 91 immediate orders**: Each order has:
   - `startTime` ≤ `block.timestamp` (immediate start)
   - Unique `endTime` (using all 91 valid future times)
   - `saleRateDelta` = `MAX_ABS_VALUE_SALE_RATE_DELTA`
   
2. **Processing accumulates current rate**: For each immediate order:
   - Line 285 or 290 calls `addSaleRateDelta(currentRate, saleRateDelta)` 
   - This adds `MAX_ABS_VALUE_SALE_RATE_DELTA` to the current rate
   - Line 298 adds negative delta to end time (properly constrained)
   - After 91 orders: current rate = `91 * MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max`

3. **Legitimate user creates future order**: When any user creates an order with `startTime > block.timestamp`:
   - Start time receives a positive delta through `_updateTime` (line 272)
   - This delta is individually constrained to `MAX_ABS_VALUE_SALE_RATE_DELTA`

4. **Virtual order execution triggers overflow**: When `lockAndExecuteVirtualOrders` crosses that future start time:
   - Lines 554-558 apply the time delta via `addSaleRateDelta` [7](#0-6) 
   - Calling `addSaleRateDelta(type(uint112).max, positiveDelta)` overflows
   - Reverts with `SaleRateDeltaOverflow`

5. **Pool permanently frozen**: All pool operations fail because `beforeSwap`, `beforeUpdatePosition`, and `beforeCollectFees` all call `lockAndExecuteVirtualOrders` [8](#0-7) 

**Security Property Broken:**
Violates README requirement: "The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital." [1](#0-0) 

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital to create 91 orders

**Preconditions**:
1. TWAMM pool must be initialized (always true for active pools)
2. Attacker needs capital for 91 orders at `MAX_ABS_VALUE_SALE_RATE_DELTA` sale rate each
3. There must be 91 distinct valid future times available (always true given the time grid system with 256-second minimum intervals)

**Execution Complexity**: Single multicall transaction to create all 91 orders simultaneously. Can be executed atomically.

**Economic Cost**: Capital locked in 91 orders, but attacker can freeze far more value held by other users

**Frequency**: Can be executed once per pool. Once executed, the DOS is permanent until attacker cancels orders. Multiple attackers can coordinate to affect multiple pools simultaneously.

**Overall Likelihood**: HIGH - Preconditions are always satisfied for any active TWAMM pool, execution is straightforward

## Recommendation

Enforce the `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint when updating the current sale rate for immediate orders. The fix requires tracking the cumulative current rate and applying the same constraint that protects future time boundaries.

**Primary Fix**: In `src/extensions/TWAMM.sol`, function `handleForwardData()`, replace the direct `addSaleRateDelta` calls (lines 285, 290) with `_addConstrainSaleRateDelta` calls that enforce the constraint on the current state.

**Alternative Mitigation**: Track a separate "current rate delta" storage slot that accumulates all immediate order contributions and is also constrained to `MAX_ABS_VALUE_SALE_RATE_DELTA`, maintaining the fundamental invariant that no single time point (including "current") can exceed the per-time limit.

## Notes

**Root Cause**: The design incorrectly assumes that constraining individual time deltas is sufficient to prevent overflow. This works for future orders where all rate changes flow through time boundaries, but fails for immediate orders which directly modify current state without creating a start time delta. The accumulation of 91 immediate orders' contributions to current state bypasses the per-time constraint entirely.

**Asymmetric Constraint Enforcement**: Future orders properly enforce `MAX_ABS_VALUE_SALE_RATE_DELTA` on both start and end time deltas, but immediate orders only enforce it on the end time delta while allowing current rate to grow unconstrained up to `type(uint112).max`.

**Attack Economics**: The attacker needs capital to create 91 orders but can freeze far more value locked by other users, making this economically viable as a griefing mechanism or ransom scenario.

**Permanent Nature**: The DOS persists until the attacker cancels enough orders to bring the current rate below `type(uint112).max - MAX_ABS_VALUE_SALE_RATE_DELTA`. Since order cancellation requires the attacker's cooperation, this is effectively permanent without intervention.

### Citations

**File:** README.md (L48-48)
```markdown
The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital.
```

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
