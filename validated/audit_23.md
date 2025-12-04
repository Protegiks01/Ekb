# Audit Report

## Title
Immediate Orders Bypass MAX_ABS_VALUE_SALE_RATE_DELTA Constraint Enabling Permanent Pool DOS

## Summary
The TWAMM extension's `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint is designed to prevent overflow by limiting sale rate deltas at each time boundary. However, immediate orders bypass this constraint when updating the current pool state, allowing an attacker to accumulate the current sale rate to `type(uint112).max` through 91 separate orders. This causes permanent pool DOS when any future time boundary with a positive net delta needs to be crossed, violating the explicit requirement that in-scope extensions must not freeze pools.

## Impact
**Severity**: High

The vulnerability enables complete and permanent freezing of TWAMM pools, locking all user capital indefinitely. All liquidity positions, pending TWAMM orders, and tokens in the pool become inaccessible because every pool operation (`beforeSwap`, `beforeUpdatePosition`, `beforeCollectFees`) requires executing virtual orders up to the current time. [1](#0-0)  Once a time boundary with positive net delta exists while current rate equals `type(uint112).max`, crossing that boundary triggers `SaleRateDeltaOverflow`, permanently preventing virtual order execution. This directly violates the security requirement that "extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital." [2](#0-1) 

**Affected Assets**: All liquidity positions in the TWAMM pool, all pending TWAMM orders, and all tokens locked in those positions.

**User Impact**: All users with positions or orders in the affected pool lose access to their funds. The attack affects the entire pool, not just the attacker's positions. Recovery requires the attacker's cooperation to cancel orders, making the DOS effectively permanent.

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, function `handleForwardData()`, lines 274-299 and lines 554-558

**Intended Logic:**
The `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint is defined as `type(uint112).max / 91` to ensure that even with 91 time boundaries each having maximum deltas, the cumulative sale rate cannot overflow `type(uint112).max`. [3](#0-2)  The constraint is enforced via `_addConstrainSaleRateDelta`, which validates that `abs(result) <= MAX_ABS_VALUE_SALE_RATE_DELTA` and reverts otherwise. [4](#0-3) 

**Actual Logic:**
Future orders correctly enforce the constraint by calling `_updateTime` for both start and end times [5](#0-4) , which internally uses `_addConstrainSaleRateDelta` at lines 172-174. [6](#0-5) 

However, immediate orders (where `block.timestamp >= startTime`) bypass the constraint for the current sale rate. They update the current state using `addSaleRateDelta` directly [7](#0-6) , which only checks if the result exceeds `type(uint112).max`, NOT `MAX_ABS_VALUE_SALE_RATE_DELTA`. [8](#0-7) 

**Exploitation Path:**

1. **Attacker creates 91 immediate orders**: Each order has `startTime ≤ block.timestamp`, unique `endTime` (using all 91 valid future times), and `saleRateDelta = MAX_ABS_VALUE_SALE_RATE_DELTA`. Processing each immediate order calls `addSaleRateDelta(currentRate, saleRateDelta)` at line 285 or 290, which adds `MAX_ABS_VALUE_SALE_RATE_DELTA` to the current rate. After 91 orders: `currentRate = 91 * MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max`. Each order also adds negative delta `-MAX_ABS_VALUE_SALE_RATE_DELTA` to its end time via `_updateTime` at line 298.

2. **Legitimate users create future orders**: When users create orders with `startTime > block.timestamp`, the start time receives a positive delta through `_updateTime`. Multiple users can reference the same start time (e.g., time T1 that already has delta `-MAX_ABS_VALUE_SALE_RATE_DELTA` from attacker's order ending there). User A adds `+MAX_ABS_VALUE_SALE_RATE_DELTA`, making T1's net delta = 0. User B then adds positive delta X, and `_addConstrainSaleRateDelta(0, X)` validates that `|0 + X| ≤ MAX_ABS_VALUE_SALE_RATE_DELTA` (passes), resulting in T1's net delta = X > 0.

3. **Virtual order execution triggers overflow**: When `lockAndExecuteVirtualOrders` crosses time T1, lines 554-558 apply the time delta: `addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)`. [9](#0-8)  With `state.saleRateToken0() = type(uint112).max` and `saleRateDeltaToken0 = X > 0`, the result exceeds `type(uint112).max`, causing `shr(112, result)` to be non-zero, triggering revert with `SaleRateDeltaOverflow`.

4. **Pool permanently frozen**: All pool operations fail because `beforeSwap`, `beforeUpdatePosition`, and `beforeCollectFees` all call `lockAndExecuteVirtualOrders`. [1](#0-0)  The pool cannot execute virtual orders past time T1, blocking all functionality.

**Root Cause**: The design incorrectly assumes that constraining individual time deltas is sufficient to prevent overflow. This works for future orders where all rate changes flow through time boundaries, but fails for immediate orders which directly modify current state without creating a start time delta. The `_addConstrainSaleRateDelta` function only constrains the NET delta at each time boundary, not the cumulative effect when current rate is already at maximum.

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital to create 91 orders at `MAX_ABS_VALUE_SALE_RATE_DELTA` sale rate each.

**Preconditions**:
1. TWAMM pool must be initialized (always true for active pools)
2. Attacker needs capital for 91 orders (locked but can freeze far more value)
3. There must be 91 distinct valid future times available (always true given the time grid system)

**Execution Complexity**: Single multicall transaction to create all 91 orders simultaneously. Can be executed atomically. Natural user behavior (creating future orders) eventually triggers the DOS.

**Overall Likelihood**: HIGH - Preconditions are always satisfied for any active TWAMM pool, execution is straightforward, and the DOS is permanent once triggered.

## Recommendation

**Primary Fix**: In `src/extensions/TWAMM.sol`, function `handleForwardData()`, lines 285 and 290, replace the direct `addSaleRateDelta` calls with calls to a new function that enforces the `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint on the cumulative current sale rate, similar to how `_addConstrainSaleRateDelta` constrains time deltas.

**Alternative Mitigation**: Track a separate "current rate delta" storage slot that accumulates all immediate order contributions and is also constrained to `MAX_ABS_VALUE_SALE_RATE_DELTA`, maintaining the fundamental invariant that no single time point (including "current") can exceed the per-time limit.

## Notes

The vulnerability arises from asymmetric constraint enforcement: future orders properly enforce `MAX_ABS_VALUE_SALE_RATE_DELTA` on both start and end time deltas, but immediate orders only enforce it on the end time delta while allowing current rate to grow unconstrained up to `type(uint112).max`. The DOS persists until the attacker cancels enough orders to bring the current rate below `type(uint112).max - MAX_ABS_VALUE_SALE_RATE_DELTA`, requiring the attacker's cooperation. This makes it economically viable as a griefing mechanism where the attacker locks their capital but freezes far more value held by other users.

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

**File:** src/extensions/TWAMM.sol (L171-175)
```text
        if (isToken1) {
            saleRateDeltaToken1 = _addConstrainSaleRateDelta(saleRateDeltaToken1, saleRateDelta);
        } else {
            saleRateDeltaToken0 = _addConstrainSaleRateDelta(saleRateDeltaToken0, saleRateDelta);
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
