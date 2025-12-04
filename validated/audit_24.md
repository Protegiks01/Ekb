# Audit Report

## Title
Immediate Orders Bypass MAX_ABS_VALUE_SALE_RATE_DELTA Constraint Enabling Permanent Pool DOS

## Summary
The TWAMM extension's `MAX_ABS_VALUE_SALE_RATE_DELTA` safety constraint can be circumvented by immediate orders, allowing an attacker to accumulate the current sale rate to `type(uint112).max` through repeated order creation. This causes permanent denial-of-service when any time boundary with a positive sale rate delta is crossed, freezing all pool operations including swaps, liquidity withdrawals, and fee collection.

## Impact
**Severity**: High

**Justification**: This vulnerability causes permanent freezing of an entire TWAMM pool, locking all user capital (liquidity positions, pending orders, accumulated fees) indefinitely until the attacker voluntarily cancels their orders. This represents complete loss of fund accessibility for all pool participants, meeting the High severity threshold for permanent capital lock.

**Affected Assets**: 
- All liquidity provider positions in the TWAMM pool
- All active TWAMM orders (both the attacker's and legitimate users')
- All accumulated protocol fees and user fee claims
- The pool's token reserves (both token0 and token1)

**Damage Quantification**:
- 100% of pool participants lose access to their capital
- Pool becomes non-functional for all operations
- Recovery requires attacker cooperation (voluntary order cancellation)
- Attack is repeatable across all TWAMM pools in the protocol

**Violation of Core Requirement**: This directly violates the explicit security requirement stated in the README: "The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital." [1](#0-0) 

## Finding Description

**Location**: `src/extensions/TWAMM.sol`, function `handleForwardData()`, lines 274-299

**Intended Safety Mechanism**:

The protocol defines `MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / 91` to ensure that even with the maximum 91 valid time boundaries each having maximum deltas, the cumulative sale rate cannot overflow `type(uint112).max`. [2](#0-1) 

This constraint is enforced through `_addConstrainSaleRateDelta()`, which validates that `abs(result) <= MAX_ABS_VALUE_SALE_RATE_DELTA` before allowing any sale rate delta to be applied to a time boundary. [3](#0-2) 

**Actual Implementation Flaw**:

Future orders (where `block.timestamp < startTime`) correctly enforce the constraint on both their start and end time boundaries by routing through `_updateTime()`, which internally calls `_addConstrainSaleRateDelta()`. [4](#0-3) 

However, immediate orders (where `block.timestamp >= startTime`) bypass this constraint when updating the current pool state. They directly call `addSaleRateDelta()` to update the current sale rate without going through the constrained `_addConstrainSaleRateDelta()` function. [5](#0-4) 

The critical difference is that `addSaleRateDelta()` only checks if the result exceeds `type(uint112).max`, NOT `MAX_ABS_VALUE_SALE_RATE_DELTA`: [6](#0-5) 

**Exploitation Path**:

1. **Accumulation Phase**: Attacker creates 91 immediate orders in a single transaction (via multicall), each with:
   - `startTime <= block.timestamp` (triggers immediate order path)
   - Unique `endTime` values (utilizing all 91 valid future times)
   - `saleRateDelta = MAX_ABS_VALUE_SALE_RATE_DELTA` (maximum allowed per order)

2. **Constraint Bypass**: Each immediate order execution at lines 285 or 290 calls `addSaleRateDelta(currentRate, MAX_ABS_VALUE_SALE_RATE_DELTA)`, which only validates against `type(uint112).max`. After 91 orders: `currentRate = 91 * MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max`

3. **Trigger Setup**: Any user (including the attacker) creates a future order with `startTime > block.timestamp`, which adds a positive delta to that future time boundary (properly constrained individually).

4. **Overflow Trigger**: When `lockAndExecuteVirtualOrders()` attempts to cross that future time boundary, it tries to apply the positive delta to the already-maxed current rate via `addSaleRateDelta(type(uint112).max, positiveDelta)`, causing overflow. [7](#0-6) 

5. **DOS Propagation**: All critical pool operations revert because they call `lockAndExecuteVirtualOrders()` in their before-hooks, permanently freezing the pool. [8](#0-7) 

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital to create 91 TWAMM orders (no special privileges required)

**Preconditions**:
1. TWAMM pool must be initialized (universally true for active pools)
2. Attacker requires capital for 91 orders with `MAX_ABS_VALUE_SALE_RATE_DELTA` sale rate
3. 91 valid future times must be available (always satisfied by the time grid design)

**Execution Complexity**: 
- Single atomic transaction via multicall
- No front-running or timing dependencies required
- No coordination with other users needed (attacker can trigger independently)

**Economic Analysis**:
- High capital requirement per order, but attacker locks their capital to freeze potentially far greater value from other users
- Economically rational as griefing attack or ransom scenario
- Attack cost bounded by order capital, but impact unbounded (entire pool value)

**Permanence**: DOS persists until attacker cancels sufficient orders to reduce current rate below overflow threshold, requiring attacker cooperation

**Overall Likelihood**: MEDIUM-HIGH - While capital-intensive, preconditions are always met, execution is straightforward, and economic incentives exist for griefing or extortion attacks.

## Recommendation

**Primary Fix**: 

In `src/extensions/TWAMM.sol`, function `handleForwardData()`, lines 285 and 290, replace direct `addSaleRateDelta()` calls with a constrained version that enforces the `MAX_ABS_VALUE_SALE_RATE_DELTA` limit on the current pool state.

Introduce a mechanism to track cumulative immediate order contributions to the current rate and ensure they remain bounded, maintaining the invariant that no time point (including "current") exceeds the per-time safety limit.

**Alternative Mitigation**:

Track a separate "current rate delta accumulator" in storage that aggregates all immediate order contributions. Apply the same `MAX_ABS_VALUE_SALE_RATE_DELTA` constraint to this accumulator, preventing unlimited accumulation in the current state while preserving the fundamental safety invariant.

## Notes

**Root Cause Analysis**: The design incorrectly treats "current time" as distinct from future time boundaries for constraint enforcement purposes. While future time deltas are constrained to prevent overflow when crossed, immediate orders accumulate directly in current state without cumulative constraint, creating an asymmetric vulnerability.

**Constraint Asymmetry**: Future orders enforce `MAX_ABS_VALUE_SALE_RATE_DELTA` on both start and end time deltas, but immediate orders only enforce it on the end time delta while allowing current rate to grow unconstrained up to `type(uint112).max`.

**Attack Economics**: The attacker's capital is locked but not lost, while the frozen pool value (potentially orders of magnitude larger) remains inaccessible to all participants. This asymmetry makes the attack economically viable for extortion or competitive sabotage scenarios.

**Additional Validation Required**: A comprehensive fix should ensure the fundamental invariant holds: for any reachable pool state and any valid time delta crossing, `currentRate + delta <= type(uint112).max`. This requires either constraining immediate order accumulation or implementing overflow-safe delta application logic.

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

**File:** src/extensions/TWAMM.sol (L647-665)
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
    }
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
