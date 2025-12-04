# Audit Report

## Title
TWAMM Extension State Corruption via Nested Reentrancy During Virtual Order Execution

## Summary
The TWAMM extension's virtual order execution function reads state from storage, executes swaps that trigger nested callbacks, then writes state back to storage. This allows nested execution to process and modify the same storage slots, with the outer call's final write overwriting the nested call's updates with stale data, corrupting the TWAMM pool state.

## Impact
**Severity**: High

This vulnerability causes state corruption in TWAMM pools, leading to incorrect sale rates, corrupted reward distributions, and broken time boundary tracking. The corruption affects all liquidity providers (incorrect fee distributions) and order placers (incorrect order execution amounts) in TWAMM pools. Virtual orders may execute with wrong amounts or fail entirely due to corrupted bitmaps and cleared time slots. The issue can be triggered unintentionally during normal protocol usage (collectFees, swap, updatePosition calls), making it a systemic risk affecting all TWAMM pools with pending virtual orders.

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, function `_executeVirtualOrdersFromWithinLock()` [1](#0-0) 

**Intended Logic:** 
The timestamp check at line 404 is intended to prevent redundant virtual order execution within the same block. The extension should execute virtual orders once per block, updating the timestamp to block.timestamp to prevent re-execution.

**Actual Logic:**
The timestamp check reads from storage at the beginning (line 389) but storage is only written at the end (line 587). During execution, CORE.swap calls trigger the beforeSwap callback [2](#0-1) [3](#0-2) 

which calls lockAndExecuteVirtualOrders again. The FlashAccountant explicitly allows nested locks with incrementing IDs: [4](#0-3) 

The nested call reads the same stale timestamp from storage (outer call hasn't written yet), passes the timestamp check, and executes virtual orders. Both calls modify shared storage: [5](#0-4) 

The nested call clears timeInfo slots (line 562) and flips bitmaps (line 564). When the outer call continues, it reads these cleared/flipped values but continues with its stale local state variable. The outer call's final write: [6](#0-5) 

overwrites the nested call's correct state with stale sale rates and corrupted reward calculations.

**Exploitation Path:**
1. **Trigger**: User calls collectFees on TWAMM pool with pending virtual orders (lastVirtualOrderExecutionTime < block.timestamp) [7](#0-6) 

2. **Outer Execution**: TWAMM's beforeCollectFees triggers lockAndExecuteVirtualOrders [8](#0-7) 
   
   Outer call reads state showing realLastVirtualOrderExecutionTime = T1 (old), enters execution loop

3. **Nested Trigger**: During virtual order execution, CORE.swap is called [9](#0-8) 
   
   This triggers beforeSwap callback which calls lockAndExecuteVirtualOrders again

4. **Nested Execution**: Nested call reads SAME stale timestamp T1 from storage (storage not yet updated), passes check, processes all intervals, clears timeInfo slots, flips bitmaps, writes final state with timestamp = block.timestamp

5. **State Corruption**: Outer call resumes with stale local state, but storage is modified (timeInfo cleared → returns 0, bitmaps flipped), outer call processes with corrupted data and overwrites nested call's correct state

**Security Property Broken:**
Violates the main invariant from README: "All positions should be able to be withdrawn at any time" and "The codebase contains extensive unit and fuzzing test suites; many of these include invariants that should be upheld by the system." The state corruption breaks fee accounting and can cause DOS of future virtual order executions due to corrupted bitmaps.

## Impact Explanation

**Affected Assets**: All TWAMM pools with active virtual orders. Specifically affects token0 and token1 balances in affected pools, liquidity provider fee shares, and TWAMM order execution.

**Damage Severity**:
- Sale rates become incorrect, causing virtual orders to execute with wrong amounts
- Reward rate calculations corrupted, causing incorrect fee distribution to liquidity providers
- Time info slots cleared by nested call cause outer call to process with zero deltas
- Bitmap corruption can cause permanent DOS (inability to execute future virtual orders)
- Potential for complete loss of value in affected orders if execution amounts are severely miscalculated

**User Impact**: All users interacting with TWAMM pools are affected. The vulnerability triggers on any call to collectFees, swap, or updatePosition on TWAMM pools with pending virtual orders.

**Trigger Conditions**: Any user can trigger with single transaction calling collectFees/swap/updatePosition on a TWAMM pool that has pending virtual orders and at least one initialized time boundary.

## Likelihood Explanation

**Attacker Profile**: Any user or contract interacting with TWAMM pools. No special permissions required. Can be triggered unintentionally during normal protocol usage.

**Preconditions**:
1. TWAMM pool must be initialized with pending virtual orders (lastVirtualOrderExecutionTime < block.timestamp) - common state
2. Pool must have at least one initialized time boundary for virtual order execution
3. User calls any function triggering beforeCollectFees, beforeSwap, or beforeUpdatePosition

**Execution Complexity**: Single transaction. The reentrancy occurs automatically through the normal extension callback mechanism during CORE.swap execution. No complex setup required.

**Economic Cost**: Only gas fees for the triggering transaction. No capital requirements.

**Frequency**: Can occur on every call to collectFees, swap, or updatePosition on TWAMM pools with pending virtual orders. Given that virtual orders accumulate over time between blocks, this is a frequent occurrence.

**Overall Likelihood**: HIGH - Easily triggered during normal protocol operations, affects all TWAMM pools with active orders.

## Recommendation

**Primary Fix - Add Transient Storage Reentrancy Guard:**

Add a reentrancy guard using transient storage in `_executeVirtualOrdersFromWithinLock`:

```solidity
// At contract level in src/extensions/TWAMM.sol:
uint256 private constant _EXECUTING_VIRTUAL_ORDERS_SLOT = 
    uint256(keccak256("TWAMM.executingVirtualOrders"));

// At start of _executeVirtualOrdersFromWithinLock (line 387):
assembly ("memory-safe") {
    let executing := tload(_EXECUTING_VIRTUAL_ORDERS_SLOT)
    if executing {
        return(0, 0)  // Already executing, return early
    }
    tstore(_EXECUTING_VIRTUAL_ORDERS_SLOT, 1)
}

// Before all return paths and at end of function:
assembly ("memory-safe") {
    tstore(_EXECUTING_VIRTUAL_ORDERS_SLOT, 0)
}
```

**Alternative Fix - Update Timestamp Immediately:**

Move the timestamp storage write to immediately after the check (before the execution loop) to prevent nested calls from passing the check:

```solidity
// In _executeVirtualOrdersFromWithinLock, after line 404:
if (realLastVirtualOrderExecutionTime != block.timestamp) {
    // Update storage IMMEDIATELY to prevent reentrancy
    stateSlot.store(TwammPoolState.unwrap(
        createTwammPoolState({
            _lastVirtualOrderExecutionTime: uint32(block.timestamp),
            _saleRateToken0: state.saleRateToken0(),
            _saleRateToken1: state.saleRateToken1()
        })
    ));
    
    // Continue with execution loop...
    // Write correct final state at end
}
```

**Recommended Approach**: Use the transient storage guard (Primary Fix) as it cleanly prevents any nested execution without requiring multiple storage writes or complex state management.

## Notes

This vulnerability demonstrates a violation of the check-effects-interactions pattern in `_executeVirtualOrdersFromWithinLock`. The timestamp-based reentrancy protection is insufficient because it reads from storage at the beginning but only writes at the end. The FlashAccountant's lock mechanism explicitly allows nested locks with different IDs, which enables the reentrancy. The vulnerability affects all TWAMM pools and can be triggered by normal protocol usage, not requiring malicious intent. The issue is particularly severe because the nested call's storage modifications (clearing time slots, flipping bitmaps) create inconsistent state for the outer call to continue processing, resulting in data corruption rather than clean failure.

### Citations

**File:** src/extensions/TWAMM.sol (L386-404)
```text
    function _executeVirtualOrdersFromWithinLock(PoolKey memory poolKey, PoolId poolId) internal {
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

            // we only conditionally load this if the state is coincidentally zero,
            // in order to not lock the pool if state is 0 but the pool _is_ initialized
            // this can only happen iff a pool has zero sale rates **and** an execution of virtual orders
            // happens on the uint32 boundary
            if (TwammPoolState.unwrap(state) == bytes32(0)) {
                if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
                    revert PoolNotInitialized();
                }
            }

            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

            // no-op if already executed in this block
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
```

**File:** src/extensions/TWAMM.sol (L455-465)
```text
                        if (sqrtRatioNext > corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount1)),
                                    _isToken1: true,
                                    _skipAhead: 0
                                })
                            );
```

**File:** src/extensions/TWAMM.sol (L537-564)
```text
                    if (initialized) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                            rewardRate0Access = 1;
                        }
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                            rewardRate1Access = 1;
                        }

                        TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, nextTime)
                            .storeTwo(bytes32(rewardRates.value0), bytes32(rewardRates.value1));

                        StorageSlot timeInfoSlot = TWAMMStorageLayout.poolTimeInfosSlot(poolId, nextTime);
                        (, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) =
                            TimeInfo.wrap(timeInfoSlot.load()).parse();

                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
                            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
                        });

                        // this time is _consumed_, will never be crossed again, so we delete the info we no longer need.
                        // this helps reduce the cost of executing virtual orders.
                        timeInfoSlot.store(0);

                        flipTime(initializedTimesBitmapSlot, nextTime);
```

**File:** src/extensions/TWAMM.sol (L587-587)
```text
                stateSlot.store(TwammPoolState.unwrap(state));
```

**File:** src/extensions/TWAMM.sol (L646-649)
```text
    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/extensions/TWAMM.sol (L659-665)
```text
    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/Core.sol (L463-469)
```text
    function collectFees(PoolKey memory poolKey, PositionId positionId)
        external
        returns (uint128 amount0, uint128 amount1)
    {
        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension()).maybeCallBeforeCollectFees(locker, poolKey, positionId);
```

**File:** src/Core.sol (L526-528)
```text
            Locker locker = _requireLocker();

            IExtension(config.extension()).maybeCallBeforeSwap(locker, poolKey, params);
```

**File:** src/base/FlashAccountant.sol (L146-172)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))

            let free := mload(0x40)
            // Prepare call to locked_(uint256) -> selector 0
            mstore(free, 0)
            mstore(add(free, 4), id) // ID argument

            calldatacopy(add(free, 36), 4, sub(calldatasize(), 4))

            // Call the original caller with the packed data
            let success := call(gas(), caller(), 0, free, add(calldatasize(), 32), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Undo the "locker" state changes
            tstore(_CURRENT_LOCKER_SLOT, current)
```
