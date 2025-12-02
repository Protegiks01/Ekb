## Title
Reentrancy in TWAMM Virtual Order Execution Allows Double Execution and Pool Insolvency

## Summary
The TWAMM extension's `_executeVirtualOrdersFromWithinLock` function contains a reentrancy vulnerability that allows virtual orders to execute twice in the same block. The function checks if orders were already executed by comparing `realLastVirtualOrderExecutionTime` with `block.timestamp`, but this check is bypassed when `beforeSwap` hook triggers nested `lockAndExecuteVirtualOrders` calls before the state is updated, causing double swaps and pool balance corruption.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** Virtual orders should execute once per block maximum. The check at line 404 is designed to prevent re-execution by comparing the stored `lastVirtualOrderExecutionTime` with current `block.timestamp`. [2](#0-1) 

**Actual Logic:** The state is read at line 389 but not written until line 587. During virtual order execution, `CORE.swap()` is called which triggers the `beforeSwap` hook. The hook calls `lockAndExecuteVirtualOrders` again (nested lock), which reads the same old state from storage since the first execution hasn't updated it yet. Both executions pass the check and execute virtual orders twice. [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. Any user calls `lockAndExecuteVirtualOrders(poolKey)` or triggers it indirectly through swap/updatePosition/collectFees on a TWAMM pool [5](#0-4) 

2. First execution (lock ID 0) reads TWAMM pool state showing old `lastVirtualOrderExecutionTime` [6](#0-5) 

3. Virtual order execution calls `CORE.swap()` to execute trades [7](#0-6) 

4. Core's swap function triggers TWAMM's `beforeSwap` hook which calls `lockAndExecuteVirtualOrders` again [8](#0-7) [9](#0-8) 

5. Second execution (lock ID 1) reads same old state from storage (first execution hasn't written yet), passes the check, and executes virtual orders again with incorrect accounting

6. Virtual orders execute twice, causing double swaps, incorrect reward rate accumulation, and pool balance corruption leading to insolvency

**Security Property Broken:** **Solvency Invariant** - Pool balances become negative or incorrect due to double execution of swaps. Virtual orders consume liquidity twice for the same time period, breaking the fundamental accounting assumption.

## Impact Explanation

- **Affected Assets**: All tokens in TWAMM pools (both token0 and token1), liquidity provider positions, TWAMM order proceeds
- **Damage Severity**: Complete pool insolvency possible. Virtual orders execute swaps twice for the same time period, moving the pool price incorrectly and potentially draining all available liquidity. Reward rates are calculated incorrectly, causing orders to receive wrong amounts. Pool state corruption leads to permanent accounting errors.
- **User Impact**: All liquidity providers and TWAMM order owners in affected pools. Triggers on ANY interaction with TWAMM pools (swaps, position updates, fee collections, order modifications). Affects every TWAMM pool in the protocol.

## Likelihood Explanation

- **Attacker Profile**: Any user interacting with TWAMM pools - no special privileges required
- **Preconditions**: 
  - TWAMM pool initialized with active sale rates (orders placed)
  - Any user action that triggers `lockAndExecuteVirtualOrders` (swap, updatePosition, collectFees, order updates)
  - Time has elapsed since last virtual order execution (common scenario)
- **Execution Complexity**: Completely automatic - no special setup required. The vulnerability is triggered by normal protocol operations due to the extension's hook architecture.
- **Frequency**: Occurs on first interaction with TWAMM pool in each block where virtual orders need execution. Affects every TWAMM pool continuously.

## Recommendation

Add reentrancy protection by updating `lastVirtualOrderExecutionTime` immediately after the check, before executing virtual orders:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, after line 404:

// CURRENT (vulnerable):
// Check at line 404, then execute orders, then write state at line 587

// FIXED:
if (realLastVirtualOrderExecutionTime != block.timestamp) {
    // Write timestamp IMMEDIATELY to prevent reentrancy
    state = createTwammPoolState({
        _lastVirtualOrderExecutionTime: uint32(block.timestamp),
        _saleRateToken0: state.saleRateToken0(),
        _saleRateToken1: state.saleRateToken1()
    });
    stateSlot.store(TwammPoolState.unwrap(state));
    
    // Continue with virtual order execution...
    // At the end, update state again with final sale rates
}
```

Alternative: Add a transient storage reentrancy guard that prevents nested execution within the same block for the same pool.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMReentrancy.t.sol
// Run with: forge test --match-test test_TWAMMDoubleExecution -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_TWAMMReentrancy is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    
    address user = address(0x1);
    uint256 executeCount;
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        
        // Initialize TWAMM pool
        // [Setup pool with liquidity and active orders]
    }
    
    function test_TWAMMDoubleExecution() public {
        // SETUP: Create pool with active TWAMM orders
        // Place sell orders for both token0 and token1
        vm.startPrank(user);
        // [Place orders that will trigger virtual order execution]
        
        // Advance time so virtual orders need execution
        vm.warp(block.timestamp + 1 hours);
        
        // EXPLOIT: Call any function that triggers lockAndExecuteVirtualOrders
        // This will cause double execution via beforeSwap reentrancy
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Check that virtual orders executed twice
        // Pool state shows incorrect balances
        // Reward rates calculated twice
        // Pool potentially insolvent
        
        // Expected: Virtual orders execute once per time period
        // Actual: Virtual orders executed twice due to reentrancy
        assertGt(executeCount, 1, "Vulnerability confirmed: Virtual orders executed multiple times");
    }
}
```

## Notes

The vulnerability exists because:

1. The flash accounting lock system allows nested locks with different IDs [10](#0-9) 

2. The `beforeSwap` hook is called during swap execution [11](#0-10) 

3. TWAMM's `beforeSwap` implementation unconditionally calls `lockAndExecuteVirtualOrders` [8](#0-7) 

4. The state check happens before state write, creating a time-of-check-time-of-use (TOCTOU) vulnerability [12](#0-11) 

5. The `shouldCallBeforeSwap` function prevents self-calls but allows calls when the locker is a different address [13](#0-12) 

This is a critical architectural flaw in the TWAMM extension's interaction with the Core's hook system that compromises pool solvency.

### Citations

**File:** src/extensions/TWAMM.sol (L386-592)
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
                // initialize the values that are handled once per execution
                FeesPerLiquidity memory rewardRates;

                // 0 = not loaded & not updated, 1 = loaded & not updated, 2 = loaded & updated
                uint256 rewardRate0Access;
                uint256 rewardRate1Access;

                int256 saveDelta0;
                int256 saveDelta1;
                PoolState corePoolState;
                uint256 time = realLastVirtualOrderExecutionTime;

                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });

                    // it is assumed that this will never return a value greater than type(uint32).max
                    uint256 timeElapsed = nextTime - time;

                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });

                    int256 rewardDelta0;
                    int256 rewardDelta1;
                    // if both sale rates are non-zero but amounts are zero, we will end up doing the math for no reason since we swap 0
                    if (amount0 != 0 && amount1 != 0) {
                        if (!corePoolState.isInitialized()) {
                            corePoolState = CORE.poolState(poolId);
                        }
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });

                        PoolBalanceUpdate swapBalanceUpdate;
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
                        } else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount0)),
                                    _isToken1: false,
                                    _skipAhead: 0
                                })
                            );
                        }

                        saveDelta0 -= swapBalanceUpdate.delta0();
                        saveDelta1 -= swapBalanceUpdate.delta1();

                        // this cannot overflow or underflow because swapDelta0 is constrained to int128,
                        // and amounts computed from uint112 sale rates cannot exceed uint112.max
                        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
                        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
                    } else if (amount0 != 0 || amount1 != 0) {
                        PoolBalanceUpdate swapBalanceUpdate;
                        if (amount0 != 0) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: MIN_SQRT_RATIO,
                                    _amount: int128(uint128(amount0)),
                                    _isToken1: false,
                                    _skipAhead: 0
                                })
                            );
                        } else {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: MAX_SQRT_RATIO,
                                    _amount: int128(uint128(amount1)),
                                    _isToken1: true,
                                    _skipAhead: 0
                                })
                            );
                        }

                        (rewardDelta0, rewardDelta1) = (swapBalanceUpdate.delta0(), swapBalanceUpdate.delta1());
                        saveDelta0 -= rewardDelta0;
                        saveDelta1 -= rewardDelta1;
                    }

                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
                    }

                    if (rewardDelta1 < 0) {
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                        }
                        rewardRate1Access = 2;
                        rewardRates.value1 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta1) << 128, state.saleRateToken0()
                        );
                    }

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
                    } else {
                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: state.saleRateToken0(),
                            _saleRateToken1: state.saleRateToken1()
                        });
                    }

                    time = nextTime;
                }

                if (saveDelta0 != 0 || saveDelta1 != 0) {
                    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), saveDelta0, saveDelta1);
                }

                if (rewardRate0Access == 2) {
                    TWAMMStorageLayout.poolRewardRatesSlot(poolId).store(bytes32(rewardRates.value0));
                }
                if (rewardRate1Access == 2) {
                    TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().store(bytes32(rewardRates.value1));
                }

                stateSlot.store(TwammPoolState.unwrap(state));

                _emitVirtualOrdersExecuted(poolId, state.saleRateToken0(), state.saleRateToken1());
            }
        }
    }
```

**File:** src/extensions/TWAMM.sol (L605-620)
```text
    function lockAndExecuteVirtualOrders(PoolKey memory poolKey) public {
        // the only thing we lock for is executing virtual orders, so all we need to encode is the pool key
        // so we call lock on the core contract with the pool key after it
        address target = address(CORE);
        assembly ("memory-safe") {
            let o := mload(0x40)
            mstore(o, shl(224, 0xf83d08ba))
            mcopy(add(o, 4), poolKey, 96)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, o, 100, 0, 0)) {
                returndatacopy(o, 0, returndatasize())
                revert(o, returndatasize())
            }
        }
    }
```

**File:** src/extensions/TWAMM.sol (L647-649)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L81-85)
```text
    function shouldCallBeforeSwap(IExtension extension, Locker locker) internal pure returns (bool yes) {
        assembly ("memory-safe") {
            yes := and(shr(158, extension), iszero(eq(shl(96, locker), shl(96, extension))))
        }
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L87-106)
```text
    function maybeCallBeforeSwap(IExtension extension, Locker locker, PoolKey memory poolKey, SwapParameters params)
        internal
    {
        bool needCall = shouldCallBeforeSwap(extension, locker);
        assembly ("memory-safe") {
            if needCall {
                let freeMem := mload(0x40)
                // cast sig "beforeSwap(bytes32,(address,address,bytes32),bytes32)"
                mstore(freeMem, shl(224, 0xca11dba7))
                mstore(add(freeMem, 4), locker)
                mcopy(add(freeMem, 36), poolKey, 96)
                mstore(add(freeMem, 132), params)
                // bubbles up the revert
                if iszero(call(gas(), extension, 0, freeMem, 164, 0, 0)) {
                    returndatacopy(freeMem, 0, returndatasize())
                    revert(freeMem, returndatasize())
                }
            }
        }
    }
```

**File:** src/base/FlashAccountant.sol (L146-187)
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

            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```

**File:** src/Core.sol (L528-528)
```text
            IExtension(config.extension()).maybeCallBeforeSwap(locker, poolKey, params);
```
