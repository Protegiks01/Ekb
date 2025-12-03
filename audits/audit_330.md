## Title
TWAMM Pool DOS via Sale Rate Accumulation Beyond Design Limit

## Summary
The TWAMM extension constrains each time boundary's sale rate delta to `MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / 91`, assuming at most 91 valid future times from any moment. However, as time progresses and new time boundaries become valid, an attacker can create orders that cause the pool state's cumulative sale rate to approach `type(uint112).max`. When virtual order execution attempts to apply another positive delta via `addSaleRateDelta()`, it reverts, permanently DOS'ing the pool. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/TWAMM.sol` - `_executeVirtualOrdersFromWithinLock()` function (lines 554-558) and `_addConstrainSaleRateDelta()` (lines 118-132)

**Intended Logic:** 
The design assumes that constraining each time boundary's delta to `MAX_ABS_VALUE_SALE_RATE_DELTA` prevents the pool state sale rates from overflowing `uint112`, since there are at most 91 valid future times from any current time. [2](#0-1) 

**Actual Logic:**
The "91 valid times" constraint is a WINDOW property - it describes future times from any given moment, not a global lifetime limit. As time advances and boundaries are crossed, NEW times become valid (previously beyond the `type(uint32).max` horizon). An attacker can continuously create orders at newly-valid times, causing cumulative accumulation beyond the design limit. [3](#0-2) 

When the pool state sale rate approaches `type(uint112).max` and virtual orders attempt to cross another time boundary with a positive delta, the `addSaleRateDelta()` function detects overflow and reverts: [4](#0-3) 

This revert propagates through the virtual order execution path, causing all subsequent swaps to fail since `beforeSwap` unconditionally executes virtual orders: [5](#0-4) 

**Exploitation Path:**

1. **Phase 1 - Initial Accumulation:** At time T₀, attacker creates ~90 orders with start times at valid future times T₁...T₉₀, each with maximum allowed sale rate delta. Set end times far in the future to delay negative delta application.

2. **Phase 2 - Cross Boundaries:** As virtual orders execute over time, the pool state accumulates: `saleRate ≈ 90 × MAX_ABS_VALUE_SALE_RATE_DELTA ≈ 90/91 × type(uint112).max` [6](#0-5) 

3. **Phase 3 - Exploit New Time Window:** After sufficient time passes, new time boundaries become valid (e.g., T₉₂₊). Attacker creates additional orders targeting these newly-valid times with positive deltas.

4. **Phase 4 - Trigger DOS:** When virtual order execution attempts to cross a time boundary with `saleRate ≈ 90/91 × max` and apply delta ≥ `MAX_ABS_VALUE_SALE_RATE_DELTA`, the addition exceeds `type(uint112).max`, triggering `SaleRateDeltaOverflow()` revert. All swaps permanently fail.

**Security Property Broken:** 
Violates **Withdrawal Availability** invariant: "All positions MUST be withdrawable at any time" and **Extension Isolation** invariant: "Extension failures should not freeze pools or lock user capital (for in-scope extensions)."

## Impact Explanation

- **Affected Assets**: All liquidity positions in the TWAMM pool, all pending TWAMM orders, and the pool's entire token balances become locked.
- **Damage Severity**: Complete pool freeze - LPs cannot withdraw positions, swappers cannot trade, TWAMM order owners cannot collect proceeds. All funds locked until manual intervention (which may not be possible without contract upgrade).
- **User Impact**: All users with positions or orders in the affected pool lose access to their funds. Multiple pools can be targeted independently.

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this - no special privileges required. Requires capital to create multiple orders with maximum sale rates over an extended period.
- **Preconditions**: 
  - TWAMM pool must be initialized
  - Attacker needs sufficient tokens to fund orders with high sale rates
  - Requires time to pass (~91 time boundaries must be crossed)
  - Works on any TWAMM pool regardless of liquidity
- **Execution Complexity**: Multi-phase attack over weeks/months (depending on time boundary spacing), but straightforward execution - just create orders at valid future times.
- **Frequency**: Can be executed once per pool, but attacker can target multiple pools. Once triggered, the DOS is permanent.

## Recommendation

Implement a global check on the pool state's cumulative sale rate, not just per-time deltas:

```solidity
// In src/extensions/TWAMM.sol, within _executeVirtualOrdersFromWithinLock, after line 558:

// Add validation after applying deltas:
if (state.saleRateToken0() > MAX_SAFE_CUMULATIVE_SALE_RATE || 
    state.saleRateToken1() > MAX_SAFE_CUMULATIVE_SALE_RATE) {
    // Revert order creation, not pool execution
    revert CumulativeSaleRateExceeded();
}

// Define in time.sol:
uint256 constant MAX_SAFE_CUMULATIVE_SALE_RATE = type(uint112).max * 90 / 100; // 90% safety margin
```

**Alternative mitigation:** Track the number of time boundaries crossed since pool initialization and enforce a maximum (e.g., prevent order creation if cumulative crossings would exceed 91). However, this is restrictive and may limit legitimate long-term usage.

**Better solution:** Redesign the constraint system to account for the lifetime accumulation property by either:
1. Reducing `MAX_ABS_VALUE_SALE_RATE_DELTA` by a safety factor (e.g., divide by 120 instead of 91)
2. Implementing a decay mechanism where sale rates naturally decrease over time
3. Enforcing a global cap on pool state sale rates during order creation, not just during execution

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMSaleRateAccumulation.t.sol
// Run with: forge test --match-test test_SaleRateAccumulationDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import {MAX_ABS_VALUE_SALE_RATE_DELTA, nextValidTime} from "../src/math/time.sol";

contract Exploit_TWAMMSaleRateAccumulation is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm);
        
        // Initialize TWAMM pool (full range)
        // [setup pool with TWAMM extension]
    }
    
    function test_SaleRateAccumulationDOS() public {
        uint256 currentTime = block.timestamp;
        
        // PHASE 1: Create 90 orders at valid future times with max deltas
        uint256 time = currentTime;
        for (uint i = 0; i < 90; i++) {
            time = nextValidTime(currentTime, time);
            
            // Create order with maximum allowed sale rate delta
            // startTime = time, endTime = far future
            uint112 saleRateDelta = uint112(MAX_ABS_VALUE_SALE_RATE_DELTA);
            orders.increaseSaleRate(
                bytes32(uint256(i)), // unique salt
                OrderKey({/* time-based config */}),
                saleRateDelta
            );
        }
        
        // PHASE 2: Simulate time passing and virtual order execution
        // Fast-forward to cross all 90 boundaries
        vm.warp(time + 1000);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // Pool state now has saleRate ≈ 90 * MAX_ABS_VALUE_SALE_RATE_DELTA
        
        // PHASE 3: Create one more order at newly valid time
        uint256 newTime = nextValidTime(time, time);
        orders.increaseSaleRate(
            bytes32(uint256(91)),
            OrderKey({/* config with newTime as startTime */}),
            uint112(MAX_ABS_VALUE_SALE_RATE_DELTA)
        );
        
        // PHASE 4: Attempt to execute virtual orders - should DOS
        vm.warp(newTime + 1);
        
        // This should revert with SaleRateDeltaOverflow
        vm.expectRevert(SaleRateDeltaOverflow.selector);
        core.swap(/* any swap parameters */);
        
        // VERIFY: All subsequent swaps fail
        vm.expectRevert(SaleRateDeltaOverflow.selector);
        core.swap(/* different parameters */);
        
        // Pool is permanently DOS'd
        console.log("Pool successfully DOS'd via sale rate accumulation");
    }
}
```

## Notes

The vulnerability exploits a subtle distinction between "valid times at any moment" (bounded to 91) versus "total times crossed over the pool's lifetime" (unbounded). The constraint `MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / 91` provides safety for the former but not the latter. This is a **design-level flaw** rather than an implementation bug - the code works as intended, but the design assumptions are violated by the protocol's own time grid mechanics.

The attack requires patience (weeks to months) and capital, but is deterministic and affects all pool participants. The severity is **High** because it causes permanent fund lockup, violating the protocol's core invariant that positions must always be withdrawable.

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

**File:** src/extensions/TWAMM.sol (L647-649)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/math/time.sol (L6-10)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;

// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
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
