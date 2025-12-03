## Title
Amount Sold Tracking Corruption When Modifying Orders Before Start Time

## Summary
The TWAMM order modification logic incorrectly calculates elapsed time when orders are modified before their `startTime`, causing `amountSold` to accumulate time that hasn't actually been used for order execution. This occurs due to uint64 underflow in the duration calculation that is not properly guarded.

## Impact
**Severity**: Low

## Finding Description
**Location:** `src/extensions/TWAMM.sol` - `handleForwardData` function, specifically the sale rate update logic (callType == 0) [1](#0-0) 

**Intended Logic:** When an order's sale rate is modified, `amountSold` should only accumulate the amount sold during the time the order was actually active (after `startTime`). The duration calculation should cap at the time since order start.

**Actual Logic:** The duration calculation uses `uint32(uint64(block.timestamp) - startTime)` which causes uint64 underflow when `block.timestamp < startTime`. This underflow results in a very large number that gets truncated to uint32, and the `min()` function then selects the time since last update instead of zero. [2](#0-1) 

**Exploitation Path:**
1. User creates an order with `startTime` in the future (e.g., 100 seconds from now)
2. At time T1 (before startTime), user calls `increaseSellAmount` to set initial sale rate
   - `lastUpdateTime` set to T1, `saleRate` set to X, `amountSold` remains 0 (correct)
3. At time T2 (still before startTime, in a different block), user calls `increaseSellAmount` again
   - Duration = `min(T2 - T1, uint32(uint64(T2) - startTime))`
   - Since T2 < startTime, the subtraction underflows to a large value
   - Duration incorrectly becomes T2 - T1
   - `amountSold` incremented by `(X * (T2 - T1)) >> 32` despite order not yet active
4. When queried, order shows artificially inflated `amountSold` that includes pre-start time

**Security Property Broken:** Accounting accuracy - `amountSold` should reflect actual execution time from `startTime`, not modification timestamps before the order begins.

## Impact Explanation
- **Affected Assets**: TWAMM order accounting data (`amountSold` field)
- **Damage Severity**: No direct fund theft or loss. Users see inflated `amountSold` values that don't reflect actual order execution. Off-chain systems or integrations relying on this data would receive incorrect information.
- **User Impact**: Users querying their order status through `executeVirtualOrdersAndGetCurrentOrderInfo` receive misleading `amountSold` values, potentially affecting trading decisions or monitoring systems. [3](#0-2) 

## Likelihood Explanation
- **Attacker Profile**: Any user creating orders with future start times
- **Preconditions**: Order must have `startTime` set in the future; user must make multiple modifications before order starts, in different blocks
- **Execution Complexity**: Simple - requires only standard order modification calls across multiple blocks
- **Frequency**: Can occur whenever users modify orders before they start

## Recommendation

The duration calculation should properly handle the case when `block.timestamp < startTime` by ensuring the duration is capped at zero:

```solidity
// In src/extensions/TWAMM.sol, handleForwardData function, lines 257-260:

// CURRENT (vulnerable):
duration: FixedPointMathLib.min(
    uint32(block.timestamp) - lastUpdateTime,
    uint32(uint64(block.timestamp) - startTime)
)

// FIXED:
duration: FixedPointMathLib.min(
    uint32(block.timestamp) - lastUpdateTime,
    // Only count time after order start; use 0 if before start
    block.timestamp >= startTime ? uint32(block.timestamp - startTime) : 0
)
```

This ensures that if the order hasn't started yet (`block.timestamp < startTime`), the duration for calculating additional `amountSold` is capped at 0, preventing accumulation of pre-start time.

## Proof of Concept

```solidity
// File: test/Exploit_AmountSoldCorruption.t.sol
// Run with: forge test --match-test test_amountSoldCorruptionBeforeStart -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_AmountSoldCorruption is Test {
    Core core;
    Orders orders;
    TWAMM twamm;
    
    function setUp() public {
        // Initialize protocol
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        // ... additional setup
    }
    
    function test_amountSoldCorruptionBeforeStart() public {
        // SETUP: Create order with future startTime
        uint64 startTime = uint64(block.timestamp + 200);
        uint64 endTime = uint64(startTime + 100);
        OrderKey memory key = createOrderKey(startTime, endTime);
        
        // First modification at time 100
        vm.warp(100);
        (uint256 id,) = orders.mintAndIncreaseSellAmount(key, 1e18, type(uint112).max);
        
        // Query - amountSold should be 0
        (,uint256 amountSold1,,) = orders.executeVirtualOrdersAndGetCurrentOrderInfo(id, key);
        assertEq(amountSold1, 0, "amountSold should be 0 before start");
        
        // Second modification at time 150 (still before startTime=300)
        vm.warp(150);
        orders.increaseSellAmount(id, key, 0.5e18, type(uint112).max);
        
        // EXPLOIT: Query again - amountSold is now corrupted
        (,uint256 amountSold2,,) = orders.executeVirtualOrdersAndGetCurrentOrderInfo(id, key);
        
        // VERIFY: amountSold incorrectly includes pre-start time
        assertGt(amountSold2, 0, "Vulnerability confirmed: amountSold non-zero before order start");
        // Order hasn't started yet, but amountSold shows execution
    }
}
```

## Notes

While this vulnerability corrupts the `amountSold` tracking, its impact is limited to reporting and accounting accuracy. The critical finding is that:

1. **No Direct Financial Loss**: Order execution logic in `_executeVirtualOrdersFromWithinLock` does not use the stored `amountSold` value [4](#0-3) 

2. **Refund Calculations Unaffected**: When decreasing sale rate, refunds are calculated based on `saleRate` and `durationRemaining`, not `amountSold` [5](#0-4) 

3. **Query Logic Has Guard**: The query function `executeVirtualOrdersAndGetCurrentOrderInfo` has a guard `if (block.timestamp > startTime)` that prevents adding more during queries before start, but it still returns the corrupted stored value [6](#0-5) 

4. **True Multicall Not Affected**: If multiple operations occur in the same transaction (true multicall), the duration becomes 0 on subsequent calls, so corruption doesn't occur within a single transaction.

The vulnerability primarily affects off-chain monitoring, user interfaces, and any protocols integrating with Ekubo that rely on accurate `amountSold` reporting for decision-making.

### Citations

**File:** src/extensions/TWAMM.sol (L248-266)
```text
                orderStateSlot.store(
                    OrderState.unwrap(
                        createOrderState({
                            _lastUpdateTime: uint32(block.timestamp),
                            _saleRate: uint112(saleRateNext),
                            _amountSold: uint112(
                                amountSold
                                    + computeAmountFromSaleRate({
                                        saleRate: saleRate,
                                        duration: FixedPointMathLib.min(
                                            uint32(block.timestamp) - lastUpdateTime,
                                            uint32(uint64(block.timestamp) - startTime)
                                        ),
                                        roundUp: false
                                    })
                            )
                        })
                    )
                );
```

**File:** src/extensions/TWAMM.sol (L302-316)
```text
                uint256 durationRemaining = endTime - FixedPointMathLib.max(block.timestamp, startTime);

                // the amount required for executing at the next sale rate for the remaining duration of the order
                uint256 amountRequired =
                    computeAmountFromSaleRate({saleRate: saleRateNext, duration: durationRemaining, roundUp: true});

                // subtract the remaining sell amount to get the delta
                int256 amountDelta;

                uint256 remainingSellAmount =
                    computeAmountFromSaleRate({saleRate: saleRate, duration: durationRemaining, roundUp: true});

                assembly ("memory-safe") {
                    amountDelta := sub(amountRequired, remainingSellAmount)
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

**File:** src/interfaces/IOrders.sol (L76-85)
```text
    /// @notice Executes virtual orders and returns current order information
    /// @dev Updates the order state by executing any pending virtual orders
    /// @param id The NFT token ID representing the order
    /// @param orderKey Key identifying the order parameters
    /// @return saleRate Current sale rate of the order
    /// @return amountSold Total amount sold so far
    /// @return remainingSellAmount Amount remaining to be sold
    /// @return purchasedAmount Amount of tokens purchased (proceeds available)
    function executeVirtualOrdersAndGetCurrentOrderInfo(uint256 id, OrderKey memory orderKey)
        external
```

**File:** src/libraries/TWAMMLib.sol (L82-104)
```text
                if (block.timestamp > startTime) {
                    uint32 secondsSinceLastUpdate = uint32(block.timestamp) - lastUpdateTime;

                    uint32 secondsSinceOrderStart = uint32(uint64(block.timestamp) - startTime);

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

                    amountSold += computeAmountFromSaleRate({
                        saleRate: saleRate, duration: saleDuration, roundUp: false
                    });
                }
```
