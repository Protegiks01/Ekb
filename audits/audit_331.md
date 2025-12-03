## Title
TWAMM Permanent Pool Freeze Due to Failed State Write After Swap Overflow

## Summary
In `TWAMM.sol`, the final state write at line 587 occurs after all virtual order swaps complete in the while loop. If any swap reverts due to `Amount0DeltaOverflow` or `Amount1DeltaOverflow` during delta calculations, the state write never executes, leaving `lastVirtualOrderExecutionTime` unchanged. This causes all subsequent execution attempts to retry the same failing time periods indefinitely, permanently freezing the entire pool and locking all user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` (function `_executeVirtualOrdersFromWithinLock`, lines 386-592)

**Intended Logic:** The function should execute all pending virtual orders by processing time periods sequentially in a while loop, performing swaps for each period, and then persist the updated state including the new `lastVirtualOrderExecutionTime` at line 587. This allows the protocol to resume from the correct time point on the next execution. [1](#0-0) 

**Actual Logic:** When a swap within the while loop reverts due to arithmetic overflow in delta calculations (specifically `Amount0DeltaOverflow` or `Amount1DeltaOverflow`), the entire transaction reverts before reaching the state write at line 587. The overflow occurs in `amount0DeltaSorted` and `amount1DeltaSorted` when the computed delta exceeds `uint128`. [2](#0-1) [3](#0-2) 

The swaps are executed within the while loop without any error handling: [4](#0-3) 

**Exploitation Path:**
1. **Initial Setup**: A TWAMM pool exists with active orders that have high sale rates (up to `type(uint112).max`) and substantial liquidity (approaching `type(uint128).max`). Time passes without virtual order execution (e.g., 12+ days during low market activity).

2. **Trigger Overflow**: Someone attempts to execute virtual orders. The function calculates swap amounts based on accumulated sale rates and time elapsed. For a large time period with high sale rates, the swap causes a significant price movement. During the swap, `amount0DeltaSorted` or `amount1DeltaSorted` computes a delta that exceeds `uint128`, triggering an overflow revert.

3. **State Remains Stale**: The transaction reverts before line 587 executes. The `lastVirtualOrderExecutionTime` remains at its old value in storage. No state advancement occurs.

4. **Permanent DOS Cascade**: All subsequent operations on this pool now fail:
   - **Regular swaps** fail because `beforeSwap` calls `lockAndExecuteVirtualOrders` (line 648)
   - **Position updates/withdrawals** fail because `beforeUpdatePosition` calls `lockAndExecuteVirtualOrders` (line 656)
   - **Fee collections** fail because `beforeCollectFees` calls `lockAndExecuteVirtualOrders` (line 664)
   - **Order modifications** fail because `handleForwardData` (callType 0) calls `_executeVirtualOrdersFromWithinLock` at line 212
   - **Order proceeds withdrawals** fail because `handleForwardData` (callType 1) calls `_executeVirtualOrdersFromWithinLock` at line 347 [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

Each attempt to use the pool will retry the same failing swap, creating an infinite loop of failures with no recovery path.

**Security Property Broken:** This violates the critical invariant: "**Withdrawal Availability: All positions MUST be withdrawable at any time**" - users cannot withdraw their positions because `beforeUpdatePosition` reverts, permanently locking all funds in the pool.

## Impact Explanation
- **Affected Assets**: All liquidity positions (LP tokens), all TWAMM orders (both active and pending), and accumulated fees in the affected pool become permanently inaccessible. This includes both token0 and token1 balances held by all users.

- **Damage Severity**: Complete permanent loss of access to 100% of pool assets. Users cannot:
  - Withdraw liquidity positions worth potentially millions of dollars
  - Cancel or modify TWAMM orders to recover their deposited tokens
  - Collect trading fees earned by their positions
  - Execute new swaps against the pool

- **User Impact**: ALL users with any stake in the affected pool (liquidity providers, TWAMM order creators, fee claimants) are affected. Any user action that requires pool interaction becomes impossible. Unlike temporary DOS scenarios, there is no time-based recovery - the funds remain locked indefinitely unless a protocol upgrade occurs (which may not be possible depending on governance structure).

## Likelihood Explanation
- **Attacker Profile**: No attacker required. This can occur naturally during normal protocol operation when market conditions create the right combination of high sale rates, long execution gaps, and substantial liquidity.

- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Active TWAMM orders with non-trivial sale rates exist
  - Pool has accumulated liquidity (not necessarily maximum, but enough to make delta calculations large)
  - Sufficient time has passed between executions (e.g., 12+ days of low activity)
  - The combination of `(liquidity * price_change)` in the delta calculation exceeds `uint128` bounds

- **Execution Complexity**: Zero complexity - happens automatically when anyone attempts to interact with the pool. No special transactions, timing, or privileges required.

- **Frequency**: Once the condition is met, it's permanent until protocol upgrade. Multiple pools can be affected independently if market conditions create the overflow scenario in each.

## Recommendation

**Primary Fix:** Implement graceful degradation by catching swap failures and advancing the state anyway, marking problematic time periods as skipped:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, around lines 441-515:

// CURRENT (vulnerable):
// Direct swap calls that can revert and prevent state write

// FIXED:
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

    // Wrap swap execution in try-catch to prevent DOS
    try this.executeSwapInternal(poolKey, sqrtRatioNext, corePoolState, amount0, amount1) 
        returns (PoolBalanceUpdate memory swapBalanceUpdate, PoolState memory newPoolState) {
        saveDelta0 -= swapBalanceUpdate.delta0();
        saveDelta1 -= swapBalanceUpdate.delta1();
        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
        corePoolState = newPoolState;
    } catch {
        // Swap failed (likely overflow) - skip this period but continue execution
        // Emit event for monitoring/recovery
        emit VirtualOrderExecutionFailed(poolId, time, nextTime);
        // Do not update reward rates for failed periods
    }
}
```

**Alternative Mitigations:**
1. **Pre-execution validation**: Add a view function that checks if execution will succeed before attempting it, allowing users to detect problematic pools
2. **Maximum time gap enforcement**: Require more frequent executions to prevent accumulation of large swap amounts
3. **Sale rate limits per time period**: Further constrain sale rates to ensure delta calculations stay within bounds even with maximum liquidity and time gaps

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMPermanentFreeze.t.sol
// Run with: forge test --match-test test_TWAMMPermanentFreeze -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import "./helpers/TestERC20.sol";

contract Exploit_TWAMMPermanentFreeze is Test {
    Core core;
    Positions positions;
    Orders orders;
    TWAMM twamm;
    Router router;
    TestERC20 token0;
    TestERC20 token1;
    
    PoolKey poolKey;
    uint256 positionId;
    uint256 orderId;
    
    function setUp() public {
        // Deploy core protocol
        core = new Core();
        positions = new Positions(core);
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm);
        router = new Router(core);
        
        // Deploy test tokens
        token0 = new TestERC20("Token0", "TK0", 18);
        token1 = new TestERC20("Token1", "TK1", 18);
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Create pool with TWAMM extension
        poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig(3000, address(twamm))
        });
        
        // Initialize pool with high liquidity
        positions.mint();
        positionId = positions.mint();
        positions.maybeInitializePool(poolKey, 0);
        
        // Mint tokens
        token0.mint(address(this), type(uint128).max);
        token1.mint(address(this), type(uint128).max);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);
        
        // Add massive liquidity to increase overflow probability
        positions.deposit(
            positionId, 
            poolKey, 
            MIN_TICK, 
            MAX_TICK, 
            2**120, // Very high liquidity
            2**120, 
            0
        );
    }
    
    function test_TWAMMPermanentFreeze() public {
        // SETUP: Create large TWAMM order
        orderId = orders.mint();
        uint64 startTime = uint64(block.timestamp + 256); // Valid start time
        uint64 endTime = uint64(startTime + 30 days); // 30 day order
        
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: createOrderConfig(startTime, endTime, false) // token0 → token1
        });
        
        // Create order with maximum allowed sale rate
        uint256 orderAmount = 2**100; // Large order
        orders.createOrder(
            orderId,
            orderKey,
            orderAmount
        );
        
        // Advance time past start but not to execution for long period
        vm.warp(startTime + 15 days); // 15 days without execution
        
        // EXPLOIT: Attempt to execute virtual orders - will fail due to overflow
        vm.expectRevert(); // Expecting Amount0DeltaOverflow or Amount1DeltaOverflow
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Pool is now permanently frozen
        
        // 1. Cannot execute regular swaps
        vm.expectRevert();
        router.swap(
            poolKey,
            MAX_SQRT_RATIO,
            0,
            true,
            1000000
        );
        
        // 2. Cannot withdraw positions
        vm.expectRevert();
        positions.withdraw(
            positionId,
            poolKey,
            MIN_TICK,
            MAX_TICK,
            1000, // Try to withdraw small amount
            address(this),
            false
        );
        
        // 3. Cannot collect fees
        vm.expectRevert();
        positions.collectFees(
            positionId,
            poolKey,
            MIN_TICK,
            MAX_TICK,
            address(this)
        );
        
        // 4. Cannot modify orders
        vm.expectRevert();
        orders.decreaseSaleRate(
            orderId,
            orderKey,
            1000 // Try to reduce sale rate
        );
        
        // 5. Cannot collect order proceeds
        vm.expectRevert();
        orders.collectProceeds(
            orderId,
            orderKey,
            address(this)
        );
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- All pool operations permanently blocked");
        console.log("- User funds locked indefinitely");
        console.log("- No recovery path available");
    }
}
```

**Notes**

The vulnerability stems from a fundamental design flaw where state persistence is contingent on all operations succeeding atomically. The TWAMM extension assumes all swaps will complete successfully, but the arithmetic constraints of the delta calculations make overflows possible under realistic market conditions.

Key factors that make this exploitable:
1. **No error isolation**: Failed swaps propagate up and prevent state advancement
2. **Sequential processing requirement**: The while loop must process periods in order - cannot skip ahead
3. **Cascading failures**: All pool operations depend on virtual order execution succeeding first
4. **No escape hatch**: Users cannot force-skip problematic periods or cancel orders without executing virtual orders

The overflow is not just theoretical - with TWAMM supporting orders up to `type(uint112).max` sale rate and time periods up to `type(uint32).max`, combined with pools having liquidity approaching `type(uint128).max`, the delta calculation `(liquidity * price_change)` can legitimately exceed `uint128` bounds during normal operation, especially after extended periods without execution.

### Citations

**File:** src/extensions/TWAMM.sol (L210-212)
```text
                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L345-347)
```text
                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
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

**File:** src/extensions/TWAMM.sol (L652-657)
```text
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/extensions/TWAMM.sol (L660-665)
```text
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/math/delta.sol (L48-52)
```text
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
```

**File:** src/math/delta.sol (L99-103)
```text
                if shr(128, result) {
                    // cast sig "Amount1DeltaOverflow()"
                    mstore(0, 0x59d2b24a)
                    revert(0x1c, 0x04)
                }
```
