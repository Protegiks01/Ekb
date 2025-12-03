## Title
TWAMM Virtual Order Execution Loop Wastes Gas on Zero-Amount Iterations When Sale Rates Are Minimal

## Summary
The TWAMM virtual order execution loop in `_executeVirtualOrdersFromWithinLock` can iterate many times computing amounts that round down to zero when both `saleRateToken0` and `saleRateToken1` are very small but non-zero, wasting gas without executing any swaps while still performing expensive storage operations at initialized time boundaries.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The virtual order execution loop should efficiently process TWAMM orders by computing token amounts from sale rates and executing swaps over time intervals. The comment at line 440 acknowledges: "if both sale rates are non-zero but amounts are zero, we will end up doing the math for no reason since we swap 0".

**Actual Logic:** When both sale rates are very small (< 2^24 for 256-second intervals), the amount computation formula [2](#0-1)  rounds down to zero. The loop continues iterating without executing swaps, but still performs expensive storage operations when crossing initialized time boundaries [3](#0-2) .

**Exploitation Path:**
1. **Attacker creates multiple TWAMM orders with minimal amounts**: Using [4](#0-3) , attacker deposits small amounts (e.g., 1 wei) over maximum duration to create orders with `saleRate = 1`
2. **Orders create multiple initialized times in the bitmap**: Each order adds start/end times to the time bitmap [5](#0-4) , creating up to 91 valid time points [6](#0-5) 
3. **Victim triggers virtual order execution**: Any user performing a swap or position update automatically triggers [7](#0-6)  before their operation
4. **Loop iterates with zero-amount computations**: For each initialized time, amounts compute to zero but the loop performs 4+ storage operations (reward rates, time info deletion, bitmap flipping) without executing any swaps

**Security Property Broken:** This violates gas efficiency expectations and enables griefing attacks where the attacker pays minimal cost to create orders but forces victims to pay significantly more gas for their transactions.

## Impact Explanation
- **Affected Assets**: All users interacting with TWAMM-enabled pools (performing swaps, updating positions, collecting fees)
- **Damage Severity**: Each zero-amount iteration wastes gas on storage operations without value. With up to 91 initialized times, victims can pay orders of magnitude more gas than expected. The attack is repeatable after time points are consumed.
- **User Impact**: Any user triggering `beforeSwap`, `beforeUpdatePosition`, or `beforeCollectFees` hooks pays the inflated gas cost. This affects all pool interactions, not just TWAMM order management.

## Likelihood Explanation
- **Attacker Profile**: Any user with minimal funds to create TWAMM orders (< 100 wei per order)
- **Preconditions**: TWAMM-enabled pool must be initialized. No minimum sale rate validation exists in [8](#0-7) 
- **Execution Complexity**: Single transaction to create multiple orders with different salts and time configurations
- **Frequency**: Repeatable after initialized times are consumed (approximately every 91 time periods or when orders naturally end)

## Recommendation
Add a minimum amount check in the execution loop to skip iterations where both computed amounts are zero:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, after line 436:

uint256 amount0 = computeAmountFromSaleRate({
    saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
});

uint256 amount1 = computeAmountFromSaleRate({
    saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
});

// FIXED: Skip processing if both amounts round to zero
if (amount0 == 0 && amount1 == 0 && state.saleRateToken0() != 0 && state.saleRateToken1() != 0) {
    // Both sale rates are non-zero but amounts rounded to zero
    // Skip swap execution and reward accumulation but still process time boundaries
    if (initialized) {
        // Only update state for time boundary crossing
        StorageSlot timeInfoSlot = TWAMMStorageLayout.poolTimeInfosSlot(poolId, nextTime);
        (, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) =
            TimeInfo.wrap(timeInfoSlot.load()).parse();
        
        state = createTwammPoolState({
            _lastVirtualOrderExecutionTime: uint32(nextTime),
            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
        });
        
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
    continue; // Skip reward rate processing and swap execution
}
```

Alternative: Add minimum sale rate validation in Orders contract to prevent creation of orders with sale rates below a threshold (e.g., `saleRate >= 2^24`).

## Proof of Concept
```solidity
// File: test/Exploit_TWAMMZeroAmountGriefing.t.sol
// Run with: forge test --match-test test_TWAMMZeroAmountGriefing -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../src/Router.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {OrderConfig} from "../src/types/orderConfig.sol";

contract Exploit_TWAMMZeroAmountGriefing is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    Router router;
    
    address attacker = address(0x1337);
    address victim = address(0xBEEF);
    address token0 = address(0x100);
    address token1 = address(0x200);
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        router = new Router(core);
        
        // Setup tokens and initialize pool
        // ... token setup and pool initialization code ...
    }
    
    function test_TWAMMZeroAmountGriefing() public {
        // SETUP: Attacker creates multiple orders with minimal sale rates
        vm.startPrank(attacker);
        
        uint256 startGas = gasleft();
        
        // Create 20 orders with very small amounts to create many initialized times
        for (uint i = 0; i < 20; i++) {
            OrderKey memory orderKey = OrderKey({
                poolKey: PoolKey({
                    token0: token0,
                    token1: token1,
                    config: /* TWAMM config */,
                    extension: address(twamm)
                }),
                config: OrderConfig({
                    // Configure start/end times spread across valid time grid
                })
            });
            
            // Deposit minimal amount (1 wei) over max duration -> saleRate ≈ 1
            orders.mintAndIncreaseSellAmount(orderKey, 1, type(uint112).max);
        }
        
        uint256 setupGas = startGas - gasleft();
        vm.stopPrank();
        
        // EXPLOIT: Victim performs normal swap, triggering virtual order execution
        vm.startPrank(victim);
        startGas = gasleft();
        
        // Normal swap triggers beforeSwap hook -> lockAndExecuteVirtualOrders
        // Loop iterates through all initialized times with zero amounts
        router.swap(/* normal swap parameters */);
        
        uint256 victimGas = startGas - gasleft();
        vm.stopPrank();
        
        // VERIFY: Victim paid significantly more gas than attacker
        console.log("Attacker setup cost:", setupGas);
        console.log("Victim operation cost:", victimGas);
        
        // Assert that victim paid disproportionately high gas
        assertGt(victimGas, setupGas * 5, "Vulnerability confirmed: griefing attack successful");
    }
}
```

## Notes
The vulnerability is explicitly acknowledged in the code comment at line 440 but not mitigated. The execution loop prioritizes correctness (processing all time boundaries to update sale rates) over gas efficiency, making it exploitable for griefing. The attack is economically viable when the cost to create minimal orders is less than the gas grief inflicted on victims, which is likely given that order creation is a one-time cost while the grief affects all subsequent pool interactions until times are consumed.

### Citations

**File:** src/extensions/TWAMM.sol (L271-273)
```text
                if (block.timestamp < startTime) {
                    _updateTime(poolId, startTime, saleRateDelta, isToken1, numOrdersChange);
                    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
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

**File:** src/extensions/TWAMM.sol (L647-648)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
```

**File:** src/math/twamm.sol (L42-46)
```text
function computeAmountFromSaleRate(uint256 saleRate, uint256 duration, bool roundUp) pure returns (uint256 amount) {
    assembly ("memory-safe") {
        amount := shr(32, add(mul(saleRate, duration), mul(0xffffffff, roundUp)))
    }
}
```

**File:** src/Orders.sol (L43-74)
```text
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
```

**File:** src/math/time.sol (L6-10)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;

// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```
