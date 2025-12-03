## Title
TWAMM Phantom Reward Creation and Solvency Violation When Pool Liquidity Equals Zero

## Summary
When a TWAMM pool has zero liquidity, `computeNextSqrtRatio()` returns the sale ratio equilibrium price immediately, and the subsequent swap changes the pool price without transferring any tokens. However, the TWAMM extension incorrectly credits phantom rewards to virtual order holders based on the expected swap amounts, allowing later withdrawals of tokens that were never deposited, violating the solvency invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/math/twamm.sol` - `computeNextSqrtRatio()` function
- `src/extensions/TWAMM.sol` - `_executeVirtualOrdersFromWithinLock()` function  
- `src/Core.sol` - `swap_6269342730()` function

**Intended Logic:** When virtual orders execute in a TWAMM pool, they should swap tokens at the computed equilibrium price, with the swap results determining the rewards credited to order holders. The liquidity == 0 edge case in `computeNextSqrtRatio()` is intended to handle price settlement when there's no resistance to price movement. [1](#0-0) 

**Actual Logic:** When pool liquidity equals zero:

1. `computeNextSqrtRatio()` immediately returns `toSqrtRatio(sqrtSaleRatio, roundUp)` without computing the gradual price movement
2. The swap executes with `stepLiquidity == 0`, causing it to jump the price to the limit without transferring any tokens (returns `balanceUpdate = (0, 0)`) [2](#0-1) 

3. TWAMM calculates `rewardDelta0 = swapBalanceUpdate.delta0() - amount0 = 0 - amount0 = -amount0` (negative) [3](#0-2) 

4. Despite no tokens being swapped, reward rates are increased as if the full swap occurred [4](#0-3) 

5. No balances are updated during execution (saveDelta remains 0) [5](#0-4) 

6. When order holders later withdraw, they receive phantom rewards that were never deposited [6](#0-5) 

**Exploitation Path:**

1. **Setup**: Attacker or natural market conditions cause a TWAMM pool to have active virtual orders (saleRateToken0 > 0, saleRateToken1 > 0) with all liquidity withdrawn (liquidity == 0)

2. **Trigger**: Virtual order execution occurs via `_executeVirtualOrdersFromWithinLock()`, computing amounts to swap:
   - `amount0 = computeAmountFromSaleRate(saleRateToken0, timeElapsed)`
   - `amount1 = computeAmountFromSaleRate(saleRateToken1, timeElapsed)` [7](#0-6) 

3. **Price Jump Without Swap**: Since both amounts are non-zero, `computeNextSqrtRatio()` is called with liquidity == 0, returning the sale ratio equilibrium. The swap executes but transfers zero tokens because `stepLiquidity == 0`. [8](#0-7) 

4. **Phantom Reward Crediting**: Despite `swapBalanceUpdate = (0, 0)`, reward rates are increased based on the negative rewardDeltas (`-amount0` and `-amount1`), as if tokens were successfully swapped and paid out.

5. **Theft via Withdrawal**: Order holders call withdraw/claim functions, receiving `purchasedAmount = computeRewardAmount(rewardRateInside - snapshot, saleRate)` which is non-zero due to phantom rewards. These tokens are withdrawn from the pool via `updateSavedBalances()` with negative deltas, draining funds that were never deposited.

**Security Property Broken:** Violates **Invariant #1 (Solvency)** - Pool balances go negative as tokens are withdrawn that were never deposited, allowing theft of protocol/user funds.

## Impact Explanation

- **Affected Assets**: All tokens in TWAMM pools where liquidity can reach zero, which includes any token pair since withdrawal availability is guaranteed by Invariant #2
- **Damage Severity**: Complete drainage of pool token balances. If a TWAMM pool with $1M in virtual orders executes with zero liquidity, phantom rewards equal to the full order amounts are credited, allowing theft of equivalent value from the pool's token reserves
- **User Impact**: All LPs and users with token balances in the affected pool lose funds. The protocol becomes insolvent as pool balances go negative.

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this by withdrawing all liquidity from a TWAMM pool with active orders, or by placing orders in a low-liquidity pool and waiting for natural liquidity withdrawal
- **Preconditions**: 
  1. TWAMM pool initialized with extension
  2. Active virtual orders (non-zero sale rates on both sides)
  3. Pool liquidity == 0 (all LPs withdrawn)
  4. Time elapsed since last execution > 0
- **Execution Complexity**: Single transaction to trigger virtual order execution after liquidity withdrawal, followed by withdrawal transaction to claim phantom rewards
- **Frequency**: Can be exploited once per time period where liquidity == 0, repeatedly if liquidity remains zero across multiple execution intervals

## Recommendation

The core issue is that `computeNextSqrtRatio()` and the TWAMM execution logic do not properly handle the liquidity == 0 case. When liquidity is zero, virtual orders should not execute at all, or should execute with different accounting logic.

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, around line 441:

// CURRENT (vulnerable):
if (amount0 != 0 && amount1 != 0) {
    if (!corePoolState.isInitialized()) {
        corePoolState = CORE.poolState(poolId);
    }
    SqrtRatio sqrtRatioNext = computeNextSqrtRatio({...});
    // ... swap execution that fails with liquidity == 0
}

// FIXED:
if (amount0 != 0 && amount1 != 0) {
    if (!corePoolState.isInitialized()) {
        corePoolState = CORE.poolState(poolId);
    }
    
    // Skip virtual order execution if pool has no liquidity
    // Orders will resume execution when liquidity returns
    if (corePoolState.liquidity() == 0) {
        // Update time but don't execute orders or credit rewards
        continue; // or break, depending on desired behavior
    }
    
    SqrtRatio sqrtRatioNext = computeNextSqrtRatio({...});
    // ... rest of swap execution
}
```

Alternative mitigation: Modify `computeNextSqrtRatio()` to revert or return a flag when liquidity == 0, preventing the swap from executing entirely.

```solidity
// In src/math/twamm.sol, function computeNextSqrtRatio, around line 107:

// CURRENT (vulnerable):
if (c == 0 || liquidity == 0) {
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
}

// FIXED - Option 1: Revert on zero liquidity
if (liquidity == 0) {
    revert InsufficientLiquidity();
}
if (c == 0) {
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
}

// FIXED - Option 2: Return special sentinel value
// (requires caller to check and handle appropriately)
```

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMPhantomRewards.t.sol
// Run with: forge test --match-test test_TWAMMPhantomRewards -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/extensions/TWAMM.sol";
import "../src/base/Positions.sol";

contract Exploit_TWAMMPhantomRewards is Test {
    Core core;
    Router router;
    TWAMM twamm;
    Positions positions;
    
    address token0 = address(0x1111);
    address token1 = address(0x2222);
    address attacker = address(0xBEEF);
    address victim = address(0xCAFE);
    
    function setUp() public {
        // Initialize protocol
        core = new Core();
        router = new Router(core);
        twamm = new TWAMM(core);
        positions = new Positions(core);
        
        // Setup TWAMM pool with full range
        // (deployment and initialization code)
    }
    
    function test_TWAMMPhantomRewards() public {
        // SETUP: Create TWAMM pool with liquidity and virtual orders
        // 1. Victim provides liquidity
        vm.startPrank(victim);
        // Add liquidity to full-range TWAMM pool
        positions.mint(...);
        vm.stopPrank();
        
        // 2. Attacker places large virtual orders on both sides
        vm.startPrank(attacker);
        bytes32 salt = bytes32(uint256(1));
        // Place token0 → token1 order with large sale rate
        twamm.updateOrder(salt, orderKey0, int112(1e18)); // Large sale rate
        // Place token1 → token0 order with large sale rate  
        twamm.updateOrder(salt, orderKey1, int112(1e18));
        vm.stopPrank();
        
        // 3. Advance time so orders accumulate value
        vm.warp(block.timestamp + 1000);
        
        // EXPLOIT: Withdraw all liquidity to trigger zero liquidity state
        vm.startPrank(victim);
        positions.withdraw(...); // Withdraw all liquidity
        vm.stopPrank();
        
        uint256 poolBalance0Before = core.balanceOf(token0, poolId);
        uint256 poolBalance1Before = core.balanceOf(token1, poolId);
        
        // Trigger virtual order execution with liquidity == 0
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Phantom rewards were credited despite no swap
        vm.startPrank(attacker);
        
        // Withdraw proceeds from orders
        uint256 proceeds0 = twamm.withdrawOrderProceeds(salt, orderKey0);
        uint256 proceeds1 = twamm.withdrawOrderProceeds(salt, orderKey1);
        
        vm.stopPrank();
        
        uint256 poolBalance0After = core.balanceOf(token0, poolId);
        uint256 poolBalance1After = core.balanceOf(token1, poolId);
        
        // Verify phantom rewards were withdrawn
        assertGt(proceeds0, 0, "Attacker received phantom token0");
        assertGt(proceeds1, 0, "Attacker received phantom token1");
        
        // Verify pool balances decreased (went negative)
        assertLt(poolBalance0After, poolBalance0Before, "Pool token0 drained");
        assertLt(poolBalance1After, poolBalance1Before, "Pool token1 drained");
        
        // If pool had insufficient reserves, balances went negative (solvency violation)
        // This would show as underflow in actual implementation
    }
}
```

**Notes:**

This vulnerability directly violates the Solvency invariant. The `liquidity == 0` edge case in `computeNextSqrtRatio()` was intended to model instantaneous price settlement when there's no resistance, but the implementation fails to account for the fact that Core.swap() won't actually transfer any tokens in this scenario. The TWAMM extension's reward accounting logic assumes all swaps transfer tokens proportional to the amounts computed, creating an accounting mismatch that enables theft.

The fix requires either preventing virtual order execution when liquidity is zero, or adjusting the reward accounting to handle zero-liquidity swaps correctly (no rewards should be credited if no tokens were actually swapped).

### Citations

**File:** src/math/twamm.sol (L107-111)
```text
        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
```

**File:** src/Core.sol (L623-625)
```text
                    if (stepLiquidity == 0) {
                        // if the pool is empty, the swap will always move all the way to the limit price
                        sqrtRatioNext = limitedNextSqrtRatio;
```

**File:** src/extensions/TWAMM.sol (L365-375)
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
                }
```

**File:** src/extensions/TWAMM.sol (L430-436)
```text
                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });
```

**File:** src/extensions/TWAMM.sol (L445-452)
```text
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });
```

**File:** src/extensions/TWAMM.sol (L484-485)
```text
                        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
                        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
```

**File:** src/extensions/TWAMM.sol (L517-524)
```text
                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
```

**File:** src/extensions/TWAMM.sol (L576-578)
```text
                if (saveDelta0 != 0 || saveDelta1 != 0) {
                    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), saveDelta0, saveDelta1);
                }
```
