# Audit Report

## Title
TWAMM Phantom Reward Creation Enabling Protocol Insolvency When Pool Liquidity Equals Zero

## Summary

When a TWAMM pool's liquidity reaches zero, virtual order execution incorrectly inflates reward rates despite no actual token swaps occurring. The zero-liquidity edge case causes `Core.swap()` to return `(0, 0)` balance updates, but TWAMM's reward accounting logic proceeds as if tokens were swapped, enabling withdrawal of tokens that were never actually exchanged through the pool.

## Impact

**Severity**: High

This vulnerability directly violates the protocol's core solvency invariant requiring that pool token balances must never go negative. [1](#0-0) 

When exploited, order holders can withdraw phantom rewards based on inflated reward rates that were credited during zero-liquidity periods when no actual token transfers occurred. This allows draining of saved balances (containing legitimately deposited tokens from other users' orders) based on rewards that were never earned through real swaps, resulting in protocol insolvency and theft of user funds.

## Finding Description

**Location:**
- `src/math/twamm.sol:107-111`, function `computeNextSqrtRatio()`
- `src/extensions/TWAMM.sol:441-578`, function `_executeVirtualOrdersFromWithinLock()`
- `src/Core.sol:623-625`, within swap execution loop

**Intended Logic:**

Virtual orders execute gradually over time by computing equilibrium prices and performing swaps through Core. Reward rates should reflect actual tokens received from swaps. The protocol guarantees that all positions can be withdrawn at any time. [2](#0-1) 

**Actual Logic:**

When pool liquidity equals zero during virtual order execution:

1. **Price Computation:** `computeNextSqrtRatio()` immediately returns the equilibrium price when `liquidity == 0`, bypassing gradual price movement: [3](#0-2) 

2. **Swap Execution:** Core.swap executes with `stepLiquidity == 0`, causing the price to jump to the limit without any token transfers: [4](#0-3) 

3. **Zero Balance Update:** The swap returns `balanceUpdate = (0, 0)` because no calculation blocks execute when `stepLiquidity == 0`.

4. **Phantom Reward Crediting:** TWAMM computes amounts from sale rates: [5](#0-4) 

   Then calculates reward deltas: [6](#0-5) 

   Since `swapBalanceUpdate = (0, 0)` but `amount0` and `amount1` are non-zero, the rewardDeltas become `-amount0` and `-amount1` (negative values).

5. **Reward Rate Inflation:** When rewardDeltas are negative, reward rates are increased as if tokens were purchased: [7](#0-6) 

6. **No Balance Adjustment:** `saveDelta0` and `saveDelta1` remain 0 since the swap returned `(0, 0)`, so `updateSavedBalances()` is never called during execution: [8](#0-7) 

7. **Theft via Withdrawal:** Order holders later withdraw proceeds based on inflated reward rates, calling `updateSavedBalances()` with negative deltas to extract tokens: [9](#0-8) 

**Exploitation Path:**

1. **Setup:** TWAMM pool initialized with active virtual orders on both sides (non-zero `saleRateToken0` and `saleRateToken1`). All LPs withdraw positions, causing pool `liquidity == 0`.

2. **Trigger:** Virtual order execution triggered. Amounts computed from sale rates indicate non-zero values: [10](#0-9) 

3. **Price Jump Without Swap:** Since both amounts are non-zero, `computeNextSqrtRatio()` is called with `liquidity == 0`, and subsequent swap executes but transfers zero tokens.

4. **Phantom Reward Crediting:** Despite `swapBalanceUpdate = (0, 0)`, reward rates increase based on the full computed amounts as if tokens were swapped.

5. **Theft via Withdrawal:** Order holders withdraw proceeds, receiving `purchasedAmount` based on phantom rewards. These tokens come from saved balances that were legitimately deposited by other users but never replenished during the zero-liquidity execution.

**Security Property Broken:**

Violates the solvency invariant that pool balances must never go negative. [1](#0-0) 

## Impact Explanation

**Affected Assets:** All tokens in TWAMM pools where liquidity can reach zero. Since the protocol guarantees withdrawal rights, any TWAMM pool can reach zero liquidity.

**Damage Severity:**
- Order holders can withdraw tokens based on phantom rewards that were never earned through actual swaps
- Saved balances (containing legitimately deposited tokens) are drained by phantom withdrawals
- If a TWAMM pool has active virtual orders executing during zero-liquidity periods, reward accounting becomes inconsistent with actual token flows
- Users attempting to withdraw legitimate proceeds may find insufficient saved balances due to prior phantom withdrawals
- Protocol becomes insolvent as the accounting system credits more rewards than tokens actually exist

**User Impact:** Theft of user funds. Users who deposited tokens for TWAMM orders may have their deposits drained by other users' phantom reward withdrawals. The system's reward accounting diverges from actual token balances.

## Likelihood Explanation

**Attacker Profile:** Any user with ability to place TWAMM orders (no special privileges required).

**Preconditions:**
1. TWAMM pool initialized with extension
2. Active virtual orders on both sides (non-zero sale rates)
3. Pool liquidity == 0 (achievable by all LPs withdrawing per withdrawal guarantee)
4. Time elapsed since last virtual order execution > 0

**Execution Complexity:**
- Attacker can place opposing TWAMM orders
- Wait for or trigger liquidity withdrawal to reach 0
- Trigger virtual order execution via any hook (single transaction)
- Withdraw phantom rewards in subsequent transaction

**Economic Cost:** Only gas fees. Minimal capital lockup required beyond initial order placement.

**Frequency:** Exploitable during any period where liquidity remains zero. Can occur naturally through normal LP withdrawals.

**Overall Likelihood:** HIGH - Scenario is achievable through normal protocol operations. The withdrawal guarantee ensures liquidity can reach zero.

## Recommendation

**Primary Fix:**

Modify `_executeVirtualOrdersFromWithinLock()` to skip virtual order execution when pool liquidity is zero:

```solidity
// In src/extensions/TWAMM.sol, after line 441:
if (amount0 != 0 && amount1 != 0) {
    if (!corePoolState.isInitialized()) {
        corePoolState = CORE.poolState(poolId);
    }
    
    // Skip virtual order execution if pool has no liquidity
    if (corePoolState.liquidity() == 0) {
        continue; // Skip to next time period
    }
    
    SqrtRatio sqrtRatioNext = computeNextSqrtRatio({...});
    // ... rest of swap execution
}
```

**Alternative Mitigation:**

Add check to only update reward rates when actual token transfers occurred:

```solidity
// In src/extensions/TWAMM.sol, before line 517:
// Only update reward rates if actual swap occurred
if (swapBalanceUpdate.delta0() != 0 || swapBalanceUpdate.delta1() != 0) {
    if (rewardDelta0 < 0) {
        // ... existing reward rate update logic
    }
    if (rewardDelta1 < 0) {
        // ... existing reward rate update logic
    }
}
```

## Notes

This vulnerability represents a critical accounting mismatch between TWAMM's reward system and Core's swap execution. The `liquidity == 0` case in `computeNextSqrtRatio()` correctly models instantaneous price settlement mathematically, but the implementation fails to account for Core.swap's behavior of returning zero balance updates when no liquidity exists. The TWAMM reward logic assumes all computed swap amounts result in proportional token transfers, creating an exploitable discrepancy when this assumption breaks down at zero liquidity.

The issue is NOT covered by the known issue about "poor execution price with low liquidity" because this concerns phantom reward creation (accounting fraud) rather than price quality degradation. The solvency violation occurs through accumulated phantom rewards enabling withdrawal of tokens never deposited, fundamentally different from receiving suboptimal prices on actual swaps.

### Citations

**File:** README.md (L200-200)
```markdown
The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.
```

**File:** README.md (L202-202)
```markdown
All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).
```

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
