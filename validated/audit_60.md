# Audit Report

## Title
TWAMM Phantom Reward Creation Enabling Protocol Insolvency When Pool Liquidity Equals Zero

## Summary
When a TWAMM pool reaches zero liquidity, virtual order execution incorrectly credits phantom rewards to order holders despite no actual token swaps occurring. The `computeNextSqrtRatio()` function immediately returns the equilibrium price when `liquidity == 0`, and Core.swap returns `balanceUpdate = (0, 0)`, but TWAMM's reward accounting logic treats this as if tokens were swapped, enabling theft of tokens that were never deposited into the pool.

## Impact
**Severity**: High

This vulnerability directly violates the protocol's core solvency invariant: "The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1." [1](#0-0) 

When exploited, attackers can drain entire TWAMM pool reserves by withdrawing phantom rewards that were credited during zero-liquidity virtual order execution. If a TWAMM pool with active virtual orders executes during a zero-liquidity state, the reward accounting inflates as if the full swap amounts were processed, but no tokens actually enter the pool. Later withdrawals based on these phantom rewards cause pool token balances to go negative, allowing theft of protocol and LP funds.

## Finding Description

**Location:** 
- `src/math/twamm.sol:107-111`, function `computeNextSqrtRatio()`
- `src/extensions/TWAMM.sol:441-578`, function `_executeVirtualOrdersFromWithinLock()`
- `src/Core.sol:623-625`, within swap execution loop

**Intended Logic:**

Virtual orders in TWAMM pools execute gradually over time by computing equilibrium prices and performing swaps through Core. The reward rates should reflect actual tokens received from swaps. When liquidity is zero, the price settlement logic was intended to handle instantaneous price movement to the equilibrium ratio without resistance. [2](#0-1) 

**Actual Logic:**

When pool liquidity equals zero during virtual order execution:

1. **Price Computation:** `computeNextSqrtRatio()` immediately returns `toSqrtRatio(sqrtSaleRatio, roundUp)` when `liquidity == 0`, bypassing gradual price movement calculation. [2](#0-1) 

2. **Swap Execution:** Core.swap executes with `stepLiquidity == 0`, causing the price to jump to the limit without any balance changes. [3](#0-2) 

3. **Zero Balance Update:** The swap returns `balanceUpdate = (0, 0)` because `calculatedAmount` remains 0 and `specifiedAmountDelta = specifiedAmount - amountRemaining = 0` when no calculation block executes.

4. **Phantom Reward Crediting:** TWAMM computes `rewardDelta0 = swapBalanceUpdate.delta0() - amount0 = 0 - amount0` and `rewardDelta1 = swapBalanceUpdate.delta1() - amount1 = 0 - amount1`. [4](#0-3) 

5. **Reward Rate Inflation:** Since both rewardDeltas are negative (assuming non-zero amounts computed from sale rates), the reward rates are increased. [5](#0-4) 

6. **No Balance Adjustment:** `saveDelta0` and `saveDelta1` remain 0 since the swap returned (0, 0), so `updateSavedBalances()` is never called during execution. [6](#0-5) 

7. **Theft via Withdrawal:** When order holders later withdraw proceeds, `purchasedAmount` is computed from the inflated reward rates, and `updateSavedBalances()` is called with negative deltas, draining tokens from the pool that were never deposited. [7](#0-6) 

**Exploitation Path:**

1. **Setup:** TWAMM pool is initialized with active virtual orders on both sides (non-zero `saleRateToken0` and `saleRateToken1`). All LPs withdraw their positions, causing pool `liquidity == 0`.

2. **Trigger:** Virtual order execution is triggered via any hook (swap, position update, or direct call to `lockAndExecuteVirtualOrders()`). Amounts are computed from sale rates and time elapsed. [8](#0-7) 

3. **Price Jump Without Swap:** Since both amounts are non-zero, `computeNextSqrtRatio()` is called with `liquidity == 0`, and the subsequent swap executes but transfers zero tokens. [9](#0-8) 

4. **Phantom Reward Crediting:** Despite `swapBalanceUpdate = (0, 0)`, reward rates are increased based on the full computed amounts as if tokens were swapped and distributed.

5. **Theft via Withdrawal:** Order holders call withdrawal functions, receiving `purchasedAmount` based on phantom rewards. These tokens are withdrawn from the pool via negative deltas in `updateSavedBalances()`, draining funds that were never deposited.

**Security Property Broken:**

Violates the solvency invariant that pool balances must never go negative. [1](#0-0) 

## Impact Explanation

**Affected Assets:** All tokens in TWAMM pools where liquidity can reach zero. Since the protocol guarantees that "all positions should be able to be withdrawn at any time," [10](#0-9)  any TWAMM pool can reach zero liquidity.

**Damage Severity:**
- Attackers can drain pool token reserves equal to the accumulated virtual order amounts during zero-liquidity periods
- If a TWAMM pool with $1M in active virtual orders operates at zero liquidity for a time period, phantom rewards approaching $1M can be credited
- Pool token balances go negative, violating core solvency invariant
- All LPs and users with balances in affected pools lose funds

**User Impact:** Protocol becomes insolvent as pool balances turn negative. All liquidity providers in the affected pool lose their deposits. The issue affects any TWAMM pool, not just those with non-standard tokens.

## Likelihood Explanation

**Attacker Profile:** Any user with the ability to place TWAMM orders and withdraw liquidity (no special privileges required).

**Preconditions:**
1. TWAMM pool initialized with extension
2. Active virtual orders on both sides (non-zero sale rates)
3. Pool liquidity == 0 (achievable by all LPs withdrawing)
4. Time elapsed since last virtual order execution > 0

**Execution Complexity:** 
- Attacker places opposing TWAMM orders
- Withdraws all liquidity (or waits for natural liquidity withdrawal)
- Triggers virtual order execution via any hook (single transaction)
- Withdraws phantom rewards in subsequent transaction

**Economic Cost:** Only gas fees. No significant capital lockup required beyond initial order placement.

**Frequency:** Exploitable once per time period where liquidity remains zero. Can be repeated across multiple execution intervals if liquidity stays at zero.

**Overall Likelihood:** HIGH - The scenario is easily achievable through normal protocol operations. The withdrawal guarantee ensures liquidity can always reach zero.

## Recommendation

**Primary Fix:**

Modify `_executeVirtualOrdersFromWithinLock()` to skip virtual order execution when pool liquidity is zero. Orders should pause when no liquidity exists and resume execution when liquidity returns.

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, after line 441:

if (amount0 != 0 && amount1 != 0) {
    if (!corePoolState.isInitialized()) {
        corePoolState = CORE.poolState(poolId);
    }
    
    // Skip virtual order execution if pool has no liquidity
    if (corePoolState.liquidity() == 0) {
        // Update lastVirtualOrderExecutionTime but don't execute orders
        // Orders will resume when liquidity returns
        continue; // Skip to next time period
    }
    
    SqrtRatio sqrtRatioNext = computeNextSqrtRatio({...});
    // ... rest of swap execution
}
```

**Alternative Mitigation:**

Modify `computeNextSqrtRatio()` to revert when `liquidity == 0`, preventing the problematic code path:

```solidity
// In src/math/twamm.sol, function computeNextSqrtRatio, line 107:

if (liquidity == 0) {
    revert InsufficientLiquidityForVirtualOrders();
}
if (c == 0) {
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
}
```

## Notes

This vulnerability represents a critical accounting mismatch between TWAMM's reward system and Core's swap execution. The `liquidity == 0` case in `computeNextSqrtRatio()` correctly models instantaneous price settlement from a mathematical perspective, but the implementation fails to account for Core.swap's behavior of returning zero balance updates when no liquidity exists. The TWAMM extension's reward logic assumes all computed swap amounts result in proportional token transfers, creating an exploitable discrepancy when this assumption breaks down at zero liquidity.

The issue is NOT covered by the known issue about "poor execution price with low liquidity" because this is about phantom reward creation (accounting fraud) rather than price quality degradation. The solvency violation occurs through accumulated phantom rewards that enable withdrawal of tokens never deposited, which is fundamentally different from receiving suboptimal prices on actual swaps.

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
