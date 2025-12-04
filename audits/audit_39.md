# Audit Report

## Title
TWAMM Distributes Unsold Tokens as Rewards During Partial Swap Execution in Bidirectional Orders

## Summary
The TWAMM extension incorrectly handles partial swap execution when both token sale rates are active. When a swap hits the price limit (`sqrtRatioLimit`) before consuming all input tokens, the unsold portion is misclassified as rewards for the opposite side, leading to protocol insolvency as tokens are distributed without being traded.

## Impact
**Severity**: High

This vulnerability violates the protocol's solvency invariant by allowing users to claim tokens from saved balances that were never actually received through trading. When swaps partially execute due to liquidity constraints, the TWAMM incorrectly treats unconsumed input tokens as rewards for the opposite side. Over multiple executions, this drains the saved balance, eventually causing legitimate withdrawal attempts to fail due to insufficient funds. The issue directly enables unauthorized token distribution and fund loss.

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, lines 441-535, function `_executeVirtualOrdersFromWithinLock()`

**Intended Logic:**
When both sale rates are active (bidirectional TWAMM orders), the protocol should execute a swap to reach the equilibrium price, distributing only the tokens actually received from successful swaps as rewards. The `rewardDelta` calculation should distinguish between: (1) tokens received as swap output (valid rewards), and (2) tokens that failed to execute due to price limits (should remain for future execution). [1](#0-0) 

**Actual Logic:**
When the swap hits `sqrtRatioLimit` before consuming all input (lines 455-477), the swap returns `delta < amount`. The code then calculates `rewardDelta = delta - amount`, which becomes negative for the unconsumed input token. This negative value is then distributed as rewards to sellers on the opposite side (lines 527-534), even though these tokens were never traded and still belong to the original depositors. [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Setup**: Create TWAMM pool with low liquidity. User A places token1 sell order with high sale rate. User B places token0 sell order with low sale rate.

2. **Trigger**: Virtual order execution occurs (anyone can call). The function computes `amount0` and `amount1` from sale rates and time elapsed.

3. **Partial Swap**: Since token1 sale rate is much higher, `sqrtRatioNext > currentPrice`. The swap attempts to sell `amount1` of token1 for token0 with `sqrtRatioLimit = sqrtRatioNext`.

4. **Limit Hit**: Due to low liquidity, the swap hits the price limit before consuming all of `amount1`. For example, if `amount1 = 1000` but only 600 is consumed: `delta1 = 600`, `rewardDelta1 = 600 - 1000 = -400`. [4](#0-3) 

5. **Incorrect Distribution**: Lines 527-534 treat the negative `rewardDelta1` as rewards: `rewardRates.value1 += 400 << 128 / saleRateToken0`. This makes 400 units of token1 claimable by token0 sellers.

6. **Reward Claiming**: Token0 sellers withdraw their "rewards" via `withdrawOrderProceeds()`, which calls `getRewardRateInside()` to compute rewards and withdraws from saved balances. [5](#0-4) [6](#0-5) 

7. **Insolvency**: The 400 token1 that was distributed as rewards was never actually swapped - it's still owed to token1 sellers whose sale rate remains active. When they try to execute in future periods or withdraw, insufficient balance causes failures.

**Security Property Broken:**
The protocol's saved balance system assumes that all withdrawable amounts correspond to actual tokens received through trading. This vulnerability breaks that invariant by allowing withdrawals of tokens that were deposited but never traded.

## Impact Explanation

**Affected Assets:** All TWAMM pools with:
- Both sale rates simultaneously active
- Low liquidity relative to order sizes  
- Imbalanced sale rates causing one-sided net swaps

**Damage Severity:**
- Each partial execution distributes unsold tokens as rewards to the opposite side
- With repeated executions (every block where virtual orders execute), the effect compounds
- In extreme cases with consistently low liquidity, this can drain the entire saved balance of one token
- Early claimants receive excess rewards; later claimants face withdrawal failures

**User Impact:**
- Token sellers whose orders execute partially: lose ownership of unconsumed tokens
- Opposite side sellers: receive inflated rewards they didn't earn
- All subsequent users: face insolvency when attempting legitimate withdrawals
- Affects both individual users and the protocol's overall solvency

## Likelihood Explanation

**Attacker Profile:** Any user can trigger this - no special privileges required. Simply placing TWAMM orders in the described conditions initiates the vulnerability.

**Preconditions:**
1. Pool must have both token0 and token1 sale rates active (common in active TWAMM markets)
2. Liquidity must be low enough that swaps hit price limits before consuming full amount (common in new/small pools)
3. Alternatively, highly imbalanced sale rates create the same effect even with moderate liquidity

**Execution Complexity:** 
- Simple: Place orders and wait for automatic virtual order execution
- No transaction timing or MEV required
- No need to front-run or manipulate prices
- Natural protocol operation triggers the bug

**Frequency:** 
- Occurs on EVERY virtual order execution where swap hits limit
- In pools with low liquidity or imbalanced orders, this is the norm rather than exception
- Can happen multiple times per day as orders execute

**Overall Likelihood:** HIGH - The conditions are common, execution is trivial, and the bug triggers automatically during normal protocol operation.

## Recommendation

The protocol must distinguish between tokens that represent swap output (valid rewards) versus tokens that failed to execute (must remain for future execution). When `rewardDelta < 0` for the token being SOLD, it represents unsold tokens and should NOT be distributed as rewards.

**Primary Fix:**
Modify lines 517-535 to only distribute negative rewardDeltas that correspond to the OUTPUT token of the swap, not the INPUT token. Track which direction the swap executed and only update the appropriate reward rate: [7](#0-6) 

Add directional logic:
- If `sqrtRatioNext > currentPrice`: token1 was sold for token0
  - Only distribute `rewardDelta0 < 0` (token0 received - valid reward for token1 sellers)
  - Do NOT distribute `rewardDelta1 < 0` (token1 unsold - belongs to token1 sellers)
- If `sqrtRatioNext < currentPrice`: token0 was sold for token1
  - Only distribute `rewardDelta1 < 0` (token1 received - valid reward for token0 sellers)
  - Do NOT distribute `rewardDelta0 < 0` (token0 unsold - belongs to token0 sellers)

**Alternative Mitigation:**
Implement a mechanism to track and roll forward unsold amounts to the next execution period, or adjust the `sqrtRatioNext` calculation to ensure swaps can always consume the full amount.

## Proof of Concept

A proof of concept would:
1. Deploy TWAMM pool with minimal liquidity (e.g., 1e18 of each token)
2. Create highly imbalanced orders: large token1 sell rate (1e10/sec), small token0 sell rate (1e6/sec)
3. Execute virtual orders after sufficient time has elapsed
4. Verify that `rewardRates.value1` increases even though token1 wasn't fully swapped
5. Show token0 sellers can claim token1 rewards exceeding what was actually traded
6. Demonstrate that saved balance becomes insufficient after multiple such executions

The expected result is that token0 sellers can withdraw more token1 than was ever received from swaps, eventually causing the protocol to become insolvent for that token.

## Notes

This vulnerability is distinct from the known issue about "TWAMM poor execution price due to low liquidity" (README lines 54-62). The known issue addresses execution quality and price received by users. This vulnerability addresses a fundamental accounting flaw where the protocol distributes tokens that were never traded, violating solvency invariants.

The root cause is that the bidirectional TWAMM implementation uses a single net swap but doesn't properly handle the case where that swap partially executes. The `rewardDelta` subtraction logic (lines 484-485) correctly identifies the accounting delta, but the distribution logic (lines 517-535) incorrectly treats ALL negative rewardDeltas as valid rewards, regardless of whether they represent swap output or unsold input.

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

**File:** src/extensions/TWAMM.sol (L430-436)
```text
                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });
```

**File:** src/extensions/TWAMM.sol (L455-477)
```text
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
```

**File:** src/extensions/TWAMM.sol (L484-485)
```text
                        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
                        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
```

**File:** src/extensions/TWAMM.sol (L527-535)
```text
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
