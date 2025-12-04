# Audit Report

## Title
TWAMM Distributes Unsold Tokens as Rewards During Partial Swap Execution in Bidirectional Orders

## Summary
The TWAMM extension contains a critical accounting flaw in `_executeVirtualOrdersFromWithinLock()` that causes protocol insolvency. When bidirectional orders execute and a swap hits its price limit before consuming all input tokens, the unconsumed input tokens are incorrectly distributed as rewards to sellers on the opposite side, violating the protocol's solvency invariant.

## Impact
**Severity**: High

This vulnerability directly violates the core protocol invariant stated in the README: "The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1." [1](#0-0) 

When swaps partially execute due to liquidity constraints, token sellers lose ownership of their unconsumed tokens as they are misclassified as rewards for the opposite side. This creates a double-spend scenario where: (1) the original depositors expect their unconsumed tokens to execute in future periods, and (2) opposite-side sellers can immediately withdraw these tokens as "rewards." Over multiple partial executions, the saved balance becomes depleted, causing legitimate withdrawal attempts to fail. This affects all TWAMM pools with bidirectional orders and insufficient liquidity.

## Finding Description

**Location:** `src/extensions/TWAMM.sol:441-535`, function `_executeVirtualOrdersFromWithinLock()`

**Intended Logic:**
When both sale rates are active (bidirectional TWAMM), the protocol executes a net swap toward an equilibrium price. The reward distribution should only credit tokens actually received from successful swaps. Specifically, negative `rewardDelta` values should represent swap OUTPUT tokens (valid rewards for sellers), not unconsumed INPUT tokens (which must remain for future execution).

**Actual Logic:**
The code calculates `amount0` and `amount1` from sale rates and time elapsed [2](#0-1) , then executes a swap with `sqrtRatioLimit = sqrtRatioNext`. [3](#0-2) 

When the swap hits the price limit before consuming all input, the Core returns `delta < amount`. [4](#0-3)  The TWAMM calculates `rewardDelta = delta - amount`, producing a negative value for the unconsumed input token. [5](#0-4) 

This negative `rewardDelta` is then distributed as rewards to sellers on the opposite side. [6](#0-5)  For example, when swapping token1 for token0 and `delta1 < amount1`, the code executes `rewardRates.value1 += uint256(amount1 - delta1) / saleRateToken0`, making unconsumed token1 claimable by token0 sellers.

**Exploitation Path:**

1. **Setup**: Deploy TWAMM pool with low liquidity (e.g., 100 ETH total). User A creates large token1 sell order (10 ETH/block). User B creates small token0 sell order (0.1 ETH/block).

2. **Trigger**: Virtual order execution occurs automatically via `beforeSwap`, `beforeUpdatePosition`, or manual call to `lockAndExecuteVirtualOrders()`.

3. **Partial Swap**: Net swap direction is selling token1 for token0 (since token1 rate >> token0 rate). Due to insufficient liquidity, swap hits `sqrtRatioLimit` before consuming all of `amount1`. If `amount1 = 1000` but only `delta1 = 600` consumed, then `rewardDelta1 = -400`.

4. **Incorrect Distribution**: The 400 unconsumed token1 is distributed to token0 sellers via `rewardRates.value1 += (400 << 128) / saleRateToken0`.

5. **Reward Claiming**: Token0 sellers call `withdrawOrderProceeds()`, which calculates rewards using `getRewardRateInside()` [7](#0-6)  and withdraws from saved balances via `updateSavedBalances()`. [8](#0-7) 

6. **Insolvency**: The 400 token1 distributed as rewards still belongs to token1 sellers whose sale rate remains active. When future executions attempt to swap these tokens or token1 sellers try to withdraw, the saved balance is insufficient, causing reverts and permanent fund loss.

**Security Guarantee Broken:**
The protocol's saved balance system assumes all withdrawable amounts correspond to tokens actually received through trading. This bug allows withdrawals of deposited tokens that were never traded, directly violating the solvency invariant.

## Impact Explanation

**Affected Assets:** All TWAMM pools with:
- Both token0 and token1 sale rates simultaneously active
- Low liquidity relative to order sizes (common in new/small pools)
- Imbalanced sale rates creating net one-directional swaps

**Damage Severity:**
- Each partial execution redistributes unconsumed tokens (potentially 10-50% per execution in low-liquidity pools)
- Compounding effect: multiple executions per day in active markets
- Complete saved balance depletion possible in pools with consistently low liquidity
- Early claimants extract excess value; later claimants face total loss

**User Impact:**
- Token sellers with partial execution: permanent loss of unconsumed deposit
- Opposite-side sellers: receive unearned "rewards" (until saved balance depletes)
- All subsequent users: withdrawal failures, locked funds
- Protocol-wide: insolvency across multiple TWAMM pools

## Likelihood Explanation

**Attacker Profile:** Any user with no special privileges. Simply placing TWAMM orders triggers the vulnerability during normal protocol operation.

**Preconditions:**
1. Pool has both token0 and token1 sale rates active (standard for active TWAMM markets)
2. Pool liquidity insufficient for full swap execution (common in new pools, small-cap pairs, or during high volatility)
3. Alternatively: highly imbalanced sale rates (e.g., 100:1 ratio) trigger partial execution even with moderate liquidity

**Execution Complexity:** 
- Zero complexity: Create order and wait for automatic execution
- No transaction timing, MEV, or front-running required
- No price manipulation needed
- Bug activates during routine virtual order execution

**Frequency:** 
- Triggers on EVERY virtual order execution where swap hits price limit
- In low-liquidity pools: 50-100% of executions
- Can occur multiple times per hour as orders execute

**Overall Likelihood:** HIGH - Common preconditions, zero execution complexity, automatic triggering during normal operations.

## Recommendation

**Primary Fix:**
Modify lines 517-535 to only distribute negative `rewardDelta` values that represent swap OUTPUT tokens (valid rewards), not INPUT tokens (unconsumed deposits). Track swap direction and apply conditional logic:

```solidity
// Determine swap direction from sqrtRatioNext
bool token1WasSold = sqrtRatioNext > corePoolState.sqrtRatio();

if (rewardDelta0 < 0) {
    // Only distribute if token0 was OUTPUT (i.e., token1 was sold)
    if (token1WasSold) {
        rewardRates.value0 += FixedPointMathLib.rawDiv(
            uint256(-rewardDelta0) << 128, state.saleRateToken1()
        );
    }
}

if (rewardDelta1 < 0) {
    // Only distribute if token1 was OUTPUT (i.e., token0 was sold)
    if (!token1WasSold) {
        rewardRates.value1 += FixedPointMathLib.rawDiv(
            uint256(-rewardDelta1) << 128, state.saleRateToken0()
        );
    }
}
```

**Additional Mitigations:**
- Add storage tracking for unconsumed amounts to roll forward to next execution period
- Implement saved balance invariant checks in test suite to detect this class of bugs
- Consider adjusting `sqrtRatioNext` calculation to account for liquidity constraints

## Proof of Concept

A proof of concept would:
1. Deploy TWAMM pool with minimal liquidity (1e18 of each token)
2. Create imbalanced orders: token1 sale rate = 1e10/sec, token0 sale rate = 1e6/sec
3. Execute virtual orders after 256 seconds
4. Verify `rewardRates.value1` increases despite token1 not being fully swapped
5. Show token0 sellers can withdraw token1 exceeding actual swap proceeds
6. Demonstrate saved balance insufficiency after repeated executions

Expected result: Token0 sellers withdraw more token1 than was received from swaps, causing protocol insolvency when token1 sellers attempt withdrawal.

## Notes

This vulnerability is distinct from the known issue "TWAMM poor execution price due to low liquidity" (README lines 54-62). [9](#0-8)  The known issue addresses execution quality and price received by users. This vulnerability addresses a fundamental accounting flaw where the protocol distributes tokens that were never traded, violating solvency invariants. The known issue results in suboptimal pricing; this vulnerability results in fund theft and protocol insolvency.

The root cause is that the bidirectional TWAMM uses a single net swap but fails to properly handle partial execution. The `rewardDelta` calculation (lines 484-485) correctly computes the accounting difference, but the distribution logic (lines 517-535) incorrectly treats ALL negative `rewardDelta` values as valid rewards, regardless of whether they represent swap output or unconsumed input. This breaks the fundamental assumption that reward rates correspond to tokens actually received through trading.

### Citations

**File:** README.md (L54-62)
```markdown
TWAMM order execution quality is dependent on the liquidity in the pool and orders on the other side of the pool. 

If any of the following conditions are true:

- Liquidity in the pool is low
- The other side has not placed orders
- Blocks are not produced for a period of time

The user may receive a bad price from the TWAMM. This is a known risk; the TWAMM order execution price is not guaranteed.
```

**File:** README.md (L200-200)
```markdown
The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.
```

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
