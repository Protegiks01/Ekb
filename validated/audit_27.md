# Audit Report

## Title
Phantom Reward Accumulation in TWAMM When Bidirectional Orders Reach Price Equilibrium

## Summary
The TWAMM virtual order execution logic contains a critical flaw where reward accounting occurs even when no swap is executed. When bidirectional orders exist and the computed next price equals the current pool price (due to equilibrium), the code accumulates phantom rewards without corresponding token inflows, violating the protocol's solvency invariant and enabling fund drainage.

## Impact
**Severity**: High

Pool insolvency occurs when reward rates increase without actual tokens entering the pool. The protocol creates reward obligations that exceed available balances, breaking the core solvency guarantee. Early withdrawers receive tokens that were never swapped into the pool, while subsequent users face transaction reverts (`SavedBalanceOverflow`) when attempting to collect legitimate rewards. This affects all TWAMM pools with bidirectional orders and creates a race-to-withdraw dynamic where timing determines fund recovery rather than legitimate entitlement.

## Finding Description

**Location:** `src/extensions/TWAMM.sol`, function `_executeVirtualOrdersFromWithinLock`, lines 441-485

**Intended Logic:** 
When both sale rates are non-zero (bidirectional orders), the system should execute a swap against pool liquidity to move the price toward equilibrium, then calculate rewards based on the actual tokens purchased from that swap. The reward deltas should reflect the difference between tokens consumed by orders and tokens received from the swap.

**Actual Logic:**
When `sqrtRatioNext` equals `corePoolState.sqrtRatio()` (occurring when the price difference is too small to detect, i.e., `c == 0` in `computeNextSqrtRatio`), neither the greater-than nor less-than conditional branches execute. [1](#0-0) 

The uninitialized `swapBalanceUpdate` variable remains as `bytes32(0)`, resulting in zero deltas when extracted. [2](#0-1) 

Subsequently, the reward delta calculations yield negative values: `rewardDelta0 = 0 - amount0 = -amount0` and `rewardDelta1 = 0 - amount1 = -amount1`. [3](#0-2) 

These negative deltas trigger reward rate accumulation as if tokens were purchased, increasing `rewardRates.value0` and `rewardRates.value1`. [4](#0-3) 

However, pool balances remain unchanged (`saveDelta0` and `saveDelta1` stay at zero) since no actual swap occurred. [5](#0-4) 

**Exploitation Path:**
1. **Setup**: Pool has bidirectional TWAMM orders with both `saleRateToken0` and `saleRateToken1` non-zero
2. **Trigger**: Price naturally reaches equilibrium or attacker manipulates price to equilibrium where `computeC` returns 0 [6](#0-5) 
3. **State Change**: Virtual order execution occurs, `computeNextSqrtRatio` returns price equal to current price
4. **Phantom Accumulation**: Neither swap branch executes, but reward rates increase based on non-zero amounts from sale rates
5. **Result**: Users can collect proceeds based on inflated reward rates while pool balances remain unchanged

**Security Guarantee Broken:**
Violates the solvency invariant—pool saved balances must support all reward claims. The system creates reward obligations without receiving corresponding tokens, allowing withdrawal of tokens that never entered the pool.

## Impact Explanation

**Affected Assets**: Both token0 and token1 in any TWAMM pool with active bidirectional orders

**Damage Severity**:
- Pool becomes insolvent when phantom rewards exceed available balances
- Early withdrawers receive tokens that never entered the pool through swaps
- Later withdrawers face `SavedBalanceOverflow` reverts when attempting to collect legitimate rewards [7](#0-6) 
- Fund lock for honest users who cannot collect their earned proceeds
- Protocol integrity compromised as balance accounting becomes decoupled from actual token flows

**User Impact**: All users with TWAMM orders in affected pools. The race-to-withdraw dynamic creates unfair outcomes where timing determines fund recovery rather than legitimate entitlement. Users who placed legitimate orders may be unable to withdraw their rightfully earned proceeds.

**Trigger Conditions**: Occurs whenever bidirectional orders exist and pool price equals or closely approximates equilibrium where `computeC` returns 0 (can happen naturally through trading activity or via deliberate price manipulation)

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital to execute swaps; no special permissions or privileged access required

**Preconditions**:
1. Pool must have bidirectional TWAMM orders (both sale rates non-zero)
2. Pool price must equal or closely approximate equilibrium where `computeC` returns 0 due to rounding in fixed-point arithmetic
3. Virtual order execution must be triggered while at equilibrium state

**Execution Complexity**: Moderate—requires either waiting for natural equilibrium conditions or executing swaps to manipulate price to the equilibrium point. The attacker then triggers virtual order execution.

**Economic Cost**: If manipulating price: gas fees plus slippage costs for price movement swaps. If waiting for natural conditions: only gas fees for triggering execution.

**Frequency**: Can occur naturally in any bidirectional TWAMM pool as markets find equilibrium; repeatable across multiple pools and time intervals. The `c == 0` condition is explicitly documented as an expected scenario, not an edge case.

**Overall Likelihood**: MEDIUM to HIGH—While it requires specific price conditions, bidirectional orders reaching equilibrium is a foreseeable and documented scenario in TWAMM design. The condition `c == 0` is explicitly handled in the math library as a normal case.

## Recommendation

**Primary Fix:**
Add an else branch to handle the equality case in the bidirectional swap logic. When `sqrtRatioNext` equals the current price, no swap should occur and no rewards should accumulate:

```solidity
// In src/extensions/TWAMM.sol, lines 454-477:
PoolBalanceUpdate swapBalanceUpdate;
if (sqrtRatioNext > corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else {
    // Price already at equilibrium - no swap occurs, no rewards to distribute
    rewardDelta0 = 0;
    rewardDelta1 = 0;
    time = nextTime;
    continue; // Skip reward accumulation
}
```

**Alternative Mitigation**:
Add validation that `swapBalanceUpdate` is non-zero before calculating reward deltas, ensuring rewards only accumulate when actual swaps occur. This would catch the uninitialized case and prevent phantom reward accumulation.

**Additional Safeguard**:
Consider adding an invariant check that verifies reward rate increases are always accompanied by corresponding increases in saved balances, maintaining the solvency guarantee at the code level.

## Notes

**Scenario Realism**: The condition `c == 0` in `computeNextSqrtRatio` is explicitly documented as occurring when "the difference b/t sale ratio and sqrt ratio is too small to be detected." This is not an edge case but a designed behavior in the math library, making this vulnerability highly realistic. [6](#0-5) 

**Root Cause**: Missing else-branch to handle price equality in bidirectional swap logic. The code assumes one of the two conditional branches (greater-than or less-than) will always execute, but equality is a valid third state that must be handled.

**Not Covered by Known Issues**: The README acknowledges TWAMM execution quality depends on liquidity and opposing orders, describing this as affecting execution price (user experience issue). The reported vulnerability creates phantom rewards that violate pool solvency (protocol integrity issue), which is fundamentally different from execution price quality concerns.

**Validation Behavior**: The `updateSavedBalances` function in Core prevents negative balances by reverting with `SavedBalanceOverflow`, which protects against complete pool drainage but creates a denial-of-service for users with legitimate reward claims once phantom rewards have been partially collected. [7](#0-6)

### Citations

**File:** src/extensions/TWAMM.sol (L454-477)
```text
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
```

**File:** src/extensions/TWAMM.sol (L479-485)
```text
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

**File:** src/types/poolBalanceUpdate.sol (L8-18)
```text
function delta0(PoolBalanceUpdate update) pure returns (int128 v) {
    assembly ("memory-safe") {
        v := signextend(15, shr(128, update))
    }
}

function delta1(PoolBalanceUpdate update) pure returns (int128 v) {
    assembly ("memory-safe") {
        v := signextend(15, update)
    }
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

**File:** src/Core.sol (L140-151)
```text
            function addDelta(u, i) -> result {
                // full‐width sum mod 2^256
                let sum := add(u, i)
                // 1 if i<0 else 0
                let sign := shr(255, i)
                // if sum > type(uint128).max || (i>=0 && sum<u) || (i<0 && sum>u) ⇒ 256-bit wrap or underflow
                if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                    mstore(0x00, 0x1293d6fa) // `SavedBalanceOverflow()`
                    revert(0x1c, 0x04)
                }
                result := sum
            }
```
