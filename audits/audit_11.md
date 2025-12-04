# Audit Report

## Title
MEVCapture Cumulative Fee Calculation: Subsequent Swaps in Same Block Pay Fees Based on Total Tick Movement

## Summary
The MEVCapture extension's `handleForwardData()` function updates `tickLast` only once per block, causing subsequent swaps within the same block to pay fees calculated on cumulative tick movement from all prior swaps rather than just their individual price impact. This results in users paying disproportionately inflated fees.

## Impact
**Severity**: Medium

Users executing swaps after other swaps in the same block pay fees based on total tick movement from the block's start, not just their own swap's price impact. This can result in 2x-10x inflated fees depending on prior swap activity. While users still receive their expected swap output, they pay significantly higher fees than warranted by their individual market impact. The excess fees are distributed to liquidity providers as intended by the protocol design, but the fee calculation methodology is unfair and creates griefing vectors.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol:177-260`, function `handleForwardData()`

**Intended Logic:** 
The MEVCapture extension should charge additional fees proportional to each swap's individual tick movement to capture MEV value fairly.

**Actual Logic:**
The state update mechanism only executes when the block timestamp changes. [1](#0-0) 

On the first swap in a new block, `tickLast` is set to the current pool tick (before the swap executes), and `lastUpdateTime` is updated to the current block timestamp. [2](#0-1) 

The swap then executes, moving the pool tick. [3](#0-2) 

The fee multiplier is calculated based on the difference between the post-swap tick and `tickLast`. [4](#0-3) 

For subsequent swaps in the same block, the condition `lastUpdateTime != currentTime` evaluates to false, so the state update block is skipped and `tickLast` remains unchanged from the start of the block. These swaps are charged fees based on the total tick movement from the block's starting position, including movements caused by prior swaps.

**Exploitation Path:**
1. **Block N, Initial State**: Pool at tick 100, MEVCapturePoolState has tickLast = 100, lastUpdateTime = N-1
2. **User A's Swap (Block N)**: Condition `(N-1) != N` is TRUE → tickLast updated to 100 (current pool tick) → Swap executes moving tick 100→110 → Fee calculated as `|110 - 100| = 10` tick spaces → User A pays fair fee
3. **User B's Swap (Block N, immediately after)**: Condition `N != N` is FALSE → tickLast remains 100 (not updated to 110) → Pool currently at tick 110 → Swap executes moving tick 110→120 → Fee calculated as `|120 - 100| = 20` tick spaces → User B pays double fee (20 spaces instead of 10)
4. **Result**: User B is charged for 20 tick spaces when they only moved 10, effectively paying for User A's price impact in addition to their own.

**Security Property Broken:**
Fair fee attribution - users should be charged fees proportional to their own market impact, not the cumulative impact of unrelated prior swaps within the same block.

## Impact Explanation

**Affected Assets**: All users swapping through MEVCapture pools when multiple swaps occur in the same block.

**Damage Severity**:
- Users pay inflated fees ranging from 2x to 10x+ depending on prior swap activity in the block
- In scenarios where a large swap precedes smaller swaps, subsequent users pay fees far exceeding their actual price impact
- Example: First swap moves 50 tick spaces, second swap moves 5 tick spaces → second user charged for 55 spaces (11x inflation)

**User Impact**: Any user whose swap transaction is included in the same block after another swap to the same MEVCapture pool. This is a common occurrence in active pools on high-throughput blocks.

**Trigger Conditions**: Occurs naturally whenever multiple swaps target the same MEVCapture pool within a single block - no special attacker action required, though can be deliberately triggered via front-running.

## Likelihood Explanation

**Attacker Profile**: Any user with the ability to submit transactions; can be exploited passively (normal market activity) or actively (deliberate front-running for griefing).

**Preconditions**:
1. MEVCapture pool with active trading
2. Multiple swap transactions targeting the same pool within the same block
3. No additional requirements

**Execution Complexity**: Trivial - occurs naturally in active markets or can be deliberately triggered by submitting a large swap transaction ahead of victim's transaction.

**Economic Cost**: Only gas fees for transaction submission; no capital lockup or special resources required.

**Frequency**: Occurs on every block where multiple users swap in the same MEVCapture pool, which is common for actively traded pools.

**Overall Likelihood**: HIGH - Trivially exploitable condition that occurs naturally in normal market operation.

## Recommendation

**Primary Fix: Update tickLast after each swap**

After the swap execution, update the pool state with the post-swap tick so subsequent swaps in the same block use the correct baseline:

```solidity
// In src/extensions/MEVCapture.sol, handleForwardData function
// After line 209 (swap execution), before fee calculation, add:

setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({
        _lastUpdateTime: currentTime, 
        _tickLast: stateAfter.tick()  // Update to post-swap tick
    })
});
```

**Alternative Fix: Use per-swap tick baseline**

Load the current pool tick immediately before each swap execution rather than at the block boundary:

```solidity
// Replace lines 191-207 with per-swap tick loading
(int32 tickBeforeSwap, uint128 fees0, uint128 fees1) =
    loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

if (fees0 != 0 || fees1 != 0) {
    CORE.accumulateAsFees(poolKey, fees0, fees1);
    saveDelta0 -= int256(uint256(fees0));
    saveDelta1 -= int256(uint256(fees1));
}

// Execute swap
(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Calculate fee based on THIS swap's movement only
uint256 feeMultiplierX64 = (FixedPointMathLib.abs(stateAfter.tick() - tickBeforeSwap) << 64) 
    / poolKey.config.concentratedTickSpacing();
```

## Proof of Concept

The provided PoC demonstrates the concept but would require refinement to account for actual pool initialization state. The vulnerability can be verified by:

1. Creating a MEVCapture pool with liquidity
2. Executing two swaps in the same transaction/block
3. Comparing the fees paid by the second swap against the tick movement it actually caused
4. Observing that the second swap pays fees based on cumulative movement from both swaps

**Expected Result**: Second swap pays fees calculated on total tick movement (both swaps) rather than just its own movement.

## Notes

The vulnerability stems from a gas optimization decision to update `MEVCapturePoolState` only once per block. However, this creates an unfair fee distribution where later swappers subsidize earlier swappers' price impact. 

While the excess fees are distributed to liquidity providers as intended by the protocol (not stolen by an attacker), the fee calculation methodology violates basic fairness principles and creates a griefing vector where malicious actors can front-run victims with large swaps to inflate the victims' fees.

The issue is isolated to fee calculation and does not affect the core swap functionality, user principal, or protocol solvency. Users still receive their expected swap outputs; they simply pay higher-than-warranted fees.

### Citations

**File:** src/extensions/MEVCapture.sol (L191-207)
```text
            if (lastUpdateTime != currentTime) {
                (int32 tick, uint128 fees0, uint128 fees1) =
                    loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
                    // never overflows int256 container
                    saveDelta0 -= int256(uint256(fees0));
                    saveDelta1 -= int256(uint256(fees1));
                }

                tickLast = tick;
                setPoolState({
                    poolId: poolId,
                    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
                });
            }
```

**File:** src/extensions/MEVCapture.sol (L209-209)
```text
            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);
```

**File:** src/extensions/MEVCapture.sol (L212-213)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
```
