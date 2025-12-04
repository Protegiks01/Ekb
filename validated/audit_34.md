# Audit Report

## Title
MEVCapture Charges Later Swappers for Cumulative Price Movement Within Same Block

## Summary
The MEVCapture extension's `handleForwardData` function only updates the `tickLast` reference point when entering a new block. When multiple swaps occur within the same block, subsequent swaps calculate their MEV fees based on cumulative tick movement from the block's start rather than their individual price impact, causing later swappers to pay unfairly high fees.

## Impact
**Severity**: Medium

This constitutes a fee miscalculation causing users to lose significant value. Later swappers within a block overpay MEV fees proportional to the cumulative price movement from all prior swaps in that block, while earlier swappers pay only for their own impact. The excess fees are collected by the protocol but represent an unfair economic burden on users who happen to trade later in a block.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData`, lines 177-260

**Intended Logic:** 
The MEVCapture extension should charge each swapper an additional fee proportional to the price impact **they individually cause**. The interface documentation states it "charges additional fees based on... tick movement during swaps" [1](#0-0) , and the code comment says "however many tick spacings were crossed" [2](#0-1) , both suggesting per-swap measurement.

**Actual Logic:**
The `tickLast` variable serves as the baseline for fee calculations but is only updated when entering a new block [3](#0-2) . The condition `if (lastUpdateTime != currentTime)` at line 191 determines whether to update `tickLast`. For the first swap in a block, this condition is true and `tickLast` is set to the current pool tick (line 202). For all subsequent swaps in that same block, the condition is false, so lines 192-206 are skipped and `tickLast` remains unchanged.

When the fee multiplier is calculated at line 213 using `abs(stateAfter.tick() - tickLast)` [4](#0-3) , later swaps measure tick movement from the stale `tickLast` (which still points to the tick before the first swap) rather than from the tick before their own execution. This causes them to be charged for cumulative movement including prior swaps' impacts.

**Exploitation Path:**
1. **Setup**: Attacker monitors mempool for pending swaps in MEVCapture-enabled pool
2. **Front-run**: Attacker submits swap with higher gas price to execute first in block
3. **First swap outcome**: Attacker's swap moves price from tick A to tick B, pays MEV fee for |B - A| tick spacings
4. **Victim execution**: Victim's swap executes second in same block, moves price from tick B to tick C
5. **Unfair charging**: Victim is charged for |C - A| tick spacings instead of |C - B|, paying for attacker's movement too
6. **Value extraction**: Attacker benefits from lower fees while victim subsidizes their impact

**Security Property Broken:**
Fee accounting accuracy - users should be charged fees proportional to their own actions, not others' actions. While the total fees collected don't exceed pool balances, the distribution is unfair and exploitable.

## Impact Explanation

**Affected Assets**: All users swapping in MEVCapture-enabled pools who are not first in their block

**Damage Severity**:
- If N swaps occur in a block with equal price impact of D ticks each:
  - Swap 1 pays for D ticks
  - Swap 2 pays for 2D ticks  
  - Swap 3 pays for 3D ticks
  - Total collected: D(1+2+...+N) = D·N(N+1)/2 tick-equivalents
  - Actual movement: N·D ticks
  - Overcollection ratio: (N+1)/2

- For 3 equal swaps: 2x overcollection
- For 5 equal swaps: 3x overcollection

**User Impact**: Any user whose swap is not first in a block overpays fees. This disproportionately affects regular users versus sophisticated MEV searchers who can ensure first position through gas price manipulation.

**Trigger Conditions**: Occurs naturally whenever multiple swaps execute in the same block in a MEVCapture pool - a common scenario in active pools.

## Likelihood Explanation

**Attacker Profile**: Any MEV searcher or sophisticated trader with mempool monitoring and transaction ordering capabilities

**Preconditions**:
1. MEVCapture-enabled pool with active trading
2. Multiple pending swaps in mempool for same block
3. No other preconditions required

**Execution Complexity**: Simple - requires only standard MEV infrastructure (mempool monitoring, gas price bidding). Single transaction to front-run and be first in block.

**Economic Cost**: Minimal - only gas fees to win transaction ordering. No capital lockup required beyond the swap itself.

**Frequency**: Exploitable continuously in every block where multiple swaps occur in the same MEVCapture pool, which is common for active trading pairs.

**Overall Likelihood**: HIGH - Common preconditions, simple execution, continuous opportunity

## Recommendation

Update `tickLast` after each swap within a block, not just at the start of the block. Modify `handleForwardData` to store the tick for fee calculation before updating state:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData
// After line 209, before line 212:

(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Store current tickLast for THIS swap's fee calculation
int32 tickForFeeCalc = tickLast;

// Calculate fee using the tick BEFORE this swap
uint256 feeMultiplierX64 =
    (FixedPointMathLib.abs(stateAfter.tick() - tickForFeeCalc) << 64) 
    / poolKey.config.concentratedTickSpacing();

// NOW update tickLast for the next swap in this block
// This ensures subsequent swaps measure from the correct baseline
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({
        _lastUpdateTime: currentTime, 
        _tickLast: stateAfter.tick()  // Use post-swap tick
    })
});
```

This ensures each swap pays fees only for the tick movement it causes, not cumulative movement from earlier swaps in the block.

## Proof of Concept

The provided test case in the claim demonstrates the issue by executing two identical swaps in the same block and verifying that the second swap receives significantly less output despite similar price impact, proving the unfair fee calculation.

**Expected PoC Result:**
- **Current behavior**: Second swap pays ~2x the fair fee (receives ~10% less output)
- **After fix**: Both swaps pay equivalent fees for equivalent price impact

## Notes

This vulnerability stems from treating `tickLast` as a per-block baseline rather than a per-swap baseline. The first swapper in each block benefits from paying only for their own price impact, while all subsequent swappers in that block are overcharged based on cumulative movement.

The total fees collected exceed what would be fair based on actual individual price impacts, creating a perverse incentive for sophisticated traders to front-run and ensure first position in each block. Regular users who cannot control transaction ordering bear disproportionate costs.

The fix is straightforward: update `tickLast` after each swap to maintain an accurate baseline for the next swap's fee calculation, regardless of whether swaps occur in the same block or different blocks.

### Citations

**File:** src/interfaces/extensions/IMEVCapture.sol (L11-11)
```text
/// @dev Extension that charges additional fees based on the relative size of the priority fee and tick movement during swaps
```

**File:** src/extensions/MEVCapture.sol (L191-206)
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
```

**File:** src/extensions/MEVCapture.sol (L212-213)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
```
