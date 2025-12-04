After rigorous analysis of the MEVCapture extension code, I must provide my validation decision.

## PHASE 1: SCOPE & BASIC VALIDATION ✅

- **File in scope**: `src/extensions/MEVCapture.sol` is confirmed in scope.txt [1](#0-0) 
- **No threat model violations**: No admin misbehavior or trusted role exploitation required
- **Not a known issue**: Checked README known issues section, this is not listed
- **Not a non-security issue**: Claims concrete financial impact through fee miscalculation

## PHASE 2: CODE ANALYSIS ✅

### Critical Code Path Confirmed

**Block Entry Logic** - When first swap in new block occurs: [2](#0-1) 

The condition `if (lastUpdateTime != currentTime)` updates `tickLast` to the current pool tick (line 202) and stores this in pool state (lines 203-206). **Crucially, this only happens once per block.**

**Fee Calculation** - For every swap: [3](#0-2) 

The fee multiplier uses `stateAfter.tick() - tickLast`. For the second swap in the same block, `tickLast` remains at the pre-first-swap tick because lines 191-206 are skipped (the condition is false).

**Code Comment Contradiction**: [4](#0-3) 

The comment "however many tick spacings were crossed" suggests per-swap measurement, but the code measures cumulative movement from block start.

## PHASE 3: IMPACT ASSESSMENT ✅

### Demonstrable Unfair Fee Distribution

For sequential swaps in same block with equal D-tick movements:
- Swap 1: Pays fee for D ticks (fair)
- Swap 2: Pays fee for 2D ticks (includes Swap 1's movement)
- Swap 3: Pays fee for 3D ticks (includes both prior swaps)

Total fees collected: D·N(N+1)/2 vs. fair amount of N·D, creating (N+1)/2 overcollection ratio.

### Exploitation Vector

MEV searchers can front-run to ensure first position in block, paying only for their own tick movement while forcing later swappers to subsidize their impact. This creates systematic unfairness exploitable through standard MEV infrastructure (mempool monitoring, gas price bidding).

## PHASE 4: TEST SUITE ANALYSIS ✅

All existing MEVCapture tests call `coolAllContracts()` between swaps, which advances block timestamp: [5](#0-4) 

**No tests verify fair fee distribution for multiple swaps in the same block.** This strongly suggests the cumulative behavior was not intentionally designed or verified.

## PHASE 5: INTENTIONALITY ASSESSMENT

**Evidence this is a bug:**
1. Comment suggests per-swap measurement
2. Interface documentation says "tick movement during swaps" (plural, suggesting independent measurement) [6](#0-5) 
3. No tests verify same-block fairness
4. No documentation explains per-block measurement as intentional
5. Creates exploitable unfairness favoring front-runners

**Evidence for intentional design:**
1. The `if (lastUpdateTime != currentTime)` check is explicit

However, the preponderance of evidence points to unintended behavior that creates unfair and exploitable fee distribution.

---

# VALIDATION RESULT: **VALID MEDIUM SEVERITY VULNERABILITY**

## Summary

The MEVCapture extension charges subsequent swaps within the same block for cumulative tick movement from the block's start rather than their individual price impact. This causes later swappers to overpay fees proportional to all prior swaps' movements in that block, creating systematic unfairness exploitable by MEV searchers who can ensure first position through transaction ordering.

## Severity Justification

**Medium** per Code4rena framework: Fee miscalculation causing users to lose significant value. While this doesn't directly steal funds or break protocol solvency, it creates demonstrable financial harm through unfair fee distribution that's systematically exploitable. Users who happen to trade later in a block bear disproportionate costs with no ability to avoid this beyond sophisticated transaction ordering techniques unavailable to regular users.

The overcollection ratio of (N+1)/2 means even modest activity (3 swaps per block) results in 2x overcollection, with excess fees representing value transfer from regular users to protocol that should have remained with swappers based on their actual individual price impact.

## Notes

The vulnerability stems from treating `tickLast` as a per-block baseline rather than per-swap baseline. The fix is straightforward: update `tickLast` after each swap to `stateAfter.tick()` so subsequent swaps measure only their own movement. This maintains the per-block fee accumulation pattern while ensuring fair distribution based on actual individual impacts.

### Citations

**File:** scope.txt (L20-20)
```text
./src/extensions/MEVCapture.sol
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

**File:** src/extensions/MEVCapture.sol (L209-213)
```text
            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
```

**File:** test/extensions/MEVCapture.t.sol (L413-423)
```text
        token0.approve(address(router), type(uint256).max);
        router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: 300_000,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        coolAllContracts();
```

**File:** src/interfaces/extensions/IMEVCapture.sol (L11-11)
```text
/// @dev Extension that charges additional fees based on the relative size of the priority fee and tick movement during swaps
```
