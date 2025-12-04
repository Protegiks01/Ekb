# Audit Report

## Title
Stale `tickLast` State in MEVCapture Causes Systematic Fee Overcharging for Subsequent Swaps Within Same Block

## Summary
The MEVCapture extension fails to update the `tickLast` state variable after each swap execution within a block, causing all subsequent swaps to calculate MEV fees based on cumulative price movement from the block's starting tick rather than their individual price impact. This results in systematic overcharging where the second swap pays approximately 2x the intended fee, the third pays 3x, and so on.

## Impact
**Severity**: Medium

This is a fee miscalculation vulnerability causing users to lose significant value. Users swapping through MEVCapture-enabled pools after the first swap in any block are systematically overcharged on MEV fees. The overcharge multiplies with each subsequent swap (2x for second, 3x for third, up to 10x+ on active pools with many swaps per block). While the excess fees are redistributed to liquidity providers rather than stolen, users are charged for price movements they did not cause, violating the documented intent of per-swap fee calculation. [1](#0-0) 

## Finding Description

**Location:** `src/extensions/MEVCapture.sol:177-260`, function `handleForwardData()`

**Intended Logic:** 
The inline comment at line 211 explicitly states "however many tick spacings were crossed is the fee multiplier," indicating the design intent is to measure each swap's individual tick movement and charge proportionally for that specific swap's price impact. [2](#0-1) 

**Actual Logic:**
The `tickLast` variable is loaded from storage at the start of each swap but is only updated when entering a new block (when `lastUpdateTime != currentTime`). After the swap executes, `tickLast` is never updated to reflect the post-swap pool tick. [3](#0-2) [4](#0-3) [5](#0-4) 

After the swap executes at line 209, the code proceeds directly to fee calculation at lines 212-213 using the stale `tickLast` value against the fresh `stateAfter.tick()` value. There is no code between lines 209-260 that updates `tickLast` in storage. [6](#0-5) 

**Exploitation Path:**
1. **Block B starts** - Pool at tick 100, MEVCapture storage has `tickLast = 100`
2. **First swap** - Lines 191-206 execute, updating storage `tickLast` to 100 (current pool tick). Swap moves pool to tick 110. Fee calculated as `abs(110-100)/tickSpacing = 10` tick spacings ✓ Correct
3. **Second swap (same block)** - Line 191 condition fails (already updated this block), lines 191-206 skipped. `tickLast` remains 100 from storage. Swap moves pool from 110 to 120. Fee calculated as `abs(120-100)/tickSpacing = 20` tick spacings when actual movement was only 10 ticks → **2x overcharge**
4. **Third swap (same block)** - Same issue continues, compounding the overcharge

**Security Property Broken:**
The inline comment documents the intended invariant that fees should be proportional to "tick spacings crossed" by each swap. The current implementation violates this by charging later swaps for cumulative price movements they did not cause.

## Impact Explanation

**Affected Assets**: All users swapping through MEVCapture-enabled pools

**Damage Severity**:
- Second swap in any block: ~2x intended MEV fee
- Third swap: ~3x intended MEV fee  
- Nth swap: ~Nx intended MEV fee
- On active pools with 10+ swaps per block: up to 10x+ overcharge
- Excess fees redistributed to LPs/protocol but extracted unfairly from users

**User Impact**: Every user executing a swap after the first swap in a block on any MEVCapture-enabled pool is systematically overcharged. This affects potentially hundreds of users daily on popular pools.

**Trigger Conditions**: Occurs automatically on every swap except the first in each block. No attacker action or special conditions required.

## Likelihood Explanation

**Attacker Profile**: No attacker required - affects all normal users swapping on MEVCapture pools

**Preconditions**:
1. Pool has MEVCapture extension enabled
2. At least one prior swap in current block (common on active pools)
3. Pool has non-zero liquidity

**Execution Complexity**: None - happens automatically during normal swap operations

**Economic Cost**: Only standard gas fees for swap transaction

**Frequency**: Occurs on EVERY swap except the first in each block, on EVERY MEVCapture pool

**Overall Likelihood**: VERY HIGH - Systematic issue affecting all subsequent swaps in every block on all MEVCapture pools

## Recommendation

**Primary Fix:**
After line 209 where the swap executes, update `tickLast` in storage to reflect the post-swap tick:

```solidity
(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

uint256 feeMultiplierX64 = 
    (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();

// Update tickLast for next swap in this block
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: stateAfter.tick()})
});
```

**Alternative Fix:**
Query the current pool tick immediately before the swap:

```solidity
int32 tickBeforeSwap = CORE.poolState(poolId).tick();
(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

uint256 feeMultiplierX64 = 
    (FixedPointMathLib.abs(stateAfter.tick() - tickBeforeSwap) << 64) / poolKey.config.concentratedTickSpacing();
```

## Proof of Concept

A PoC would execute two equal-sized swaps in the same direction within a single block and verify that:
- First swap fee is proportional to its tick movement
- Second swap fee is approximately 2x the first swap's fee despite similar tick movement
- This demonstrates the cumulative fee calculation bug

The existing test `test_second_swap_with_additional_fees_gas_price` executes this scenario but does not assert on individual swap fee correctness.

## Notes

This vulnerability stems from incomplete state management where `tickLast` is only refreshed at block boundaries but not after individual swaps. The Core contract correctly updates the pool tick after each swap, but MEVCapture fails to track this for subsequent fee calculations.

The inconsistency between the first swap (which calculates fees correctly) and subsequent swaps (which use stale `tickLast` values) strongly indicates unintended behavior rather than deliberate design. The inline comment explicitly documenting per-swap measurement further confirms this is a bug violating the intended specification.

### Citations

**File:** src/extensions/MEVCapture.sol (L182-184)
```text
            MEVCapturePoolState state = getPoolState(poolId);
            uint32 lastUpdateTime = state.lastUpdateTime();
            int32 tickLast = state.tickLast();
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

**File:** src/extensions/MEVCapture.sol (L209-209)
```text
            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);
```

**File:** src/extensions/MEVCapture.sol (L211-213)
```text
            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
```
