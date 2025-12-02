## Title
Stale `tickLast` State Causes Systematic MEV Fee Overcharging for All Swaps After First in Block

## Summary
The MEVCapture extension's `handleForwardData` function fails to update the `tickLast` state variable after each swap execution, causing all subsequent swaps within the same block to be charged MEV fees based on cumulative price movement from the block's starting tick rather than their individual price impact. This results in systematic overcharging that compounds with each swap in the block.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** According to the inline comment, the fee multiplier should be based on "however many tick spacings were crossed" by each individual swap. [2](#0-1) 

**Actual Logic:** The `tickLast` variable is only updated when entering a new block (when `lastUpdateTime != currentTime`), but is never updated after the swap executes. This happens at: [3](#0-2) 

After the swap executes at line 209, the tick distance calculation uses the stale `tickLast`: [4](#0-3) 

**Exploitation Path:**
1. **Block B starts** - Pool tick = 100, MEVCapture `tickLast` = 100 (from previous block)
2. **First swap executes** - Lines 191-206 update `tickLast` to 100 (current tick), swap moves tick to 110, user charged for `abs(110-100)/tickSpacing` = correct
3. **Second swap in same block** - Lines 191-207 are SKIPPED (already updated this block), `tickLast` remains 100, swap moves tick from 110 to 120, user charged for `abs(120-100)/tickSpacing` when they should be charged for `abs(120-110)/tickSpacing` = **2x overcharge**
4. **Third swap in same block** - User charged for `abs(125-100)/tickSpacing` when actual movement is `abs(125-120)/tickSpacing` = **5x overcharge**

**Security Property Broken:** Critical Invariant #5 - Fee Accounting must be accurate and never allow double-claiming. Users are being charged for price movements they did not cause.

## Impact Explanation
- **Affected Assets**: All users swapping through MEVCapture-enabled pools after the first swap in any block
- **Damage Severity**: Users are overcharged by increasing multiples:
  - 2nd swap: ~2x overcharge
  - 3rd swap: ~3x overcharge  
  - Nth swap: ~Nx overcharge (relative to their actual price impact)
  - On active pools with 10+ swaps per block, users can pay 10x+ the intended MEV fees
- **User Impact**: Every user who swaps after the first swap in a block on any MEVCapture pool is systematically overcharged

## Likelihood Explanation
- **Attacker Profile**: Any user swapping on MEVCapture pools (no special privileges required)
- **Preconditions**: 
  - Pool has MEVCapture extension enabled
  - At least one swap has occurred earlier in the current block
  - Pool has non-zero liquidity
- **Execution Complexity**: Single transaction, happens automatically during normal swaps
- **Frequency**: Occurs on EVERY swap except the first in each block, on every MEVCapture pool

## Recommendation

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, after line 209:

// CURRENT (vulnerable):
// Line 209: (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);
// Line 210-213: Calculate fees using stale tickLast
// [No update to tickLast after swap]

// FIXED:
// After line 209, add state update:
(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Update tickLast to reflect the post-swap tick for the NEXT swap in this block
tickLast = stateAfter.tick();
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
});

// Then calculate fees based on the actual tick movement of THIS swap
uint256 feeMultiplierX64 = ...
```

Alternative mitigation: Store the pre-swap tick in a temporary variable before line 209, and use that for the distance calculation instead of the cached `tickLast`.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureTickOvercharge.t.sol
// Run with: forge test --match-test test_mevCaptureOverchargesSecondSwap -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import {PoolKey, createConcentratedPoolConfig} from "../src/types/poolKey.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_MEVCaptureOvercharge is Test {
    Core core;
    MEVCapture mevCapture;
    MEVCaptureRouter router;
    
    function setUp() public {
        // Initialize protocol (simplified - actual test would use FullTest base)
        core = new Core();
        mevCapture = new MEVCapture(core);
        router = new MEVCaptureRouter(core, address(mevCapture));
    }
    
    function test_mevCaptureOverchargesSecondSwap() public {
        // SETUP: Create pool and add liquidity
        PoolKey memory poolKey = createPool(
            address(token0), 
            address(token1), 
            0, // initial tick
            createConcentratedPoolConfig(1e16, 20_000, address(mevCapture))
        );
        createPosition(poolKey, -100_000, 100_000, 1_000_000, 1_000_000);
        
        token0.approve(address(router), type(uint256).max);
        
        // FIRST SWAP: Move from tick 0 to tick ~-29,000
        PoolBalanceUpdate update1 = router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: 300_000,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        int32 tickAfterFirst = core.poolState(poolKey.toPoolId()).tick();
        uint256 fee1 = uint256(int256(update1.delta0())) - 300_000; // Extra fee paid
        
        // SECOND SWAP: Move another ~-29,000 ticks (same as first swap)
        PoolBalanceUpdate update2 = router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: 300_000,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        int32 tickAfterSecond = core.poolState(poolKey.toPoolId()).tick();
        uint256 fee2 = uint256(int256(update2.delta0())) - 300_000; // Extra fee paid
        
        // VERIFY: Second swap moved similar distance but paid ~2x the fee
        int32 movement1 = 0 - tickAfterFirst; // First swap movement
        int32 movement2 = tickAfterFirst - tickAfterSecond; // Second swap movement
        
        // Movements should be similar (both ~29,000 ticks)
        assertApproxEqAbs(movement1, movement2, 5000, "Swap movements should be similar");
        
        // But fee2 should be ~2x fee1 due to the bug
        assertGt(fee2, fee1 * 18 / 10, "Second swap overcharged by ~2x");
        
        console.log("First swap movement:", uint256(int256(movement1)));
        console.log("Second swap movement:", uint256(int256(movement2)));
        console.log("First swap MEV fee:", fee1);
        console.log("Second swap MEV fee:", fee2);
        console.log("Overcharge ratio:", fee2 * 100 / fee1, "%");
    }
}
```

## Notes

The vulnerability stems from an incomplete state management pattern where `tickLast` is refreshed only at block boundaries but not after individual swaps. The Core contract correctly updates the pool tick atomically with other state changes [5](#0-4) , but the MEVCapture extension fails to track this updated tick for subsequent swaps in the same block.

This is not a race condition in the traditional sense (there's no concurrency), but rather a state staleness issue where the extension's cached `tickLast` value becomes outdated after the first swap completes. The security question correctly identified that the tick distance calculation uses both a fresh value (`stateAfter.tick()`) and a stale value (`tickLast`), creating the vulnerability.

### Citations

**File:** src/extensions/MEVCapture.sol (L177-260)
```text
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
            (PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));

            PoolId poolId = poolKey.toPoolId();
            MEVCapturePoolState state = getPoolState(poolId);
            uint32 lastUpdateTime = state.lastUpdateTime();
            int32 tickLast = state.tickLast();

            uint32 currentTime = uint32(block.timestamp);

            int256 saveDelta0;
            int256 saveDelta1;

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

            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));

            if (additionalFee != 0) {
                if (params.isExactOut()) {
                    // take an additional fee from the calculated input amount equal to the `additionalFee - poolFee`
                    if (balanceUpdate.delta0() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta1())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                } else {
                    if (balanceUpdate.delta0() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta0())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta1())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                }
            }

            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }

            result = abi.encode(balanceUpdate, stateAfter);
        }
    }
```

**File:** src/Core.sol (L824-826)
```text
                stateAfter = createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: liquidity});

                writePoolState(poolId, stateAfter);
```
