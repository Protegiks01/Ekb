# Audit Report

## Title
Stale Tick Reference in MEVCapture Causes Cumulative Fee Overcharging for Multiple Swaps Within Same Block

## Summary
The MEVCapture extension updates its stored `tickLast` reference only once per block, causing subsequent swaps in the same block to calculate fees based on cumulative tick movement from the block start rather than individual swap movements. This results in users paying exponentially inflated fees (2x, 3x, 4x...) for the 2nd, 3rd, 4th... swaps in any block.

## Impact
**Severity**: Medium

Users executing swaps on MEVCapture pools after the first swap in a block are systematically overcharged fees. The fee calculation uses a stale `tickLast` value that doesn't reflect the pool's current state after previous swaps, causing the fee multiplier to compound across sequential swaps. For example, if three swaps each move the pool by 1 tick spacing, the fees charged are 1x (correct), 2x (100% overcharge), and 3x (200% overcharge) instead of 1x for all three. This violates the fee accounting accuracy expected by users and results in significant financial loss, particularly in high-activity blocks.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData()`, lines 177-215 [1](#0-0) 

**Intended Logic:** 
According to the interface documentation, MEVCapture should "charge additional fees based on... tick movement during swaps" (singular), meaning each individual swap's price impact should determine its fee. [2](#0-1) 

**Actual Logic:**
The extension only updates `tickLast` when entering a new block (when `lastUpdateTime != currentTime` at line 191). For the first swap in a block, `tickLast` is set to the current pool tick before the swap (line 202), and the pool state is persisted (lines 203-206). However, after the swap executes (line 209) and fees are calculated (line 213), `tickLast` is never updated to reflect the new pool position. All subsequent swaps in the same block skip the state update block (lines 191-207) and calculate their fees using the stale `tickLast` value from the block start.

**Exploitation Path:**

1. **Block N begins**: Pool at tick 1000, MEVCapture state has `tickLast = 1000`, `lastUpdateTime = N-1`
   
2. **First swap** (any user via MEVCaptureRouter):
   - `lastUpdateTime != currentTime` → state update block executes
   - `tickLast` set to 1000 (current pool tick before swap)
   - Swap moves pool from tick 1000 to tick 1020 (1 tick spacing, spacing=20)
   - Fee multiplier = |1020 - 1000| / 20 = 1.0x ✓ Correct
   - `tickLast` remains 1000 (not updated after swap)

3. **Second swap** (different user, same block):
   - `lastUpdateTime == currentTime` → state update block SKIPPED
   - `tickLast` still = 1000 (stale!)
   - Swap moves pool from tick 1020 to tick 1040 (1 tick spacing)
   - Fee multiplier = |1040 - 1000| / 20 = 2.0x ✗ Should be 1.0x
   - User pays double the correct additional fee

4. **Third swap** (same block):
   - Fee multiplier = |1060 - 1000| / 20 = 3.0x ✗ Should be 1.0x
   - User pays triple the correct additional fee [3](#0-2) 

**Security Guarantee Broken:**
The README states that position fee collection must be accurate (implied in main invariants section). Users are being charged based on stale state data rather than their actual swap's price impact, violating fundamental fee accounting principles.

## Impact Explanation

**Affected Assets**: All users swapping on MEVCapture pools; all MEVCapture pool liquidity providers receive inflated fees

**Damage Severity**:
- 2nd swap in any block: pays 2x the intended additional fee (100% overcharge)
- 3rd swap in any block: pays 3x the intended additional fee (200% overcharge)  
- Nth swap: pays Nx the intended fee ((N-1) × 100% overcharge)
- With a 1% base pool fee and 1 tick spacing movement:
  - Expected: 1% base + ~1% additional = ~2% total
  - Actual for 2nd swap: 1% base + ~2% additional = ~3% total (50% overcharge)
  - Actual for 3rd swap: 1% base + ~3% additional = ~4% total (100% overcharge)

**User Impact**: Any user executing a swap after another swap has already occurred in the current block on any MEVCapture pool. This affects legitimate users, not attackers. In high-activity blocks with multiple swaps, multiple users are overcharged.

**Trigger Conditions**: Occurs automatically whenever a MEVCapture pool processes its 2nd, 3rd, 4th... swap in any block.

## Likelihood Explanation

**Attacker Profile**: No attacker required - all users are automatically affected when swapping after the first swap in a block

**Preconditions**:
1. MEVCapture pool must be initialized (true for all MEVCapture pools)
2. At least one swap must have already occurred in the current block
3. Pool must have non-zero fee and concentrated liquidity (enforced at initialization) [4](#0-3) 

**Execution Complexity**: Zero complexity - happens automatically to any swap routed through MEVCaptureRouter after the first swap in a block [5](#0-4) 

**Economic Cost**: No additional cost beyond normal swap gas fees

**Frequency**: Occurs on every swap after the first in each block across all MEVCapture pools. High-activity blocks on popular pools will see multiple users affected per block.

**Overall Likelihood**: HIGH - Trivial to trigger, affects multiple users per active block

## Recommendation

**Primary Fix:**
Update `tickLast` after each swap to reflect the current pool state, not just at the start of each block:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, after line 209:

(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Update tickLast for next swap in same block
int32 newTick = stateAfter.tick();

// Calculate fee multiplier using the tick BEFORE this update
uint256 feeMultiplierX64 =
    (FixedPointMathLib.abs(newTick - tickLast) << 64) / poolKey.config.concentratedTickSpacing();

// Update tickLast for next swap (whether in this block or next)
tickLast = newTick;

// Persist state if this was the first swap in a new block
if (lastUpdateTime != currentTime) {
    setPoolState({
        poolId: poolId,
        state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
    });
}
```

**Alternative Consideration:**
If the design intent is to charge based on cumulative block movement (though no documentation suggests this), this should be clearly documented and the fairness to later swappers reconsidered, as they pay for others' price impact.

## Proof of Concept

The existing test suite includes `test_second_swap_with_additional_fees_gas_price()` which performs two swaps in the same block but doesn't verify the fee amounts match individual tick movements. A complete PoC would:

1. Initialize a MEVCapture pool with known tick spacing (e.g., 20,000)
2. Execute first swap moving 1 tick spacing
3. Execute second swap (same block) also moving 1 tick spacing  
4. Verify second swap pays ~2x fees instead of the same fees as first swap
5. Execute third swap and observe ~3x fee escalation

Expected behavior: All three swaps should pay approximately equal fees (each moves 1 tick spacing)
Actual behavior: Second swap pays ~2x, third pays ~3x due to cumulative calculation from stale `tickLast`

## Notes

This vulnerability demonstrates the security risk of storing and reusing pool state (tick values) in extensions without updating after each operation. The MEVCapturePoolState type stores both `lastUpdateTime` and `tickLast` in a single bytes32 slot: [6](#0-5) 

The design correctly uses `lastUpdateTime` to trigger state updates once per block, but fails to maintain `tickLast` accuracy after each swap within that block. This creates a mismatch between the extension's view of the pool state and the actual Core pool state, leading to incorrect fee calculations.

### Citations

**File:** src/extensions/MEVCapture.sol (L64-81)
```text
    function beforeInitializePool(address, PoolKey memory poolKey, int32 tick)
        external
        override(BaseExtension, IExtension)
        onlyCore
    {
        if (poolKey.config.isStableswap()) {
            revert ConcentratedLiquidityPoolsOnly();
        }
        if (poolKey.config.fee() == 0) {
            // nothing to multiply == no-op extension
            revert NonzeroFeesOnly();
        }

        setPoolState({
            poolId: poolKey.toPoolId(),
            state: createMEVCapturePoolState({_lastUpdateTime: uint32(block.timestamp), _tickLast: tick})
        });
    }
```

**File:** src/extensions/MEVCapture.sol (L177-215)
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
```

**File:** src/interfaces/extensions/IMEVCapture.sol (L9-12)
```text
/// @title MEV Capture Interface
/// @notice Interface for the Ekubo MEV Capture Extension
/// @dev Extension that charges additional fees based on the relative size of the priority fee and tick movement during swaps
interface IMEVCapture is IExposedStorage, ILocker, IForwardee, IExtension {
```

**File:** src/MEVCaptureRouter.sol (L27-43)
```text
    function _swap(uint256 value, PoolKey memory poolKey, SwapParameters params)
        internal
        override
        returns (PoolBalanceUpdate balanceUpdate, PoolState stateAfter)
    {
        if (poolKey.config.extension() != MEV_CAPTURE) {
            (balanceUpdate, stateAfter) = CORE.swap(value, poolKey, params.withDefaultSqrtRatioLimit());
        } else {
            (balanceUpdate, stateAfter) = abi.decode(
                CORE.forward(MEV_CAPTURE, abi.encode(poolKey, params.withDefaultSqrtRatioLimit())),
                (PoolBalanceUpdate, PoolState)
            );
            if (value != 0) {
                SafeTransferLib.safeTransferETH(address(CORE), value);
            }
        }
    }
```

**File:** src/types/mevCapturePoolState.sol (L1-25)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

type MEVCapturePoolState is bytes32;

using {lastUpdateTime, tickLast} for MEVCapturePoolState global;

function lastUpdateTime(MEVCapturePoolState state) pure returns (uint32 v) {
    assembly ("memory-safe") {
        v := shr(224, state)
    }
}

function tickLast(MEVCapturePoolState state) pure returns (int32 v) {
    assembly ("memory-safe") {
        v := signextend(3, state)
    }
}

function createMEVCapturePoolState(uint32 _lastUpdateTime, int32 _tickLast) pure returns (MEVCapturePoolState s) {
    assembly ("memory-safe") {
        // s = (lastUpdateTime << 224) | tickLast
        s := or(shl(224, _lastUpdateTime), and(_tickLast, 0xffffffff))
    }
}
```
