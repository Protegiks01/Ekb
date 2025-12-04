# Audit Report

## Title
Stale Tick Reference in MEVCapture Causes Cumulative Fee Overcharging for Multiple Swaps Within Same Block

## Summary
The MEVCapture extension maintains a per-pool `tickLast` reference that is only updated once per block, causing all subsequent swaps in the same block to calculate additional fees based on cumulative tick movement from the block start rather than from the previous swap's end position. This systematic design flaw results in exponentially escalating fee overcharges (2x, 3x, 4x...) for the 2nd, 3rd, 4th... swaps within any block.

## Impact
**Severity**: Medium - Systematic fee miscalculation causing significant user value loss

Users executing swaps on MEVCapture pools after the first swap in a block are systematically overcharged additional fees. The vulnerability stems from the `handleForwardData()` function's state management logic, which only updates the stored `tickLast` reference when entering a new block, never after individual swap execution. This causes the fee multiplier calculation to measure cumulative price movement from the block start rather than from the immediate pre-swap tick position.

For example, if three sequential swaps each move the pool by 1 tick spacing:
- Swap 1: Pays 1x additional fee (correct - measures movement from block start)
- Swap 2: Pays 2x additional fee (100% overcharge - measures from block start, not from Swap 1 end)  
- Swap 3: Pays 3x additional fee (200% overcharge - measures from block start, not from Swap 2 end)

With a 1% base pool fee and 1 tick spacing movement, Swap 2 pays ~3% total fee instead of ~2% (50% overcharge), and Swap 3 pays ~4% instead of ~2% (100% overcharge). This violates the fundamental fee accounting principle that users should be charged based on their own price impact, not others'.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The MEVCapture interface documentation states it should "charge additional fees based on... tick movement during swaps" [2](#0-1) , suggesting each swap's individual price impact determines its fee.

**Actual Logic:**
The `handleForwardData()` function loads `tickLast` from storage at line 184, then conditionally updates it only when `lastUpdateTime != currentTime` (line 191). Inside this conditional block (lines 192-207), the function:
1. Loads the current pool tick before any swap (line 192)
2. Sets `tickLast = tick` at line 202  
3. Persists the state with `setPoolState()` at lines 203-206

The swap then executes at line 209, potentially moving the pool to a new tick. The fee multiplier calculation at lines 212-213 uses `stateAfter.tick() - tickLast`, but **`tickLast` is never updated after the swap completes**. 

For the first swap in a block, this correctly measures movement from the pre-swap tick. However, all subsequent swaps in the same block skip the conditional update block (lines 191-207) because `lastUpdateTime == currentTime`, causing them to calculate fees using the stale `tickLast` value from the block start.

**Exploitation Path:**

**Block N Setup:** Pool at tick 1000, MEVCapture state: `{lastUpdateTime: N-1, tickLast: 1000}`

**Swap 1 (Block N, t=0):**
1. Load state: `lastUpdateTime = N-1`, `tickLast = 1000`
2. Condition `N-1 != N` evaluates true → enter update block
3. Load current pool tick = 1000, set `tickLast = 1000`
4. Persist state: `{lastUpdateTime: N, tickLast: 1000}`
5. Execute swap: pool moves 1000 → 1020 (1 tick spacing, spacing=20)
6. Calculate fee: `|1020 - 1000| / 20 = 1.0x` ✓ Correct
7. **`tickLast` remains 1000 in storage** (never updated post-swap)

**Swap 2 (Block N, t=5 seconds):**
1. Load state: `lastUpdateTime = N`, `tickLast = 1000` (stale!)
2. Condition `N != N` evaluates false → **skip update block**
3. Pool currently at tick 1020
4. Execute swap: pool moves 1020 → 1040 (1 tick spacing)
5. Calculate fee: `|1040 - 1000| / 20 = 2.0x` ✗ Should be `|1040 - 1020| / 20 = 1.0x`
6. User pays **double the correct additional fee**

**Swap 3 (Block N, t=10 seconds):**
1. Load stale `tickLast = 1000`, skip update block
2. Pool at 1040, moves to 1060
3. Calculate fee: `|1060 - 1000| / 20 = 3.0x` ✗ Should be 1.0x  
4. User pays **triple the correct additional fee**

**Security Guarantee Broken:**
Users expect fees to reflect their own swap's price impact. Instead, they're charged for cumulative block-wide price movement, violating fair fee accounting principles implied by the protocol's design.

## Impact Explanation

**Affected Assets:** All user funds swapping through MEVCapture pools; LP fees are inflated (benefiting LPs at swappers' expense)

**Damage Severity:**
- N-th swap in any block pays N× the correct additional fee, representing (N-1) × 100% overcharge
- In a block with 5 swaps each moving 1 tick spacing: total overcharge = 0 + 100% + 200% + 300% + 400% = 1000% extra fees collected
- Real-world scenario (1% base fee, 1 tick spacing movement):
  - Expected per swap: 1% base + 1% additional = 2% total
  - Swap 2 actual: 1% base + 2% additional = 3% (50% overcharge on total)
  - Swap 3 actual: 1% base + 3% additional = 4% (100% overcharge on total)

**User Impact:** Any user executing a swap when another swap has already occurred in the current block on any MEVCapture pool. Affects legitimate users indiscriminately—not attackers. High-activity pools in busy blocks see multiple users systematically overcharged per block.

**Trigger Conditions:** Occurs automatically whenever a MEVCapture pool processes its 2nd, 3rd, 4th... swap within the same block. No special state, permissions, or attacker actions required.

## Likelihood Explanation

**Attacker Profile:** No attacker required—vulnerability affects all users automatically through normal protocol usage

**Preconditions:**
1. MEVCapture pool must be initialized (true for all deployed MEVCapture pools) [3](#0-2) 
2. At least one swap must have already executed in the current block
3. Pool must have non-zero fee (enforced at initialization, line 72-75)
4. Pool must use concentrated liquidity with tick spacing (enforced at initialization, line 69-71)

**Execution Complexity:** Zero complexity—happens automatically to any swap routed through MEVCaptureRouter after the first swap in a block [4](#0-3) 

**Economic Cost:** No additional cost beyond normal swap gas fees

**Frequency:** Occurs on every swap after the first in each block across all MEVCapture pools. Popular pools in high-activity blocks will see multiple users affected per block.

**Overall Likelihood:** HIGH—trivial to trigger (no attacker actions needed), affects multiple users per active block, high frequency in production environments

## Recommendation

**Primary Fix:**
After executing the swap at line 209, update `tickLast` to `stateAfter.tick()` and persist it to storage for use by subsequent swaps in the same block:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, after line 209:

(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Calculate fee multiplier using the current tickLast (before update)
uint256 feeMultiplierX64 =
    (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();

// Update tickLast for next swap (critical fix)
tickLast = stateAfter.tick();
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
});

// Continue with fee application...
uint64 poolFee = poolKey.config.fee();
uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**Alternative Consideration:**
If the design intent is genuinely to charge based on cumulative block movement (though no documentation supports this interpretation), this behavior should be explicitly documented in the interface and README, and the fairness implications for later swappers should be reconsidered, as they pay for price impact they did not cause.

## Proof of Concept

The existing test suite includes `test_second_swap_with_additional_fees_gas_price()` which performs two swaps in the same block but does not verify that both swaps pay fees proportional to their individual tick movements. 

A complete PoC demonstrating this vulnerability would:

1. Initialize a MEVCapture pool with known parameters (e.g., tick spacing = 20,000, initial tick = 700,000)
2. Add liquidity across a range
3. Execute Swap 1: move pool by exactly 1 tick spacing, record additional fee amount
4. In same block, execute Swap 2: move pool by exactly 1 tick spacing (same magnitude as Swap 1)
5. Verify Swap 2 pays approximately 2× the additional fee that Swap 1 paid
6. Execute Swap 3 in same block with same tick movement, verify 3× fee

**Expected behavior:** All three swaps should pay approximately equal additional fees (each moves 1 tick spacing)

**Actual behavior:** Swap 1 pays 1×, Swap 2 pays 2×, Swap 3 pays 3× due to cumulative calculation from stale `tickLast`

## Notes

This vulnerability demonstrates the critical importance of maintaining synchronization between extension state views and actual Core pool state. The `MEVCapturePoolState` type stores both `lastUpdateTime` and `tickLast` in a packed bytes32 slot [5](#0-4) . While the design correctly uses `lastUpdateTime` to trigger state refreshes once per block for fee accumulation purposes, it fails to update `tickLast` after each swap within that block. This creates a divergence between the extension's view of pool state (tick at block start) and actual pool state (tick after N swaps), leading to systematic fee miscalculation.

The root cause is treating `tickLast` as a block-level cache rather than a swap-level reference point. Each swap should update this value to maintain accurate fee calculations for subsequent swaps within the same block.

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

**File:** src/interfaces/extensions/IMEVCapture.sol (L11-11)
```text
/// @dev Extension that charges additional fees based on the relative size of the priority fee and tick movement during swaps
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
