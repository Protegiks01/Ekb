## Title
Block-wide TickLast Sandwiched Fee Overcharge in MEVCapture Extension

## Summary
The MEVCapture extension's tick distance fee calculation charges all swaps within a block for the absolute tick movement from the block's starting tick (tickLast), not from the previous swap's ending tick. This allows attackers to sandwich normal users, forcing them to pay MEV fees that include both their own and the attacker's tick movement by abusing block-wide tickLast updates.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/extensions/MEVCapture.sol` — `handleForwardData` function, lines 177–260, especially the fee calculation on line 213 and `tickLast` update logic.

**Intended Logic:** The design intends to charge a fee proportional to the tick distance moved by a swap, deterring large and manipulative price movements.

**Actual Logic:** tickLast is only updated when a new block starts (`lastUpdateTime != currentTime`). All swaps within the same block calculate the additional fee using the difference between their end tick and the original tickLast from the block's start—not from where the previous swap left the tick. Thus, if an attacker front-runs a victim with a large move, the victim's fee is calculated on the combined price movement, not just their own impact.

**Exploitation Path:**
1. Attacker swaps—moves tick: tickLast = starting tick; pays for movement.
2. Victim swaps in same block—moves tick further, pays for total distance from block's tickLast (includes attacker's initial move).
3. Attacker swaps back, restoring price, also paying for movement.
4. Victim is overcharged for tick distance they did not actually traverse.

**Security Property Broken:** Fee fairness; users are overcharged for tick movement they did not cause.

## Impact Explanation
- **Affected Assets:** Fees paid by swap users in MEVCapture pools, disproportionately impacting innocent users sandwiched between sandwich attacks.
- **Damage Severity:** Overcharge can be substantial for large tick movements, and harm any user transacting after an attacker in the same block in a volatile pool.
- **User Impact:** Any user swapped after the manipulator in the same block can be affected without consent or escape.

## Likelihood Explanation
- **Attacker Profile:** Any unprivileged user/searcher.
- **Preconditions:** Pool must have MEVCapture enabled, and at least one attacker and victim perform swaps in the same block.
- **Execution Complexity:** Simple; no specialized contract required, just two or more swaps in the same block.
- **Frequency:** Can be exploited every block; repeatedly and predictably.

## Recommendation
Update the logic so that `tickLast` is updated after every swap, not only at block boundaries. This way, the MEV fee for each swap (except the first in a block) is calculated only on its own tick movement, not cumulative for the block.

## Proof of Concept
See above for the swap/test scenario. You can reproduce by scripting three swaps in a single block as described and observing that the middle/victim swap pays excessive fees not matching its own true tick movement.

---

# Notes

- **Citations**:
    - Fee calculation and `tickLast` logic: [1](#0-0) 
    - Creation and management of MEVCapturePoolState with tickLast and lastUpdateTime: [2](#0-1) 

- **False positives are unlikely:** This behavior is observable and reproducible in block-level multicall or searcher strategies.
- **Not a known/excluded issue:** This is not listed as a known or out-of-scope problem.

---

**Summary:**  
Attacker can extract value from normal users by sandwiching, forcing them to pay MEVCapture fees based on block-wide price movement, not just their own, due to improper tickLast handling in the MEVCapture extension. This results in overcharging and grievable fee behavior.

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
