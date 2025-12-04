# Audit Report

## Title
Incorrect MEV Fee Calculation for Multiple Swaps in Same Block Due to Stale tickLast Reference

## Summary
The MEVCapture extension's `handleForwardData()` function only updates its `tickLast` state once per block (when `lastUpdateTime != currentTime`), causing subsequent swaps within the same transaction to calculate MEV capture fees using a stale tick reference that doesn't reflect the pool's current position. This results in users being systematically overcharged or undercharged based on cumulative tick movement from the start of the block rather than each individual swap's actual tick movement.

## Impact
**Severity**: Medium

The vulnerability causes incorrect MEV fee calculation when users perform multiple swaps through MEVCapture pools in a single transaction. Users executing batch operations via `multiMultihopSwap()` or `multicall()` will experience fee miscalculation that can range from 2x to several multiples of the correct amount, depending on the number of swaps and their directional alignment. While this doesn't cause protocol insolvency or direct theft of principal, it represents a significant financial loss through systematic overcharging for legitimate multi-hop trading operations. The issue affects all users employing standard Router batch functions with MEVCapture pools—a common pattern for optimizing gas costs and achieving price improvement through multi-hop routes.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData`, lines 177-260 [1](#0-0) 

**Intended Logic:** 
Each swap through a MEVCapture pool should charge additional fees proportional to the tick distance moved by that specific swap. The comment at line 211 states "however many tick spacings were crossed is the fee multiplier", indicating the intent to measure individual swap tick movement. The fee calculation formula `(abs(stateAfter.tick() - tickLast) << 64) / tickSpacing` should use `tickLast` as the pool's tick position immediately before the current swap executes.

**Actual Logic:**
The `tickLast` variable is only refreshed from Core storage when the conditional check `lastUpdateTime != currentTime` evaluates to true (line 191). This occurs only once per block. When multiple swaps execute in the same transaction:

1. **First swap**: The condition passes, `tickLast` is updated to the current pool tick (line 202), state is saved (lines 203-206), swap executes, and fee is correctly calculated
2. **Subsequent swaps**: The condition fails because `lastUpdateTime == currentTime`, causing lines 192-206 to be skipped. The `tickLast` value loaded from storage (line 184) represents the tick position at the START of the first swap, not the current pool position. The pool has since moved, but `tickLast` remains stale, causing fee calculation to use cumulative tick distance from block start rather than the individual swap's movement.

**Exploitation Path:**

1. **Setup**: User prepares multiple swaps through MEVCapture pool(s) using Router's batch functions
2. **First swap execution**: Via `handleForwardData()`, pool moves from tick 100→150, `tickLast=100` saved to storage, MEV fee correctly calculated for 50-tick movement
3. **Second swap execution**: Loads `tickLast=100` from storage, but pool is currently at tick 150. Line 191 check fails, so `tickLast` remains 100 without refresh
4. **Fee miscalculation**: Swap moves pool 150→200, but fee calculated as `abs(200-100)=100` ticks instead of correct `abs(200-150)=50` ticks
5. **Result**: User charged MEV fee for 100 ticks (2x overcharge) instead of the actual 50-tick movement [2](#0-1) [3](#0-2) 

**Security Property Broken:**
While this doesn't violate the main solvency invariant in README line 200, it breaks the implicit fee accounting accuracy requirement—users must pay fees that accurately reflect their swap's actual tick movement, not cumulative movement from an arbitrary earlier point in the block.

## Impact Explanation

**Affected Assets**: All users performing multiple swaps through MEVCapture pools via `multiMultihopSwap()` or `multicall()` in a single transaction, across all token pairs using the MEVCapture extension [4](#0-3) [5](#0-4) 

**Damage Severity**:
- Users executing N swaps in same direction experience cumulative overcharge: first swap correct, second charged for 2x distance, third for 3x distance, etc.
- For example, 5 swaps each moving 20 ticks would charge for 20+40+60+80+100=300 total ticks instead of correct 20+20+20+20+20=100 ticks (3x overcharge)
- Opposite direction swaps create undercharging: swaps that reverse direction may pay near-zero MEV fees despite moving significant tick distance
- Impact scales with number of swaps per transaction and tick distances moved

**User Impact**: Any user utilizing Router's batch swap functions (`multiMultihopSwap`, `multicall`) with MEVCapture pools—a standard usage pattern for:
- Multi-hop trades routing through multiple pools
- Portfolio rebalancing operations
- Gas optimization through batched transactions
- Sophisticated trading strategies requiring atomic multi-swap execution

## Likelihood Explanation

**Attacker Profile**: Any user, including:
- Innocent users performing legitimate multi-hop swaps (unintentionally overcharged)
- Sophisticated actors potentially exploiting undercharging scenarios through carefully constructed opposite-direction swap sequences

**Preconditions**:
1. MEVCapture pool must be initialized and have non-zero liquidity (true for all active pools)
2. Multiple swaps routed through MEVCapture pool(s) in single transaction
3. No other special conditions required

**Execution Complexity**: Trivial—single transaction using standard Router functions (`multiMultihopSwap` or `multicall`) that are publicly documented and commonly used for gas optimization

**Economic Cost**: Only standard transaction gas fees, no capital lockup or special setup required

**Frequency**: Every transaction containing multiple swaps through MEVCapture pools. Given MEVCapture is designed as a core extension and batch operations are standard practice, this could affect hundreds of transactions daily.

**Overall Likelihood**: HIGH - The vulnerability triggers automatically whenever users employ normal batch swap patterns through MEVCapture pools, with no special actions or conditions needed.

## Recommendation

**Primary Fix:**
Modify `handleForwardData()` to always load the current pool tick from Core before each swap, while maintaining the once-per-block fee accumulation logic:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData:

// Move tick loading OUTSIDE the time-gated block
(int32 currentTick, uint128 fees0, uint128 fees1) = 
    loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

// Keep fee accumulation gated by time to prevent double-accumulation
if (lastUpdateTime != currentTime) {
    if (fees0 != 0 || fees1 != 0) {
        CORE.accumulateAsFees(poolKey, fees0, fees1);
        saveDelta0 -= int256(uint256(fees0));
        saveDelta1 -= int256(uint256(fees1));
    }
}

// Always use freshly loaded current tick
tickLast = currentTick;

// Always update state to reflect current tick regardless of time
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
});

// Rest of function continues with correct tickLast value...
```

This ensures:
- Each swap's MEV fee reflects only its own tick movement
- Fee accumulation still happens once per block (prevents double-claiming)
- State consistently tracks the actual pool tick after each swap

**Alternative mitigation:** Store `stateAfter.tick()` as the new `tickLast` after each swap completes, ensuring the next swap in the same block uses the correct starting tick reference.

## Notes

The root cause stems from an optimization attempting to minimize state reads/writes by updating `tickLast` only once per block. However, this optimization breaks fee accounting correctness when multiple swaps occur within a single transaction—a common scenario explicitly enabled by Router's batch operation functions.

The vulnerability manifests differently based on swap directions:
- **Same direction swaps**: Systematic overcharging (cumulative distance calculation)
- **Opposite direction swaps**: Potential undercharging (net distance smaller than sum of individual movements)

Both scenarios violate fee accounting accuracy. The proposed fix maintains gas efficiency for the single-swap case while ensuring correctness for multi-swap scenarios by refreshing the tick reference before each swap without redundant fee accumulation.

The comment at line 211 ("however many tick spacings were crossed is the fee multiplier") confirms the intended behavior is per-swap measurement, not cumulative block-level measurement, supporting the assessment that this is a bug rather than intentional design.

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

**File:** src/Router.sol (L390-403)
```text
    /// @notice Executes multiple multi-hop swaps in a single transaction
    /// @param swaps Array of swap structs, each containing a route and initial token amount
    /// @param calculatedAmountThreshold Minimum total final amount to receive (for slippage protection)
    /// @return results Array of delta arrays, one for each swap
    function multiMultihopSwap(Swap[] memory swaps, int256 calculatedAmountThreshold)
        external
        payable
        returns (PoolBalanceUpdate[][] memory results)
    {
        results = abi.decode(
            lock(abi.encode(CALL_TYPE_MULTI_MULTIHOP_SWAP, msg.sender, swaps, calculatedAmountThreshold)),
            (PoolBalanceUpdate[][])
        );
    }
```

**File:** src/base/PayableMulticallable.sol (L17-19)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }
```
