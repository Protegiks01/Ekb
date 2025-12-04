# Audit Report

## Title
MEVCapture Intra-Block Fee Accumulation Bypass Allows Liquidity Providers to Steal Fees

## Summary
The MEVCapture extension contains a critical temporal desynchronization vulnerability where `handleForwardData()` updates `lastUpdateTime` immediately after accumulating old fees but before storing newly generated MEV fees in `savedBalances`. This creates a same-block window allowing attackers to insert liquidity positions after fee generation but before fee accumulation, enabling systematic theft of MEV fees from legitimate liquidity providers.

## Impact
**Severity**: High

Attackers can steal MEV fees from legitimate LPs on every block with swap activity. The attack enables proportional theft based on attacker liquidity: equal liquidity steals 50% of fees, 9x liquidity steals 90%. This is repeatable, automatable via MEV bots, requires minimal capital (can use flash loans), and has no defense mechanism available to victims. All MEVCapture-enabled pools are vulnerable.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, functions `handleForwardData()` (lines 177-260), `accumulatePoolFees()` (lines 105-125), and `locked_6416899205()` (lines 127-155)

**Intended Logic:** 
The MEVCapture extension is designed to capture additional fees based on tick movement during swaps and distribute them proportionally to liquidity providers who were actively providing liquidity when the fees were generated. The `beforeUpdatePosition` hook explicitly states it "Prevents new liquidity from collecting on fees". [1](#0-0) 

**Actual Logic:**
The implementation creates a temporal gap between fee generation and accumulation through these steps:

1. **Fee Generation in `handleForwardData()`**: When a swap occurs in block N as the first transaction:
   - Lines 191-199: If `lastUpdateTime != currentTime`, old fees are loaded from `savedBalances` and accumulated via `CORE.accumulateAsFees()` [2](#0-1) 
   - Lines 203-206: Critical step - `lastUpdateTime` is updated to current block timestamp [3](#0-2) 
   - Line 209: Swap executes, potentially moving ticks
   - Lines 212-252: NEW MEV fees are calculated based on tick movement [4](#0-3) 
   - Lines 254-256: NEW fees stored in `savedBalances` WITHOUT accumulation [5](#0-4) 

2. **Position Addition Bypass**: When `Core.updatePosition()` is called in the same block N:
   - Line 368 in Core.sol triggers `beforeUpdatePosition` hook which calls `accumulatePoolFees()`
   - Line 110 in MEVCapture checks `state.lastUpdateTime() != uint32(block.timestamp)` [6](#0-5) 
   - Since both equal block N, condition is FALSE and function returns WITHOUT calling `locked_6416899205()`
   - Position snapshot is taken with `feesPerLiquidityInsideLast` that does NOT include new fees [7](#0-6) 

3. **Delayed Accumulation Exploitation**: In block N+1, any action triggers `accumulatePoolFees()`:
   - Time check passes (N != N+1), calls `locked_6416899205()`
   - Lines 136-148: Loads fees from `savedBalances` and distributes via `accumulateAsFees()` [8](#0-7) 
   - Lines 254-267 in Core.sol distribute fees proportionally across ALL current liquidity [9](#0-8) 
   - Position from block N receives unearned fee share

**Exploitation Path:**

1. **Block N, Tx 1**: Large swap via `MEVCapture.forward()` moves ticks significantly
   - Old fees accumulated, `lastUpdateTime` set to block N
   - Swap generates 10 ETH in MEV fees stored in `savedBalances`
   - Fees NOT in `feesPerLiquidity` yet

2. **Block N, Tx 2**: Attacker adds 9x existing liquidity via `Core.updatePosition()`
   - `beforeUpdatePosition` calls `accumulatePoolFees()`
   - Time check fails (both block N), returns without accumulation
   - Position created with snapshot excluding new fees

3. **Block N+1**: Any action triggers accumulation
   - Time check passes, `locked_6416899205()` accumulates 10 ETH
   - Distributed: attacker (9L) gets 9 ETH, legitimate LPs (L) get 1 ETH
   - 9 ETH stolen from legitimate providers

4. **Block N+1**: Attacker removes liquidity and collects fees
   - Fee calculation uses `feesPerLiquidity` difference [10](#0-9) 
   - Attacker extracts 9 ETH earned before position existed

**Security Property Broken:**
Violates the fee accounting invariant that positions should only collect fees generated while their liquidity was active. The `beforeUpdatePosition` hook's documented purpose to "prevent new liquidity from collecting on fees" is defeated by the same-block timing bypass.

## Impact Explanation

**Affected Assets**: All pools using MEVCapture extension. MEV fees earned by legitimate liquidity providers are directly stolen.

**Damage Severity**:
- Mathematical theft ratio: attacker with A liquidity added to existing L liquidity receives `fees × A/(L+A)`
- Equal liquidity (A=L): 50% theft
- 9x liquidity (A=9L): 90% theft
- Attack repeatable every block with swap activity
- Cumulative losses compound over time
- High-volume pools with substantial MEV suffer greatest impact

**User Impact**: All legitimate LPs in MEVCapture pools experience diluted fee earnings with no defense mechanism. Victims cannot prevent exploitation as it occurs through normal contract operations. LPs who provided liquidity during fee-generating swaps receive only a fraction of their earned fees.

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital. No special permissions, roles, or privileges required. MEV searchers and bots will automate detection and exploitation.

**Preconditions**:
1. Pool uses MEVCapture extension (standard for Ekubo)
2. Swaps generate MEV fees (normal in volatile markets)
3. Attacker has capital for liquidity (flash loans minimize permanent commitment)
4. No special pool state required

**Execution Complexity**: Low - single-block attack:
- Monitor mempool for large swaps
- Submit liquidity addition in same block after swap
- Wait for next block for accumulation
- Remove liquidity and collect fees
- Fully automatable via smart contracts

**Economic Cost**: Only gas fees plus one-block capital lockup. Flash loans can amplify with minimal permanent capital.

**Frequency**: Exploitable every block with swap activity. In active pools, continuous exploitation is possible.

**Overall Likelihood**: HIGH - Simple execution, economically viable, automatable, and repeatable on every active block.

## Recommendation

**Primary Fix (Remove Premature Timestamp Update):**

Modify `handleForwardData()` to NOT update `lastUpdateTime` at lines 203-206 after accumulating old fees. This ensures subsequent calls to `accumulatePoolFees()` in the same block will still trigger fee accumulation, distributing new fees before new positions are created.

Additionally, modify `locked_6416899205()` to only update `lastUpdateTime` when fees are actually accumulated: [11](#0-10) 

Replace the unconditional update with conditional logic that preserves `lastUpdateTime` when no fees are accumulated, ensuring the next call in the same block will trigger accumulation.

**Alternative Fix (Immediate Accumulation):**

Modify `handleForwardData()` to immediately accumulate newly calculated MEV fees after line 252 instead of only storing them in `savedBalances`. This ensures fees are atomically distributed to the exact liquidity set active during the swap, eliminating any timing window.

**Rationale**: Both fixes eliminate the temporal gap between fee generation and accumulation. The primary fix maintains gas optimization intent while closing the exploit window. The alternative fix provides stronger atomicity guarantees by ensuring fees are distributed to providers who were active during fee generation.

## Proof of Concept

The existing test suite demonstrates the vulnerability through ABSENCE of same-block testing. The test `test_new_position_does_not_get_fees` validates protection works ONLY when time advances between swap and position creation: [12](#0-11) 

Notice line 640 calls `advanceTime(1)` [13](#0-12)  which warps to a new block before creating position 2.

**To demonstrate the vulnerability:**
1. Create position 1 with initial liquidity
2. Execute swap in block N generating MEV fees
3. **Without calling advanceTime()**, create position 2 in same block N
4. Advance to block N+1 and trigger fee accumulation
5. Verify position 2 incorrectly receives fees despite not being active during swap

**Expected Result**: Position 2 receives proportional share of fees from block N, violating the stated protection mechanism.

## Notes

This vulnerability stems from an architectural decision to batch fee accumulation across blocks for gas optimization, combined with insufficient enforcement of the temporal requirement that positions should only earn fees after creation. The `lastUpdateTime` check creates the exploit window by preventing same-block re-accumulation.

The vulnerability is particularly severe because:
1. It defeats the explicitly stated security control
2. Existing tests only validate cross-block scenarios
3. Attack is deterministic, not dependent on race conditions
4. Capital requirements can be minimized using flash loans
5. Automated MEV bots can systematically exploit every block

The fix must ensure atomicity between fee generation and distribution, eliminating any window where positions can be inserted before fees are accumulated to the providers who earned them.

### Citations

**File:** src/extensions/MEVCapture.sol (L96-102)
```text
    /// Prevents new liquidity from collecting on fees
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        accumulatePoolFees(poolKey);
    }
```

**File:** src/extensions/MEVCapture.sol (L110-124)
```text
        if (state.lastUpdateTime() != uint32(block.timestamp)) {
            address target = address(CORE);
            assembly ("memory-safe") {
                let o := mload(0x40)
                mstore(o, shl(224, 0xf83d08ba))
                mcopy(add(o, 4), poolKey, 96)
                mstore(add(o, 100), poolId)

                // If the call failed, pass through the revert
                if iszero(call(gas(), target, 0, o, 132, 0, 0)) {
                    returndatacopy(o, 0, returndatasize())
                    revert(o, returndatasize())
                }
            }
        }
```

**File:** src/extensions/MEVCapture.sol (L136-148)
```text
        (int32 tick, uint128 fees0, uint128 fees1) = loadCoreState(poolId, poolKey.token0, poolKey.token1);

        if (fees0 != 0 || fees1 != 0) {
            CORE.accumulateAsFees(poolKey, fees0, fees1);
            unchecked {
                CORE.updateSavedBalances(
                    poolKey.token0,
                    poolKey.token1,
                    PoolId.unwrap(poolId),
                    -int256(uint256(fees0)),
                    -int256(uint256(fees1))
                );
            }
```

**File:** src/extensions/MEVCapture.sol (L151-154)
```text
        setPoolState({
            poolId: poolId,
            state: createMEVCapturePoolState({_lastUpdateTime: uint32(block.timestamp), _tickLast: tick})
        });
```

**File:** src/extensions/MEVCapture.sol (L191-200)
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
```

**File:** src/extensions/MEVCapture.sol (L203-206)
```text
                setPoolState({
                    poolId: poolId,
                    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
                });
```

**File:** src/extensions/MEVCapture.sol (L212-252)
```text
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
```

**File:** src/extensions/MEVCapture.sol (L254-256)
```text
            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }
```

**File:** src/Core.sol (L254-267)
```text
                if (liquidity != 0) {
                    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
                    }
                    if (amount1 != 0) {
                        StorageSlot slot1 = slot0.next();
                        slot1.store(
                            bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
                        );
                    }
```

**File:** src/Core.sol (L436-437)
```text
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
```

**File:** src/types/position.sol (L33-51)
```text
function fees(Position memory position, FeesPerLiquidity memory feesPerLiquidityInside)
    pure
    returns (uint128, uint128)
{
    uint128 liquidity;
    uint256 difference0;
    uint256 difference1;
    assembly ("memory-safe") {
        liquidity := mload(add(position, 0x20))
        // feesPerLiquidityInsideLast is now at offset 0x40 due to extraData field
        let positionFpl := mload(add(position, 0x40))
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
    }

    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
```

**File:** test/extensions/MEVCapture.t.sol (L640-641)
```text
        advanceTime(1);
        (uint256 id2,) = createPosition(poolKey, 600_000, 800_000, 1_000_000, 2_000_000);
```

**File:** test/FullTest.sol (L258-262)
```text
    function advanceTime(uint256 by) internal returns (uint256 next) {
        require(by <= type(uint32).max, "advanceTime called with by > type(uint32).max");
        next = vm.getBlockTimestamp() + by;
        vm.warp(next);
    }
```
