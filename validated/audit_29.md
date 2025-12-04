# Audit Report

## Title
MEVCapture Intra-Block Fee Accumulation Bypass Allows Liquidity Providers to Steal Fees

## Summary
The MEVCapture extension's `handleForwardData()` function updates `lastUpdateTime` immediately after swaps but stores newly generated MEV fees in `savedBalances` without accumulating them to `feesPerLiquidity`. This creates a same-block timing window where attackers can add liquidity after swaps generate fees but before those fees are accumulated, receiving an unearned share of MEV fees when accumulation occurs in the next block. [1](#0-0) 

## Impact
**Severity**: High

Attackers can systematically steal MEV fees from legitimate liquidity providers who were active during swaps. With liquidity equal to existing pool liquidity, attackers steal ~50% of MEV fees per block; with 9x existing liquidity, they steal ~90%. This attack is repeatable every block, compounds over time, and affects all MEVCapture-enabled pools with no defense available to legitimate LPs.

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, functions `handleForwardData()` (lines 177-260), `accumulatePoolFees()` (lines 105-125), and `locked_6416899205()` (lines 127-155)

**Intended Logic:** 
MEVCapture is designed to capture additional fees based on tick movement during swaps and distribute these fees proportionally to liquidity providers who were actively providing liquidity during the swap that generated the fees. The `beforeUpdatePosition` hook's comment states "Prevents new liquidity from collecting on fees". [2](#0-1) 

**Actual Logic:**
The implementation creates a temporal desynchronization between fee generation and fee accumulation:

1. During a swap in `handleForwardData()`, if this is the first transaction in block N, the function:
   - Accumulates any old fees from previous blocks [3](#0-2) 
   - Updates `lastUpdateTime` to block N timestamp [4](#0-3) 
   - Executes the swap and calculates NEW MEV fees based on tick movement [5](#0-4) 
   - Stores these NEW fees in `savedBalances` without accumulating them [6](#0-5) 

2. When a position is added via `Core.updatePosition()` in the same block N, the `beforeUpdatePosition` hook calls `accumulatePoolFees()`, which checks if `lastUpdateTime != block.timestamp`. [7](#0-6) 
   - Since both equal block N, the condition is FALSE
   - The function returns WITHOUT calling `locked_6416899205()` to accumulate fees
   - The position's `feesPerLiquidityInsideLast` snapshot is taken BEFORE fees are accumulated [8](#0-7) 

3. In block N+1, any action triggers `accumulatePoolFees()`:
   - Now `lastUpdateTime (block N) != block.timestamp (block N+1)` is TRUE
   - `locked_6416899205()` is called, loading fees from `savedBalances` [9](#0-8) 
   - `accumulateAsFees()` distributes fees proportionally across ALL current liquidity [10](#0-9) 
   - The position added in block N receives fees generated BEFORE it was created

**Exploitation Path:**

1. **Block N, Transaction 1**: Large swap through `MEVCapture.forward()` moves ticks significantly
   - `handleForwardData()` accumulates old fees, updates `lastUpdateTime = block N`
   - Swap generates 10 ETH in MEV fees, stored in `savedBalances`
   - Fees NOT yet in `feesPerLiquidity`

2. **Block N, Transaction 2**: Attacker calls `Core.updatePosition()` to add 9x existing liquidity
   - `beforeUpdatePosition` calls `accumulatePoolFees()` 
   - Time check fails (both block N), function returns without accumulating
   - Position created with `feesPerLiquidityInsideLast` snapshot taken before fees accumulated

3. **Block N+1**: Any action triggers accumulation
   - Time check passes, `locked_6416899205()` accumulates 10 ETH across all liquidity
   - Attacker (9L liquidity) receives 9 ETH, legitimate LPs (L liquidity) receive 1 ETH
   - Attacker stole 9 ETH of fees earned by legitimate LPs during block N swap

4. **Block N+1**: Attacker removes liquidity and collects fees
   - Position fee calculation uses difference in `feesPerLiquidity` [11](#0-10) 
   - Attacker extracts unearned 9 ETH

**Security Property Broken:**
Violates the fee accounting invariant that positions should only collect fees generated while their liquidity was active in the pool. The `beforeUpdatePosition` hook's stated purpose to "prevent new liquidity from collecting on fees" is defeated by the same-block timing bypass.

## Impact Explanation

**Affected Assets**: All pools using MEVCapture extension. LP fee earnings are directly stolen by attackers exploiting position timing.

**Damage Severity**:
- Attacker can steal proportional share: with A liquidity added to existing L liquidity, attacker receives `fees * A/(L+A)`
- Adding equal liquidity (A=L): steals 50% of MEV fees from that block
- Adding 9x liquidity (A=9L): steals 90% of MEV fees
- Attack is repeatable every block with swap activity
- Cumulative loss compounds over time as attackers systematically exploit each block's fee generation
- High-volume pools with substantial MEV fees suffer greatest losses

**User Impact**: All legitimate liquidity providers in MEVCapture pools experience diluted fee earnings. Victims have no defense mechanism since the exploit occurs through normal contract operations. LPs who provided liquidity during swaps that generated fees receive only a fraction of what they earned.

## Likelihood Explanation

**Attacker Profile**: Any user with sufficient capital can execute this attack. No special permissions, privileges, or protocol roles required. Sophisticated MEV searchers and bots will automate detection and exploitation.

**Preconditions**:
1. Pool must use MEVCapture extension (standard for Ekubo pools designed to capture MEV)
2. Swaps must generate MEV fees (occurs in volatile markets with large trades)
3. Attacker needs capital for liquidity (can use flash loans to amplify without permanent commitment)
4. No special pool state required

**Execution Complexity**: Low complexity, single-block attack:
- Monitor mempool for large swaps generating MEV fees
- Submit transaction to add liquidity in same block, immediately after swap
- Wait for next block for fees to accumulate
- Collect fees and remove liquidity
- Can bundle transactions atomically or use smart contract for automation

**Economic Cost**: Only gas fees plus temporary capital lockup (capital can be removed after fee collection). Flash loans can amplify attack with minimal permanent capital.

**Frequency**: Exploitable on EVERY block with swap activity. In active pools, this means continuous exploitation potential.

**Overall Likelihood**: HIGH - Attack is simple, economically viable, automatable, and repeatable on every active block.

## Recommendation

**Primary Fix (Conditional lastUpdateTime Update):**

Modify `locked_6416899205()` to only update `lastUpdateTime` when fees are actually accumulated: [12](#0-11) 

Change the unconditional `setPoolState()` at lines 151-154 to be conditional:

```solidity
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
    // Only update lastUpdateTime when fees are actually accumulated
    setPoolState({
        poolId: poolId,
        state: createMEVCapturePoolState({_lastUpdateTime: uint32(block.timestamp), _tickLast: tick})
    });
} else {
    // When no fees to accumulate, update only tickLast, preserve lastUpdateTime
    MEVCapturePoolState oldState = getPoolState(poolId);
    setPoolState({
        poolId: poolId,
        state: createMEVCapturePoolState({_lastUpdateTime: oldState.lastUpdateTime(), _tickLast: tick})
    });
}
```

**Alternative Fix (Immediate Accumulation in handleForwardData):**

Modify `handleForwardData()` to immediately accumulate newly generated MEV fees before updating `lastUpdateTime`. After calculating new fees (lines 212-252), instead of just storing in `savedBalances`, also call `accumulateAsFees()` immediately. This ensures fees are distributed to the exact liquidity set active during the swap, with no timing window for position insertion.

**Rationale**: Both fixes eliminate the temporal gap between fee generation and accumulation that creates the exploit window. The primary fix is simpler and maintains the batching optimization intent. The alternative fix provides stronger atomicity guarantees.

## Proof of Concept

The existing test suite demonstrates the vulnerability through ABSENCE of same-block testing. The test `test_new_position_does_not_get_fees` at lines 611-650 validates the protection works ONLY when time advances between swap and position creation. [13](#0-12) 

Notice line 640 calls `advanceTime(1)` which warps to a new block before creating position 2. [14](#0-13) 

A proof of concept demonstrating the vulnerability requires:
1. Create position 1 with initial liquidity
2. Execute swap in block N generating MEV fees
3. **Without advancing time**, create position 2 in same block N
4. Advance to block N+1 and trigger fee accumulation
5. Verify position 2 incorrectly receives fees despite not being active during swap

Expected result: Position 2 receives proportional share of fees from block N, violating the intended protection.

## Notes

This vulnerability stems from an architectural decision to batch fee accumulation across blocks for gas optimization, combined with insufficient enforcement of the temporal requirement that positions should only earn fees after their creation. The `lastUpdateTime` check at line 110 creates the exploit window by preventing same-block re-accumulation.

The vulnerability is particularly severe because:
1. It defeats the explicitly stated security control ("Prevents new liquidity from collecting on fees")
2. Existing tests only validate cross-block scenarios, missing same-block timing attacks
3. The attack is deterministic, not dependent on race conditions or miner manipulation
4. Capital requirements can be minimized using flash loans
5. Automated MEV bots can systematically exploit this on every block

The fix must ensure atomicity between fee generation and distribution, eliminating any window where positions can be inserted before fees are accumulated to the liquidity providers who actually earned them.

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

**File:** src/extensions/MEVCapture.sol (L136-154)
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
        }

        setPoolState({
            poolId: poolId,
            state: createMEVCapturePoolState({_lastUpdateTime: uint32(block.timestamp), _tickLast: tick})
        });
```

**File:** src/extensions/MEVCapture.sol (L191-207)
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
            }
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
