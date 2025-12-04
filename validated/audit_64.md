# Audit Report

## Title
Fee Calculation Overflow Causes Permanent Position Lock Due to Unchecked Fee Accumulation and Checked uint128 Cast

## Summary
The Ekubo protocol accumulates fees using unchecked arithmetic with wraparound semantics throughout its fee tracking system, but calculates position fees using a checked `uint128()` cast. This mismatch causes the cast to revert when `(feesPerLiquidityDifference * liquidity) >> 128` exceeds `type(uint128).max`, permanently locking users from collecting fees or partially withdrawing their positions.

## Impact
**Severity**: High

Users suffer permanent loss of accumulated fees. When fee values grow large (particularly at extreme ticks with low liquidity), users cannot collect any fees or partially withdraw liquidity. They can only fully withdraw by forfeiting ALL accumulated fees, constituting direct loss of user funds that violates the protocol's core invariant that positions must be withdrawable with fees at any time.

## Finding Description

**Location:** `src/types/position.sol:48-50`, function `fees()`

**Intended Logic:** 
According to the code documentation, "if the computed fees overflow the uint128 type, it will return only the lower 128 bits." [1](#0-0) 

**Actual Logic:**
In Solidity 0.8+, the `uint128()` cast includes overflow checking by default and will revert (not truncate) if the value exceeds `type(uint128).max`. The fee calculation multiplies potentially large wraparound values without proper bounds checking. [2](#0-1) 

**Exploitation Path:**

1. **Fee Accumulation (Unchecked)**: Fees accumulate unbounded in global `fees_per_liquidity` using unchecked arithmetic that allows wraparound. The accumulation adds `(feeAmount << 128) / liquidity` to the global fee tracker within an unchecked block. [3](#0-2) 

2. **Tick Updates (Unchecked Wraparound)**: When ticks are crossed during swaps (which occurs within a large unchecked block starting at line 507), tick fees are updated with wraparound subtraction operations that can produce very large wrapped values. [4](#0-3) 

3. **Fees Inside Calculation (Unchecked)**: The fees inside a position's range are calculated using unchecked wraparound arithmetic through operations like `global0 - upper0 - lower0`, which can produce extremely large values when operands wrap. [5](#0-4) 

4. **Position Update Triggers Revert**: When users attempt to collect fees or partially withdraw, `updatePosition()` calls `position.fees()` at line 434, which reverts when the checked cast fails. [6](#0-5) 

The `collectFees()` function also calls `position.fees()` and will revert identically. [7](#0-6) 

**Security Property Broken:** 
The protocol violates the invariant that all positions must be withdrawable at any time. Users cannot collect fees or partially withdraw, and are forced to forfeit accumulated fees via full withdrawal. [8](#0-7) 

## Impact Explanation

**Affected Assets**: All liquidity positions where `(feesPerLiquidityDifference * liquidity) >> 128 > type(uint128).max`

**Damage Severity**:
- Users **cannot collect any fees** - `collectFees()` reverts when calling `position.fees()`
- Users **cannot partially withdraw** liquidity - `updatePosition()` with `liquidityNext != 0` reverts when calling `position.fees()`
- Users can only **fully withdraw** by setting `liquidityNext = 0`, which bypasses the `position.fees()` call but resets accumulated fees to zero, forfeiting all earned fees
- This constitutes direct and permanent loss of user funds (forfeited fees)

**User Impact**: Any user with positions at extreme ticks (especially near MAX_TICK/MIN_TICK) or in pools with high fee accumulation over time. Most likely to affect long-lived positions in active pools.

**Trigger Conditions**: Occurs naturally through normal protocol usage - no attacker action required.

## Likelihood Explanation

**Attacker Profile**: Not an active attack - this is a design flaw that naturally occurs as fees accumulate through normal protocol operation.

**Preconditions**:
1. Pool has significant swap activity generating fees
2. Position exists with large liquidity amount
3. Fees per liquidity accumulate to large values (accelerated at extreme ticks with low liquidity)
4. Time passes with multiple tick crossings using wraparound arithmetic

**Execution Complexity**: Occurs naturally through normal protocol usage; no special exploitation needed.

**Economic Cost**: No cost - happens automatically as protocol operates.

**Frequency**: Increasingly likely over time as fees accumulate; inevitable for long-lived positions at extreme ticks.

**Overall Likelihood**: MEDIUM to HIGH - Guaranteed to occur eventually for positions at extreme ticks, probable for any long-lived position in active pools.

## Recommendation

**Primary Fix:**
Wrap the `uint128()` casts in an `unchecked` block to match the documented behavior and maintain consistency with the protocol's unchecked fee tracking system:

```solidity
// In src/types/position.sol, function fees, lines 48-50:

// CURRENT (vulnerable):
return (
    uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
    uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
);

// FIXED:
unchecked {
    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
}
```

**Alternative Fix:**
Clamp to maximum value instead of truncating:
```solidity
return (
    uint128(min(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128), type(uint128).max)),
    uint128(min(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128), type(uint128).max))
);
```

## Proof of Concept

The vulnerability can be demonstrated mathematically:

```solidity
// If difference ≈ 2^200 (from wraparound) and liquidity ≈ 2^127:
// (2^200 * 2^127) >> 128 = 2^199
// This exceeds type(uint128).max = 2^128 - 1
// Therefore uint128() cast reverts in Solidity 0.8+

uint256 difference = 2**200;
uint128 liquidity = type(uint128).max / 2;
uint256 result = (difference * liquidity) >> 128;
// result ≈ 2^199, which is >> type(uint128).max
// uint128(result) will revert
```

The PoC demonstrates that when wraparound arithmetic produces large difference values (which is possible through the unchecked operations in fee accumulation and tick crossing), multiplying by large liquidity amounts produces results that exceed `uint128.max`, causing the checked cast to revert.

## Notes

This vulnerability exists due to a mismatch between Solidity 0.8+'s default checked arithmetic for explicit type conversions and the protocol's intentional use of unchecked wraparound arithmetic throughout its fee tracking system. The code comment explicitly states the intent to truncate overflows by returning "only the lower 128 bits," but the implementation reverts instead. This breaks the protocol's fee accounting model and forces users to forfeit earned fees to recover their liquidity.

### Citations

**File:** src/types/position.sol (L27-28)
```text
///      Note: if the computed fees overflow the uint128 type, it will return only the lower 128 bits. It is assumed that accumulated
///      fees will never exceed type(uint128).max.
```

**File:** src/types/position.sol (L48-51)
```text
    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
```

**File:** src/Core.sol (L197-215)
```text
        unchecked {
            if (tick < tickLower) {
                feesPerLiquidityInside.value0 = lower0 - upper0;
                feesPerLiquidityInside.value1 = lower1 - upper1;
            } else if (tick < tickUpper) {
                uint256 global0;
                uint256 global1;
                {
                    (bytes32 g0, bytes32 g1) = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).loadTwo();
                    (global0, global1) = (uint256(g0), uint256(g1));
                }

                feesPerLiquidityInside.value0 = global0 - upper0 - lower0;
                feesPerLiquidityInside.value1 = global1 - upper1 - lower1;
            } else {
                feesPerLiquidityInside.value0 = upper0 - lower0;
                feesPerLiquidityInside.value1 = upper1 - lower1;
            }
        }
```

**File:** src/Core.sol (L253-269)
```text
            unchecked {
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
                }
            }
```

**File:** src/Core.sol (L430-432)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
```

**File:** src/Core.sol (L434-437)
```text
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
```

**File:** src/Core.sol (L462-495)
```text
    /// @inheritdoc ICore
    function collectFees(PoolKey memory poolKey, PositionId positionId)
        external
        returns (uint128 amount0, uint128 amount1)
    {
        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension()).maybeCallBeforeCollectFees(locker, poolKey, positionId);

        PoolId poolId = poolKey.toPoolId();

        Position storage position;
        StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
        assembly ("memory-safe") {
            position.slot := positionSlot
        }

        FeesPerLiquidity memory feesPerLiquidityInside;
        if (poolKey.config.isStableswap()) {
            // Stableswap pools: use global fees per liquidity
            StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
            feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
            feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
        } else {
            // Concentrated pools: calculate fees per liquidity inside the position bounds
            feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                poolId, readPoolState(poolId).tick(), positionId.tickLower(), positionId.tickUpper()
            );
        }

        (amount0, amount1) = position.fees(feesPerLiquidityInside);

        position.feesPerLiquidityInsideLast = feesPerLiquidityInside;

```

**File:** src/Core.sol (L786-798)
```text
                                tickFplFirstSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplSecondSlot.load()))
                                );
                            } else {
                                tickFplFirstSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplSecondSlot.load()))
                                );
```
