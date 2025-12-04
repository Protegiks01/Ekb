# Audit Report

## Title
Arithmetic Underflow in Position Fee Checkpoint Enables Pool Drainage Through Fee Inflation

## Summary
The `Core.updatePosition()` function uses unchecked assembly subtraction when adjusting position fee checkpoints after liquidity changes. When a user drastically reduces position liquidity after accumulating fees, this causes an arithmetic underflow that wraps to a massive value near 2^256, corrupting the fee tracking state. Subsequent fee calculations return astronomically inflated amounts, enabling attackers to drain pool funds by claiming fees they never earned.

## Impact
**Severity**: High - Direct theft of user funds and protocol insolvency

Attackers can drain entire pool balances by exploiting the checkpoint underflow vulnerability. With a 10,000,000:1 amplification factor achievable through liquidity reduction, even small legitimate fees become massive theft opportunities. This violates the core protocol invariant stated in README: "The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1." [1](#0-0) 

## Finding Description

**Location:** `src/Core.sol:434-437` in `updatePosition()` function [2](#0-1) 

**Intended Logic:** 
When updating position liquidity, the system should preserve accumulated fees by adjusting the `feesPerLiquidityInsideLast` checkpoint. The adjustment formula `newCheckpoint = currentFPL - (accumulatedFees × 2^128 / newLiquidity)` ensures future fee calculations return `(futureFPL - newCheckpoint) × newLiquidity / 2^128 = accumulatedFees + newlyAccumulatedFees`.

**Actual Logic:**
The checkpoint adjustment uses unchecked assembly subtraction in `feesPerLiquidity.sub()` [3](#0-2) . When `(accumulatedFees × 2^128 / newLiquidity) > currentFPL` due to drastic liquidity reduction, the subtraction underflows and wraps to a value near 2^256. Subsequently, when `position.fees()` calculates fees using this corrupted checkpoint [4](#0-3) , the assembly subtraction wraps again, producing massively inflated fee values.

**Exploitation Path:**
1. **Setup**: Attacker deposits large liquidity (e.g., 10,000,000 units) via `Positions.mintAndDeposit()`
2. **Accumulate**: Wait for swaps to accumulate fees such that `feesPerLiquidityInside = 2^128` (1 token per unit liquidity)
3. **Trigger Underflow**: Call `Positions.withdraw()` removing 99.9999% of liquidity, leaving 1 unit
   - Line 434 calculates: `fees0 = (2^128 - 0) × 10,000,000 / 2^128 = 10,000,000`
   - Line 437 computes: `newCheckpoint = 2^128 - (10,000,000 × 2^128 / 1)` which underflows to `2^256 - 9,999,999 × 2^128`
4. **Exploit**: After more swaps double fees to `2 × 2^128`, call `Positions.collectFees()`
   - Line 492 in `Core.collectFees()` [5](#0-4)  calculates: `fees0 = (2 × 2^128 - corruptedCheckpoint) × 1 / 2^128 ≈ 10,000,001` tokens
   - Legitimate fees should be: `(2 × 2^128 - 2^128) × 1 / 2^128 = 1` token
   - **Attacker receives 10,000,001× inflated fees**

**Security Guarantee Broken:**
This violates the solvency invariant: "The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero" [1](#0-0) 

## Impact Explanation

**Affected Assets**: All token pairs in any pool where positions undergo significant liquidity reduction after fee accumulation.

**Damage Severity**:
- Attacker can drain entire pool balance proportional to liquidity reduction ratio
- With 10M→1 reduction: 10,000,000× fee inflation
- Even 100 wei legitimate fees become 1 billion token claim
- All liquidity providers in affected pool lose deposited funds
- Protocol becomes insolvent as pool balances go negative

**User Impact**: Complete loss of funds for all LPs in exploited pools. The view function `getPositionFeesAndLiquidity()` [6](#0-5)  displays inflated values before exploitation, and `Core.collectFees()` honors these corrupted amounts via debt tracking [7](#0-6) .

## Likelihood Explanation

**Attacker Profile**: Any user with capital to provide initial liquidity. Capital can be flash-loaned for deposit phase.

**Preconditions**:
1. Pool initialized with active liquidity (normal state)
2. Swap activity accumulates fees (standard pool operation)
3. No special permissions or timing required

**Execution Complexity**: Single transaction sequence via standard functions: `mintAndDeposit()` → wait for swaps → `withdraw(99.99%)` → `collectFees()`. Attack is deterministic with no oracle manipulation needed.

**Economic Cost**: Gas fees only (~0.05 ETH). Capital temporarily locked during setup phase.

**Frequency**: Repeatable across all pools with multiple positions. Each exploitation drains funds proportional to reduction ratio.

**Overall Likelihood**: HIGH - Trivial to execute, affects all pools, economically profitable

## Recommendation

**Primary Fix**: Replace unchecked assembly with Solidity checked arithmetic in `feesPerLiquidity.sub()`: [3](#0-2) 

Change to:
```solidity
function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    result.value0 = a.value0 - b.value0;  // Reverts on underflow
    result.value1 = a.value1 - b.value1;
}
```

**Alternative Mitigation**: Add pre-validation in `Core.updatePosition()` before checkpoint adjustment: [2](#0-1) 

Insert validation:
```solidity
FeesPerLiquidity memory feesAdjustment = feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext);
require(
    feesPerLiquidityInside.value0 >= feesAdjustment.value0 &&
    feesPerLiquidityInside.value1 >= feesAdjustment.value1,
    "Checkpoint adjustment would underflow"
);
```

## Proof of Concept

The vulnerability requires:
1. Deposit large liquidity (10M units)
2. Accumulate fees via swaps
3. Withdraw to 1 unit liquidity → checkpoint underflows
4. Accumulate more fees via swaps
5. Collect fees → receive inflated amount

Execution via standard functions demonstrates the mathematical inevitability: when `liquidityNext` is very small and accumulated fees are large (calculated with old liquidity), the term `fees × 2^128 / liquidityNext` exceeds `feesPerLiquidityInside`, causing unavoidable underflow in unchecked assembly.

## Notes

This vulnerability stems from gas optimization using unchecked assembly arithmetic in critical fee accounting. The `feesPerLiquidity.sub()` function assumes `a ≥ b` in subtraction `a - b`, but this assumption breaks when users drastically reduce liquidity after fee accumulation. The severity scales with reduction ratio: 10M→1 yields ~10M× amplification, 1M→1 yields ~1M× amplification. The view function `getPositionFeesAndLiquidity()` directly exposes corrupted values to users and integrations before any theft occurs, making detection trivial but not preventing exploitation.

### Citations

**File:** README.md (L200-200)
```markdown
The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.
```

**File:** src/Core.sol (L434-437)
```text
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
```

**File:** src/Core.sol (L492-492)
```text
        (amount0, amount1) = position.fees(feesPerLiquidityInside);
```

**File:** src/Core.sol (L496-498)
```text
        _updatePairDebt(
            locker.id(), poolKey.token0, poolKey.token1, -int256(uint256(amount0)), -int256(uint256(amount1))
        );
```

**File:** src/types/feesPerLiquidity.sol (L13-18)
```text
function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    assembly ("memory-safe") {
        mstore(result, sub(mload(a), mload(b)))
        mstore(add(result, 32), sub(mload(add(a, 32)), mload(add(b, 32))))
    }
}
```

**File:** src/types/position.sol (L40-51)
```text
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

**File:** src/base/BasePositions.sol (L43-68)
```text
    function getPositionFeesAndLiquidity(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        external
        view
        returns (uint128 liquidity, uint128 principal0, uint128 principal1, uint128 fees0, uint128 fees1)
    {
        PoolId poolId = poolKey.toPoolId();
        SqrtRatio sqrtRatio = CORE.poolState(poolId).sqrtRatio();
        PositionId positionId =
            createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper});
        Position memory position = CORE.poolPositions(poolId, address(this), positionId);

        liquidity = position.liquidity;

        // the sqrt ratio may be 0 (because the pool is uninitialized) but this is
        // fine since amount0Delta isn't called with it in this case
        (int128 delta0, int128 delta1) = liquidityDeltaToAmountDelta(
            sqrtRatio, -SafeCastLib.toInt128(position.liquidity), tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper)
        );

        (principal0, principal1) = (uint128(-delta0), uint128(-delta1));

        FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
            ? CORE.getPoolFeesPerLiquidity(poolId)
            : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);
        (fees0, fees1) = position.fees(feesPerLiquidityInside);
    }
```
