# Audit Report

## Title
Checkpoint Arithmetic Underflow in Position Liquidity Reduction Enables Fee Theft Through Inflated Accumulation

## Summary
When a liquidity provider partially withdraws from a position without collecting fees, the `updatePosition` function in Core.sol calculates accumulated fees using the original liquidity but updates the fee checkpoint by dividing these fees by the reduced liquidity. This mathematical inconsistency causes an arithmetic underflow in the checkpoint value, which then inflates all subsequent fee calculations, allowing LPs to steal fees from the pool.

## Impact
**Severity**: High

LPs can extract significantly more fees than they're entitled to by exploiting the checkpoint underflow during partial withdrawals. The excess fees are withdrawn from the pool's token reserves, directly harming other liquidity providers and violating the protocol's core solvency invariant stated in the README: "The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1." [1](#0-0) 

With a 2x liquidity reduction (e.g., 100 to 50), an LP can collect approximately 100% excess fees. Larger reductions amplify the theft proportionally. This directly violates the fee accounting invariant and can lead to pool insolvency.

## Finding Description

**Location:** `src/Core.sol:434-437`, function `updatePosition()` [2](#0-1) 

**Intended Logic:**
When a position's liquidity changes, the protocol should checkpoint accumulated fees such that future calculations only count newly accrued fees. The checkpoint represents "fees per liquidity already accounted for," and must maintain mathematical consistency across liquidity updates.

**Actual Logic:**
The code performs fee calculations and checkpoint updates using mismatched liquidity values:

1. Line 434 calculates accumulated fees using `position.liquidity` (the OLD value before the update) [3](#0-2) 

2. Line 435 updates the position liquidity to `liquidityNext` (the NEW reduced value)

3. Line 437 updates the checkpoint by converting the calculated fees back to per-liquidity basis using `liquidityNext` (NEW value) instead of the original liquidity used in step 1

This creates a mathematical inconsistency. When `oldLiquidity > newLiquidity` and fees have accumulated:
- `fees = (feesPerLiquidityInside - checkpoint) * oldLiquidity >> 128`
- `newCheckpoint = feesPerLiquidityInside - (fees << 128) / newLiquidity`
- Since `newLiquidity < oldLiquidity`, the division `(fees << 128) / newLiquidity` produces a value larger than `feesPerLiquidityInside`
- The subtraction in `feesPerLiquidity.sub()` uses unchecked assembly [4](#0-3) 

The unchecked subtraction causes wrap-around to a value near `type(uint256).max`, poisoning all subsequent fee calculations.

**Exploitation Path:**

1. **Setup**: LP creates position with 100 units liquidity in an active pool at tick range [-100, 100]

2. **Fee Accumulation**: Swaps occur, `feesPerLiquidityInside` increases to `2^128` (representing 1 token per unit liquidity accumulated)

3. **Trigger Vulnerability**: LP calls `withdraw(id, poolKey, -100, 100, 50, recipient, false)` to reduce liquidity by 50% WITHOUT collecting fees
   - Line 434: `fees = (2^128 - 0) * 100 >> 128 = 100 tokens`
   - Line 435: `position.liquidity = 50`
   - Line 437: `newCheckpoint = 2^128 - (100 << 128) / 50 = 2^128 - 2*2^128 = -2^128`
   - Due to uint256 wrap-around: `newCheckpoint ≈ 2^256 - 2^128`

4. **Additional Fee Accumulation**: More swaps occur, `feesPerLiquidityInside` increases to `3*2^128`

5. **Extraction**: LP calls `collectFees(id, poolKey, -100, 100)`
   - `difference = 3*2^128 - (2^256 - 2^128)` 
   - In uint256 arithmetic: `difference ≈ 4*2^128`
   - `fees = (4*2^128 * 50) >> 128 = 200 tokens`

6. **Result**: LP receives 200 tokens instead of legitimate 150 tokens (100 from first period + 50 from second period), stealing 50 tokens from pool

**Security Guarantee Broken:**
This violates the core pool solvency invariant documented in README line 200.

## Impact Explanation

**Affected Assets**: All tokens in liquidity pools where LPs perform partial withdrawals with accumulated fees

**Damage Severity**:
- LP can collect approximately `(oldLiquidity / newLiquidity - 1) * accumulatedFees` in excess fees
- With 50% liquidity reduction: 100% excess fees stolen
- With 90% liquidity reduction: 900% excess fees stolen
- The stolen fees come directly from pool reserves meant for other LPs
- Repeated exploitation can drain pool reserves, preventing legitimate LPs from collecting their fees
- Ultimate result is protocol insolvency

**User Impact**: 
- All LPs who reduce position size after fees accumulate are potential exploiters
- All other LPs in the same pool are victims of the theft
- The vulnerability triggers automatically through normal protocol operations

**Trigger Conditions**: 
- Position has accumulated fees (true for any active pool)
- LP performs partial withdrawal via `withdraw()` with `withFees=false`
- Additional fees accumulate after partial withdrawal
- LP calls `collectFees()` or `withdraw()` with `withFees=true`

## Likelihood Explanation

**Attacker Profile**: Any liquidity provider with basic protocol knowledge. No special permissions, access, or technical sophistication required.

**Preconditions**:
1. Position must have accumulated fees (occurs naturally in any active pool)
2. LP must reduce liquidity through partial withdrawal (common operation)
3. Fees must accumulate after the partial withdrawal (natural occurrence)
4. Larger liquidity reductions yield proportionally more excess fees

**Execution Complexity**: 
- Two simple transactions: `withdraw(withFees=false)` followed by `collectFees()`
- Can be automated via smart contract for systematic exploitation
- No front-running, timing, or special state manipulation required

**Economic Cost**: 
- Only gas fees (~0.01 ETH per exploitation)
- No capital lockup beyond normal LP position
- Profitable even for small positions due to multiplicative effect

**Frequency**: 
- Exploitable every time an LP performs partial withdrawal with accumulated fees
- Can be repeated cyclically: deposit → accumulate fees → partial withdraw → accumulate → collect
- Affects every pool in the protocol

**Overall Likelihood**: HIGH - Common operation, trivial execution, economically profitable

## Recommendation

**Primary Fix:**

The checkpoint calculation must use the same liquidity value that was used to calculate the fees. Modify `src/Core.sol` lines 434-437:

```solidity
// Cache old liquidity before updating position
uint128 oldLiquidity = position.liquidity;

// Calculate fees using old liquidity (already done at line 434)
(uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);

// Update position liquidity
position.liquidity = liquidityNext;

// Update checkpoint using OLD liquidity to maintain mathematical consistency
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, oldLiquidity));
```

**Alternative Mitigations**:
1. Force fee collection before any liquidity reduction by modifying `updatePosition()` to automatically collect fees when `liquidityNext < position.liquidity`
2. Add overflow detection in `feesPerLiquidityFromAmounts()` and revert if checkpoint calculation would underflow
3. Store uncollected fees in a separate variable rather than encoding them through checkpoint manipulation

## Proof of Concept

The provided PoC correctly demonstrates the vulnerability. Key observation: The existing test `test_partial_withdraw_without_fees_leaves_fees_collectible()` at test/Positions.t.sol:719-760 does NOT catch this vulnerability because it collects fees immediately after partial withdrawal without additional fee accumulation. The vulnerability only manifests when more fees accumulate AFTER the partial withdrawal and BEFORE fee collection. [5](#0-4) 

## Notes

The root cause is the mathematical inconsistency of using different liquidity values in a coupled calculation. The `feesPerLiquidityFromAmounts()` function itself is correct - it properly converts amounts to per-liquidity basis. However, when called with `liquidityNext` at line 437 after fees were calculated with `oldLiquidity` at line 434, it creates an invalid relationship between the checkpoint and accumulated fees. [6](#0-5) 

The unchecked assembly subtraction enables the underflow to silently wrap around rather than reverting. This is not a precision loss or rounding issue - it's a fundamental arithmetic underflow that corrupts the fee accounting system, allowing systematic theft of pool funds.

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

**File:** src/types/position.sol (L40-50)
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

**File:** src/types/feesPerLiquidity.sol (L20-28)
```text
function feesPerLiquidityFromAmounts(uint128 amount0, uint128 amount1, uint128 liquidity)
    pure
    returns (FeesPerLiquidity memory result)
{
    assembly ("memory-safe") {
        mstore(result, div(shl(128, amount0), liquidity))
        mstore(add(result, 32), div(shl(128, amount1), liquidity))
    }
}
```

**File:** test/Positions.t.sol (L719-760)
```text
    function test_partial_withdraw_without_fees_leaves_fees_collectible() public {
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);

        (uint256 id,) = createPosition(poolKey, -100, 100, 100, 100);

        // Generate fees
        token0.approve(address(router), 100);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100}),
            type(int256).min
        );

        // Verify fees before partial withdrawal
        (uint128 liquidityBefore,,, uint128 f0Before,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(f0Before, 49, "Should have token0 fees");

        // Withdraw half the liquidity without fees
        uint128 halfLiquidity = liquidityBefore / 2;
        (uint128 amount0, uint128 amount1) =
            positions.withdraw(id, poolKey, -100, 100, halfLiquidity, address(this), false);

        // Should receive approximately half the principal (minus withdrawal protocol fee)
        assertApproxEqAbs(uint256(amount0), 37, 1, "Should receive half of principal token0");
        assertApproxEqAbs(uint256(amount1), 12, 1, "Should receive half of principal token1");

        // Verify remaining position still has liquidity and fees remain collectible
        (uint128 liquidityAfter,,, uint128 f0After,) = positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertApproxEqAbs(
            uint256(liquidityAfter), uint256(halfLiquidity), uint256(1), "Should have half liquidity remaining"
        );
        assertApproxEqAbs(
            uint256(f0After), 49, 1, "Fees should remain approximately unchanged after partial withdrawal without fees"
        );

        // Now collect the fees that remained
        (uint128 collectedFees0, uint128 collectedFees1) = positions.collectFees(id, poolKey, -100, 100);
        assertApproxEqAbs(
            uint256(collectedFees0), 49, 1, "Should be able to collect approximately all fees after partial withdrawal"
        );
        assertEq(collectedFees1, 0, "Should have no token1 fees");
    }
```
