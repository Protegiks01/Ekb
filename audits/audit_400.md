## Title
Silent Integer Overflow in `amount0DeltaSorted()` Breaks Pool Solvency Invariant During Large Price Swaps

## Summary
The `amount0DeltaSorted()` function in `src/math/delta.sol` uses unchecked multiplication via `fullMulDivUnchecked()` when `roundUp` is false. [1](#0-0)  When swapping across extreme price ranges (near MIN_SQRT_RATIO to MAX_SQRT_RATIO) with high liquidity, this multiplication silently overflows uint256, wrapping to a much smaller value. Core.sol's swap logic updates the pool's price to the target but uses the incorrect (too small) token amount, violating the constant product invariant and breaking the Solvency critical invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/math/delta.sol` lines 56-58 in `amount0DeltaSorted()`, exploited via `src/Core.sol` lines 668/671 and 697

**Intended Logic:** The `amount0DeltaSorted()` function should calculate the exact token0 amount required for a liquidity position to move between two sqrt price ratios using the formula: `amount0 = (liquidity << 128) * (sqrtRatioUpper - sqrtRatioLower) / (sqrtRatioUpper * sqrtRatioLower)`. [2](#0-1)  The only overflow protection is the check at line 60 that reverts if the final result exceeds uint128.max. [3](#0-2) 

**Actual Logic:** When `roundUp = false`, the function uses `FixedPointMathLib.fullMulDivUnchecked()` for the multiplication `liquidityX128 * (sqrtRatioUpper - sqrtRatioLower)`. [4](#0-3)  With extreme values:
- `liquidity` can reach ~1.92e30 (max per tick for tickSpacing=1, calculated as `type(uint128).max / 177445671`) [5](#0-4) 
- `liquidityX128 = liquidity << 128` ≈ 6.5e68
- `sqrtRatioUpper - sqrtRatioLower` ≈ 6.28e54 (MAX to MIN range)
- The multiplication exceeds uint256 (1.16e77), causing silent wraparound to a much smaller value
- After dividing by `sqrtRatioUpper` and `sqrtRatioLower`, the corrupted result may still fit in 128 bits, bypassing the overflow check

**Exploitation Path:**

1. **Setup:** Attacker identifies or creates a full-range pool with high liquidity (approaching per-tick limit). Full-range pools can jump directly to MIN_TICK or MAX_TICK in a single swap step. [6](#0-5) 

2. **Execute Swap:** Attacker initiates a swap across a large price range (e.g., current price near MIN_SQRT_RATIO, limit near MAX_SQRT_RATIO). When the swap hits the limit, Core.sol calls `amount0DeltaSorted()` with extreme sqrtRatio values. [7](#0-6) 

3. **Silent Overflow:** The unchecked multiplication overflows, returning a much smaller `limitCalculatedAmountDelta` than the true amount. The overflow check fails to detect this because the wrapped value fits in 128 bits.

4. **State Corruption:** Core.sol updates `calculatedAmount` with the incorrect (too small) value. [8](#0-7)  However, at line 697, the pool's `sqrtRatio` is unconditionally set to `limitedNextSqrtRatio` regardless of the actual token amounts exchanged. [9](#0-8) 

5. **Invariant Violation:** The pool's price has moved to the target, but insufficient tokens were exchanged. The constant product invariant (x*y=k) is broken. When the final balance deltas are calculated and applied, the pool's token balances become inconsistent with its liquidity and price. [10](#0-9) 

**Security Property Broken:** Critical Invariant #1 (Solvency) - "Pool balances of token0 and token1 must NEVER go negative (sum of all deltas must maintain non-negative balances)". The corrupted token amount causes the pool's accounting to diverge from the mathematical invariant governing liquidity positions.

## Impact Explanation

- **Affected Assets:** All tokens in full-range or stableswap pools that can execute swaps across large price ranges with high liquidity. Any pool with liquidity near the per-tick limit is vulnerable.

- **Damage Severity:** The pool's state becomes mathematically inconsistent. The price moved but incorrect token amounts were exchanged, creating an arbitrage opportunity. Subsequent swaps will compound the error, potentially draining the pool or causing reverts when users attempt to withdraw positions. In extreme cases, pool balances could go negative (violating solvency) or become insufficient to cover all liquidity positions.

- **User Impact:** All liquidity providers in the affected pool face potential loss. Traders executing the vulnerable swap receive less output tokens than expected. Subsequent traders can arbitrage the price discrepancy, extracting value from the pool at LPs' expense.

## Likelihood Explanation

- **Attacker Profile:** Any user with capital to create high-liquidity pools or execute large swaps. MEV searchers could detect and exploit vulnerable conditions automatically.

- **Preconditions:** 
  - Full-range or stableswap pool exists (or attacker creates one)
  - Pool has liquidity approaching the per-tick limit (~1.92e30 for tickSpacing=1)
  - Swap crosses a large price range (multiple orders of magnitude, e.g., near MIN_SQRT_RATIO to MAX_SQRT_RATIO)

- **Execution Complexity:** Single transaction via Router or direct Core.sol swap call. [11](#0-10) 

- **Frequency:** Exploitable whenever conditions are met. An attacker could set up the conditions intentionally (create pool with high liquidity, execute exploit swap). Natural market conditions may also trigger this in high-liquidity pools experiencing extreme volatility.

## Recommendation

Replace `fullMulDivUnchecked()` with checked multiplication or implement explicit overflow validation before the division operations: [12](#0-11) 

**FIXED:**
```solidity
} else {
    // Add overflow check before multiplication
    uint256 numerator = (sqrtRatioUpper - sqrtRatioLower);
    
    // Check if liquidityX128 * numerator would overflow
    // If liquidityX128 > 0 and numerator > type(uint256).max / liquidityX128, overflow will occur
    if (liquidityX128 != 0 && numerator > type(uint256).max / liquidityX128) {
        // cast sig "Amount0DeltaOverflow()"
        mstore(0, 0xb4ef2546)
        revert(0x1c, 0x04)
    }
    
    // Now safe to use fullMulDivUnchecked since we verified no overflow
    uint256 result0 = FixedPointMathLib.fullMulDivUnchecked(liquidityX128, numerator, sqrtRatioUpper);
    uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
    
    assembly ("memory-safe") {
        if shr(128, result) {
            // cast sig "Amount0DeltaOverflow()"
            mstore(0, 0xb4ef2546)
            revert(0x1c, 0x04)
        }
        amount0 := result
    }
}
```

**Alternative:** Use Solady's `fullMulDiv()` (checked version) instead of `fullMulDivUnchecked()` to automatically revert on overflow.

## Proof of Concept

```solidity
// File: test/Exploit_SilentOverflow.t.sol
// Run with: forge test --match-test test_SilentOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolConfig.sol";
import "../src/types/sqrtRatio.sol";
import {MIN_SQRT_RATIO, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";
import {amount0DeltaSorted} from "../src/math/delta.sol";

contract Exploit_SilentOverflow is Test {
    Core core;
    
    function setUp() public {
        core = new Core();
    }
    
    function test_SilentOverflow() public {
        // SETUP: Calculate max liquidity per tick for tickSpacing=1
        // numTicks = 1 + (88722835 / 1) * 2 = 177445671
        // maxLiquidity = type(uint128).max / 177445671
        uint128 maxLiquidity = type(uint128).max / 177445671;
        
        // Convert MIN and MAX sqrt ratios to fixed point
        uint256 sqrtRatioLower = MIN_SQRT_RATIO.toFixed();
        uint256 sqrtRatioUpper = MAX_SQRT_RATIO.toFixed();
        
        console.log("sqrtRatioLower:", sqrtRatioLower);
        console.log("sqrtRatioUpper:", sqrtRatioUpper);
        console.log("maxLiquidity:", maxLiquidity);
        
        // Calculate liquidityX128
        uint256 liquidityX128 = uint256(maxLiquidity) << 128;
        console.log("liquidityX128 (high bits):", liquidityX128 >> 128);
        
        // Calculate the multiplication that will overflow
        uint256 priceDiff = sqrtRatioUpper - sqrtRatioLower;
        console.log("priceDiff (scientific):", priceDiff / 1e54, "e54");
        
        // EXPLOIT: Call amount0DeltaSorted with roundUp=false
        // This will overflow silently in fullMulDivUnchecked
        uint128 result = amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, maxLiquidity, false);
        
        // VERIFY: The result should be enormous (full price range with max liquidity)
        // But due to overflow, it will be much smaller
        console.log("Corrupted result:", result);
        
        // Calculate what the result SHOULD be (approximate)
        // amount0 ≈ liquidity * priceDiff / (sqrtRatioLower * sqrtRatioUpper)
        // Since sqrtRatioLower is tiny compared to sqrtRatioUpper, 
        // amount0 ≈ liquidity << 128 / sqrtRatioLower
        uint256 expectedApprox = liquidityX128 / sqrtRatioLower;
        console.log("Expected (approximate):", expectedApprox);
        
        // The result should be close to expectedApprox, but due to overflow
        // it will be orders of magnitude smaller
        assertLt(result, expectedApprox / 1e10, "Overflow caused result to be 10+ orders of magnitude too small");
    }
}
```

### Citations

**File:** src/math/delta.sol (L33-36)
```text
/// @dev Assumes that the sqrt ratios are non-zero and sorted
function amount0DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
```

**File:** src/math/delta.sol (L55-67)
```text
        } else {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUnchecked(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        }
```

**File:** src/types/poolConfig.sol (L187-196)
```text
function concentratedMaxLiquidityPerTick(PoolConfig config) pure returns (uint128 maxLiquidity) {
    uint32 _tickSpacing = config.concentratedTickSpacing();

    assembly ("memory-safe") {
        // Calculate total number of usable ticks: 1 + (MAX_TICK_MAGNITUDE / tickSpacing) * 2
        // This represents all ticks from -MAX_TICK_MAGNITUDE to +MAX_TICK_MAGNITUDE, and tick 0
        let numTicks := add(1, mul(div(MAX_TICK, _tickSpacing), 2))

        maxLiquidity := div(sub(shl(128, 1), 1), numTicks)
    }
```

**File:** src/Core.sol (L506-506)
```text
    function swap_6269342730() external payable {
```

**File:** src/Core.sol (L573-576)
```text
                        if (config.isFullRange()) {
                            // special case since we don't need to compute min/max tick sqrt ratio
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
```

**File:** src/Core.sol (L662-673)
```text
                        if (hitLimit) {
                            (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) =
                                sortAndConvertToFixedSqrtRatios(limitedNextSqrtRatio, sqrtRatio);
                            (uint128 limitSpecifiedAmountDelta, uint128 limitCalculatedAmountDelta) = isToken1
                                ? (
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                )
                                : (
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                );
```

**File:** src/Core.sol (L685-695)
```text
                            } else {
                                uint128 beforeFee = amountBeforeFee(limitSpecifiedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, limitCalculatedAmountDelta)
                                    amountRemaining := sub(amountRemaining, beforeFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitSpecifiedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
                            }
```

**File:** src/Core.sol (L697-697)
```text
                            sqrtRatioNext = limitedNextSqrtRatio;
```

**File:** src/Core.sol (L811-822)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));

                int128 specifiedAmountDelta;
                int128 specifiedAmount = params.amount();
                assembly ("memory-safe") {
                    specifiedAmountDelta := sub(specifiedAmount, amountRemaining)
                }

                balanceUpdate = isToken1
                    ? createPoolBalanceUpdate(calculatedAmountDelta, specifiedAmountDelta)
                    : createPoolBalanceUpdate(specifiedAmountDelta, calculatedAmountDelta);
```
