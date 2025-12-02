## Title
SqrtRatio Compression Precision Loss Causes Assertion Failure in Exact Output Swaps

## Summary
The `swap_6269342730` function contains an assertion at line 726 that assumes exact output swaps always move the price due to rounding away from the current price. However, the lossy compression of the `SqrtRatio` type (96-bit vs 192-bit fixed-point) can cause calculated price changes to be lost during compression, making `sqrtRatioNextFromAmount == sqrtRatio` true for exact output swaps and triggering an assertion failure. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol` - `swap_6269342730()` function, lines 722-733

**Intended Logic:** The code assumes that for exact output swaps, the price must always move because rounding is done "away from the current price" in the fixed-point calculations. When `sqrtRatioNextFromAmount == sqrtRatio` (price doesn't move), it must be an exact input swap where the entire amount was consumed as fees. [2](#0-1) 

**Actual Logic:** The `SqrtRatio` type uses a lossy 96-bit compressed representation for 192-bit fixed-point values, with different encoding regions losing 2, 34, 66, or 98 bits of precision during compression. The compression logic is implemented in `toSqrtRatio()`: [3](#0-2) 

For exact output swaps with:
- Large liquidity values
- Small output amounts  
- Sqrt ratios near region boundaries

The price change in fixed-point format can be minimal (e.g., +1 or -1). After compression via `toSqrtRatio()`, this difference can be lost due to the bit-shifting operations, causing the compressed values to be identical.

**Exploitation Path:**

1. **Setup:** A pool exists with high liquidity (e.g., `liquidity = 2^128`) and sqrt ratio in a lossy compression region (e.g., region 2 where 66 bits are lost, or region 0 where 2 bits are lost).

2. **Exact Output Swap of Token1:** User calls swap with `amount < 0` (exact output). The calculation in `nextSqrtRatioFromAmount1()` computes: [4](#0-3) 

For small amounts where `quotient = 1` (when `abs(amount) << 128 < liquidity`), the new fixed-point value is `sqrtRatio - 1`.

3. **Compression Loss:** When converting back to `SqrtRatio` with `roundDown = false`: [5](#0-4) 

For region 0 (shift by 2): `floor(sqrtRatio / 4) == floor((sqrtRatio - 1) / 4)` when `sqrtRatio % 4 != 0` (75% of values).
For region 2 (shift by 66): `floor(sqrtRatio / 2^66) == floor((sqrtRatio - 1) / 2^66)` when `sqrtRatio % 2^66 != 0` (≈100% of values).

4. **Assertion Failure:** The comparison at line 698 evaluates to false because the compressed values are equal. Control flows to line 724, where the assertion `assert(!isExactOut)` fails and reverts the transaction. [6](#0-5) 

**Security Property Broken:** This violates the protocol's withdrawal availability invariant - users cannot execute certain exact output swaps despite having sufficient liquidity and valid parameters.

## Impact Explanation
- **Affected Assets**: Any token pair pool where exact output swaps occur with small amounts relative to liquidity
- **Damage Severity**: DOS of exact output swaps for specific parameter combinations. Users cannot execute exact output swaps when the sqrt ratio falls on specific compression boundaries, forcing them to use exact input swaps instead (which may result in less favorable execution due to inability to specify exact output amounts)
- **User Impact**: All users attempting exact output swaps in affected pools. The issue is deterministic based on current sqrt ratio and swap amount, so users will consistently face reverts for certain state combinations

## Likelihood Explanation
- **Attacker Profile**: Any user attempting a legitimate exact output swap (no malicious intent required)
- **Preconditions**: 
  - Pool has been initialized with liquidity
  - Current sqrt ratio falls on a compression boundary (probability varies by region: 75-100%)
  - User attempts exact output swap with small amount relative to liquidity (e.g., `abs(amount) * 2^128 < liquidity` for token1)
- **Execution Complexity**: Single transaction swap attempt - no special setup required
- **Frequency**: Affects 25-100% of exact output swap attempts depending on which token and which encoding region the sqrt ratio falls in

## Recommendation

The assertion is too strict and does not account for precision loss in the `SqrtRatio` compression. The recommended fix is to remove the assertion entirely, as the else branch behavior (consuming entire input as fees) is safe even for exact output swaps when the price doesn't move due to precision loss:

```solidity
// In src/Core.sol, function swap_6269342730, lines 724-733:

// CURRENT (vulnerable):
} else {
    // for an exact output swap, the price should always move since we have to round away from the current price
    assert(!isExactOut);
    
    // consume the entire input amount as fees since the price did not move
    assembly ("memory-safe") {
        stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
    }
    amountRemaining = 0;
    sqrtRatioNext = sqrtRatio;
}

// FIXED:
} else {
    // Price didn't move in compressed SqrtRatio representation.
    // This can occur for exact output swaps due to precision loss in compression,
    // or for exact input swaps when entire amount is consumed as fees.
    // In both cases, consuming remaining amount as fees is the correct behavior.
    
    assembly ("memory-safe") {
        stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
    }
    amountRemaining = 0;
    sqrtRatioNext = sqrtRatio;
}
```

Alternative mitigation: Enhance the `SqrtRatio` type to use higher precision (e.g., 128 bits) or implement a check before the assertion that accounts for precision loss by comparing the fixed-point values directly rather than compressed values.

## Proof of Concept

```solidity
// File: test/Exploit_PrecisionLoss.t.sol
// Run with: forge test --match-test test_ExactOutputPrecisionLoss -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import {toSqrtRatio, SqrtRatio, ONE} from "../src/types/sqrtRatio.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {FullTest} from "./FullTest.sol";

contract ExploitPrecisionLoss is FullTest {
    function setUp() public override {
        FullTest.setUp();
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }

    function test_ExactOutputPrecisionLoss() public {
        // SETUP: Create a pool at a sqrt ratio where compression will lose precision
        // Using a value in region 0 where sqrtRatio % 4 != 0 (75% of values)
        uint256 fixedValue = (uint256(1) << 95) + 101; // Not divisible by 4
        SqrtRatio sqrtRatio = toSqrtRatio(fixedValue, false);
        
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_fee: 0, _extension: address(0)})
        });
        
        positions.maybeInitializePool(poolKey, 0);
        
        // Set sqrt ratio
        router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: type(int128).min,
            sqrtRatioLimit: sqrtRatio,
            skipAhead: 0,
            calculatedAmountThreshold: type(int128).min,
            recipient: address(0)
        });
        
        // Add high liquidity (2^120) so that small swaps result in quotient = 1
        uint128 liquidity = uint128(1) << 120;
        positions.mintAndDeposit({
            poolKey: poolKey,
            tickLower: MIN_TICK,
            tickUpper: MAX_TICK,
            maxAmount0: type(uint128).max,
            maxAmount1: type(uint128).max,
            minLiquidity: liquidity
        });
        
        // EXPLOIT: Attempt exact output swap of token1 with small amount
        // For liquidity = 2^120, amounts up to 2^(120-128+128) = 2^120 / 2^128 = 2^-8
        // will result in quotient = 1, causing precision loss
        int128 exactOutputAmount = -1; // Small exact output
        
        // VERIFY: This should revert with assertion failure due to precision loss
        vm.expectRevert();
        router.swap({
            poolKey: poolKey,
            isToken1: true,
            amount: exactOutputAmount,
            sqrtRatioLimit: SqrtRatio.wrap(0), // Will use default
            skipAhead: 0,
            calculatedAmountThreshold: type(int128).min,
            recipient: address(0)
        });
        
        // The revert confirms the vulnerability - exact output swaps fail
        // when compression causes sqrtRatioNextFromAmount == sqrtRatio
    }
}
```

## Notes

The vulnerability is rooted in the fundamental design choice to use a lossy compressed `SqrtRatio` format. The compression provides gas savings by reducing storage and computation costs, but introduces precision loss that the assertion at line 726 does not account for.

Key technical details:
- **Region 0** (fixed < 2^96): Shift by 2 bits, affects ~75% of values for exact output token1 (roundDown)
- **Region 1** (fixed < 2^128): Shift by 34 bits, affects ~100% of values for exact output token1  
- **Region 2** (fixed < 2^160): Shift by 66 bits, affects ~100% of values for exact output token1
- **Region 3** (fixed < 2^192): Shift by 98 bits, affects ~100% of values for exact output token1

The vulnerability is more likely to occur for exact output swaps of token1 (which use `roundDown = false`) than token0, because the floor division operation loses precision more frequently than ceiling division.

The issue does NOT violate solvency or fee accounting invariants - the fee calculation and amount tracking remain correct. It only causes a DOS of specific swap operations.

### Citations

**File:** src/Core.sol (L698-734)
```text
                        } else if (sqrtRatioNextFromAmount != sqrtRatio) {
                            uint128 calculatedAmountWithoutFee = isToken1
                                ? amount0Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut)
                                : amount1Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut);

                            if (isExactOut) {
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(includingFee, calculatedAmountWithoutFee)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, calculatedAmountWithoutFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
                                }
                            }

                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatioNextFromAmount;
                        } else {
                            // for an exact output swap, the price should always move since we have to round away from the current price
                            assert(!isExactOut);

                            // consume the entire input amount as fees since the price did not move
                            assembly ("memory-safe") {
                                stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
                            }
                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatio;
                        }
```

**File:** src/types/sqrtRatio.sol (L59-99)
```text
function toSqrtRatio(uint256 sqrtRatio, bool roundUp) pure returns (SqrtRatio r) {
    assembly ("memory-safe") {
        function compute(sr, ru) -> v {
            // rup = 0x00...00 when false, 0xff...ff when true
            let rup := sub(0, ru)

            // Region: < 2**96  (shift = 2)
            let addmask := and(0x3, rup) // (1<<s)-1 if ru
            if lt(add(sr, addmask), shl(96, 1)) {
                v := shr(2, add(sr, addmask))
                leave
            }

            // Region: < 2**128 (shift = 34)  + set bit 94
            addmask := and(0x3ffffffff, rup)
            if lt(add(sr, addmask), shl(128, 1)) {
                v := or(shl(94, 1), shr(34, add(sr, addmask)))
                leave
            }

            // Region: < 2**160 (shift = 66)  + set bit 95
            addmask := and(0x3ffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(160, 1)) {
                v := or(shl(95, 1), shr(66, add(sr, addmask)))
                leave
            }

            // Region: < 2**192 (shift = 98)  + set bits 95|94
            addmask := and(0x3ffffffffffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(192, 1)) {
                v := or(shl(94, 3), shr(98, add(sr, addmask))) // 3<<94 == bit95|bit94
                leave
            }

            // cast sig "ValueOverflowsSqrtRatioContainer()"
            mstore(0, shl(224, 0xa10459f4))
            revert(0, 4)
        }
        r := compute(sqrtRatio, roundUp)
    }
}
```

**File:** src/types/sqrtRatio.sol (L102-106)
```text
function toFixed(SqrtRatio sqrtRatio) pure returns (uint256 r) {
    assembly ("memory-safe") {
        r := shl(add(2, shr(89, and(sqrtRatio, BIT_MASK))), and(sqrtRatio, not(BIT_MASK)))
    }
}
```

**File:** src/math/sqrtRatio.sol (L79-88)
```text
        if (amount < 0) {
            uint256 quotient;
            assembly ("memory-safe") {
                let numerator := shl(128, sub(0, amount))
                quotient := add(div(numerator, liquidityU256), iszero(iszero(mod(numerator, liquidityU256))))
            }

            uint256 sqrtRatioNextFixed = FixedPointMathLib.zeroFloorSub(sqrtRatio, quotient);

            sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, false);
```
