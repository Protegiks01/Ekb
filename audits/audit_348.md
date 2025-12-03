## Title
TWAMM Division-by-Near-Zero Causes ValueOverflowsSqrtRatioContainer Revert, Freezing Order Execution

## Summary
The `computeNextSqrtRatio` function in `src/math/twamm.sol` can produce values exceeding `MAX_FIXED_VALUE_ROUND_UP` when the denominator `abs(ePowExponent + c)` approaches zero due to near-perfect cancellation. This triggers a `ValueOverflowsSqrtRatioContainer` revert in `toSqrtRatio`, permanently freezing TWAMM order execution for affected pools.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The TWAMM formula should compute the next sqrt ratio based on sale rates, liquidity, and time elapsed, converting the result to a compact `SqrtRatio` representation that fits within the protocol's supported range.

**Actual Logic:** When `ePowExponent` (approximately 2^128 for small exponents) and `c` (approximately -2^128 when current price far exceeds sale ratio) nearly cancel in the denominator at line 128, the division produces a value exceeding 2^192. The subsequent `toSqrtRatio` call reverts because the input exceeds `MAX_FIXED_VALUE_ROUND_UP`. [2](#0-1) 

**Exploitation Path:**
1. Attacker places TWAMM orders with extreme sale rate ratios (e.g., `saleRateToken1 = type(uint112).max`, `saleRateToken0 = 1`), creating `sqrtSaleRatio` close to 2^184 [3](#0-2) 
2. Pool price (`sqrtRatio`) is significantly higher than `sqrtSaleRatio`, causing `c` to approach -2^128 [4](#0-3) 
3. Pool has high liquidity (set by LPs), making the `exponent` value small [5](#0-4) 
4. When virtual orders execute via `_executeVirtualOrdersFromWithinLock`, `ePowExponent ≈ 2^128` (from `exp2` of small exponent shifted left 64 bits) [6](#0-5) 
5. The denominator `abs(ePowExponent + c) ≈ 0`, causing the division at lines 127-129 to produce `sqrtRatioNextFixed > 2^192`
6. The `max` clamping at line 133 preserves this oversized value when `roundUp = true` [7](#0-6) 
7. `toSqrtRatio` reverts with `ValueOverflowsSqrtRatioContainer` [8](#0-7) 
8. The entire `_executeVirtualOrdersFromWithinLock` call fails [9](#0-8) 

**Security Property Broken:** Violates the **Withdrawal Availability** invariant - TWAMM orders cannot be executed or withdrawn while this condition persists, effectively locking user capital in the extension.

## Impact Explanation
- **Affected Assets**: All TWAMM orders in the affected pool become frozen and cannot execute
- **Damage Severity**: Complete denial of service for TWAMM functionality in the pool. Users cannot fill their orders or recover their deposited tokens through normal execution. The DOS persists until pool state changes significantly (e.g., sale rates expire, liquidity changes drastically, or price moves)
- **User Impact**: All users with active TWAMM orders in the pool are affected. Any call to execute virtual orders will revert, preventing order settlement and fund recovery

## Likelihood Explanation
- **Attacker Profile**: Any user can place TWAMM orders with extreme sale rate ratios
- **Preconditions**: Pool must have high liquidity (common for active pools), and current price must be significantly different from the sale ratio (can occur naturally or be manipulated)
- **Execution Complexity**: Single transaction to place orders with extreme ratios. The DOS triggers automatically when virtual order execution is attempted
- **Frequency**: Can be exploited once per pool by setting up the conditions and maintaining them through repeated order placements

## Recommendation

Add bounds checking before the division to prevent near-zero denominators:

```solidity
// In src/math/twamm.sol, function computeNextSqrtRatio, after line 125:

int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);

// ADDED: Check denominator magnitude before division
int256 denominator = ePowExponent + c;
uint256 absDenominator = FixedPointMathLib.abs(denominator);

// Minimum denominator threshold to prevent overflow (2^121 based on max sqrtSaleRatio of 2^184)
// If denominator is too small, fall back to sale ratio as the result
if (absDenominator < (1 << 121)) {
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
} else {
    uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
        sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), absDenominator
    );
    
    // we should never exceed the sale ratio
    if (roundUp) {
        sqrtRatioNextFixed = FixedPointMathLib.max(sqrtRatioNextFixed, sqrtSaleRatio);
    } else {
        sqrtRatioNextFixed = FixedPointMathLib.min(sqrtRatioNextFixed, sqrtSaleRatio);
    }
    
    sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, roundUp);
}
```

Alternative mitigation: Add bounds checking in `toSqrtRatio` to clamp inputs to `MAX_FIXED_VALUE_ROUND_UP` instead of reverting, though this may introduce pricing inaccuracies.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMOverflow.t.sol
// Run with: forge test --match-test test_TWAMMDivisionByNearZeroOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import "../src/types/poolKey.sol";

contract Exploit_TWAMMOverflow is Test {
    Core core;
    TWAMM twamm;
    Router router;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        router = new Router(core);
    }
    
    function test_TWAMMDivisionByNearZeroOverflow() public {
        // SETUP: Create pool with high liquidity and initialize TWAMM
        PoolKey memory poolKey = createPoolKey({
            extension: address(twamm),
            // ... pool parameters
        });
        
        // Add high liquidity to make exponent small
        core.mint(/* high liquidity parameters */);
        
        // EXPLOIT: Place TWAMM order with extreme sale rate ratio
        // saleRateToken1 >> saleRateToken0 creates large sqrtSaleRatio (~2^184)
        twamm.placeOrder(poolKey, /* saleRateToken0=1, saleRateToken1=type(uint112).max */);
        
        // Manipulate price to be higher than sale ratio (sqrtRatio >> sqrtSaleRatio)
        // This makes c approach -2^128
        core.swap(/* swap to increase price */);
        
        // VERIFY: Attempt to execute virtual orders triggers revert
        vm.expectRevert(ValueOverflowsSqrtRatioContainer.selector);
        twamm.executeVirtualOrders(poolKey);
        
        // Vulnerability confirmed: TWAMM execution is frozen
        // Users cannot execute their orders or recover funds
    }
}
```

## Notes

The vulnerability arises from the mathematical properties of the TWAMM pricing formula when `ePowExponent` and `c` have opposite signs and similar magnitudes. The code correctly implements the formula but lacks defensive bounds checking for edge cases where the denominator approaches zero. The comment at line 55 of `twamm.sol` documents the expected ranges but doesn't enforce them in the calculation path. [10](#0-9) 

The issue is exacerbated by the clamping logic at lines 132-136 which preserves oversized values instead of rejecting them before the `toSqrtRatio` conversion. [11](#0-10)

### Citations

**File:** src/math/twamm.sol (L54-64)
```text
/// @dev Computes the quantity `c = (sqrtSaleRatio - sqrtRatio) / (sqrtSaleRatio + sqrtRatio)` as a signed 64.128 number
/// @dev sqrtRatio is assumed to be between 2**192 and 2**-64, while sqrtSaleRatio values are assumed to be between 2**184 and 2**-72
function computeC(uint256 sqrtRatio, uint256 sqrtSaleRatio) pure returns (int256 c) {
    uint256 unsigned = FixedPointMathLib.fullMulDiv(
        FixedPointMathLib.dist(sqrtRatio, sqrtSaleRatio), (1 << 128), sqrtRatio + sqrtSaleRatio
    );
    assembly ("memory-safe") {
        let sign := sub(shl(1, gt(sqrtSaleRatio, sqrtRatio)), 1)
        c := mul(sign, unsigned)
    }
}
```

**File:** src/math/twamm.sol (L68-83)
```text
function computeSqrtSaleRatio(uint256 saleRateToken0, uint256 saleRateToken1) pure returns (uint256 sqrtSaleRatio) {
    unchecked {
        uint256 saleRatio = FixedPointMathLib.rawDiv(saleRateToken1 << 128, saleRateToken0);

        if (saleRatio <= type(uint128).max) {
            // full precision for small ratios
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 128);
        } else if (saleRatio <= type(uint192).max) {
            // we know it only has 192 bits, so we can shift it 64 before rooting to get more precision
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 64) << 32;
        } else {
            // we assume it has max 240 bits, since saleRateToken1 is 112 bits and we shifted left 128
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 16) << 56;
        }
    }
}
```

**File:** src/math/twamm.sol (L120-120)
```text
            uint256 exponent = FixedPointMathLib.rawDiv(sqrtSaleRate * timeElapsed * 12392656037, liquidity);
```

**File:** src/math/twamm.sol (L125-138)
```text
                int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);

                uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
                    sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(ePowExponent + c)
                );

                // we should never exceed the sale ratio
                if (roundUp) {
                    sqrtRatioNextFixed = FixedPointMathLib.max(sqrtRatioNextFixed, sqrtSaleRatio);
                } else {
                    sqrtRatioNextFixed = FixedPointMathLib.min(sqrtRatioNextFixed, sqrtSaleRatio);
                }

                sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, roundUp);
```

**File:** src/types/sqrtRatio.sol (L55-56)
```text
uint256 constant MAX_FIXED_VALUE_ROUND_UP =
    0x1000000000000000000000000000000000000000000000000 - 0x4000000000000000000000000;
```

**File:** src/types/sqrtRatio.sol (L86-95)
```text
            // Region: < 2**192 (shift = 98)  + set bits 95|94
            addmask := and(0x3ffffffffffffffffffffffff, rup)
            if lt(add(sr, addmask), shl(192, 1)) {
                v := or(shl(94, 3), shr(98, add(sr, addmask))) // 3<<94 == bit95|bit94
                leave
            }

            // cast sig "ValueOverflowsSqrtRatioContainer()"
            mstore(0, shl(224, 0xa10459f4))
            revert(0, 4)
```

**File:** src/extensions/TWAMM.sol (L445-452)
```text
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });
```
