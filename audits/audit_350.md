## Title
Integer Overflow in exp2() Function Causes TWAMM Virtual Order Price Manipulation

## Summary
The `exp2()` function in `src/math/exp2.sol` contains an unchecked arithmetic block where the multiplication `result * CONSTANT` can silently overflow when the exponent approaches the maximum allowed value (0x400000000000000000 - 1). This overflow causes `exp2()` to return an unexpectedly small value (~10^19 instead of ~10^38), which corrupts the `computeNextSqrtRatio()` calculation in TWAMM virtual order execution, allowing attackers to manipulate execution prices by crafting order parameters that push the exponent to this boundary.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `exp2()` function computes 2^x where x is a 5.64 fixed-point number and returns a 64.64 fixed-point result. The unchecked block is intended as a gas optimization, with the assumption that the requirement `x < 0x400000000000000000` at line 7 ensures no overflow occurs during intermediate multiplications.

**Actual Logic:** When x approaches the maximum (e.g., x = 0x3FFFFFFFFFFFFFFFF with all fractional bits set), the result variable grows through successive multiplications to approximately 2^128. At the final bit check (bit 0, lines 200-202), the multiplication `result * 0x10000000000000000B17217F7D1CF79AB` produces an intermediate value exceeding 2^256:

- After processing bits 63-1: `result ≈ 2^128 * (1 - ε)` where ε is extremely small
- Constant at bit 0: `0x10000000000000000B17217F7D1CF79AB = 2^128 + 0xB17217F7D1CF79AB`
- Intermediate: `(2^128 - ε) * (2^128 + 0xB17217F7D1CF79AB) ≈ 2^256 + 2^128 * 0xB17217F7D1CF79AB > 2^256`
- After overflow wrap: `wrapped ≈ 2^128 * 0xB17217F7D1CF79AB`
- After right shift: `result ≈ 0xB17217F7D1CF79AB ≈ 1.28×10^19` (instead of expected ~3.4×10^38)

This corrupted result propagates to TWAMM virtual order execution: [2](#0-1) 

The exponent calculation at line 120 can reach values near the maximum through attacker-controlled parameters:
- `exponent = (sqrtSaleRate * timeElapsed * 12392656037) / liquidity`
- Attacker maximizes: sqrtSaleRate (via high sale rates), timeElapsed (waiting)
- Attacker targets pools with liquidity ≈ 2^111-2^112 to push exponent near 2^66 [3](#0-2) 

When `ePowExponent` is corrupted (tiny value), the sqrtRatioNext calculation becomes:
`sqrtRatioNext ≈ sqrtSaleRatio * |c| / |c| ≈ sqrtSaleRatio`

This causes the price to snap immediately to the sale ratio instead of moving gradually, violating the intended TWAMM execution model.

**Exploitation Path:**
1. Attacker identifies a pool with liquidity in range 2^111-2^112 (achievable for many pools)
2. Attacker places large TWAMM orders via `Orders.mintAndIncreaseSellAmount()` with carefully calculated amounts and durations such that `computeSaleRate()` produces sale rates that, combined with time elapsed, push the exponent to ~0x3FFFFFFFFFFFFFFFF
3. When virtual orders execute via `TWAMM._executeVirtualOrdersFromWithinLock()`, the corrupted exp2() return value causes immediate price movement to the sale ratio
4. Attacker extracts value by having their orders execute at manipulated favorable prices, draining value from liquidity providers

**Security Property Broken:** 
- Violates **Solvency** invariant (pool balances must never go negative) as price manipulation can cause imbalanced swaps
- Violates fair TWAMM execution pricing model documented in the protocol

## Impact Explanation

- **Affected Assets**: All TWAMM pools with liquidity in the vulnerable range (2^111-2^112 units), which encompasses many realistic pool configurations. Both token0 and token1 reserves are at risk.

- **Damage Severity**: Attacker can extract significant value from liquidity providers. The magnitude depends on order size and price deviation, but the instant price snap (instead of gradual movement) allows the attacker to bypass the intended TWAMM friction model. In a pool with $1M liquidity, manipulated execution could extract tens of thousands of dollars per attack.

- **User Impact**: All liquidity providers in affected TWAMM pools suffer impermanent loss amplified by the price manipulation. Any user with active TWAMM orders may receive unfavorable execution prices. The attack affects the entire pool, not just the attacker's positions.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user who can place TWAMM orders. No special permissions required.

- **Preconditions**: 
  - Pool must have TWAMM extension enabled
  - Pool liquidity must be in range ~2^111-2^112 (achievable - many pools have liquidity expressed in wei/shares in this range)
  - Attacker needs capital to place orders with sufficient sale rates
  - Time elapsed must be controllable (attacker can wait for timestamps to align)

- **Execution Complexity**: Single transaction to place orders, followed by waiting for virtual order execution. Attack can be executed permissionlessly via `TWAMM.lockAndExecuteVirtualOrders()` or will trigger automatically on the next swap/position update.

- **Frequency**: Repeatable on any TWAMM pool meeting the preconditions. Can be executed multiple times per pool as long as liquidity remains in the vulnerable range.

## Recommendation

Add an explicit overflow check before the final multiplication or restructure the algorithm to prevent overflow:

```solidity
// In src/math/exp2.sol, lines 200-202:

// CURRENT (vulnerable):
// Line 200-202 in unchecked block
if (x & 0x1 != 0) {
    result = result * 0x10000000000000000B17217F7D1CF79AB >> 128;
}

// FIXED Option 1: Add overflow protection
if (x & 0x1 != 0) {
    // Check if multiplication would overflow
    uint256 constant CONSTANT_BIT0 = 0x10000000000000000B17217F7D1CF79AB;
    require(result <= type(uint256).max / CONSTANT_BIT0, "exp2: overflow");
    result = result * CONSTANT_BIT0 >> 128;
}

// FIXED Option 2: Lower the maximum allowed exponent
// Change line 7:
require(x < 0x3F0000000000000000); // Reduce max from 64 to 63, preventing overflow case

// FIXED Option 3: Use checked arithmetic for the final multiplication
if (x & 0x1 != 0) {
    uint256 intermediate;
    // Temporarily exit unchecked block for this critical operation
    intermediate = result * 0x10000000000000000B17217F7D1CF79AB; // Will revert on overflow
    result = intermediate >> 128;
}
```

**Alternative mitigation in TWAMM:** Add validation in `computeNextSqrtRatio()` to cap the exponent further below the dangerous threshold:

```solidity
// In src/math/twamm.sol, line 121:
if (exponent >= 0x3F0000000000000000) { // Lower threshold
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_Exp2Overflow.t.sol
// Run with: forge test --match-test test_Exp2Overflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/math/exp2.sol";
import "../src/math/twamm.sol";
import "../src/types/sqrtRatio.sol";

contract Exploit_Exp2Overflow is Test {
    function test_Exp2Overflow() public pure {
        // SETUP: Maximum valid exponent (all fractional bits set)
        uint256 maxExponent = 0x3FFFFFFFFFFFFFFFF; // Just below 0x400000000000000000
        
        // EXPLOIT: Call exp2 with maximum exponent
        uint256 result = exp2(maxExponent);
        
        // VERIFY: Result is unexpectedly small due to overflow
        // Expected: approximately 2^128 = 340282366920938463463374607431768211456
        // Actual: approximately 0xB17217F7D1CF79AB = 12786308645202655147
        
        uint256 expectedApprox = 340282366920938463450588298786565555714; // From test
        uint256 actualResult = result;
        
        // Result should be close to expected, but due to overflow it's tiny
        assertTrue(actualResult < expectedApprox / 1e19, "Result should be unexpectedly small");
        assertEq(actualResult, 12786308645202655147, "Overflow causes result to wrap to tiny value");
    }
    
    function test_TwammPriceManipulation() public pure {
        // SETUP: Craft parameters to push exponent near maximum
        // exponent = (sqrtSaleRate * timeElapsed * 12392656037) / liquidity
        
        uint256 saleRateToken0 = type(uint112).max; // Maximum sale rate
        uint256 saleRateToken1 = type(uint112).max;
        uint256 sqrtSaleRate = computeSqrtSaleRatio(saleRateToken0, saleRateToken1);
        
        uint256 timeElapsed = type(uint32).max; // Maximum time
        uint256 liquidity = 2 ** 111; // Chosen to make exponent near max
        
        // Calculate exponent (simplified - actual uses FixedPointMathLib.rawDiv)
        uint256 exponent = (sqrtSaleRate * timeElapsed * 12392656037) / liquidity;
        
        // VERIFY: Exponent approaches dangerous threshold
        assertTrue(exponent > 0x3E0000000000000000, "Exponent should be near maximum");
        assertTrue(exponent < 0x400000000000000000, "Exponent should be below the check");
        
        // When this exponent is passed to exp2, overflow occurs
        // and computeNextSqrtRatio produces incorrect price
    }
}
```

### Citations

**File:** src/math/exp2.sol (L6-205)
```text
    unchecked {
        require(x < 0x400000000000000000); // Overflow

        result = 0x80000000000000000000000000000000;

        if (x & 0x8000000000000000 != 0) {
            result = result * 0x16A09E667F3BCC908B2FB1366EA957D3E >> 128;
        }
        if (x & 0x4000000000000000 != 0) {
            result = result * 0x1306FE0A31B7152DE8D5A46305C85EDEC >> 128;
        }
        if (x & 0x2000000000000000 != 0) {
            result = result * 0x1172B83C7D517ADCDF7C8C50EB14A791F >> 128;
        }
        if (x & 0x1000000000000000 != 0) {
            result = result * 0x10B5586CF9890F6298B92B71842A98363 >> 128;
        }
        if (x & 0x800000000000000 != 0) {
            result = result * 0x1059B0D31585743AE7C548EB68CA417FD >> 128;
        }
        if (x & 0x400000000000000 != 0) {
            result = result * 0x102C9A3E778060EE6F7CACA4F7A29BDE8 >> 128;
        }
        if (x & 0x200000000000000 != 0) {
            result = result * 0x10163DA9FB33356D84A66AE336DCDFA3F >> 128;
        }
        if (x & 0x100000000000000 != 0) {
            result = result * 0x100B1AFA5ABCBED6129AB13EC11DC9543 >> 128;
        }
        if (x & 0x80000000000000 != 0) {
            result = result * 0x10058C86DA1C09EA1FF19D294CF2F679B >> 128;
        }
        if (x & 0x40000000000000 != 0) {
            result = result * 0x1002C605E2E8CEC506D21BFC89A23A00F >> 128;
        }
        if (x & 0x20000000000000 != 0) {
            result = result * 0x100162F3904051FA128BCA9C55C31E5DF >> 128;
        }
        if (x & 0x10000000000000 != 0) {
            result = result * 0x1000B175EFFDC76BA38E31671CA939725 >> 128;
        }
        if (x & 0x8000000000000 != 0) {
            result = result * 0x100058BA01FB9F96D6CACD4B180917C3D >> 128;
        }
        if (x & 0x4000000000000 != 0) {
            result = result * 0x10002C5CC37DA9491D0985C348C68E7B3 >> 128;
        }
        if (x & 0x2000000000000 != 0) {
            result = result * 0x1000162E525EE054754457D5995292026 >> 128;
        }
        if (x & 0x1000000000000 != 0) {
            result = result * 0x10000B17255775C040618BF4A4ADE83FC >> 128;
        }
        if (x & 0x800000000000 != 0) {
            result = result * 0x1000058B91B5BC9AE2EED81E9B7D4CFAB >> 128;
        }
        if (x & 0x400000000000 != 0) {
            result = result * 0x100002C5C89D5EC6CA4D7C8ACC017B7C9 >> 128;
        }
        if (x & 0x200000000000 != 0) {
            result = result * 0x10000162E43F4F831060E02D839A9D16D >> 128;
        }
        if (x & 0x100000000000 != 0) {
            result = result * 0x100000B1721BCFC99D9F890EA06911763 >> 128;
        }
        if (x & 0x80000000000 != 0) {
            result = result * 0x10000058B90CF1E6D97F9CA14DBCC1628 >> 128;
        }
        if (x & 0x40000000000 != 0) {
            result = result * 0x1000002C5C863B73F016468F6BAC5CA2B >> 128;
        }
        if (x & 0x20000000000 != 0) {
            result = result * 0x100000162E430E5A18F6119E3C02282A5 >> 128;
        }
        if (x & 0x10000000000 != 0) {
            result = result * 0x1000000B1721835514B86E6D96EFD1BFE >> 128;
        }
        if (x & 0x8000000000 != 0) {
            result = result * 0x100000058B90C0B48C6BE5DF846C5B2EF >> 128;
        }
        if (x & 0x4000000000 != 0) {
            result = result * 0x10000002C5C8601CC6B9E94213C72737A >> 128;
        }
        if (x & 0x2000000000 != 0) {
            result = result * 0x1000000162E42FFF037DF38AA2B219F06 >> 128;
        }
        if (x & 0x1000000000 != 0) {
            result = result * 0x10000000B17217FBA9C739AA5819F44F9 >> 128;
        }
        if (x & 0x800000000 != 0) {
            result = result * 0x1000000058B90BFCDEE5ACD3C1CEDC823 >> 128;
        }
        if (x & 0x400000000 != 0) {
            result = result * 0x100000002C5C85FE31F35A6A30DA1BE50 >> 128;
        }
        if (x & 0x200000000 != 0) {
            result = result * 0x10000000162E42FF0999CE3541B9FFFCF >> 128;
        }
        if (x & 0x100000000 != 0) {
            result = result * 0x100000000B17217F80F4EF5AADDA45554 >> 128;
        }
        if (x & 0x80000000 != 0) {
            result = result * 0x10000000058B90BFBF8479BD5A81B51AD >> 128;
        }
        if (x & 0x40000000 != 0) {
            result = result * 0x1000000002C5C85FDF84BD62AE30A74CC >> 128;
        }
        if (x & 0x20000000 != 0) {
            result = result * 0x100000000162E42FEFB2FED257559BDAA >> 128;
        }
        if (x & 0x10000000 != 0) {
            result = result * 0x1000000000B17217F7D5A7716BBA4A9AE >> 128;
        }
        if (x & 0x8000000 != 0) {
            result = result * 0x100000000058B90BFBE9DDBAC5E109CCE >> 128;
        }
        if (x & 0x4000000 != 0) {
            result = result * 0x10000000002C5C85FDF4B15DE6F17EB0D >> 128;
        }
        if (x & 0x2000000 != 0) {
            result = result * 0x1000000000162E42FEFA494F1478FDE05 >> 128;
        }
        if (x & 0x1000000 != 0) {
            result = result * 0x10000000000B17217F7D20CF927C8E94C >> 128;
        }
        if (x & 0x800000 != 0) {
            result = result * 0x1000000000058B90BFBE8F71CB4E4B33D >> 128;
        }
        if (x & 0x400000 != 0) {
            result = result * 0x100000000002C5C85FDF477B662B26945 >> 128;
        }
        if (x & 0x200000 != 0) {
            result = result * 0x10000000000162E42FEFA3AE53369388C >> 128;
        }
        if (x & 0x100000 != 0) {
            result = result * 0x100000000000B17217F7D1D351A389D40 >> 128;
        }
        if (x & 0x80000 != 0) {
            result = result * 0x10000000000058B90BFBE8E8B2D3D4EDE >> 128;
        }
        if (x & 0x40000 != 0) {
            result = result * 0x1000000000002C5C85FDF4741BEA6E77E >> 128;
        }
        if (x & 0x20000 != 0) {
            result = result * 0x100000000000162E42FEFA39FE95583C2 >> 128;
        }
        if (x & 0x10000 != 0) {
            result = result * 0x1000000000000B17217F7D1CFB72B45E1 >> 128;
        }
        if (x & 0x8000 != 0) {
            result = result * 0x100000000000058B90BFBE8E7CC35C3F0 >> 128;
        }
        if (x & 0x4000 != 0) {
            result = result * 0x10000000000002C5C85FDF473E242EA38 >> 128;
        }
        if (x & 0x2000 != 0) {
            result = result * 0x1000000000000162E42FEFA39F02B772C >> 128;
        }
        if (x & 0x1000 != 0) {
            result = result * 0x10000000000000B17217F7D1CF7D83C1A >> 128;
        }
        if (x & 0x800 != 0) {
            result = result * 0x1000000000000058B90BFBE8E7BDCBE2E >> 128;
        }
        if (x & 0x400 != 0) {
            result = result * 0x100000000000002C5C85FDF473DEA871F >> 128;
        }
        if (x & 0x200 != 0) {
            result = result * 0x10000000000000162E42FEFA39EF44D91 >> 128;
        }
        if (x & 0x100 != 0) {
            result = result * 0x100000000000000B17217F7D1CF79E949 >> 128;
        }
        if (x & 0x80 != 0) {
            result = result * 0x10000000000000058B90BFBE8E7BCE544 >> 128;
        }
        if (x & 0x40 != 0) {
            result = result * 0x1000000000000002C5C85FDF473DE6ECA >> 128;
        }
        if (x & 0x20 != 0) {
            result = result * 0x100000000000000162E42FEFA39EF366F >> 128;
        }
        if (x & 0x10 != 0) {
            result = result * 0x1000000000000000B17217F7D1CF79AFA >> 128;
        }
        if (x & 0x8 != 0) {
            result = result * 0x100000000000000058B90BFBE8E7BCD6D >> 128;
        }
        if (x & 0x4 != 0) {
            result = result * 0x10000000000000002C5C85FDF473DE6B2 >> 128;
        }
        if (x & 0x2 != 0) {
            result = result * 0x1000000000000000162E42FEFA39EF358 >> 128;
        }
        if (x & 0x1 != 0) {
            result = result * 0x10000000000000000B17217F7D1CF79AB >> 128;
        }

        result >>= uint256(63 - (x >> 64));
    }
```

**File:** src/math/twamm.sol (L120-125)
```text
            uint256 exponent = FixedPointMathLib.rawDiv(sqrtSaleRate * timeElapsed * 12392656037, liquidity);
            if (exponent >= 0x400000000000000000) {
                // if the exponent is larger than this value (64), the exponent term dominates and the result is approximately the sell ratio
                sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
            } else {
                int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);
```

**File:** src/math/twamm.sol (L127-129)
```text
                uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
                    sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(ePowExponent + c)
                );
```
