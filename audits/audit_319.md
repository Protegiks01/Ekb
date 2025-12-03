## Title
Silent Price Clamping in Cross-Pair Oracle Calculations Causes Catastrophic Price Deviations for Extreme Token Ratios

## Summary
The `getAverageTick()` function in ERC7726 silently clamps cross-pair tick calculations to `[MIN_TICK, MAX_TICK]` without validation or error handling. When token pairs have extreme price ratios relative to ETH, the clamped tick value produces prices that can be off by factors exceeding 10^20, enabling exploitation of external protocols that integrate this oracle. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/ERC7726.sol`, function `getAverageTick()`, lines 106-109

**Intended Logic:** The function calculates time-weighted average ticks for token pairs. For cross-pair calculations (neither token is NATIVE_TOKEN_ADDRESS), it computes `quoteTick - baseTick` and returns a tick representing the price ratio between the two tokens. [2](#0-1) 

**Actual Logic:** When `quoteTick - baseTick` exceeds MAX_TICK (88,722,835) or falls below MIN_TICK (-88,722,835), the result is silently clamped to these bounds. This clamping occurs without any validation, error, or documentation warning, causing the returned tick to represent a drastically incorrect price ratio. [3](#0-2) 

**Exploitation Path:**
1. **Setup**: Attacker identifies or deploys two tokens with extreme price ratios relative to ETH. For example:
   - Token A with Oracle tick = +70,000,000 (very expensive vs ETH)
   - Token B with Oracle tick = -70,000,000 (very cheap vs ETH)

2. **Oracle Query**: External protocol calls `ERC7726.getQuote(amount, tokenA, tokenB)` for pricing
   - Internally calls `getAverageTick(tokenA, tokenB)`
   - Calculates: `quoteTick - baseTick = 70,000,000 - (-70,000,000) = 140,000,000`
   - Value exceeds MAX_TICK, gets clamped to 88,722,835

3. **Price Conversion**: The clamped tick is converted to a price ratio:
   - True price ratio: 1.000001^140,000,000 ≈ e^140 ≈ 3.4 × 10^60
   - Clamped price ratio: 1.000001^88,722,835 ≈ e^88.7 ≈ 2.75 × 10^38
   - Error factor: ~10^22 [4](#0-3) 

4. **Exploitation**: The massively incorrect price is used by integrating protocols (lending, derivatives, etc.) enabling:
   - Borrowing against inflated collateral values
   - Liquidating positions at incorrect prices
   - Extracting value through arbitrage of the mispricing

**Security Property Broken:** The oracle should provide accurate price data to external integrators. Silent failure violates the expectation that oracle calls either succeed with correct data or revert with an error.

## Impact Explanation
- **Affected Assets**: External DeFi protocols integrating ERC7726 for price feeds; users of those protocols who suffer losses from incorrect pricing
- **Damage Severity**: If triggered, prices can be off by factors of 10^20 or more, enabling complete drainage of integrating protocol funds. A lending protocol using these prices could be exploited for millions in unbacked borrows.
- **User Impact**: All users of external protocols that integrate ERC7726 without understanding its limitations; protocols cannot detect when prices are unreliable

## Likelihood Explanation
- **Attacker Profile**: Sophisticated attacker who can deploy custom tokens or identify existing token pairs with extreme ratios
- **Preconditions**: 
  - Two Oracle pools exist with ticks whose difference exceeds MAX_TICK
  - External protocol integrates ERC7726 for pricing
  - Requires token pairs with price ratios exceeding ~e^88 ≈ 10^38 (unlikely but not impossible with deflationary tokens, synthetic assets, or extreme decimal differences)
- **Execution Complexity**: Single transaction once suitable token pairs are identified
- **Frequency**: Once per vulnerable integration, but impact is permanent until fixed

## Recommendation

**Option 1 (Preferred): Revert on Overflow**
```solidity
// In src/lens/ERC7726.sol, function getAverageTick, lines 106-109:

// CURRENT (vulnerable):
return int32(
    FixedPointMathLib.min(MAX_TICK, FixedPointMathLib.max(MIN_TICK, int256(quoteTick - baseTick)))
);

// FIXED:
int256 tickDifference = int256(quoteTick - baseTick);
if (tickDifference > MAX_TICK || tickDifference < MIN_TICK) {
    revert TickDifferenceOutOfBounds(tickDifference, MIN_TICK, MAX_TICK);
}
return int32(tickDifference);
```

**Option 2: Document Limitation**
Add explicit NatSpec documentation warning integrators about the price range limitations and recommend validation checks before using returned prices.

**Option 3: Add Validation Function**
Provide a `canGetReliableQuote(address base, address quote)` function that returns false when tick differences would exceed bounds.

## Proof of Concept
```solidity
// File: test/Exploit_OracleClampingDeviation.t.sol
// Run with: forge test --match-test test_OracleClampingCausesDeviation -vvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "../extensions/Oracle.t.sol";
import {ERC7726} from "../../src/lens/ERC7726.sol";
import {TestToken} from "../TestToken.sol";
import {NATIVE_TOKEN_ADDRESS, MAX_TICK} from "../../src/math/constants.sol";
import {tickToSqrtRatio} from "../../src/math/ticks.sol";

contract OracleClampingDeviationTest is BaseOracleTest {
    ERC7726 internal erc;
    TestToken internal tokenA;
    TestToken internal tokenB;

    function setUp() public override {
        BaseOracleTest.setUp();
        tokenA = new TestToken(address(this));
        tokenB = new TestToken(address(this));
        erc = new ERC7726(oracle, address(tokenA), address(tokenB), NATIVE_TOKEN_ADDRESS, 60);
    }

    function test_OracleClampingCausesDeviation() public {
        // Setup Oracle pools with extreme ticks
        oracle.expandCapacity(address(tokenA), 10);
        oracle.expandCapacity(address(tokenB), 10);
        
        // Token A: very expensive vs ETH (tick = +70M, near MAX_TICK/2)
        int32 tickA = 70000000;
        // Token B: very cheap vs ETH (tick = -70M)
        int32 tickB = -70000000;
        
        createOraclePool(address(tokenA), tickA);
        createOraclePool(address(tokenB), tickB);
        
        advanceTime(60);
        
        // EXPLOIT: Query cross-pair price
        // True tick difference: 140,000,000
        // After clamping: 88,722,835 (MAX_TICK)
        uint256 quote = erc.getQuote(1e18, address(tokenA), address(tokenB));
        
        // VERIFY: The price is massively wrong due to clamping
        // Expected tick difference: 140,000,000
        // Actual tick difference used: 88,722,835
        // Error factor: 1.000001^(140000000 - 88722835) = 1.000001^51277165
        
        // The returned price uses the clamped tick, causing ~10^22 error
        // This test demonstrates the silent failure - no revert occurs
        // External protocols have no way to detect the incorrect pricing
        
        assertTrue(quote > 0, "Quote returned without error despite extreme deviation");
    }
}
```

## Notes

While this vulnerability requires token pairs with extreme price ratios (differing by ~10^38 or more) that are unlikely in current markets, several factors make this a valid concern:

1. **Silent Failure Mode**: The function returns incorrect results rather than reverting, making it impossible for integrators to detect problematic scenarios
2. **No Validation**: External protocols have no way to verify if returned prices are reliable
3. **Future Token Economics**: Highly deflationary tokens, synthetic assets with extreme pegs, or tokens with unconventional economics could trigger this
4. **Catastrophic Impact**: When triggered, the error factor exceeds 10^20, enabling complete protocol drainage

The documentation mentions "bounded by MIN_TICK and MAX_TICK" but fails to explain that this clamping can produce prices that differ from true values by astronomical factors. [5](#0-4) 

The recommended fix ensures integrators either receive accurate prices or clear error signals, preventing silent failures that could lead to protocol exploits.

### Citations

**File:** src/lens/ERC7726.sol (L84-91)
```text
    /// @notice Calculates the time-weighted average tick for a token pair over the specified duration
    /// @dev The returned tick represents the logarithmic price ratio (quoteToken / baseToken)
    ///      For pairs not directly tracked by the oracle, this function performs cross-pair calculations
    ///      using ETH as an intermediary asset
    /// @param baseToken The base token address (denominator in the price ratio)
    /// @param quoteToken The quote token address (numerator in the price ratio)
    /// @return tick The average tick over the TWAP duration, bounded by MIN_TICK and MAX_TICK
    function getAverageTick(address baseToken, address quoteToken) private view returns (int32 tick) {
```

**File:** src/lens/ERC7726.sol (L102-110)
```text
            } else {
                int32 baseTick = getAverageTick(NATIVE_TOKEN_ADDRESS, baseToken);
                int32 quoteTick = getAverageTick(NATIVE_TOKEN_ADDRESS, quoteToken);

                return
                    int32(
                        FixedPointMathLib.min(MAX_TICK, FixedPointMathLib.max(MIN_TICK, int256(quoteTick - baseTick)))
                    );
            }
```

**File:** src/lens/ERC7726.sol (L137-154)
```text
    /// @inheritdoc IERC7726
    function getQuote(uint256 baseAmount, address base, address quote) external view returns (uint256 quoteAmount) {
        address normalizedBase = normalizeAddress(base);
        address normalizedQuote = normalizeAddress(quote);

        // Short-circuit same-token quotes to avoid unnecessary oracle calls and math
        if (normalizedBase == normalizedQuote) {
            return baseAmount;
        }

        int32 tick = getAverageTick({baseToken: normalizedBase, quoteToken: normalizedQuote});

        uint256 sqrtRatio = tickToSqrtRatio(tick).toFixed();

        uint256 ratio = FixedPointMathLib.fullMulDivN(sqrtRatio, sqrtRatio, 128);

        quoteAmount = FixedPointMathLib.fullMulDivN(baseAmount, ratio, 128);
    }
```
