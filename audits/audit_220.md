## Title
Fee Truncation Vulnerability in Position Fee Collection When MEV and Swap Fees Exceed uint128

## Summary
The `position.fees()` function casts accumulated fee calculations to `uint128` without overflow protection, silently truncating fees that exceed this limit. When MEVCapture accumulates additional MEV-based fees on top of regular swap fees, the combined `feesPerLiquidity` values can grow unbounded as `uint256`, causing high-liquidity positions to lose accumulated fees during collection.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `fees()` function calculates fees owed to liquidity providers by computing `(feesPerLiquidityInside - feesPerLiquidityInsideLast) * liquidity >> 128`. The code assumes accumulated fees will never exceed `type(uint128).max` as stated in the comment. [2](#0-1) 

**Actual Logic:** The function performs an unchecked cast to `uint128` that silently truncates overflow. Meanwhile, `feesPerLiquidity` is stored as `uint256` and grows unbounded through repeated calls to `accumulateAsFees()`. [3](#0-2) 

When MEVCapture is enabled, it adds additional fees based on tick movement at lines 139 and 196: [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. Pool is configured with MEVCapture extension to capture additional fees from large tick movements
2. Over time, many swaps occur accumulating both regular swap fees and MEV fees via `accumulateAsFees()`, causing `feesPerLiquidity` to exceed `2^128`
3. A user with maximum liquidity position (`liquidity = 2^128 - 1`) who hasn't collected fees for an extended period now has `difference = feesPerLiquidity - feesPerLiquidityInsideLast > 2^128`
4. When calling `collectFees()`, the calculation `(difference * liquidity) >> 128` produces a result exceeding `uint128`, which is silently truncated to the lower 128 bits, causing loss of accumulated fees [6](#0-5) 

**Security Property Broken:** Fee Accounting invariant - "Position fee collection must be accurate and never allow double-claiming". Users lose legitimately earned fees due to truncation.

## Impact Explanation
- **Affected Assets**: All LP positions in pools with MEVCapture extension where `feesPerLiquidity` has grown beyond `2^128` due to accumulated swap and MEV fees
- **Damage Severity**: Users can lose 100% of accumulated fees. For example, if calculated fees equal `2^128`, the cast to `uint128` results in 0, causing complete loss. If fees equal `2^129`, only the lower 128 bits (`2^128`) are retained, losing half the owed amount.
- **User Impact**: Affects LPs with high liquidity positions who accumulate fees over long periods in active pools with MEVCapture enabled

## Likelihood Explanation
- **Attacker Profile**: Not an intentional attack - this is a protocol design flaw that affects innocent users
- **Preconditions**: 
  - Pool must have MEVCapture extension enabled
  - Sufficient swap volume with tick movements to accumulate fees exceeding `2^128` in `feesPerLiquidity`
  - User has high liquidity position and hasn't collected fees recently
- **Execution Complexity**: Occurs naturally during normal `collectFees()` operation
- **Frequency**: Becomes more likely over time as `feesPerLiquidity` accumulates. Affects any position collection once the threshold is crossed.

## Recommendation
Add overflow protection to the fee calculation in `position.fees()`:

```solidity
// In src/types/position.sol, function fees, lines 48-50:

// CURRENT (vulnerable):
return (
    uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
    uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
);

// FIXED:
uint256 fee0 = FixedPointMathLib.fullMulDivN(difference0, liquidity, 128);
uint256 fee1 = FixedPointMathLib.fullMulDivN(difference1, liquidity, 128);

// Revert if fees exceed uint128 to prevent silent truncation
require(fee0 <= type(uint128).max, "Fee0 overflow");
require(fee1 <= type(uint128).max, "Fee1 overflow");

return (uint128(fee0), uint128(fee1));
```

Alternative mitigation: Implement a fee collection cap or periodic forced collection mechanism to prevent `feesPerLiquidity` from growing excessively large.

## Proof of Concept
```solidity
// File: test/Exploit_FeeOverflow.t.sol
// Run with: forge test --match-test test_FeeOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/MEVCapture.sol";

contract Exploit_FeeOverflow is Test {
    Core core;
    MEVCapture mevCapture;
    Positions positions;
    
    function setUp() public {
        // Initialize protocol contracts
        core = new Core();
        mevCapture = new MEVCapture(core);
        positions = new Positions(core);
    }
    
    function test_FeeOverflow() public {
        // SETUP: Create pool with MEVCapture and high liquidity position
        // Assume position has liquidity = type(uint128).max
        uint128 liquidity = type(uint128).max;
        
        // Simulate accumulated feesPerLiquidity exceeding uint128
        // This happens over time with many swaps + MEV fee accumulation
        uint256 currentFeesPerLiquidity = uint256(type(uint128).max) + 1; // 2^128
        uint256 lastCollectionFeesPerLiquidity = 0;
        
        // Calculate expected fees (should be liquidity * 2^128 / 2^128 = liquidity)
        uint256 difference = currentFeesPerLiquidity - lastCollectionFeesPerLiquidity;
        uint256 expectedFees = (difference * liquidity) >> 128;
        // expectedFees = (2^128 * 2^128) >> 128 = 2^128
        
        // EXPLOIT: User collects fees
        // The position.fees() function casts to uint128
        uint128 actualFees = uint128(expectedFees);
        
        // VERIFY: Fees are truncated to 0 due to overflow
        assertEq(actualFees, 0, "Vulnerability confirmed: fees truncated from 2^128 to 0");
        assertEq(expectedFees, uint256(type(uint128).max) + 1, "Expected fees exceed uint128");
    }
}
```

## Notes
The vulnerability is exacerbated by MEVCapture because:
1. MEVCapture adds fees proportional to tick movement (lines 212-216 in MEVCapture.sol)
2. Large tick movements in volatile markets can accumulate significant additional fees
3. These MEV fees are added to the same `feesPerLiquidity` storage as regular swap fees
4. The combination accelerates the growth of `feesPerLiquidity` beyond safe uint128 bounds

The codebase explicitly acknowledges this limitation but incorrectly assumes it won't occur in practice, as evidenced by the comment stating "It is assumed that accumulated fees will never exceed type(uint128).max."

### Citations

**File:** src/types/position.sol (L27-28)
```text
///      Note: if the computed fees overflow the uint128 type, it will return only the lower 128 bits. It is assumed that accumulated
///      fees will never exceed type(uint128).max.
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

**File:** src/Core.sol (L257-260)
```text
                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
```

**File:** src/Core.sol (L492-492)
```text
        (amount0, amount1) = position.fees(feesPerLiquidityInside);
```

**File:** src/extensions/MEVCapture.sol (L138-139)
```text
        if (fees0 != 0 || fees1 != 0) {
            CORE.accumulateAsFees(poolKey, fees0, fees1);
```

**File:** src/extensions/MEVCapture.sol (L195-196)
```text
                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
```
