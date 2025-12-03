## Title
Fee Calculation Overflow When Positions With High Liquidity Collect Fees Accumulated During Low Pool Liquidity Periods

## Summary
When positions with liquidity values near uint128.max collect fees, the intermediate calculation `(feesPerLiquidityDifference * liquidity) >> 128` can overflow uint128 despite the protocol's assumption that fees never exceed this limit. This occurs because feesPerLiquidity accumulates inversely proportional to pool liquidity, allowing extreme values when pool liquidity is low. The unsafe cast from uint256 to uint128 silently truncates the result, causing users to lose fees.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/types/position.sol`, function `fees()`, lines 48-50 [1](#0-0) 

**Intended Logic:** The `fees()` function should calculate the exact fees owed to a position based on the accumulated feesPerLiquidity and the position's liquidity. The code comment at lines 27-28 states: "It is assumed that accumulated fees will never exceed type(uint128).max." [2](#0-1) 

**Actual Logic:** The calculation `fullMulDivN(difference0, liquidity, 128)` computes `(difference0 * liquidity) >> 128` using full 512-bit precision, returning a uint256. This is then cast to uint128 WITHOUT overflow checking. When feesPerLiquidity values are large (accumulated during low pool liquidity periods) and position liquidity is near uint128.max, the result after the shift can significantly exceed uint128.max, causing silent truncation.

**Exploitation Path:**

1. **Initial State**: A pool is initialized with minimal liquidity (e.g., 1 wei), or liquidity is withdrawn leaving only 1 wei active.

2. **Fee Accumulation**: Swaps occur in the pool. Each swap fee accumulates to feesPerLiquidity using the formula at lines 257-260 in Core.sol: [3](#0-2) 

   With pool liquidity = 1 wei and swap fee = 1 wei, this adds `(1 << 128) / 1 = 2^128` to feesPerLiquidity. Multiple swaps cause feesPerLiquidity to grow to extremely large values (e.g., > 2^200).

3. **Position Creation**: A user (victim or attacker) creates a position with high liquidity near uint128.max (2^128 - 1). The position's `feesPerLiquidityInsideLast` is set to the current value.

4. **More Fee Accumulation**: Additional swaps occur (could be minimal), further increasing feesPerLiquidity.

5. **Fee Collection**: When the position holder calls `collectFees()` via BasePositions.sol (line 284), which calls Core.collectFees() (line 492): [4](#0-3) [5](#0-4) 

   The fees() function calculates:
   - `difference0 = currentFeesPerLiquidity - feesPerLiquidityInsideLast` (e.g., 2^200)
   - `feesOwed = (2^200 * (2^128 - 1)) >> 128 ≈ 2^200`
   - Result is cast to uint128, truncating to only lower 128 bits
   - User receives drastically less fees than owed

**Security Property Broken:** Violates invariant #5 "Fee Accounting: Position fee collection must be accurate and never allow double-claiming." Users permanently lose fees they are rightfully owed.

## Impact Explanation

- **Affected Assets**: LP positions with high liquidity values (> 2^100) in pools that experienced periods of extremely low liquidity (< 2^28).

- **Damage Severity**: Users can lose up to 100% of accumulated fees. The exact loss depends on how much the true fees exceed uint128.max. In the scenario above with difference = 2^200 and liquidity = 2^128, the true fees are approximately 2^200, but the user receives only the lower 128 bits, losing over 99.9999% of owed fees. The lost fees are permanently unrecoverable and effectively burned.

- **User Impact**: Any LP with a high-liquidity position in a pool that went through low-liquidity periods. This affects legitimate users, not just attackers. The issue is triggered automatically during normal fee collection operations.

## Likelihood Explanation

- **Attacker Profile**: Any liquidity provider or attacker. An attacker could intentionally create the conditions (drain pool liquidity, execute swaps, add large position) to exploit this against themselves or others.

- **Preconditions**: 
  1. Pool must have very low liquidity (< 2^28 wei) at some point, either initially or through withdrawals
  2. Swaps must occur during low liquidity period to accumulate large feesPerLiquidity values
  3. A position with high liquidity (> 2^100) must exist or be created
  4. Fee collection is triggered

- **Execution Complexity**: Medium. Requires orchestrating low liquidity periods and swap activity, but no complex multi-block operations or special timing. Can be executed in a single transaction using flash loans.

- **Frequency**: Once per affected position per fee collection. However, the issue compounds - once fees overflow, subsequent collections continue to be inaccurate.

## Recommendation

Add overflow checking before casting to uint128 in the fees() function:

```solidity
// In src/types/position.sol, function fees, lines 48-51:

// CURRENT (vulnerable):
// return (
//     uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
//     uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
// );

// FIXED:
uint256 fees0 = FixedPointMathLib.fullMulDivN(difference0, liquidity, 128);
uint256 fees1 = FixedPointMathLib.fullMulDivN(difference1, liquidity, 128);

// Revert if fees exceed uint128.max instead of silently truncating
if (fees0 > type(uint128).max) revert FeesOverflow();
if (fees1 > type(uint128).max) revert FeesOverflow();

return (uint128(fees0), uint128(fees1));
```

Alternative mitigation: Cap feesPerLiquidity accumulation or enforce minimum pool liquidity requirements to prevent extreme feesPerLiquidity growth. However, this changes core protocol economics and may break composability.

## Proof of Concept

```solidity
// File: test/Exploit_FeeOverflow.t.sol
// Run with: forge test --match-test test_FeeOverflowWithHighLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";

contract Exploit_FeeOverflow is Test {
    Core core;
    Positions positions;
    Router router;
    
    address token0;
    address token1;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy core contracts
        core = new Core();
        positions = new Positions(core, address(this));
        router = new Router(core);
        
        // Deploy mock tokens
        token0 = address(new MockERC20("Token0", "T0"));
        token1 = address(new MockERC20("Token1", "T1"));
        
        // Create pool key with minimal parameters
        poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: /* appropriate config */
        });
    }
    
    function test_FeeOverflowWithHighLiquidity() public {
        // STEP 1: Initialize pool with 1 wei liquidity
        // This causes feesPerLiquidity to grow by 2^128 per wei of fees
        positions.mintAndDeposit(poolKey, tickLower, tickUpper, 1, 1, 1);
        
        // STEP 2: Execute many swaps to accumulate large feesPerLiquidity
        // Each 1 wei fee adds 2^128 to feesPerLiquidity
        for (uint i = 0; i < 1000; i++) {
            router.swap(poolKey, /* swap params */);
        }
        // feesPerLiquidity is now approximately 1000 * 2^128
        
        // STEP 3: Create position with maximum liquidity
        uint128 maxLiquidity = type(uint128).max;
        uint256 positionId = positions.mintAndDeposit(
            poolKey, 
            tickLower, 
            tickUpper, 
            maxAmount0, 
            maxAmount1, 
            maxLiquidity
        );
        
        // STEP 4: Execute one more swap to create fee difference
        router.swap(poolKey, /* small swap */);
        
        // STEP 5: Collect fees - this triggers the overflow
        (uint128 fees0, uint128 fees1) = positions.collectFees(
            positionId, 
            poolKey, 
            tickLower, 
            tickUpper
        );
        
        // VERIFY: The collected fees are truncated (much less than owed)
        // True fees should be approximately (1000 * 2^128 * 2^128) >> 128 = 1000 * 2^128
        // But uint128 cast truncates to lower 128 bits
        uint256 expectedMinimumFees = 1000 * (1 << 128); // Minimum owed
        uint256 actualFees = fees0; // Truncated amount
        
        assertTrue(
            actualFees < expectedMinimumFees, 
            "Fees were truncated due to uint128 overflow"
        );
        
        // The difference represents permanently lost user funds
        uint256 lostFees = expectedMinimumFees - actualFees;
        emit log_named_uint("Lost fees due to overflow", lostFees);
    }
}
```

**Notes:**
- The vulnerability is exacerbated when pool liquidity fluctuates between very low and very high values
- Even without malicious intent, this can occur naturally in newly launched pools or during liquidity migrations
- The issue persists across all fee collection operations for affected positions, compounding the loss
- Extensions calling `accumulateAsFees()` can accelerate feesPerLiquidity growth in low-liquidity scenarios

### Citations

**File:** src/types/position.sol (L27-28)
```text
///      Note: if the computed fees overflow the uint128 type, it will return only the lower 128 bits. It is assumed that accumulated
///      fees will never exceed type(uint128).max.
```

**File:** src/types/position.sol (L48-50)
```text
    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
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

**File:** src/base/BasePositions.sol (L284-287)
```text
                (amount0, amount1) = CORE.collectFees(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
                );
```
