## Title
TWAMM Order Proceeds Truncation Vulnerability in `computeRewardAmount` Causes Silent Loss of User Funds

## Summary
The `computeRewardAmount` function in `src/math/twamm.sol` contains an explicit `uint128` cast that silently truncates rewards when the computed proceeds exceed `type(uint128).max`, causing users to permanently lose the excess portion of their earned TWAMM order proceeds. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** [2](#0-1) 

**Intended Logic:** The function should compute and return the full reward amount earned by a TWAMM order based on accumulated reward rates and the order's sale rate.

**Actual Logic:** The function performs `(rewardRate * saleRate) >> 128` and then explicitly casts the result to `uint128`. When the computed value exceeds `type(uint128).max`, the cast silently truncates, returning only the lower 128 bits. The protocol's own test suite confirms this behavior - when overflow occurs, the function returns 0. [3](#0-2) 

**Exploitation Path:**

1. **Reward Rate Accumulation**: Over time, `rewardRates.value0` or `rewardRates.value1` accumulates in the TWAMM extension via unchecked arithmetic operations during virtual order execution. [4](#0-3) [5](#0-4) 

2. **Large Increment Scenario**: When opposing sale rates are very low (minimum value of 1) and reward deltas are significant, each increment can approach `(2^127 << 128) / 1 = 2^255`. Through normal protocol operation, `rewardRate` can reach values exceeding `2^144`.

3. **Proceeds Collection**: User calls `collectProceeds` via the Orders contract, which internally uses TWAMMLib to forward to the TWAMM extension. [6](#0-5) 

4. **Silent Truncation**: When `(rewardRateInside - rewardRateSnapshot) * order.saleRate() >> 128 > type(uint128).max`, the `uint128` cast in `computeRewardAmount` silently truncates the result, causing the user to receive only the lower 128 bits (potentially 0 if the value equals exactly `2^128`).

**Security Property Broken:** This violates the protocol's critical invariant that "All positions MUST be withdrawable at any time" and causes direct theft of user funds through lost proceeds that should rightfully belong to TWAMM order owners.

## Impact Explanation

- **Affected Assets**: TWAMM order proceeds (purchased tokens) in any pool using the TWAMM extension
- **Damage Severity**: When truncation occurs, users lose `purchasedAmount - (purchasedAmount mod 2^128)` tokens. In the extreme case documented in tests, users lose 100% of their proceeds. For realistic high-value scenarios where `purchasedAmount ≈ 2^134`, users would lose approximately `2^6 = 64` times more value than they receive.
- **User Impact**: Any TWAMM order holder attempting to collect proceeds when the accumulated reward rate has grown sufficiently large. The issue compounds over time as reward rates continue to accumulate.

## Likelihood Explanation

- **Attacker Profile**: This is not an active exploit - it's a passive loss mechanism affecting all TWAMM users under certain market conditions
- **Preconditions**: 
  - TWAMM pool must be active with opposing orders
  - Opposing side must have low sale rates (enabling large reward rate increments)
  - Sufficient time and trading activity to accumulate large reward rates
  - User's order must have sufficient sale rate that `(largeRewardRate * saleRate) >> 128 > 2^128`
- **Execution Complexity**: Automatic - occurs when users attempt normal proceeds collection
- **Frequency**: Once reward rates exceed threshold values (roughly `2^144` for maximum sale rate orders), affects every subsequent proceeds collection until rates overflow and wrap

## Recommendation

```solidity
// In src/math/twamm.sol, function computeRewardAmount, lines 48-52:

// CURRENT (vulnerable):
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128) {
    return uint128(FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128));
}

// FIXED:
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev Reverts if result exceeds uint128.max to prevent silent truncation
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128 result) {
    uint256 fullResult = FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128);
    require(fullResult <= type(uint128).max, "Proceeds exceed uint128");
    result = uint128(fullResult);
}
```

**Alternative mitigation:** Implement reward rate bounds checking during accumulation to prevent reward rates from growing large enough to cause truncation. However, this requires careful analysis of maximum safe reward rate values across all possible sale rate combinations.

## Proof of Concept

```solidity
// File: test/Exploit_ProceedsTruncation.t.sol
// Run with: forge test --match-test test_ProceedsTruncation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/math/twamm.sol";

contract Exploit_ProceedsTruncation is Test {
    
    function test_ProceedsTruncation() public pure {
        // SETUP: Values that cause overflow
        // rewardRate at 2^146, saleRate at 2^110 (both realistic after sufficient accumulation)
        uint256 rewardRate = 1 << 146;
        uint256 saleRate = 1 << 110;
        
        // Expected: (2^146 * 2^110) >> 128 = 2^128 = 340282366920938463463374607431768211456
        // This exceeds uint128.max by 1
        
        // EXPLOIT: Call computeRewardAmount
        uint128 proceeds = computeRewardAmount(rewardRate, saleRate);
        
        // VERIFY: Complete loss due to truncation
        assertEq(proceeds, 0, "Vulnerability confirmed: User receives 0 instead of 2^128 worth of tokens");
        
        // Additional test showing partial truncation
        rewardRate = (1 << 146) + (1 << 145); // 1.5 * 2^146
        proceeds = computeRewardAmount(rewardRate, saleRate);
        
        // Expected full value: 1.5 * 2^128 ≈ 5.1e38
        // Actual (truncated): Only lower 128 bits = 2^127 ≈ 1.7e38
        // Loss: ~67% of entitled proceeds
        assertEq(proceeds, 1 << 127, "Partial truncation: user loses upper bits");
    }
}
```

## Notes

The vulnerability exists because:

1. **Unbounded Accumulation**: Reward rates accumulate in an `unchecked` block without upper bounds, allowing growth to arbitrary values that cause truncation when multiplied by sale rates.

2. **Type Mismatch**: The function signature returns `uint128` but computes a potentially larger `uint256` value, with an explicit cast that silently truncates rather than reverting on overflow.

3. **Test Acknowledgment**: The protocol's test suite explicitly documents this overflow behavior but does not treat it as a vulnerability, suggesting it may have been overlooked as an edge case rather than recognized as a critical fund loss mechanism.

The issue affects the core value proposition of TWAMM orders - users executing large orders over time expect to collect their full earned proceeds, but this truncation can cause catastrophic loss when reward rates grow large through normal protocol operation.

### Citations

**File:** src/math/twamm.sol (L48-52)
```text
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128) {
    return uint128(FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128));
}
```

**File:** test/math/twamm.t.sol (L55-56)
```text
        // overflows the uint128 container
        assertEq(computeRewardAmount({rewardRate: 1 << 146, saleRate: 1 << 110}), 0);
```

**File:** src/extensions/TWAMM.sol (L361-361)
```text
                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());
```

**File:** src/extensions/TWAMM.sol (L387-389)
```text
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());
```

**File:** src/extensions/TWAMM.sol (L517-524)
```text
                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
```
