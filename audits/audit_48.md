# Audit Report

## Title
Silent uint128 Overflow in computeRewardAmount Causes Permanent Loss of TWAMM Order Proceeds

## Summary
The `computeRewardAmount` function in `src/math/twamm.sol` performs an unsafe cast to `uint128` that silently truncates proceeds when accumulated reward rates exceed specific thresholds. This causes users to permanently lose buyToken proceeds above `type(uint128).max` when collecting from TWAMM orders, violating the core invariant that users should be able to collect all accumulated proceeds.

## Impact
**Severity**: High

Users permanently lose all proceeds above `type(uint128).max` when the accumulated pool reward rate causes `(rewardRate * saleRate) >> 128` to exceed the uint128 maximum. The lost funds cannot be recovered, as the overflow happens during the calculation itself, and only the truncated value flows through the withdrawal process. This affects any pool where cumulative TWAMM trading volume causes reward rate accumulation beyond the overflow threshold.

## Finding Description

**Location:** `src/math/twamm.sol:48-52`, function `computeRewardAmount()`

**Intended Logic:** 
The function is designed to compute reward amounts as `(rewardRate * saleRate) >> 128` and return the proceeds to be collected by TWAMM order owners. The function comment states: "saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow." [1](#0-0) 

**Actual Logic:**
While `saleRate` is indeed constrained to `≤ type(uint112).max`, the `rewardRate` parameter is stored as `uint256` and grows unboundedly as virtual orders execute over time. The reward rate accumulates via the formula shown in the TWAMM extension: [2](#0-1) 

When the multiplication result after right-shifting exceeds `type(uint128).max`, the explicit `uint128` cast silently truncates the result. The codebase's own test suite documents this overflow behavior: [3](#0-2) 

**Exploitation Path:**

1. **Reward Rate Accumulation**: Over time, as virtual orders execute in a pool, the global reward rate accumulates. Each execution adds `(purchasedAmount << 128) / counterpartySaleRate` to the reward rate, which is stored as unbounded `uint256` in storage.

2. **Overflow Trigger**: When an order owner calls `collectProceeds`, the TWAMM extension calculates the proceeds using the accumulated reward rate: [4](#0-3) 

3. **Silent Truncation**: If `(rewardRateInside - rewardRateSnapshot) * order.saleRate() >> 128` exceeds `type(uint128).max`, the `computeRewardAmount` function returns a truncated value. This truncated value flows through the entire call chain without any overflow detection.

4. **Loss of Proceeds**: The Orders contract receives the truncated uint128 value and withdraws only this amount to the user: [5](#0-4) 

The call chain enforces uint128 throughout: [6](#0-5) 

**Security Property Broken:**
This violates the fundamental invariant that users should be able to collect all accumulated proceeds from their TWAMM orders. The protocol fails to maintain user fund accounting integrity when reward rates exceed the overflow threshold.

## Impact Explanation

**Affected Assets**: All buyToken proceeds in TWAMM orders within pools where cumulative reward rates cause overflow. This affects high-volume trading pairs processing sufficient cumulative TWAMM volume.

**Damage Severity**:
Users lose 100% of their proceeds above `type(uint128).max`. When overflow occurs at the boundary:
- True proceeds = 2^128 tokens
- Truncated proceeds = 0 tokens  
- Loss = 100% (entire proceeds)

For proceeds exceeding the threshold by larger amounts, the loss represents all bits above bit 127 of the true amount.

**User Impact**: Any TWAMM order owner attempting to collect proceeds after the pool's reward rate reaches the overflow threshold permanently loses the excess portion of their accumulated buyToken. This affects all users in the pool, not just specific orders.

**Trigger Conditions**: No special user action required - overflow occurs automatically through normal protocol operation as pools accumulate sufficient trading volume.

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a systemic accounting error affecting all users in high-volume pools.

**Preconditions**:
1. Pool must be initialized with TWAMM extension
2. Cumulative virtual order executions must accumulate `rewardRate` to threshold levels
3. Specific volume requirements depend on:
   - Token decimals (6-decimal tokens like USDC more vulnerable than 18-decimal)
   - Counterparty sale rate distribution (smaller opposing orders accelerate accumulation)
   - Time horizon (accumulation is global and monotonic)

**Execution Complexity**: Automatic - occurs through normal `collectProceeds` calls once threshold is reached.

**Frequency**: Permanent once threshold is reached for a pool. All subsequent `collectProceeds` calls on affected pools suffer from truncation.

**Overall Likelihood**: MEDIUM - Requires sustained high cumulative volume. More likely in pools with lower-decimal tokens and periods of imbalanced order flow. Achievable in major pools over extended timeframes, though not immediate.

## Recommendation

**Primary Fix:**
Change `computeRewardAmount` return type from `uint128` to `uint256` to accommodate full reward calculation:

```solidity
// In src/math/twamm.sol, function computeRewardAmount()
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint256) {
    return FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128);
}
```

**Additional Required Changes:**
1. Update all functions in the call chain to handle `uint256` proceeds:
   - `TWAMMLib.collectProceeds()` return type
   - `Orders.collectProceeds()` return type
   - `Orders.handleLockData()` proceeds variable type
   - `TWAMM.handleForwardData()` purchasedAmount handling

2. Add explicit overflow check before withdrawal if `ACCOUNTANT.withdraw()` is constrained to uint128:
```solidity
if (proceeds > type(uint128).max) {
    revert ProceedsOverflow();
}
```

**Alternative Mitigation:**
Cap reward rate accumulation at a safe threshold (e.g., 2^140) to prevent overflow while maintaining accounting within uint128 bounds. This trades off protocol scalability for safety.

## Proof of Concept

The vulnerability is demonstrated by the existing test in the codebase at `test/math/twamm.t.sol:56`, which shows that with `rewardRate = 1 << 146` and `saleRate = 1 << 110`, the function returns 0 due to uint128 overflow. This represents a scenario where the true proceeds should be 2^128, but the truncation results in complete loss.

**Notes:**

1. The function comment claiming "never expected to overflow" is demonstrably incorrect - it only accounts for `saleRate` constraints while ignoring unbounded `rewardRate` growth.

2. The reward rate is stored as `uint256` in pool storage with no upper bound, making overflow mathematically certain given sufficient cumulative trading volume.

3. The existing test documents the overflow behavior but does not assert it as correct, suggesting this may have been identified but not fully addressed.

4. The likelihood varies significantly based on token decimals and trading patterns, with 6-decimal tokens (USDC, USDT) being substantially more vulnerable than 18-decimal tokens (ETH, most ERC20s).

5. Once a pool reaches the overflow threshold, the issue affects ALL users collecting proceeds, not just specific orders, making this a systemic accounting failure rather than an isolated edge case.

### Citations

**File:** src/math/twamm.sol (L48-52)
```text
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128) {
    return uint128(FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128));
}
```

**File:** src/extensions/TWAMM.sol (L361-361)
```text
                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());
```

**File:** src/extensions/TWAMM.sol (L517-525)
```text
                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
                    }
```

**File:** test/math/twamm.t.sol (L55-56)
```text
        // overflows the uint128 container
        assertEq(computeRewardAmount({rewardRate: 1 << 146, saleRate: 1 << 110}), 0);
```

**File:** src/Orders.sol (L165-169)
```text
            uint128 proceeds = CORE.collectProceeds(TWAMM_EXTENSION, bytes32(id), orderKey);

            if (proceeds != 0) {
                ACCOUNTANT.withdraw(orderKey.buyToken(), recipient, proceeds);
            }
```

**File:** src/libraries/TWAMMLib.sol (L139-144)
```text
    function collectProceeds(ICore core, ITWAMM twamm, bytes32 salt, OrderKey memory orderKey)
        internal
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(core.forward(address(twamm), abi.encode(uint256(1), salt, orderKey)), (uint128));
    }
```
