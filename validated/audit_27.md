# Audit Report

## Title
DOS on Native Token Swaps When Delta0 is Zero Due to Missing Refund Logic

## Summary
The Router's ETH refund logic is incorrectly nested inside a `balanceUpdate.delta0() != 0` condition, causing legitimate user transactions to revert when native ETH is sent but the swap results in zero delta. This violates the FlashAccountant's invariant that all debts must be settled before lock completion.

## Impact
**Severity**: Medium

Users attempting to swap native ETH with parameters that result in `delta0() == 0` will experience transaction reverts with `DebtsNotZeroed`, wasting gas fees. While no permanent fund loss occurs (the entire transaction reverts), this creates a DOS condition for legitimate swap configurations, particularly when `sqrtRatioLimit` equals the current pool price or when pools lack liquidity in the specified range.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData`, lines 133-146 [1](#0-0) 

**Intended Logic:** 
When swapping native ETH as token0, the Router should calculate the difference between sent value and actual swap delta, then refund any excess ETH to the swapper regardless of whether a swap occurred.

**Actual Logic:**
The ETH refund logic at lines 134-142 only executes when `balanceUpdate.delta0() != 0`. When a swap results in `delta0() == 0` but the user sent ETH (`value > 0`), this entire refund block is skipped, leaving unhandled negative debt that causes the lock to fail.

**Exploitation Path:**

1. **Setup**: User initiates swap with `router.swap{value: 1000}()` where `poolKey.token0 == NATIVE_TOKEN_ADDRESS`, `amount = 1000` (exact input), and `sqrtRatioLimit` set to current pool price

2. **Value Calculation**: Router calculates `value = 1000` because the swap meets all conditions (not token1, not exact out, token0 is native): [2](#0-1) 

3. **No-op Swap**: Core.swap receives `msg.value = 1000` but the condition `stateAfter.sqrtRatio() != sqrtRatioLimit` fails because they're equal, resulting in a no-op swap with `balanceUpdate = (0, 0)`: [3](#0-2) 

4. **Debt Adjustment**: Despite the no-op swap, Core's `_updatePairDebtWithNative` adjusts debt by `debtChange0 - msg.value = 0 - 1000 = -1000`, crediting the locker with negative debt (protocol owes 1000 wei back): [4](#0-3) 

5. **Skipped Refund**: Back in Router, the check `if (balanceUpdate.delta0() != 0)` evaluates to FALSE, causing the entire refund logic block to be skipped. The -1000 native token debt remains unhandled.

6. **Revert on Lock End**: When the lock completes, FlashAccountant detects `nonzeroDebtCount > 0` and reverts with `DebtsNotZeroed`: [5](#0-4) 

**Security Property Broken:**
FlashAccountant's core invariant requires all debts to be settled to zero before lock completion. The negative debt (credit) from sent ETH remains unhandled, violating this invariant.

## Impact Explanation

**Affected Assets**: Native ETH sent by users in swap transactions that result in zero delta

**Damage Severity**:
- Users lose gas fees on reverted transactions (can be significant during high gas periods)
- Creates DOS condition preventing certain legitimate swap configurations
- No permanent loss of swap value (ETH returned via transaction revert)
- Affects any user who sends ETH with swap parameters resulting in `delta0() == 0`

**User Impact**: Legitimate users making honest swap attempts, particularly during high volatility when market prices move to their specified limits between transaction submission and execution

**Trigger Conditions**: Any swap meeting these criteria:
- Pool with `NATIVE_TOKEN_ADDRESS` as token0
- User sends ETH with exact input swap
- Swap results in `delta0() == 0` (most commonly when `sqrtRatioLimit` equals current pool price)

## Likelihood Explanation

**Attacker Profile**: Not malicious—affects legitimate users making honest transactions

**Preconditions**:
1. Pool initialized with native ETH as token0 (common)
2. User sends ETH (`value > 0`) with exact input swap (standard operation)
3. Swap results in `delta0() == 0` (occurs when sqrtRatioLimit equals current price, or pool lacks liquidity in specified range)

**Execution Complexity**: Single transaction, no special setup required, can occur naturally

**Economic Cost**: Only gas fees, no capital required

**Frequency**: Occurs whenever preconditions are met—more likely during:
- High volatility when prices move to user-specified limits
- User error in setting sqrtRatioLimit to current price
- Pools with sparse liquidity

**Overall Likelihood**: MEDIUM - Straightforward to trigger, requires common conditions that occur naturally

## Recommendation

Restructure the logic to always handle native token refunds when `value > 0`, regardless of whether `delta0()` is zero:

```solidity
// Handle native token refund regardless of delta0() value
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    if (valueDifference > 0) {
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
    }
} else if (balanceUpdate.delta0() != 0) {
    ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
}
```

This ensures that when native ETH is sent, the refund calculation executes regardless of the swap outcome, properly withdrawing any negative debt created by Core's debt adjustment.

## Notes

This vulnerability specifically affects native token (ETH) swaps where the swap execution results in `delta0() == 0`. The bug does NOT affect:
- Non-native token swaps (ERC20 tokens) - handled correctly even when delta is zero
- Swaps where `delta0()` is non-zero - refund logic executes correctly  
- The "increasing" branch (lines 121-127) - different code path without ETH refund logic

The root cause is the assumption that if `delta0() == 0`, no payment or refund is needed. However, when `msg.value` is sent, Core ALWAYS adjusts debt by subtracting `msg.value` (line 344), even if the swap does nothing. This creates a negative debt (credit) that must be withdrawn, but the Router's conditional check prevents this from happening.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L133-146)
```text
                    if (balanceUpdate.delta0() != 0) {
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
```

**File:** src/Core.sol (L340-344)
```text
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
```

**File:** src/Core.sol (L540-541)
```text
            // 0 swap amount or sqrt ratio limit == sqrt ratio is no-op
            if (amountRemaining != 0 && stateAfter.sqrtRatio() != sqrtRatioLimit) {
```

**File:** src/base/FlashAccountant.sol (L175-180)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
```
