# Audit Report

## Title
Excess Native Token (ETH) in Router Can Be Stolen by Any User via Unprotected refundNativeToken()

## Summary
The `refundNativeToken()` function in PayableMulticallable (inherited by Router) allows any caller to drain the entire ETH balance without ownership verification. When users send excess ETH to swap functions, the surplus accumulates because the Router only forwards the calculated required amount to Core, leaving the difference vulnerable to theft by any attacker monitoring the contract balance.

## Impact
**Severity**: High - Direct theft of user funds

This vulnerability enables complete theft of all accumulated excess ETH in the Router contract. Any user who sends more ETH than required for their swap loses the surplus to whoever calls `refundNativeToken()` first. The impact scales with protocol usage - if multiple users overpay before an attacker claims the balance, a single transaction steals from all victims simultaneously.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The function is documented to "allow callers to recover ETH that was sent for transient payments but not fully consumed," suggesting it should only refund ETH belonging to the caller.

**Actual Logic:**
The function unconditionally transfers the Router's entire ETH balance to `msg.sender` without any tracking of who deposited what amount.

**Exploitation Path:**

1. **Victim overpays on single swap**: User calls `router.swap{value: 10 ETH}(...)` for a swap requiring only 5 ETH. The Router calculates `value = 5 ETH` based on swap parameters [2](#0-1) , then forwards exactly 5 ETH to Core via assembly call [3](#0-2) .

2. **Incomplete refund mechanism**: The refund logic only handles the difference between the calculated `value` and actual `balanceUpdate.delta0()` [4](#0-3) . Since both equal 5 ETH, `valueDifference = 0` and no refund occurs. The logic never accounts for `msg.value - value`, leaving 5 ETH stuck in the Router.

3. **Multihop swaps worse**: For multihop swaps, `_swap()` is called with `value=0` [5](#0-4) , and only `totalSpecified` amount is transferred to the Accountant [6](#0-5) . There is no automatic refund mechanism at all.

4. **Attacker steals accumulated ETH**: Attacker calls `router.refundNativeToken()`, which sends the entire balance to them.

**Security Property Broken:**
Users should not lose funds to other unprivileged actors. The fundamental security property that user assets remain under their control unless explicitly authorized is violated.

## Impact Explanation

**Affected Assets**: Native ETH sent by any user performing swaps through the Router contract.

**Damage Severity**:
- Attackers can drain 100% of accumulated excess ETH in a single transaction
- Complete and permanent loss for all victims whose excess ETH remains unclaimed
- No recovery mechanism exists once stolen
- Scales with protocol adoption - more users means more accumulated ETH to steal

**User Impact**: Any user who sends more ETH than precisely required becomes a victim, including:
- Users who manually miscalculate required amounts
- Frontends that don't calculate exact ETH requirements
- Users whose transactions execute at different prices than when submitted (slippage/price movement reducing required ETH)
- Multicall users who don't explicitly include a refund call at the end

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or contract - no special permissions, positions, or capital required.

**Preconditions**:
1. One or more users must have sent excess ETH to Router (highly likely given calculation complexity and price volatility)
2. Router must have non-zero ETH balance
3. No pool initialization, liquidity requirements, or complex state dependencies

**Execution Complexity**: Single function call with no parameters. Can be automated with a simple monitoring bot that watches `address(router).balance` and immediately calls `refundNativeToken()` when non-zero.

**Economic Cost**: Only gas fees (~$5-20 depending on network conditions), no capital lockup.

**Frequency**: Continuously exploitable. Can target every overpayment, multiple times per block if multiple users overpay.

**Overall Likelihood**: HIGH - Trivial to execute, affects all users, easily automated.

## Recommendation

**Primary Fix - Track ETH Ownership Per Caller:**

Modify PayableMulticallable to track deposits per address and only refund what belongs to the caller. This requires adding state storage and updating swap functions to track usage.

**Alternative Fix - Automatic Full Refund:**

Modify Router's `handleLockData` to automatically refund the entire Router balance to the swapper at the end of each swap operation (both single and multihop), ensuring no ETH ever accumulates.

**Nuclear Option - Remove Function:**

Remove `refundNativeToken()` entirely and require users to send exact amounts. Add validation to revert if `msg.value` exceeds requirements.

## Proof of Concept

The provided PoC demonstrates the vulnerability by showing:
1. Victim sends 10 ETH for a 5 ETH swap
2. 5 ETH remains in Router (verified by balance check)
3. Attacker calls `refundNativeToken()` and steals the 5 ETH
4. Victim cannot recover their funds

**Expected PoC Result:**
- Router balance goes from 5 ETH to 0 ETH
- Attacker balance increases by 5 ETH
- Victim has no recourse to recover stolen funds

## Notes

This vulnerability exists because the `refundNativeToken()` function has external visibility with no access control and no per-user accounting. The mismatch between `msg.value` (what user sends) and the calculated `value` parameter (what Router forwards to Core) creates the exploitable gap. The comment in PayableMulticallable suggests the design intent was to help users recover excess payments, but without ownership tracking, it instead creates a race condition where first caller wins all accumulated ETH.

The issue affects both single and multihop swaps through different code paths, but the root cause is identical: no mechanism exists to refund `msg.value - actualUsed` back to the original sender, and the refund function allows any caller to claim all accumulated funds.

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L135-142)
```text
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/Router.sol (L189-190)
```text
                        (PoolBalanceUpdate update,) = _swap(
                            0,
```

**File:** src/Router.sol (L229-230)
```text
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
```

**File:** src/libraries/CoreLib.sol (L139-139)
```text
            if iszero(call(gas(), core, value, free, 132, free, 64)) {
```
