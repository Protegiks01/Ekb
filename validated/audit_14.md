# Audit Report

## Title
Cross-User ETH Theft in Router via Pooled Balance Exploitation in Exact Output Swaps

## Summary
The Router contract fails to isolate native ETH (`msg.value`) per transaction, enabling direct theft of user funds. When users send excess `msg.value` that remains in the Router's balance, subsequent users can execute exact output swaps with minimal `msg.value`, causing the Router to use the pooled balance (including trapped funds from previous users) to settle their debt. This violates the fundamental security property that each user's funds should only be used for their own transactions.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds through cross-transaction balance exploitation. Any ETH trapped in the Router becomes available for subsequent attackers to steal via exact output swaps while deliberately underpaying. An attacker can monitor the Router's balance on-chain and execute theft transactions with minimal capital risk, stealing 100% of accumulated trapped ETH.

## Finding Description

**Location:** `src/Router.sol:106-110, 134-146`, function `handleLockData()`

**Intended Logic:**
Each user's `msg.value` should only be used to settle their own swap debt. The Router provides `refundNativeToken()` to allow users to recover excess ETH, implying per-user fund ownership. [1](#0-0)  The FlashAccountant correctly tracks debt per lock ID. [2](#0-1) 

**Actual Logic:**
The Router calculates `value` based on swap parameters (exact input/output logic), NOT based on the actual `msg.value` sent by the user. [3](#0-2)  For exact output swaps, `value = 0` regardless of `msg.value`. When payment is required, `SafeTransferLib.safeTransferETH` transfers from the Router's **total balance**, which includes accumulated ETH from all previous users. [4](#0-3)  The Router never validates that `msg.value` matches the required payment amount, and never isolates ETH per lock ID.

**Exploitation Path:**

1. **User A traps ETH**: User A calls `Router.swap{value: 10 ETH}()` with exact input parameters requiring only 5 ETH. The Router calculates `value = 5 ETH`, forwards 5 ETH to Core via `_swap()`, but the remaining 5 ETH stays in the Router's balance. User A doesn't use multicall with `refundNativeToken()`.

2. **Attacker exploits**: User B (attacker) calls `Router.swap{value: 1 ETH}()` with exact output parameters. Because `params.isExactOut() == true`, the ternary condition at line 107 evaluates to false, setting `value = 0`.

3. **Swap determines cost**: The swap executes and determines `balanceUpdate.delta0() = 4 ETH` is needed to achieve the desired output.

4. **Pooled balance used**: At line 135, `valueDifference = 0 - 4 = -4`. Line 141 executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 4 ETH)`, which transfers 4 ETH from the Router's total balance (5 ETH from User A + 1 ETH from User B = 6 ETH available).

5. **Debt settled with stolen funds**: The 4 ETH reaches Core's `receive()` function, which credits -4 ETH to User B's lock debt (current lock ID). User B's debt goes from +4 ETH to 0 ETH, transaction succeeds.

6. **Theft complete**: User B paid 1 ETH but received tokens worth 4 ETH. The 3 ETH difference was stolen from User A's trapped funds.

**Security Property Broken:**
Violates the fund isolation invariant - each user's transaction should only use that user's funds. The Router's failure to isolate `msg.value` per lock ID enables theft across transactions.

## Impact Explanation

**Affected Assets**: All native ETH sent to the Router via `msg.value` that exceeds the calculated swap amount. Every user performing native token swaps without using multicall + `refundNativeToken()` is at risk.

**Damage Severity**:
- Attacker can steal 100% of trapped ETH in the Router contract
- If Router accumulates 50 ETH from multiple users, attacker can drain it with a single exact output swap while sending minimal `msg.value`
- Sophisticated attackers can monitor `Router.balance` on-chain and strategically execute theft transactions
- Creates a "first come first served" attack surface where fastest attackers drain accumulated funds

**User Impact**:
- Users who overpay lose excess ETH permanently to attackers
- Honest users may unknowingly use others' trapped ETH, creating complex liability issues
- No warning or revert when users send excess `msg.value`
- Protocol reputation damage from direct user fund theft

**Trigger Conditions**: Single transaction exploit requiring only:
1. Router has non-zero ETH balance (common if any user overpaid)
2. Pool with `token0 == NATIVE_TOKEN_ADDRESS` exists with liquidity
3. Attacker has minimal ETH for gas + small `msg.value`

## Likelihood Explanation

**Attacker Profile**: Any user (EOA or contract) with basic protocol knowledge. No special permissions required.

**Preconditions**:
1. Router must have trapped ETH from previous users (highly likely, as users commonly overpay or don't know about `refundNativeToken()`)
2. Active pool with native token as token0 (standard configuration)
3. Pool has sufficient liquidity for the exact output swap

**Execution Complexity**: Single transaction calling `Router.swap()` with exact output parameters and minimal `msg.value`. No complex MEV, front-running, or multi-step setup required.

**Economic Cost**: Only gas fees plus minimal `msg.value` (can be 1 wei). No capital lockup or risk.

**Frequency**: Continuously exploitable. Every time ETH is trapped in Router, attackers can steal it. Attack can be repeated across multiple transactions until Router is drained.

**Overall Likelihood**: HIGH - Trivial single-transaction exploit with high probability of preconditions (users commonly overpay), affecting any user who doesn't use multicall pattern.

## Recommendation

**Primary Fix: Per-lock ETH tracking with validation**
Track ETH sent per lock ID using transient storage and validate that payments come from the tracked amount rather than the contract's total balance. At lock end, verify all tracked ETH was consumed or explicitly refunded.

**Alternative Fix: Auto-refund excess ETH**
Automatically refund `address(this).balance` to `msg.sender` at the end of each lock, eliminating the need for explicit `refundNativeToken()` calls and preventing ETH accumulation.

**Alternative Fix: Validate msg.value matches required payment**
Add validation that when `SafeTransferLib.safeTransferETH` is called at line 141, the amount being sent does not exceed the current transaction's `msg.value`.

**Additional Mitigations**:
- Document that users MUST use multicall with `refundNativeToken()` when sending native tokens
- Emit events when ETH remains in Router after lock completion for monitoring
- Consider adding a `maxETH` parameter to swap functions as an upper bound check

## Proof of Concept

A Foundry PoC would demonstrate:
1. User A sends 10 ETH for a 5 ETH exact input swap, leaving 5 ETH trapped in Router
2. User B performs exact output swap requiring 4 ETH but sends only 1 ETH via `msg.value`
3. User B successfully completes swap and receives tokens
4. User B's actual cost is only 1 ETH despite swap requiring 4 ETH
5. Router balance decreased by 4 ETH (from 6 ETH to 2 ETH), proving User A's funds were used

**Expected PoC Result:**
- **If Vulnerable**: All assertions pass, User B completes 4 ETH swap while paying only 1 ETH
- **If Fixed**: Transaction reverts with "Insufficient payment" or "Excess ETH not refunded"

## Notes

This vulnerability stems from an architectural mismatch: the FlashAccountant correctly implements per-lock debt tracking, but the Router fails to implement per-lock ETH isolation. While `PayableMulticallable` provides `refundNativeToken()` as a recovery mechanism, the design flaw is that trapped ETH is accessible to ANY subsequent transaction, not just the original sender.

The root cause is that `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount)` transfers from the contract's total balance using standard Solidity `call{value}` semantics, with no tracking of which ETH belongs to which lock/user. This creates a pooled balance that violates the isolation principle required for secure multi-user contracts.

The vulnerability is particularly severe because:
1. Users have no indication when they've sent excess `msg.value`
2. The protocol doesn't enforce or clearly document the multicall + refund pattern
3. User mistakes (overpaying) should not enable theft by other users
4. The attack is economically rational and easily automated

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/base/FlashAccountant.sol (L384-393)
```text
    receive() external payable {
        uint256 id = _getLocker().id();

        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
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

**File:** src/Router.sol (L134-146)
```text
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
