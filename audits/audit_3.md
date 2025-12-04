# Audit Report

## Title
Cross-User ETH Theft in Router via Pooled Balance Exploitation in Exact Output Swaps

## Summary
The Router contract fails to isolate native ETH (`msg.value`) per transaction, allowing subsequent users to exploit trapped ETH from previous users. When User A sends excess `msg.value` that remains in the Router's balance, User B can perform an exact output swap with minimal `msg.value` and the Router will use the pooled balance (including User A's funds) to settle User B's debt, resulting in direct theft.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds through cross-transaction balance exploitation. Any ETH trapped in the Router (from users who send more `msg.value` than needed and don't call `refundNativeToken()`) becomes available for subsequent users to steal. An attacker can monitor the Router's balance and execute exact output swaps while deliberately underpaying, causing the Router to use trapped funds to complete their payment. This violates the fundamental security property that each user's funds should only be used for their own transactions.

## Finding Description

**Location:** `src/Router.sol:106-110, 134-146`, function `handleLockData()`

**Intended Logic:**
Each user's `msg.value` should only be used to settle their own swap debt. The Router provides `refundNativeToken()` [1](#0-0)  to allow users to recover excess ETH, implying per-user fund ownership. The flash accounting system correctly tracks debt per lock ID [2](#0-1) .

**Actual Logic:**
The Router calculates `value` based on swap parameters (exact input/output logic) at lines 106-110 [3](#0-2) , NOT based on the actual `msg.value` sent by the user. For exact output swaps, `value = 0` regardless of `msg.value`. When payment is required (line 141), `SafeTransferLib.safeTransferETH` transfers from the Router's **total balance** [4](#0-3) , which includes accumulated ETH from all previous users. The Router never validates that `msg.value` matches the required payment amount, and never isolates ETH per lock ID.

**Exploitation Path:**

1. **User A traps ETH**: User A calls `Router.swap{value: 10 ETH}()` with exact input parameters requiring only 5 ETH. The Router calculates `value = 5 ETH`, sends 5 ETH to Core, but the remaining 5 ETH stays in the Router's balance. User A doesn't use multicall with `refundNativeToken()`.

2. **Attacker exploits**: User B (attacker) calls `Router.swap{value: 1 ETH}()` with exact output parameters. Because `params.isExactOut() == true`, line 107 sets `value = 0`.

3. **Swap determines cost**: The swap executes and determines `balanceUpdate.delta0() = 4 ETH` is needed to achieve the desired output.

4. **Pooled balance used**: At line 135, `valueDifference = 0 - 4 = -4`. Line 141 executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 4 ETH)`, which transfers 4 ETH from the Router's total balance (5 ETH from User A + 1 ETH from User B = 6 ETH available).

5. **Debt settled with stolen funds**: The 4 ETH reaches Core's `receive()` function, which credits -4 ETH to User B's lock debt. User B's debt goes from +4 ETH to 0 ETH, transaction succeeds.

6. **Theft complete**: User B paid 1 ETH but received tokens worth 4 ETH. The 3 ETH difference was stolen from User A's trapped funds.

**Security Property Broken:**
Violates the solvency and fund isolation invariant - each user's transaction should only use that user's funds. The Router's failure to isolate `msg.value` per lock ID enables theft across transactions.

## Impact Explanation

**Affected Assets**: All native ETH sent to the Router via `msg.value` that exceeds the calculated swap amount. Every user performing native token swaps without using multicall + `refundNativeToken()` is at risk.

**Damage Severity**:
- Attacker can steal 100% of trapped ETH in the Router contract
- If Router accumulates 50 ETH from multiple users, attacker can drain it with a single 50 ETH exact output swap while sending only 1 wei via `msg.value`
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
1. Router must have trapped ETH from previous users (likely, as users commonly overpay or don't know about `refundNativeToken()`)
2. Active pool with native token as token0 (standard configuration)
3. Pool has sufficient liquidity for the exact output swap

**Execution Complexity**: Single transaction calling `Router.swap()` with exact output parameters and minimal `msg.value`. No complex MEV, front-running, or multi-step setup required.

**Economic Cost**: Only gas fees (~$5-20) plus minimal `msg.value` (can be 1 wei). No capital lockup or risk.

**Frequency**: Continuously exploitable. Every time ETH is trapped in Router, attackers can steal it. Attack can be repeated across multiple transactions until Router is drained.

**Overall Likelihood**: HIGH - Trivial single-transaction exploit with high probability of preconditions (users commonly overpay), affecting any user who doesn't use multicall pattern.

## Recommendation

**Primary Fix: Validate msg.value and revert on excess**
```solidity
// In src/Router.sol, function handleLockData
// Store msg.value at lock start in transient storage
// At lock end, verify msg.value was fully used or explicitly refunded

// Option: Add check after line 146
if (msg.value > 0 && address(this).balance >= msg.value) {
    revert ExcessETHNotRefunded();
}
```

**Alternative Fix: Auto-refund excess ETH**
Modify `handleLockData` to automatically refund `address(this).balance` to `msg.sender` at the end of the lock, eliminating the need for explicit `refundNativeToken()` calls.

**Alternative Fix: Per-lock ETH isolation**
Track ETH sent per lock ID using transient storage:
```solidity
// At lock start: tstore(LOCK_ETH_SLOT + lockId, msg.value)
// At line 141: Use tracked amount instead of contract balance
// At lock end: Verify tracked amount was fully consumed
```

**Additional Mitigations**:
- Document that users MUST use multicall with `refundNativeToken()` when sending native tokens
- Consider adding a `maxETH` parameter to swap functions as an upper bound check
- Emit events when ETH is trapped in Router for monitoring

## Proof of Concept

The provided PoC demonstrates:
1. User A sends 10 ETH for a 5 ETH swap, leaving 5 ETH trapped
2. User B performs exact output swap requiring 4 ETH but sends only 1 ETH
3. User B successfully completes swap (receives tokens)
4. User B's actual cost is only ~1 ETH despite needing 4 ETH
5. Router balance decreased by more than User B's payment, proving User A's funds were used

**Expected PoC Result:**
- **If Vulnerable**: Assertions pass, User B spends ~1 ETH but completes 4 ETH swap, Router balance decreases by 4 ETH
- **If Fixed**: Transaction reverts with "Excess ETH not refunded" or "Insufficient payment"

## Notes

This vulnerability stems from an architectural mismatch: the FlashAccountant correctly implements per-lock debt tracking, but the Router fails to implement per-lock ETH isolation. While `PayableMulticallable` provides `refundNativeToken()` as a recovery mechanism, the design flaw is that trapped ETH is accessible to ANY subsequent transaction, not just the original sender.

The root cause is that `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount)` at line 141 [5](#0-4)  transfers from the contract's total balance using standard Solidity `call{value}` semantics, with no tracking of which ETH belongs to which lock/user. This creates a pooled balance that violates the isolation principle required for secure multi-user contracts.

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
