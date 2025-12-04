# Audit Report

## Title
Native Token Payment Logic Asymmetry in Router Enables ETH Theft

## Summary
The Router contract's `handleLockData` function contains a critical asymmetry in native ETH payment logic. When users perform exact-output swaps to buy token1 with native ETH (token0), the Router incorrectly sets `value=0` and pays from its accumulated balance instead of the user's `msg.value`, enabling attackers to drain accumulated ETH by executing identical swaps with zero payment.

## Impact
**Severity**: High

Users performing exact-output swaps with native ETH lose any excess ETH sent beyond the exact amount required, as it accumulates in the Router contract. Attackers can then drain this accumulated ETH by executing identical swaps with `msg.value=0`, causing the Router to use its balance to pay for the attacker's swap, resulting in free tokens for the attacker and permanent loss for victims.

## Finding Description

**Location:** `src/Router.sol:106-147`, function `handleLockData()` [1](#0-0) 

**Intended Logic:** 
The Router should consistently handle native token payments by either: (1) forwarding user's `msg.value` to Core and settling via `valueDifference` refund logic, or (2) validating that `msg.value` covers the required payment before using Router's balance.

**Actual Logic:**
The `value` variable calculation only accounts for ONE scenario: exact-input swaps of token0 when token0 is native ETH. It fails to account for exact-output swaps where token1 is purchased with native ETH (token0). [2](#0-1) 

When `isToken1=true` and `isExactOut=true` with `token0=NATIVE_TOKEN_ADDRESS`:
- `increasing = params.isPriceIncreasing()` evaluates to `true XOR true = false`
- The `increasing=false` branch executes at lines 128-147 [3](#0-2) 

In this branch, when `delta0 > 0` (pool requires ETH payment):
- `valueDifference = int256(0) - int256(delta0) = -delta0` (negative)
- Line 141 executes: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)))`
- This transfers ETH from **Router's balance**, not from the user's `msg.value`
- User's `msg.value` remains stuck in Router contract

**Exploitation Path:**
1. **Victim Setup**: User calls `Router.swap{value: 10 ether}(poolKey, params, threshold)` where `params` has `isToken1=true`, `amount=-1 ether` (exact output), and `poolKey.token0=NATIVE_TOKEN_ADDRESS`
2. **Partial Use**: Swap calculates `delta0 = 1.05 ether` needed. Router transfers 1.05 ETH from its balance to Accountant (line 141). User's 10 ETH remains in Router.
3. **Accumulation**: Excess 8.95 ETH sits in Router contract
4. **Attacker Exploitation**: Attacker calls `Router.swap{value: 0}(poolKey, params, threshold)` with identical parameters
5. **Theft**: Router uses the accumulated 8.95 ETH to pay for attacker's swap, giving attacker tokens without payment
6. **Result**: Victim loses 8.95 ETH permanently, attacker gains tokens for free

**Security Property Broken:**
User fund isolation - one user's `msg.value` should never be usable to pay for another user's transactions. The Router acts as an unintended escrow that allows first-come-first-served access to accumulated native token balances.

## Impact Explanation

**Affected Assets**: All native ETH sent by users performing exact-output swaps with `isToken1=true` and `token0=NATIVE_TOKEN_ADDRESS`

**Damage Severity**:
- Users lose 100% of excess ETH sent beyond the calculated delta amount
- No automatic refund mechanism - requires separate `refundNativeToken()` call creating race condition
- Attackers can drain entire accumulated Router balance through repeated zero-value swaps
- Unlimited loss potential - scales with Router balance accumulation

**User Impact**: Any user performing this specific swap pattern with excess ETH loses funds. The existence of `refundNativeToken()` as a separate function suggests the design acknowledges ETH accumulation but provides insufficient protection. [4](#0-3) 

**Trigger Conditions**: Single transaction by unprivileged attacker

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or contract. No special permissions, initial capital, or privileged position required beyond gas fees.

**Preconditions**:
1. Router must have accumulated ETH balance from previous victims (trivially observable via block explorer)
2. Pool with native token0 must exist and be initialized (common for major tokens)
3. Sufficient liquidity for swap execution (normal operating condition)

**Execution Complexity**: Single transaction calling `Router.swap{value: 0}()` with correct parameters. No multi-block coordination, no front-running required, no complex state manipulation needed.

**Economic Cost**: Only gas fees (~$5-20 depending on network). No capital lockup or slippage costs.

**Frequency**: Continuously exploitable. Each time Router accumulates ETH from victims, attacker can drain it. Multiple attackers can compete to drain accumulated funds.

**Overall Likelihood**: HIGH - Trivial execution, clear economic incentive, no barriers to entry

## Recommendation

**Primary Fix:**
Add comprehensive value calculation that accounts for ALL scenarios where native token0 needs to be paid:

```solidity
// In src/Router.sol, handleLockData function, around line 106:

// Calculate if ETH needs to be sent upfront to Core
bool needsEthForToken0 = poolKey.token0 == NATIVE_TOKEN_ADDRESS && (
    (!params.isToken1() && !params.isExactOut()) ||  // Exact input of ETH
    (params.isToken1() && params.isExactOut())       // Exact output of token1, paying with ETH
);

uint256 value = needsEthForToken0 ? address(this).balance : 0;
```

Then ensure refund logic properly handles excess sent to Core in both branches.

**Alternative Fix (more conservative):**
Revert on unsupported pattern until proper handling is implemented:

```solidity
// Add before swap execution:
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && params.isToken1() && params.isExactOut()) {
    revert UnsupportedNativeTokenSwapDirection();
}
```

**Additional Mitigations**:
- Add `msg.value` validation to ensure users aren't unknowingly contributing to shared Router balance
- Consider tracking per-lock `msg.value` to prevent cross-contamination
- Document expected behavior for native token swaps clearly

## Proof of Concept

The provided PoC logic is conceptually correct but requires proper pool initialization and token setup. The core vulnerability flow is:

1. Deploy Router and Core
2. Create pool with `token0=NATIVE_TOKEN_ADDRESS`, `token1=MockERC20`
3. Add liquidity to pool
4. Victim calls `Router.swap{value: 10 ether}(poolKey, {isToken1:true, amount:-1 ether, ...}, threshold)`
5. Verify Router balance increased by ~9 ether (excess not used)
6. Attacker calls `Router.swap{value: 0}(poolKey, {isToken1:true, amount:-1 ether, ...}, threshold)`
7. Verify attacker received token1 output without paying ETH
8. Verify Router balance decreased by ~1 ether (used victim's funds)

**Expected Result**: Attacker gains tokens, victim loses 9 ETH, Router balance reduced

## Notes

The vulnerability stems from incomplete handling of the four possible native token swap scenarios:
1. ✅ Exact input token0 (native) → token1: Correctly sends `value` to Core
2. ✅ Exact output token0 (native) → token1: Correctly handles via ERC20 `payFrom`
3. ✅ Exact input token1 → token0 (native): Correctly withdraws from Accountant
4. ❌ **Exact output token1 ← token0 (native)**: Incorrectly uses Router balance instead of msg.value

The asymmetry between increasing/decreasing branches and the reliance on `SafeTransferLib.safeTransferETH` from Router's undifferentiated balance creates the exploit vector. The existence of `refundNativeToken()` acknowledges accumulation but doesn't prevent theft.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L112-112)
```text
                bool increasing = params.isPriceIncreasing();
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
