# Audit Report

## Title
Native Token Payment Logic Asymmetry in Router Enables ETH Theft via Accumulated Balance Exploitation

## Summary
The Router contract's `handleLockData` function contains an incomplete native ETH payment calculation that only accounts for exact-input swaps of token0, failing to handle exact-output swaps where token1 is purchased with native token0. This causes user-sent ETH to accumulate in the Router contract instead of being properly associated with their swap, enabling attackers to drain accumulated funds by executing identical swaps with zero value that consume the Router's shared balance.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds. When users perform exact-output swaps to buy token1 with native ETH as token0, their `msg.value` accumulates in the Router contract while the Router uses its existing balance to pay for the swap. Attackers can then execute identical swaps with `msg.value=0`, causing the Router to use the accumulated ETH (victims' funds) to pay for the attacker's transactions, resulting in free tokens for attackers and permanent, irrecoverable loss for victims. The attack requires only a single transaction and minimal gas costs, with unlimited loss potential scaling with accumulated Router balance.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The Router should consistently handle native token payments by forwarding the user's `msg.value` to Core when token0 is the native token and payment is required, with proper refund logic for any excess sent.

**Actual Logic:**
The `value` variable calculation at lines 106-110 only evaluates to non-zero for the single scenario: `!params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS`. This fails to account for exact-output swaps where token1 is purchased with native token0 (token0 payment required). [2](#0-1) 

When `isToken1=true` and `isExactOut=true` with `token0=NATIVE_TOKEN_ADDRESS`, the price direction calculation at line 112 yields `increasing = isPriceIncreasing() = isExactOut XOR isToken1 = true XOR true = false`, confirmed by the implementation: [3](#0-2) 

This directs execution to the `increasing=false` branch (lines 128-147). When `delta0 > 0` (pool requires ETH payment for token0), the native token handling logic executes: [4](#0-3) 

Since `value=0`, line 135 calculates `valueDifference = 0 - delta0 = -delta0` (negative). Line 141 then executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)))`, which transfers ETH from the **Router's contract balance**, not from the user's `msg.value`. The user's sent ETH remains trapped in the Router contract, available for any subsequent caller.

**Exploitation Path:**
1. **Victim Transaction**: User calls `Router.swap{value: 10 ether}(poolKey, params, threshold)` where `params.isToken1()=true`, `params.amount()=-1 ether` (exact output), `poolKey.token0=NATIVE_TOKEN_ADDRESS`
2. **Accumulation**: Swap requires 1.05 ETH. Router transfers 1.05 ETH from its balance to ACCOUNTANT (line 141). User's 10 ETH remains in Router, creating 8.95 ETH excess
3. **Attack**: Attacker observes Router balance, calls `Router.swap{value: 0}(poolKey, params, threshold)` with identical parameters
4. **Theft**: Router again uses its balance (victim's 8.95 ETH) to pay for attacker's swap via line 141
5. **Result**: Attacker receives tokens without payment, victim loses 8.95 ETH permanently

**Security Property Broken:**
User fund isolation - each user's `msg.value` should only be usable for their own transaction within the lock. The Router's shared balance model allows first-come-first-served consumption across unrelated users.

## Impact Explanation

**Affected Assets**: All native ETH sent by users performing exact-output swaps with `isToken1=true` and `token0=NATIVE_TOKEN_ADDRESS`

**Damage Severity:**
- Victims lose 100% of excess ETH sent beyond the exact swap requirement
- No automatic refund - requires manual `refundNativeToken()` call which is racy
- Attackers can drain entire accumulated Router balance through repeated zero-value swaps
- Loss scales linearly with Router accumulation from multiple victims [5](#0-4) 

The existence of `refundNativeToken()` suggests acknowledgment of potential accumulation, but it provides insufficient protection as it's callable by anyone and subject to front-running by exploiters.

**User Impact**: Any user performing this swap pattern loses their excess funds with no recourse. The vulnerability is not self-evident to users who reasonably expect standard DEX refund behavior.

**Trigger Conditions**: Single transaction by any unprivileged attacker, observable via Router balance checks on block explorer

## Likelihood Explanation

**Attacker Profile**: Any EOA or contract with no special permissions, initial capital requirements, or privileged position beyond gas fees

**Preconditions:**
1. Router must have accumulated ETH balance from previous victims (publicly observable on-chain)
2. Pool with native token0 must exist and be initialized (standard for ETH/token pairs)
3. Sufficient liquidity for swap execution (normal operating condition)

**Execution Complexity**: Single transaction calling `Router.swap{value: 0}()` with appropriate parameters. No multi-block coordination, complex state manipulation, or front-running required.

**Economic Cost**: Only gas fees (approximately $5-20). No capital lockup, slippage costs, or opportunity costs.

**Frequency**: Continuously exploitable. Each accumulation event creates new exploitable balance. Multiple attackers can compete to drain accumulated funds, creating MEV opportunity.

**Overall Likelihood**: HIGH - Trivial execution, clear economic incentive, zero barriers to entry, observable precondition

## Recommendation

**Primary Fix:**
Expand the value calculation to account for all scenarios requiring native token0 payment:

```solidity
// In src/Router.sol, handleLockData function, replace lines 106-110:

uint256 value = FixedPointMathLib.ternary(
    poolKey.token0 == NATIVE_TOKEN_ADDRESS && (
        (!params.isToken1() && !params.isExactOut()) ||  // Exact input of native token0
        (params.isToken1() && params.isExactOut())       // Exact output of token1, paying with native token0
    ),
    address(this).balance,  // Use Router's current balance (includes msg.value)
    0
);
```

The existing refund logic at lines 137-139 will properly handle excess ETH sent to Core.

**Alternative Fix (Conservative):**
Block unsupported pattern until comprehensive solution implemented:

```solidity
// Add validation before swap execution in handleLockData:
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && params.isToken1() && params.isExactOut()) {
    revert UnsupportedNativeTokenSwapDirection();
}
```

**Additional Mitigations:**
- Implement per-lock `msg.value` tracking to prevent cross-user contamination
- Add `msg.value` validation to detect unexpected native token contributions
- Document expected native token swap behavior and limitations
- Consider automatic refund at lock completion rather than requiring separate call

## Proof of Concept

**Setup:**
1. Deploy Router and Core contracts
2. Initialize pool with `token0=NATIVE_TOKEN_ADDRESS` and `token1=MockERC20`
3. Add liquidity to pool to enable swaps

**Execution:**
1. Victim calls `Router.swap{value: 10 ether}(poolKey, {isToken1:true, amount:-1 ether, ...}, threshold)`
2. Verify Router balance increased by approximately 9 ETH (excess not used for swap)
3. Attacker calls `Router.swap{value: 0}(poolKey, {isToken1:true, amount:-1 ether, ...}, threshold)`
4. Verify attacker received token1 output without paying ETH
5. Verify Router balance decreased by approximately 1 ETH (used victim's accumulated funds)

**Expected Result:**
- If vulnerable: Attacker gains tokens, victim loses approximately 9 ETH, Router balance reduced
- If fixed: Attacker transaction reverts due to insufficient Router balance, or refund properly returns victim's excess ETH

## Notes

The vulnerability stems from incomplete enumeration of the four possible native token swap scenarios in the Router's value calculation logic. The asymmetry between the `increasing=true` branch (which correctly handles native token withdrawal) and the `increasing=false` branch (which assumes non-zero value was sent to Core) creates the exploit vector. The Router's reliance on `SafeTransferLib.safeTransferETH` from its undifferentiated shared balance, combined with the payable multicall pattern and lack of per-lock value tracking, enables cross-user fund contamination that violates fundamental security properties of user fund isolation.

### Citations

**File:** src/Router.sol (L106-147)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

                int128 amountCalculated = params.isToken1() ? -balanceUpdate.delta0() : -balanceUpdate.delta1();
                if (amountCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
                }

                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
                } else {
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
                    }

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
                }
```

**File:** src/types/swapParameters.sol (L66-72)
```text
function isPriceIncreasing(SwapParameters params) pure returns (bool yes) {
    bool _isExactOut = params.isExactOut();
    bool _isToken1 = params.isToken1();
    assembly ("memory-safe") {
        yes := xor(_isExactOut, _isToken1)
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
