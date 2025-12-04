# Audit Report

## Title
Router Multihop Swap ETH Payment Source Mismatch Allows Theft of User Funds

## Summary
The Router's `handleLockData` function uses the contract's ETH balance to pay the FlashAccountant when native token payment is required in multihop swaps, without validating that `msg.value` covers the payment amount. This allows attackers to exploit excess ETH left in the Router by previous users, effectively receiving tokens while paying zero or insufficient ETH, or directly stealing funds via the unrestricted `refundNativeToken()` function.

## Impact
**Severity**: High - Direct theft of user funds via two attack vectors: (1) underpaying for swaps using others' deposited ETH, or (2) front-running with `refundNativeToken()` to drain the Router's balance.

The vulnerability enables complete loss of excess ETH sent by users performing multihop swaps with native tokens. Any user who sends more `msg.value` than strictly required loses the excess to either subsequent swap attackers who underpay, or MEV bots monitoring the mempool and front-running with `refundNativeToken()` calls.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData`, lines 226-244 [1](#0-0) 

**Intended Logic:** 
When a multihop swap requires native ETH payment (when `totalSpecified > 0` and `specifiedToken` is `NATIVE_TOKEN_ADDRESS`, or when `totalCalculated < 0` and `calculatedToken` is `NATIVE_TOKEN_ADDRESS`), the user should pay the required ETH amount via `msg.value`, which the Router then forwards to the FlashAccountant. The Router should validate that sufficient ETH was provided.

**Actual Logic:**
The Router unconditionally uses `SafeTransferLib.safeTransferETH` to send ETH from its own balance to the FlashAccountant at lines 230 and 240, without any verification that `msg.value` equals or exceeds the required payment amount. The Router contract does not even reference `msg.value` anywhere in its code. If the Router has accumulated ETH from previous users who sent excess `msg.value`, attackers can exploit this by: (1) sending zero or insufficient `msg.value` for their own swaps and using the accumulated ETH, or (2) directly calling the public `refundNativeToken()` function to drain all ETH.

**Exploitation Path:**

1. **Victim Setup**: User Alice calls `multihopSwap` with a route requiring 1 ETH payment. Alice accidentally or conservatively sends 2 ETH as `msg.value`.
   - The swap executes successfully, using 1 ETH
   - Line 230 or 240 executes: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 1 ETH)` from Router's balance
   - 1 ETH remains stuck in the Router contract

2. **Attacker Exploit - Path A (Underpayment)**: User Bob calls `multihopSwap` with a route requiring 1 ETH payment but sends 0 ETH as `msg.value`.
   - Line 230 or 240 executes: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 1 ETH)`
   - The Router uses Alice's leftover 1 ETH to pay for Bob's swap
   - Bob receives output tokens from the swap without paying anything

3. **Attacker Exploit - Path B (Direct Theft)**: Any user (including MEV bots) monitoring the mempool detects Alice's transaction leaves ETH in the Router and immediately calls the public `refundNativeToken()` function. [2](#0-1) 

   - All ETH in the Router is transferred to the attacker's address
   - Alice loses her 1 ETH completely

4. **Result**: Alice's excess 1 ETH is stolen by Bob (via underpaid swap) or any front-running attacker (via `refundNativeToken()` call).

**Security Property Broken:**
Direct theft of user funds. The Router acts as an unintended public ETH pool where anyone can withdraw or consume funds deposited by others, violating the fundamental security property that users should only lose funds they explicitly authorize for their own transactions.

**Code Evidence:**

The multihop swap settlement logic transfers ETH from the Router's balance without validating `msg.value`: [1](#0-0) 

The `refundNativeToken()` function is public and refunds all ETH to any caller: [2](#0-1) 

## Impact Explanation

**Affected Assets**: Native ETH sent to the Router contract via `msg.value` in multihop swap transactions.

**Damage Severity**:
- Complete loss of excess ETH sent by users performing multihop swaps with native tokens
- Attackers can execute swaps receiving full token value while paying zero or partial ETH
- MEV bots can continuously monitor the mempool for transactions that leave ETH in the Router and immediately extract it
- Protocol reputation damage as users lose funds through what appears to be normal swap usage

**User Impact**: 
- Casual users who may not calculate exact `msg.value` requirements
- Conservative users who send slightly more ETH to avoid reversion
- Integration developers who implement safety margins in payment amounts
- Any user making a calculation error or experiencing UI bugs that cause excess `msg.value`

**Trigger Conditions**: 
- Occurs whenever `Router.balance > 0` from any previous transaction
- No pool-specific conditions required
- Exploitable immediately after any user leaves excess ETH

## Likelihood Explanation

**Attacker Profile**: 
- Any unprivileged EOA or contract can exploit this
- MEV bots can monitor mempool for transactions leaving ETH in Router
- No special permissions, positions, or capital required

**Preconditions**:
1. Router contract has ETH balance > 0 (from any previous user who sent excess `msg.value`)
2. No other preconditions required - pools do not need special state

**Execution Complexity**: 
- Single transaction - attacker simply calls `multihopSwap` with insufficient `msg.value` to consume accumulated ETH, or directly calls `refundNativeToken()` to extract all ETH
- No complex setup, multi-step execution, or timing requirements
- Can be automated by MEV bots

**Economic Cost**: 
- Only gas fees required (~0.01-0.05 ETH depending on network congestion)
- No capital lockup or risk to attacker
- Profit = stolen ETH minus gas fees

**Frequency**: 
- Continuously exploitable whenever Router accumulates ETH
- Every user mistake or conservative overpayment creates new theft opportunity
- Can target multiple victims' deposits in sequence

**Overall Likelihood**: HIGH - The combination of easy execution, continuous availability, and common user behaviors (overpaying for safety, calculation errors) makes this highly likely to be exploited in production.

## Recommendation

**Fix 1: Validate msg.value matches required payment (Recommended)**

In `src/Router.sol`, function `handleLockData`, add validation after calculating `totalSpecified` and `totalCalculated` (after line 224, before line 226): [3](#0-2) 

Add this validation logic:
```solidity
// Calculate total ETH payment required
uint256 requiredEthPayment = 0;
if (totalSpecified > 0 && specifiedToken == NATIVE_TOKEN_ADDRESS) {
    requiredEthPayment += uint256(totalSpecified);
}
if (totalCalculated < 0 && calculatedToken == NATIVE_TOKEN_ADDRESS) {
    requiredEthPayment += uint256(-totalCalculated);
}
// Validate msg.value matches exactly
if (msg.value != requiredEthPayment) {
    revert IncorrectEthAmount(requiredEthPayment, msg.value);
}
```

**Fix 2: Restrict or track refundNativeToken**

Either:
- Remove `refundNativeToken()` entirely (forcing exact `msg.value` with Fix 1)
- Or implement per-user balance tracking to prevent theft of others' funds

**Recommended Approach**: 
Implement Fix 1 with strict `msg.value == requiredEthPayment` validation to prevent any ETH accumulation in the Router. This makes `refundNativeToken()` unnecessary and eliminates the vulnerability completely. This approach is consistent with how single swaps handle ETH refunds through the ACCOUNTANT withdrawal mechanism rather than leaving funds in the Router.

## Notes

The vulnerability stems from an architectural inconsistency: single swaps handle ETH refunds properly through the FlashAccountant withdrawal mechanism (lines 134-142), but multihop swaps lack equivalent refund logic and rely on users knowing to call `refundNativeToken()` in the same multicall. However, `refundNativeToken()` being public and refunding to `msg.sender` creates the theft vulnerability. The Router never validates `msg.value`, making it exploitable by both underpayment attacks and direct theft via `refundNativeToken()`.

### Citations

**File:** src/Router.sol (L170-224)
```text
            unchecked {
                int256 totalCalculated;
                int256 totalSpecified;
                address specifiedToken;
                address calculatedToken;

                for (uint256 i = 0; i < swaps.length; i++) {
                    Swap memory s = swaps[i];
                    results[i] = new PoolBalanceUpdate[](s.route.length);

                    TokenAmount memory tokenAmount = s.tokenAmount;
                    totalSpecified += tokenAmount.amount;

                    for (uint256 j = 0; j < s.route.length; j++) {
                        RouteNode memory node = s.route[j];

                        bool isToken1 = tokenAmount.token == node.poolKey.token1;
                        require(isToken1 || tokenAmount.token == node.poolKey.token0);

                        (PoolBalanceUpdate update,) = _swap(
                            0,
                            node.poolKey,
                            createSwapParameters({
                                _amount: tokenAmount.amount,
                                _isToken1: isToken1,
                                _sqrtRatioLimit: node.sqrtRatioLimit,
                                _skipAhead: node.skipAhead
                            })
                        );
                        results[i][j] = update;

                        if (isToken1) {
                            if (update.delta1() != tokenAmount.amount) revert PartialSwapsDisallowed();
                            tokenAmount = TokenAmount({token: node.poolKey.token0, amount: -update.delta0()});
                        } else {
                            if (update.delta0() != tokenAmount.amount) revert PartialSwapsDisallowed();
                            tokenAmount = TokenAmount({token: node.poolKey.token1, amount: -update.delta1()});
                        }
                    }

                    totalCalculated += tokenAmount.amount;

                    if (i == 0) {
                        specifiedToken = s.tokenAmount.token;
                        calculatedToken = tokenAmount.token;
                    } else {
                        if (specifiedToken != s.tokenAmount.token || calculatedToken != tokenAmount.token) {
                            revert TokensMismatch(i);
                        }
                    }
                }

                if (totalCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, totalCalculated);
                }
```

**File:** src/Router.sol (L226-244)
```text
                if (totalSpecified < 0) {
                    ACCOUNTANT.withdraw(specifiedToken, swapper, uint128(uint256(-totalSpecified)));
                } else if (totalSpecified > 0) {
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
                    }
                }

                if (totalCalculated > 0) {
                    ACCOUNTANT.withdraw(calculatedToken, swapper, uint128(uint256(totalCalculated)));
                } else if (totalCalculated < 0) {
                    if (calculatedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-totalCalculated)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, calculatedToken, uint128(uint256(-totalCalculated)));
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
