# Audit Report

## Title
Router Multihop Swap Missing ETH Payment Validation Enables Fund Theft

## Summary
The Router's `handleLockData` function for multihop swaps transfers ETH from the contract's balance to the FlashAccountant without validating that `msg.value` covers the required payment amount. This allows attackers to steal excess ETH left in the Router by previous users through either underpaying for their own swaps or directly calling the public `refundNativeToken()` function.

## Impact
**Severity**: High - Direct theft of user funds

Users who send excess `msg.value` when executing multihop swaps with native tokens will lose the excess ETH to attackers who can either: (1) execute subsequent multihop swaps with insufficient `msg.value`, consuming the accumulated ETH, or (2) directly call `refundNativeToken()` to drain the Router's entire ETH balance. This violates the fundamental security invariant that users should only lose funds they explicitly authorize for their specific transactions.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData`, lines 226-244 [1](#0-0) 

**Intended Logic:**
When a multihop swap requires native ETH payment, the user should pay the exact required ETH amount via `msg.value`. The Router should validate that sufficient ETH was provided and refund any excess, similar to how single swaps handle ETH payments.

**Actual Logic:**
The Router unconditionally uses `SafeTransferLib.safeTransferETH` to send ETH from its own balance to the FlashAccountant at lines 230 and 240, without validating that `msg.value` matches the required payment amount. The multihop swap logic (lines 151-244) never references `msg.value` and lacks the refund logic present in single swaps. [2](#0-1) 

**Exploitation Path:**

1. **Victim Setup**: Alice calls `multihopSwap{value: 2 ETH}()` with a route requiring only 1 ETH payment
   - The swap executes successfully
   - Line 230 or 240 transfers 1 ETH from Router's balance to ACCOUNTANT
   - 1 ETH remains in the Router contract

2. **Attacker Exploit - Path A (Underpayment)**: Bob calls `multihopSwap{value: 0}()` with a route requiring 1 ETH payment
   - Line 230 or 240 successfully transfers 1 ETH from Router's balance (Alice's leftover ETH)
   - Bob receives output tokens without paying
   - Alice loses 1 ETH

3. **Attacker Exploit - Path B (Direct Theft)**: Any user calls the public `refundNativeToken()` function [3](#0-2) 
   
   - All ETH in the Router is transferred to the caller
   - Alice loses 1 ETH completely

**Security Property Broken:**
Users should only lose funds they explicitly authorize for their specific transactions. The Router unintentionally acts as a public ETH pool where anyone can withdraw or consume funds deposited by others.

## Impact Explanation

**Affected Assets**: Native ETH sent to the Router contract via `msg.value` in multihop swap transactions

**Damage Severity**:
- Complete loss of excess ETH sent by users performing multihop swaps
- Attackers execute swaps receiving full token value while paying zero or insufficient ETH
- MEV bots can monitor mempool and immediately extract accumulated ETH via `refundNativeToken()`

**User Impact**:
- Users who send conservative safety margins to avoid reversion
- Users who make calculation errors in `msg.value`
- Integration developers implementing safety buffers
- Any user whose UI sends incorrect `msg.value`

**Trigger Conditions**:
- Occurs whenever `Router.balance > 0` from previous transactions
- No pool-specific conditions required
- Exploitable immediately after any user leaves excess ETH

## Likelihood Explanation

**Attacker Profile**: Any unprivileged EOA or contract can exploit this vulnerability. MEV bots can monitor the mempool for transactions leaving ETH in the Router and immediately extract it.

**Preconditions**:
1. Router contract has ETH balance > 0 from any previous user who sent excess `msg.value`
2. No other preconditions required

**Execution Complexity**: Single transaction - attacker either calls `multihopSwap{value: 0}()` to consume accumulated ETH, or directly calls `refundNativeToken()` to extract all ETH.

**Economic Cost**: Only gas fees required. No capital lockup or risk to attacker. Profit equals stolen ETH minus gas fees.

**Frequency**: Continuously exploitable whenever Router accumulates ETH. Every user mistake or conservative overpayment creates a new theft opportunity.

**Overall Likelihood**: HIGH - The combination of easy execution, continuous availability, and common user behaviors (overpaying for safety, calculation errors) makes exploitation highly likely.

## Recommendation

**Primary Fix - Add msg.value Validation:**

In `src/Router.sol`, function `handleLockData`, add validation after line 224: [4](#0-3) 

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
require(msg.value == requiredEthPayment, "Incorrect ETH amount");
```

**Alternative Fix - Add Refund Logic:**

Alternatively, implement automatic refund logic similar to single swaps to return excess ETH to the user within the same transaction.

**Recommended Approach**: Implement strict `msg.value` validation to prevent any ETH accumulation in the Router. This makes `refundNativeToken()` unnecessary for multihop swaps and eliminates both attack vectors.

## Notes

**Design Inconsistency**: Single swaps properly handle ETH refunds through explicit refund logic, but multihop swaps lack equivalent functionality. This architectural inconsistency strongly suggests the missing validation is a bug rather than intentional design. [2](#0-1) 

The test suite demonstrates multihop ETH swaps being called with exact payment amounts, but includes no tests for excess ETH handling or `refundNativeToken()` usage, further indicating the vulnerability was overlooked. [5](#0-4)

### Citations

**File:** src/Router.sol (L134-142)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/Router.sol (L222-224)
```text
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

**File:** test/Router.t.sol (L351-366)
```text
    function test_multiMultihopSwap_eth_payment() public {
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 1000, 1000);

        Swap[] memory swaps = new Swap[](2);

        RouteNode[] memory route = new RouteNode[](2);
        route[0] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);
        route[1] = RouteNode(poolKey, SqrtRatio.wrap(0), 0);

        swaps[0] = Swap(route, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 150}));
        swaps[1] = Swap(route, TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 50}));

        // eth multihop swap
        router.multiMultihopSwap{value: 200}(swaps, type(int256).min);
    }
```
