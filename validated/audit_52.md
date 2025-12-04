# Audit Report

## Title
Unprotected `refundNativeToken` Allows Theft of User ETH Left in Router/Orders/BasePositions Contracts

## Summary
The `PayableMulticallable.refundNativeToken()` function lacks access control and refunds the entire contract balance to any caller. When users send excess native ETH for exact output swaps where input amounts cannot be known in advance, unused ETH remains in contracts and can be stolen by any attacker in a subsequent transaction.

## Impact
**Severity**: High - Direct theft of user funds

Users performing exact output swaps with native ETH cannot calculate the precise input amount needed in advance. When they send excess ETH for safety, the remainder stays in the Router/Orders/BasePositions contracts after the swap completes. Any attacker can immediately call `refundNativeToken()` to steal all accumulated ETH from these contracts, resulting in 100% loss of excess funds. MEV bots can trivially automate this attack by monitoring contract balances.

## Finding Description

**Location:** [1](#0-0) , impacts [2](#0-1) , [3](#0-2) , and [4](#0-3) 

**Intended Logic:**
The function is designed to refund excess ETH sent for "transient payments" where exact amounts are difficult to calculate in advance, as stated in the comment "allows callers to recover ETH that was sent for transient payments but not fully consumed." [5](#0-4) 

**Actual Logic:**
The function has no access control and refunds the ENTIRE contract balance to ANY caller without tracking which address sent which ETH amount. [1](#0-0) 

**Exploitation Path:**

1. **Victim Transaction:** Alice performs an exact output swap wanting to receive a specific token amount but doesn't know the ETH input required. She sends 1 ETH via `msg.value` for safety.

2. **ETH Not Forwarded:** In `Router.handleLockData()`, for exact output swaps (negative amount), the `value` variable is set to 0 because the condition `!params.isExactOut()` evaluates to false. [6](#0-5) 

3. **Zero ETH to Core:** The Router calls `_swap(value, ...)` with `value=0`, which forwards 0 ETH to Core. [7](#0-6) 

4. **Partial Payment:** After the swap completes, only the exact amount needed (e.g., 0.5 ETH from `balanceUpdate.delta0()`) is transferred from Router's balance to ACCOUNTANT. The remaining 0.5 ETH stays in the Router contract. [8](#0-7) 

5. **Attacker Extraction:** Bob (or any MEV bot) calls `refundNativeToken()` and receives all of Alice's excess 0.5 ETH. [1](#0-0) 

**Security Guarantee Broken:**
Users should be able to safely recover their own excess payments. The current implementation allows any third party to steal these funds.

## Impact Explanation

**Affected Assets:** Native ETH sent to Router, Orders, or BasePositions contracts via `msg.value`

**Damage Severity:**
- Complete loss of excess ETH for affected users (100% of overpayment)
- Particularly impacts exact output swaps where input amounts cannot be known in advance
- Users sending extra ETH for safety in volatile markets lose all excess
- Attackers can automate extraction via MEV bots monitoring contract balances
- Affects all three user-facing contracts that inherit PayableMulticallable

**User Impact:**
- Users performing exact output swaps with native ETH
- Users who send more than the exact amount needed
- Users who don't use multicall to batch `refundNativeToken()` in the same transaction
- Users calling swap functions directly instead of through multicall

## Likelihood Explanation

**Attacker Profile:** Any EOA or smart contract. No special permissions, positions, or capital required. MEV bots can trivially automate this attack.

**Preconditions:**
1. User sends more ETH than needed via `msg.value` (common for exact output swaps where input is unknown)
2. User doesn't call `refundNativeToken()` in the same transaction via multicall
3. Contract has non-zero ETH balance

**Execution Complexity:** Single external function call. Requires no setup, no specific market conditions, no timing requirements beyond detecting contract ETH balance > 0.

**Economic Cost:** Only gas fees (~$0.50 at 20 gwei). No capital lockup, no slippage, no opportunity cost.

**Frequency:** Continuous exploitation possible. Every user transaction leaving excess ETH creates a new theft opportunity.

**Overall Likelihood:** HIGH - Trivial to execute, affects common user behavior (exact output swaps), no barriers to entry.

## Recommendation

Implement proper tracking of ETH contributions per user using transient storage or a mapping that tracks contributions per address and only allows refunds to the original sender. Alternatively, automatically refund excess ETH at the end of each payable function within the same transaction, eliminating the need for manual refund calls and preventing ETH from remaining in contracts between transactions.

## Proof of Concept

A PoC would demonstrate:
1. Setup pool with liquidity in an ETH/token pair
2. Alice calls `Router.swap{value: 1 ether}()` with negative amount (exact output swap)
3. Verify Router balance shows remaining ETH after swap completes
4. Bob calls `Router.refundNativeToken()` in separate transaction
5. Bob receives Alice's excess ETH, Alice loses funds

## Notes

- This vulnerability affects three contracts that inherit `PayableMulticallable`: Router, Orders, and BasePositions [9](#0-8) [10](#0-9) [11](#0-10) 
- The issue is particularly severe for exact output swaps where users cannot calculate input amounts in advance due to the sign-bit encoding of `isExactOut()` [12](#0-11) 
- No tests or documentation demonstrate the intended multicall + refund pattern
- The asymmetry in handling (automatic refund for exact input swaps but not exact output) combined with an unprotected refund function indicates a design oversight

### Citations

**File:** src/base/PayableMulticallable.sol (L21-24)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Router.sol (L1-1)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
```

**File:** src/Router.sol (L52-52)
```text
contract Router is UsesCore, PayableMulticallable, BaseLocker {
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

**File:** src/Orders.sol (L1-1)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L1-1)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/libraries/CoreLib.sol (L139-139)
```text
            if iszero(call(gas(), core, value, free, 132, free, 64)) {
```

**File:** src/types/swapParameters.sol (L60-64)
```text
function isExactOut(SwapParameters params) pure returns (bool yes) {
    assembly ("memory-safe") {
        yes := and(shr(159, params), 1)
    }
}
```
