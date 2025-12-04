# Audit Report

## Title
Excess Native Token Theft via Unprotected refundNativeToken() in Orders and BasePositions

## Summary
The `refundNativeToken()` function inherited from `PayableMulticallable` lacks access control, allowing any attacker to steal accumulated excess ETH from Orders and BasePositions contracts. When users send more ETH than required for TWAMM orders or position deposits, the surplus remains in the contract and becomes vulnerable to theft by any external caller.

## Impact
**Severity**: High

This vulnerability enables direct theft of user funds. Any user sending excess ETH to Orders.sol or BasePositions.sol (whether intentionally for safety margins or due to calculation complexity) will lose their surplus to the first attacker who calls `refundNativeToken()`. The function sends the ENTIRE contract balance to `msg.sender`, enabling attackers to accumulate theft across multiple users' excess payments. This represents 100% loss of excess funds for affected users with no recovery mechanism.

## Finding Description

**Location:** `src/base/PayableMulticallable.sol:25-29`, inherited by `src/Orders.sol` and `src/base/BasePositions.sol`

**Intended Logic:** 
The `refundNativeToken()` function is designed to allow users to recover excess ETH sent for "transient payments" in multicall batches. The design assumes users will include this call in the same transaction to reclaim any unused ETH immediately. [1](#0-0) 

**Actual Logic:**
The function completely lacks access control and unconditionally sends the entire contract balance to ANY `msg.sender`, regardless of who originally sent the ETH. When users send ETH to Orders or BasePositions, only the calculated amount (determined by `CORE.updateSaleRate()` for orders or liquidity calculations for positions) gets transferred to the ACCOUNTANT. Any excess remains trapped in the contract. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. **Setup**: Alice calls `Orders.increaseSellAmount{value: 10 ETH}()` to create a TWAMM order, but the actual requirement calculated by `CORE.updateSaleRate()` is only 9.5 ETH (exact amounts are difficult to predict due to time-based sale rate calculations)
2. **Funds Split**: Orders.sol transfers 9.5 ETH to ACCOUNTANT via `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount))`, leaving 0.5 ETH in the Orders contract
3. **Discovery**: Bob (attacker) monitors `Orders.balance` and observes the accumulated ETH (could be from multiple users)
4. **Theft**: Bob calls `Orders.refundNativeToken()` with zero preconditions
5. **Result**: Bob receives the entire balance (0.5 ETH) that belonged to Alice

**Security Property Broken:**
Direct theft of user funds - violates the fundamental security expectation that user assets remain under their control unless explicitly transferred. The README states "All positions should be able to be withdrawn at any time" (line 202), but this applies to positions, not the ETH refund mechanism which has no such protection.

**Design Inconsistency:**
Router.sol implements the CORRECT pattern with automatic refunds within the same transaction: [4](#0-3) 

Orders and BasePositions fail to implement this safe pattern, creating an exploitable security gap within the protocol.

## Impact Explanation

**Affected Assets**: Native ETH (address(0)) sent to Orders and BasePositions contracts

**Damage Severity**:
- Attackers can steal 100% of all accumulated excess ETH from multiple users in a single call
- For TWAMM orders, exact payment amounts are inherently difficult to calculate due to time-based sale rate conversions (80.32 fixed-point format with duration calculations)
- Users sending "safe" excess amounts lose their entire surplus
- No recovery mechanism exists - stolen funds are permanently lost
- Cross-user theft: single call drains ALL accumulated excess from ALL users

**User Impact**: 
Any user who:
- Sends excess ETH for safety margins when exact amounts are uncertain
- Uses single transaction calls instead of multicall batches
- Doesn't include `refundNativeToken()` in their multicall (no documentation requires this)
- Gets front-run when attempting to call `refundNativeToken()` themselves

## Likelihood Explanation

**Attacker Profile**: Any EOA or contract - zero special permissions or positions required

**Preconditions**:
1. Users send excess ETH to Orders or BasePositions (HIGH probability - sale rate calculations are complex, users naturally send extra for safety)
2. Users don't call `refundNativeToken()` in the same transaction (HIGH probability - no enforcement exists, many users call functions directly)

**Execution Complexity**: Trivial - single call to `refundNativeToken()` with no parameters, no state setup required

**Economic Cost**: Only gas fees (~0.01 ETH on mainnet), zero capital lockup

**Frequency**: Continuously exploitable - attacker can monitor mempool for transactions sending ETH to these contracts, front-run any legitimate refund attempts, or simply call whenever `contract.balance > 0`

**Overall Likelihood**: HIGH - Trivial execution combined with high probability of users sending excess ETH for TWAMM orders where exact amounts depend on block.timestamp and complex calculations

## Recommendation

**Primary Fix:**
Implement automatic refund logic in Orders.sol and BasePositions.sol matching the safe pattern used in Router.sol. In the `handleLockData` function, immediately refund excess ETH to the original payer within the same transaction:

```solidity
// In src/Orders.sol, function handleLockData, lines 146-151:
if (saleRateDelta > 0) {
    if (sellToken == NATIVE_TOKEN_ADDRESS) {
        int256 valueDifference = int256(msg.value) - int256(uint256(amount));
        
        if (valueDifference > 0) {
            ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, recipientOrPayer, uint128(uint256(valueDifference)));
        } else if (valueDifference < 0) {
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
        } else {
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
        }
    } else {
        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
    }
}
```

**Alternative Solutions**:
1. Add sender tracking in PayableMulticallable to ensure only the original depositor can call `refundNativeToken()`
2. Remove `refundNativeToken()` entirely and require exact payment amounts, reverting on excess
3. Implement automatic cleanup at the end of each lock cycle

## Notes

**Root Cause**: Orders and BasePositions inherit PayableMulticallable but fail to implement automatic refund logic like Router.sol, creating an inconsistent and exploitable security model across the protocol.

**Affected Contracts**: Both Orders.sol and BasePositions.sol are vulnerable as they inherit PayableMulticallable and handle native token payments without automatic refunds.

**Flash Accounting Invariant**: This vulnerability does NOT violate the flash accounting invariant - excess ETH remains in the Orders/BasePositions contracts (not ACCOUNTANT), and flash accounting deltas balance correctly. However, the lack of refund protection creates a separate HIGH severity vulnerability enabling direct theft.

### Citations

**File:** src/base/PayableMulticallable.sol (L21-29)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L146-151)
```text
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
```

**File:** src/base/BasePositions.sol (L256-258)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
```

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
