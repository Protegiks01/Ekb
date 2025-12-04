# Audit Report

## Title
Router Multihop Swap Allows Theft of Residual Native Tokens Due to Missing msg.value Validation

## Summary
The Router's `multihopSwap` function transfers native ETH from its contract balance to settle debts without validating that `msg.value` matches the required amount. This architectural flaw allows attackers to steal residual ETH left by previous users who overpaid, resulting in direct theft of user funds through a single transaction exploit.

## Impact
**Severity**: High

Direct theft of user funds with no protocol-level protection. Any user who sends excess ETH for multihop swaps becomes a victim, and subsequent users can immediately extract that value by underpaying. The impact scales with Router usage - the more users overpay (intentionally for slippage protection, or due to front-end estimation), the more funds accumulate for theft. Unlike single swaps which have built-in refund mechanisms, multihop swaps have zero validation or refund logic, creating a critical security gap. [1](#0-0) 

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData()`, lines 189-198 (swap execution) and lines 226-234 (settlement)

**Intended Logic:** 
When a user initiates a multihop swap with native tokens, the Router should validate that `msg.value` matches or exceeds the required ETH amount (`totalSpecified`), transfer exactly that amount to the FlashAccountant, and refund any excess to the user - consistent with how single swaps operate.

**Actual Logic:**
The Router transfers ETH from its accumulated contract balance (`address(this).balance`) without any validation that the ETH belongs to the current transaction's user or that `msg.value` covers the requirement. The settlement logic at line 230 uses `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)))` which draws from the Router's total balance, not the current user's payment. [2](#0-1) 

**Exploitation Path:**

1. **Victim Setup**: User A calls `multihopSwap{value: 1.1 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router receives 1.1 ETH. Settlement at line 230 transfers 1 ETH to ACCOUNTANT. Result: 0.1 ETH remains in Router contract.

2. **Attacker Execution**: User B (attacker) calls `multihopSwap{value: 0.9 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router now has 0.1 + 0.9 = 1 ETH total. Settlement at line 230 transfers 1 ETH to ACCOUNTANT using the combined balance. Result: User B paid only 0.9 ETH but received full 1 ETH swap execution.

3. **Fund Loss**: User A lost 0.1 ETH permanently. User B gained 0.1 ETH of free swap value.

**Security Guarantee Broken:**
Violates flash accounting invariant that debts must be settled by the current locker with their own funds. Also breaks user fund isolation - the protocol fails to maintain proper accounting of which ETH belongs to which user.

**Root Cause - Asymmetric Settlement Logic:**
Lines 229-230 show native token settlement transfers from Router balance, while line 232 shows ERC20 settlement uses `ACCOUNTANT.payFrom(swapper, ...)` which correctly pulls from the user. This asymmetry creates the vulnerability. [3](#0-2) 

**Missing Implementation - Comparison with Single Swap:**
The single swap path (lines 105-146) correctly implements native token handling with refund logic at lines 134-142. The developers clearly understood that excess ETH must be refunded. However, this protection was NOT implemented for the multihop path (lines 151-251), creating an exploitable gap. [4](#0-3) 

## Impact Explanation

**Affected Assets**: All native ETH sent to Router for multihop/multi-multihop swaps

**Damage Severity**:
- Users lose 100% of excess ETH they send beyond `totalSpecified`
- Attackers can extract all accumulated residual ETH with zero capital risk
- No per-transaction limit - theft scales with number of overpaying users
- Permanent loss - no recovery mechanism unless victim manually calls `refundNativeToken()` before attacker

**User Impact**: Any user sending ETH for multihop swaps is at risk. Common scenarios creating residual:
- Sending round amounts (1 ETH instead of 0.987 ETH)
- Slippage protection buffers
- Front-end estimation errors
- Price impact causing actual swap to consume less than estimated

**Trigger Conditions**: Single transaction from any address. No special pool state, liquidity requirements, or timing constraints.

## Likelihood Explanation

**Attacker Profile**: Any user with ability to call Router functions. No special privileges, capital requirements, or technical sophistication needed.

**Preconditions**:
1. Residual ETH exists in Router (easily created by any overpaying user)
2. Attacker observes Router balance on-chain or monitors mempool
3. No other preconditions required

**Execution Complexity**: Single transaction calling `multihopSwap()` or `multiMultihopSwap()` with `msg.value < totalSpecified`. Attacker simply underpays by the amount of residual available.

**Economic Cost**: Only gas fees (~$20-50 depending on route complexity). No capital lockup, no failed transaction risk if residual balance checked first.

**Frequency**: Continuously exploitable. Attacker can:
- Monitor Router balance continuously 
- Front-run refund attempts
- Extract value immediately after each overpayment

**Overall Likelihood**: HIGH - Trivial execution, no barriers, continuous monitoring possible, economically profitable even for small amounts.

## Recommendation

Implement msg.value validation and refund logic in the multihop settlement path, mirroring the protection that exists for single swaps:

```solidity
// In src/Router.sol, function handleLockData(), around lines 228-234:

if (totalSpecified > 0) {
    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
        uint256 required = uint128(uint256(totalSpecified));
        
        // Validate sufficient payment
        if (msg.value < required) {
            revert InsufficientNativeTokenPayment(required, msg.value);
        }
        
        // Transfer required amount
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), required);
        
        // Refund excess to user
        unchecked {
            if (msg.value > required) {
                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(msg.value - required));
            }
        }
    } else {
        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
    }
}
```

**Alternative**: Track `msg.value` at the start of `handleLockData()` and validate it matches native token requirements before any settlement occurs.

## Notes

**Why refundNativeToken() Doesn't Protect:**
The `refundNativeToken()` function exists in the inherited `PayableMulticallable` contract, but it:
1. Must be manually called by users (not automatic)
2. Can be called by ANY user to drain entire balance to themselves
3. Creates a race condition between victim recovery and attacker exploitation
4. Confirms the developers knew ETH could accumulate, but provided inadequate protection [5](#0-4) 

**Architecture Context:**
The entry point for multihop swaps is `multihopSwap()` (lines 380-388), marked `payable`. It calls `lock()` which invokes the FlashAccountant. The ACCOUNTANT callback to `locked_6416899205()` in BaseLocker eventually reaches `handleLockData()` where the vulnerable settlement occurs. Throughout this call chain, `msg.value` is never validated or tracked. [6](#0-5) 

**Design Inconsistency:**
The single swap implementation correctly handles native token with value tracking and refunds (lines 106-110 calculate required value, lines 134-142 implement refund logic). The multihop implementation passes `value: 0` to internal swaps (line 189) and defers all settlement to the end, but FORGOT to implement the corresponding msg.value validation and refund at settlement time. This is a clear implementation gap, not an intentional design choice.

### Citations

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

**File:** src/Router.sol (L189-198)
```text
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
```

**File:** src/Router.sol (L226-234)
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
```

**File:** src/Router.sol (L380-388)
```text
    function multihopSwap(Swap memory s, int256 calculatedAmountThreshold)
        external
        payable
        returns (PoolBalanceUpdate[] memory result)
    {
        result = abi.decode(
            lock(abi.encode(CALL_TYPE_MULTIHOP_SWAP, msg.sender, s, calculatedAmountThreshold)), (PoolBalanceUpdate[])
        );
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
