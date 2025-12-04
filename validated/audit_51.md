# Audit Report

## Title
Router Multihop Swap Allows Theft of Residual Native Tokens Due to Missing msg.value Validation

## Summary
The Router's `multihopSwap` and `multiMultihopSwap` functions transfer native ETH from the Router's accumulated contract balance to settle debts without validating that `msg.value` matches the required amount. This allows attackers to steal residual ETH left by previous users who overpaid, resulting in direct theft of user funds.

## Impact
**Severity**: High

Direct theft of user funds with no protocol-level protection. Any user who sends excess ETH for multihop swaps becomes a victim, and subsequent users can immediately extract that value by underpaying. The vulnerability exists because the Router uses `address(this).balance` for settlement without per-user accounting, allowing one user's overpayment to subsidize another user's underpayment.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData()`, lines 189 (swap execution) and line 230 (settlement)

**Intended Logic:** 
When a user initiates a multihop swap with native tokens, the Router should validate that `msg.value` matches or exceeds the required ETH amount (`totalSpecified`), transfer exactly that amount to the FlashAccountant, and refund any excess to the user—consistent with how single swaps operate.

**Actual Logic:**
The Router transfers ETH from its accumulated contract balance without any validation that the ETH belongs to the current transaction's user or that `msg.value` covers the requirement. At line 230, `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)))` draws from the Router's total balance, not the current user's payment. [1](#0-0) 

**Exploitation Path:**

1. **Victim Setup**: User A calls `multihopSwap{value: 1.1 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router receives 1.1 ETH. Settlement at line 230 transfers 1 ETH to ACCOUNTANT. Router retains 0.1 ETH residual.

2. **Attacker Execution**: User B calls `multihopSwap{value: 0.9 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router balance: 0.1 + 0.9 = 1 ETH. Line 230 transfers 1 ETH to ACCOUNTANT using the combined balance. User B paid only 0.9 ETH but received full 1 ETH swap execution.

3. **Fund Loss**: User A permanently lost 0.1 ETH. User B gained 0.1 ETH of free swap value.

**Security Guarantee Broken:**
Violates flash accounting invariant that debts must be settled by the current locker with their own funds. The protocol fails to maintain proper accounting of which ETH belongs to which user.

**Root Cause - msg.value Context Loss:**
The `multihopSwap()` entry point is payable, but when it calls `lock()` at line 386, the BaseLocker forwards the call to ACCOUNTANT with `value: 0`. When ACCOUNTANT calls back to `handleLockData()`, `msg.value` is 0—the original payment amount is inaccessible. The settlement logic at line 230 therefore cannot validate against the original `msg.value`. [2](#0-1) [3](#0-2) 

**Root Cause - Asymmetric Settlement Logic:**
Line 230 shows native token settlement transfers from Router balance, while line 232 shows ERC20 settlement uses `ACCOUNTANT.payFrom(swapper, ...)` which correctly pulls from the user. This asymmetry creates the vulnerability. [4](#0-3) 

**Missing Implementation - Comparison with Single Swap:**
The single swap path (lines 105-146) correctly implements native token handling with refund logic at lines 134-142. The developers clearly understood that excess ETH must be refunded. However, this protection was NOT implemented for the multihop path, creating an exploitable gap. [5](#0-4) 

The multihop path passes `value: 0` to all internal swaps at line 189, deferring settlement to the end without corresponding validation or refund. [6](#0-5) 

## Impact Explanation

**Affected Assets**: All native ETH sent to Router for multihop/multi-multihop swaps

**Damage Severity**:
- Users lose 100% of excess ETH they send beyond `totalSpecified`
- Attackers can extract all accumulated residual ETH with zero capital risk
- No per-transaction limit—theft scales with number of overpaying users
- Permanent loss unless victim manually calls `refundNativeToken()` before attacker

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

**Frequency**: Continuously exploitable. Attacker can monitor Router balance, front-run refund attempts, and extract value immediately after each overpayment.

**Overall Likelihood**: HIGH - Trivial execution, no barriers, continuous monitoring possible, economically profitable even for small amounts.

## Recommendation

**Primary Fix:**
Store `msg.value` at the start of `multihopSwap()` by encoding it in the lock data, then validate and refund in `handleLockData()`:

```solidity
// In multihopSwap() at line 385-387:
result = abi.decode(
    lock(abi.encode(CALL_TYPE_MULTIHOP_SWAP, msg.sender, msg.value, s, calculatedAmountThreshold)),
    (PoolBalanceUpdate[])
);

// In handleLockData() at lines 156-159, decode msg.value:
if (callType == CALL_TYPE_MULTIHOP_SWAP) {
    Swap memory s;
    uint256 providedValue;
    (, swapper, providedValue, s, calculatedAmountThreshold) = 
        abi.decode(data, (uint256, address, uint256, Swap, int256));
    // ...
}

// In settlement at lines 228-234, add validation and refund:
if (totalSpecified > 0) {
    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
        uint256 required = uint128(uint256(totalSpecified));
        
        // Validate sufficient payment
        if (providedValue < required) {
            revert InsufficientNativeTokenPayment(required, providedValue);
        }
        
        // Transfer required amount
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), required);
        
        // Refund excess
        unchecked {
            if (providedValue > required) {
                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(providedValue - required));
            }
        }
    } else {
        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
    }
}
```

**Additional Mitigation:**
Implement similar fix for `multiMultihopSwap()`.

## Notes

**Why refundNativeToken() Doesn't Protect:**
The `refundNativeToken()` function exists in PayableMulticallable but is inadequate because it:
1. Must be manually called by users (not automatic)
2. Can be called by ANY user to drain entire balance to themselves
3. Creates a race condition between victim recovery and attacker exploitation [7](#0-6) 

**Design Inconsistency:**
The single swap implementation correctly handles native token with value tracking (lines 106-110) and refunds (lines 134-142). The multihop implementation passes `value: 0` to internal swaps and defers settlement to the end, but FORGOT to implement the corresponding msg.value validation and refund. This is a clear implementation gap, not an intentional design choice.

### Citations

**File:** src/Router.sol (L105-146)
```text
            unchecked {
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

**File:** src/base/BaseLocker.sol (L44-73)
```text
    function lock(bytes memory data) internal returns (bytes memory result) {
        address target = address(ACCOUNTANT);

        assembly ("memory-safe") {
            // We will store result where the free memory pointer is now, ...
            result := mload(0x40)

            // But first use it to store the calldata

            // Selector of lock()
            mstore(result, shl(224, 0xf83d08ba))

            // We only copy the data, not the length, because the length is read from the calldata size
            let len := mload(data)
            mcopy(add(result, 4), add(data, 32), len)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, result, add(len, 4), 0, 0)) {
                returndatacopy(result, 0, returndatasize())
                revert(result, returndatasize())
            }

            // Copy the entire return data into the space where the result is pointing
            mstore(result, returndatasize())
            returndatacopy(add(result, 32), 0, returndatasize())

            // Update the free memory pointer to be after the end of the data, aligned to the next 32 byte word
            mstore(0x40, and(add(add(result, add(32, returndatasize())), 31), not(31)))
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
