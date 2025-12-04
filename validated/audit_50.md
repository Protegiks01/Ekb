# Audit Report

## Title
Router Multihop Swap Allows Theft of Residual Native Tokens Due to Missing msg.value Validation

## Summary
The Router's `multihopSwap` and `multiMultihopSwap` functions accept native ETH payments but fail to validate that `msg.value` covers the required swap amount (`totalSpecified`). Settlement logic transfers ETH from the Router's accumulated contract balance instead of enforcing per-transaction payment requirements, enabling attackers to execute swaps using residual ETH left by previous users who overpaid.

## Impact
**Severity**: High

Direct theft of user funds with trivial exploitation. Any user sending excess ETH for multihop swaps becomes a victim, as subsequent users can immediately steal that residual by underpaying. The vulnerability violates the fundamental invariant that each user must settle their own debts with their own funds. Unlike single swaps which implement refund logic, multihop swaps lack both validation and refund mechanisms, creating a persistent attack vector that scales with Router usage.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData()`, lines 189-198 (swap execution) and lines 226-234 (settlement) [1](#0-0) [2](#0-1) 

**Intended Logic:**
When a user initiates a multihop swap with native tokens, the Router should validate that `msg.value` matches or exceeds the required ETH amount, transfer exactly that amount to settle the debt, and refund any excess to the user—mirroring the protection implemented for single swaps.

**Actual Logic:**
The Router transfers ETH from its accumulated contract balance without validating that `msg.value` covers the requirement. At line 189, internal swaps receive `value: 0`, deferring all native token settlement to lines 229-230. The settlement uses `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)))` which draws from `address(this).balance`, not the current user's payment.

**Exploitation Path:**

1. **Victim Setup**: User A calls `multihopSwap{value: 1.1 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router receives 1.1 ETH. Settlement transfers 1 ETH to ACCOUNTANT via line 230. ACCOUNTANT's `receive()` function reduces debt by 1 ETH. [3](#0-2)  Result: 0.1 ETH remains in Router's balance.

2. **Attacker Execution**: User B calls `multihopSwap{value: 0.9 ETH}` for a route requiring `totalSpecified = 1 ETH`. Router now has 0.1 + 0.9 = 1 ETH total. Settlement transfers 1 ETH to ACCOUNTANT using combined balance. ACCOUNTANT's `receive()` reduces debt by 1 ETH. Result: User B paid only 0.9 ETH but received full 1 ETH swap execution.

3. **Fund Loss**: User A permanently lost 0.1 ETH. User B gained 0.1 ETH of free swap value.

**Security Guarantee Broken:**
The flash accounting model requires that each locker settles debts with their own funds. The FlashAccountant validates debts reach zero before lock release [4](#0-3)  but does NOT validate the source of those funds, allowing cross-user fund usage.

**Root Cause - Asymmetric Settlement Logic:**
Line 230 shows native token settlement transfers from Router balance, while line 232 shows ERC20 settlement uses `ACCOUNTANT.payFrom(swapper, ...)` which correctly pulls from the user. This asymmetry creates the vulnerability—ERC20 tokens cannot be stolen this way because `payFrom` enforces per-user accounting.

**Missing Implementation - Comparison with Single Swap:**
The single swap path correctly implements native token handling with refund logic: [5](#0-4) 

Lines 134-142 calculate `valueDifference` and refund excess ETH to the swapper. This protection was NOT implemented for the multihop path (lines 151-251), creating an exploitable implementation gap.

## Impact Explanation

**Affected Assets**: All native ETH sent to Router for multihop/multi-multihop swaps

**Damage Severity**:
- Users lose 100% of excess ETH they send beyond `totalSpecified` (no cap on loss per transaction)
- Attackers extract all accumulated residual ETH with zero capital risk
- Theft scales with Router usage—more users overpaying means more funds available for theft
- Permanent loss unless victim manually calls `refundNativeToken()` before attacker (creating a race condition)

**User Impact**: Any user sending ETH for multihop swaps faces risk. Common scenarios creating residual:
- Slippage protection buffers (user sends extra ETH as safety margin)
- Round amount payments (1 ETH instead of 0.987 ETH)
- Front-end estimation errors
- Price impact causing actual swap to consume less than estimated

**Trigger Conditions**: Single transaction from any address. No special pool state, liquidity requirements, or timing constraints needed.

## Likelihood Explanation

**Attacker Profile**: Any user with ability to call Router functions. No special privileges, capital requirements, or technical sophistication needed.

**Preconditions**:
1. Residual ETH exists in Router (easily created by any overpaying user through normal usage)
2. Attacker observes Router balance on-chain or monitors mempool for overpayment transactions
3. No other preconditions required

**Execution Complexity**: Single transaction calling `multihopSwap()` or `multiMultihopSwap()` [6](#0-5)  with `msg.value < totalSpecified`. Attacker simply underpays by the amount of residual available.

**Economic Cost**: Only gas fees (~$20-50 depending on route complexity). No capital lockup, no failed transaction risk if residual balance checked first.

**Frequency**: Continuously exploitable. Attacker can monitor Router balance continuously, front-run refund attempts, and extract value immediately after each overpayment.

**Overall Likelihood**: HIGH - Trivial execution, no barriers, continuous monitoring possible, economically profitable even for small amounts.

## Recommendation

Implement msg.value validation and refund logic in the multihop settlement path, mirroring the protection that exists for single swaps:

```solidity
// In src/Router.sol, function handleLockData(), around lines 228-234:

if (totalSpecified > 0) {
    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
        uint256 required = uint128(uint256(totalSpecified));
        
        // Validate sufficient payment
        require(msg.value >= required, "Insufficient native token payment");
        
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

**Alternative**: Track `msg.value` at the start of `handleLockData()` and validate it matches native token requirements before any settlement occurs, ensuring full compatibility with the flash accounting model.

## Notes

**Why refundNativeToken() Doesn't Protect:**
The `refundNativeToken()` function exists in the inherited `PayableMulticallable` contract: [7](#0-6) 

However, it provides inadequate protection because:
1. Must be manually called by users (not automatic)
2. Can be called by ANY user to drain entire balance to themselves (line 27 sends to `msg.sender`)
3. Creates a race condition between victim recovery and attacker exploitation
4. Confirms the developers knew ETH could accumulate, but the mitigation is insufficient for a security-critical issue

**Architecture Context:**
The entry point is `multihopSwap()` (marked `payable`), which calls `lock()` on the FlashAccountant. [8](#0-7)  At line 61, the `call` passes `value: 0`, meaning no ETH is forwarded to ACCOUNTANT during the lock. Throughout this call chain, `msg.value` is never validated or tracked against native token requirements.

**Design Inconsistency:**
The single swap implementation correctly handles native tokens with value tracking and refunds. The multihop implementation passes `value: 0` to internal swaps and defers all settlement to the end, but FORGOT to implement the corresponding msg.value validation and refund at settlement time. This is a clear implementation gap, not an intentional design choice, as evidenced by the refund logic present in single swaps.

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

**File:** src/base/FlashAccountant.sol (L174-181)
```text
            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
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
