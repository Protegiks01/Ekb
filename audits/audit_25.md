# Audit Report

## Title
Router ETH Payment Logic Bypass Allowing Theft of Router's ETH Balance via Exact Output Token1 Swaps

## Summary
The Router contract fails to forward user-provided ETH to Core when executing exact output swaps for token1 where token0 is the native token. Instead, the Router incorrectly uses its own accumulated balance to settle the ETH debt, allowing attackers to receive tokens without payment.

## Impact
**Severity**: High

Direct theft of Router-held ETH. Attackers can drain all ETH accumulated in the Router contract from previous user operations (multicall with partial ETH usage, users not calling `refundNativeToken()`). In production, the Router legitimately accumulates temporary ETH balances as designed through `PayableMulticallable` inheritance, making this vulnerability highly exploitable with potentially significant financial impact.

## Finding Description

**Location:** `src/Router.sol`, function `handleLockData()`, lines 106-146 [1](#0-0) 

**Intended Logic:** 
When users execute swaps requiring ETH payment, they should send ETH via `msg.value`. The Router should forward this ETH to Core by passing it as the `value` parameter in the swap call. The flash accounting system then properly tracks the ETH payment against the swap debt.

**Actual Logic:**
The `value` variable is only set to non-zero when `!params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS`. This condition exclusively covers exact input swaps of token0 (ETH), but fails to handle exact output swaps where the user wants to receive token1 and pay with token0 (ETH). [2](#0-1) 

**Exploitation Path:**
1. **Precondition**: Router has accumulated ETH balance (realistic - occurs from multicall operations or users not calling `refundNativeToken()`)
2. **Attacker Setup**: Identifies pool with `token0 = NATIVE_TOKEN_ADDRESS`, prepares parameters with `isToken1 = true`, `amount < 0` (exact output)
3. **Exploit Call**: Calls `Router.swap{value: 0}()` sending no ETH
4. **Value Miscalculation**: Condition at line 107 evaluates to false, `value` remains 0
5. **No ETH Forwarded**: `_swap(0, poolKey, params)` calls Core with zero ETH value
6. **Debt Creation**: Core.swap() creates positive debt for ETH in flash accounting system [3](#0-2) 

7. **Price Direction**: `increasing = xor(true, true) = false`, execution reaches lines 134-146
8. **Incorrect Settlement**: `valueDifference = 0 - balanceUpdate.delta0() < 0` triggers line 141 [4](#0-3) 

9. **Router Balance Used**: `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), ...)` sends ETH from Router's contract balance
10. **Debt Cleared**: Accountant's `receive()` function accounts the ETH payment, zeroing the debt [5](#0-4) 

11. **Result**: Attacker receives output tokens without paying any ETH; Router's balance decreases

**Security Property Broken:**
Violates fundamental invariant that users must pay for swaps. The Router loses ETH without receiving payment from the current user.

## Impact Explanation

**Affected Assets**: All ETH held in Router's contract balance

**Damage Severity**:
- Complete drainage of Router's accumulated ETH
- Any ETH from multicall operations with partial usage becomes vulnerable
- High-volume DEX operations naturally accumulate ETH in Router through legitimate usage patterns
- Each exploit steals ETH cost of one swap transaction
- Repeatable until Router balance exhausted

**User Impact**: Users who sent ETH to Router for legitimate swaps but didn't call `refundNativeToken()` lose their funds. The Router is explicitly designed to hold temporary balances. [6](#0-5) 

## Likelihood Explanation

**Attacker Profile**: Any unprivileged EOA or contract

**Preconditions**:
1. Router has non-zero ETH balance (realistic - occurs naturally in production)
2. Pool with `token0 = NATIVE_TOKEN_ADDRESS` exists with liquidity (standard setup)
3. No timing constraints or special state required

**Execution Complexity**: Single transaction calling standard `Router.swap()` function with easily crafted parameters

**Economic Cost**: Only gas fees, no capital requirement since attacker pays nothing

**Frequency**: Continuously exploitable until Router's ETH depleted

**Overall Likelihood**: HIGH - Trivial single-transaction exploit with realistic preconditions

## Recommendation

Fix the `value` calculation to handle all ETH payment scenarios:

```solidity
// In src/Router.sol, lines 106-110:
uint256 value = 0;
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    if (!params.isToken1() && !params.isExactOut()) {
        // Exact input ETH: user knows exact amount to send
        value = uint128(params.amount());
    } else if (params.isToken1() && params.isExactOut()) {
        // Exact output token1, paying with ETH: forward all msg.value
        value = msg.value;
    }
}
```

Alternative: Require ETH payments via multicall with explicit payment calls, removing special handling from single swap path.

## Notes

- Vulnerability specifically affects `CALL_TYPE_SINGLE_SWAP` code path
- Multihop swap paths (lines 229-234) handle ETH differently and are not affected
- Root cause: incomplete conditional logic at lines 106-110
- Router's `PayableMulticallable` design legitimately accumulates ETH, making exploitation highly viable in production

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L112-114)
```text
                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
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

**File:** src/Core.sol (L340-345)
```text
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
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
