# Audit Report

## Title
Insufficient msg.value Validation in BasePositions Allows Theft of Contract ETH Balance

## Summary
The `BasePositions.deposit()` function for pools with native token (ETH) as `token0` fails to validate that `msg.value >= amount0`. When users deposit to ETH pools, their `msg.value` remains in the BasePositions contract while the contract pays the FlashAccountant from its existing balance. This allows attackers to drain all accumulated ETH by calling `deposit()` with `msg.value = 0`, receiving positions funded by other users' overpayments.

## Impact
**Severity**: High - Direct theft of user funds

An attacker can steal all ETH accumulated in the BasePositions contract through repeated calls to `deposit()` with `msg.value = 0`. The contract accumulates ETH when users overpay (sending more than the calculated `amount0` required), with these funds intended for refund via `refundNativeToken()`. [1](#0-0)  Each attack drains up to the calculated `amount0` per transaction, requiring only gas fees to execute. All users with pending ETH refunds permanently lose their funds.

## Finding Description

**Location:** `src/base/BasePositions.sol`, lines 71-96 (`deposit()`) and lines 253-262 (`handleLockData()`)

**Intended Logic:**
When depositing liquidity to pools where `token0 == NATIVE_TOKEN_ADDRESS`, users should send `msg.value >= amount0` to cover the required ETH. The contract should validate this and revert if insufficient ETH is provided.

**Actual Logic:**
The contract never validates `msg.value`. The user's `msg.value` stays in BasePositions while the contract pays the debt from its accumulated balance.

**Exploitation Path:**

1. **Setup**: BasePositions accumulates ETH (e.g., 0.5 ETH from users who overpaid and haven't called `refundNativeToken()`)

2. **Trigger**: Attacker calls `deposit()` with `msg.value = 0` for a pool where `poolKey.token0 == NATIVE_TOKEN_ADDRESS` [2](#0-1) 

3. **msg.value isolation**: The `lock()` function calls ACCOUNTANT via assembly with `value=0`, so any `msg.value` stays in BasePositions [3](#0-2) 

4. **No value forwarded to Core**: `handleLockData()` calls `CORE.updatePosition()` as a regular external call without `.value()` syntax, forwarding no ETH [4](#0-3) 

5. **Core creates full debt**: With `msg.value == 0`, Core creates full debt for the native token without any reduction [5](#0-4) 

6. **Contract pays from its balance**: Line 257 executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0)`, which sends ETH from BasePositions' balance (including prior users' overpayments), not from the attacker's `msg.value` [6](#0-5) 

7. **Debt settlement succeeds**: ACCOUNTANT's `receive()` function credits the payment against the debt [7](#0-6) 

8. **Result**: Attacker receives a position worth `amount0` ETH without paying, stealing from the contract's accumulated balance

**Security Property Broken:**
User funds held in the contract (overpayments awaiting refund) are stolen by attackers who receive positions without proper payment.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user

**Preconditions**:
1. BasePositions contract has non-zero ETH balance (expected given `refundNativeToken()` exists for handling overpayments)
2. Pool initialized with `token0 == NATIVE_TOKEN_ADDRESS` (common for ETH pools)

**Execution Complexity**: Single transaction calling `deposit()` with `msg.value = 0`

**Economic Cost**: Only gas fees (~$20-50), no capital lockup

**Frequency**: Repeatable until contract drained

**Overall Likelihood**: HIGH - Trivial execution, affects common ETH pools, contract expected to hold user ETH

## Recommendation

**Primary Fix - Validate msg.value:**

Add validation in `handleLockData()` when `poolKey.token0 == NATIVE_TOKEN_ADDRESS`:

```solidity
// In src/base/BasePositions.sol, handleLockData(), before line 257:
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    require(msg.value >= amount0, "Insufficient ETH sent");
    if (amount0 != 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
    }
    // Refund excess
    if (msg.value > amount0) {
        SafeTransferLib.safeTransferETH(caller, msg.value - amount0);
    }
    if (amount1 != 0) {
        ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
    }
}
```

**Alternative Fix - Forward msg.value to Core:**

Modify `CORE.updatePosition()` call to forward `msg.value` similar to how Router handles swaps [8](#0-7) . This would integrate with Core's native payment handling logic and reduce debt automatically.

## Notes

This vulnerability specifically affects deposits when `token0 == NATIVE_TOKEN_ADDRESS`. The Router contract handles native tokens correctly by explicitly calculating and forwarding value to Core. The presence of `refundNativeToken()` confirms BasePositions is designed to accumulate ETH from overpayments, making this attack highly practical. The architectural decision to retain `msg.value` in BasePositions rather than forwarding to Core, combined with the absence of validation, creates this critical vulnerability.

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/base/BasePositions.sol (L71-79)
```text
    function deposit(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
```

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** src/base/BasePositions.sol (L253-262)
```text
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
            } else {
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
                if (amount1 != 0) {
                    ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
                }
            }
```

**File:** src/base/BaseLocker.sol (L61-61)
```text
            if iszero(call(gas(), target, 0, result, add(len, 4), 0, 0)) {
```

**File:** src/Core.sol (L336-344)
```text
        if (msg.value == 0) {
            // No native token payment included in the call, so use optimized pair update
            _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
        } else {
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
```

**File:** src/base/FlashAccountant.sol (L384-392)
```text
    receive() external payable {
        uint256 id = _getLocker().id();

        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
        }
```

**File:** src/Router.sol (L106-114)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
```
