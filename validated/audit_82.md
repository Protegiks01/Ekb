# Audit Report

## Title
Insufficient msg.value Validation in BasePositions Allows Theft of Contract ETH Balance

## Summary
The `BasePositions.deposit()` function for pools with native token (ETH) as `token0` does not validate that `msg.value >= amount0`. When ETH is sent with the deposit call, it remains in the BasePositions contract while the contract uses its existing balance to pay the FlashAccountant. This allows attackers to drain accumulated ETH from the contract by depositing with insufficient or zero payment.

## Impact
**Severity**: High

Direct theft of user funds. Attackers can steal all ETH accumulated in the BasePositions contract (from users who overpaid and haven't called `refundNativeToken()`). The attack requires only a single transaction with no special permissions, can be repeated until the contract is drained, and causes permanent loss of user funds.

## Finding Description

**Location:** `src/base/BasePositions.sol`, function `handleLockData()`, lines 253-262

**Intended Logic:**
When a user deposits liquidity to a pool where `token0` is `NATIVE_TOKEN_ADDRESS`, the user should send sufficient `msg.value` to cover the required ETH amount (`amount0`). The contract should validate this and revert if insufficient ETH is provided.

**Actual Logic:**
The contract sends ETH from its own balance to ACCOUNTANT without verifying that `msg.value >= amount0`. The vulnerability occurs through this execution path:

**Exploitation Path:**

1. **Setup**: BasePositions contract accumulates ETH balance (e.g., 1 ETH from users who overpaid and haven't called `refundNativeToken()`) [7](#0-6) 

2. **Trigger**: Attacker calls `deposit()` with `msg.value = 0` for a pool where `poolKey.token0 == NATIVE_TOKEN_ADDRESS` [1](#0-0) 

3. **msg.value remains in BasePositions**: The `lock()` function calls `ACCOUNTANT.lock()` with `value=0` (third parameter in assembly call), so the attacker's `msg.value` stays in BasePositions and is never forwarded [2](#0-1) 

4. **Core creates full debt**: `handleLockData()` calls `CORE.updatePosition()` as a regular external call without forwarding value [3](#0-2) 
   
   Since `msg.value == 0` in this context, Core creates full debt for `NATIVE_TOKEN_ADDRESS` without any reduction [4](#0-3) 

5. **Contract uses its own balance**: Line 257 executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0)` which sends ETH from the BasePositions contract's balance, **not from the user's msg.value** [9](#0-8) 

6. **Debt settlement succeeds**: The ACCOUNTANT's receive() function credits the payment and zeros the debt [6](#0-5) 

7. **Result**: Attacker receives a position worth 0.5 ETH while paying nothing, stealing 0.5 ETH from the contract's accumulated balance

**Security Property Broken:**
Violates user fund security - ETH sitting in the contract awaiting refund is stolen by attackers who receive positions without proper payment.

## Impact Explanation

**Affected Assets**: All ETH balance accumulated in the BasePositions contract, including overpayments from legitimate users awaiting `refundNativeToken()` calls

**Damage Severity**:
- Attacker can drain the entire ETH balance of the contract by repeatedly calling `deposit()` with `msg.value = 0`
- Each attack steals up to the calculated `amount0` per transaction
- Permanent loss of user funds (ETH that should be available for refund)

**User Impact**: All users who have pending ETH refunds in the contract lose their funds. Anyone who overpaid and planned to call `refundNativeToken()` will find the contract balance has been drained.

**Trigger Conditions**: Single unprivileged transaction, no special state required beyond contract having non-zero ETH balance

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user - no special permissions or tokens required

**Preconditions**:
1. BasePositions contract must have non-zero ETH balance (expected behavior given the `refundNativeToken()` function exists for handling overpayments)
2. Pool must be initialized with `token0 == NATIVE_TOKEN_ADDRESS` (common for ETH pools)

**Execution Complexity**: Single transaction attack - simply call `deposit()` with `msg.value = 0`

**Economic Cost**: Only gas fees, no capital lockup required

**Frequency**: Can be exploited repeatedly until contract is drained (once per transaction, limited only by gas and available contract balance)

**Overall Likelihood**: HIGH - Trivial to execute, affects common ETH pools, contract is expected to hold user ETH

## Recommendation

**Primary Fix - Validate msg.value:**

Add validation in `src/base/BasePositions.sol`, function `handleLockData()`, around line 253-262 to check that `msg.value >= amount0` when `poolKey.token0 == NATIVE_TOKEN_ADDRESS`. Also implement automatic refund of excess ETH to prevent users from losing overpayments.

**Alternative Fix:**

Modify the call to `CORE.updatePosition()` to explicitly forward `msg.value`, similar to how Router handles swaps: [8](#0-7) 

This would integrate with Core's native payment handling logic and reduce debt automatically.

## Notes

This vulnerability specifically affects the deposit flow when `token0 == NATIVE_TOKEN_ADDRESS`. The Router contract handles this correctly by explicitly calculating and forwarding the required value, but BasePositions uses a different pattern that lacks validation.

The presence of the `refundNativeToken()` function confirms that the contract is designed to accumulate ETH from overpayments, making this attack highly practical and realistic. The architectural decision to keep `msg.value` in the BasePositions contract rather than forwarding it to Core, combined with the lack of validation, creates this critical vulnerability.

### Citations

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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
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
