# Audit Report

## Title
Router Accumulated ETH Can Be Stolen Via Exact-Output Swaps With Zero Payment

## Summary
The Router contract allows attackers to steal accumulated ETH by executing exact-output swaps with zero `msg.value`. When `valueDifference` becomes negative, the Router incorrectly sends ETH from its own balance to settle the swap debt, enabling theft of ETH left by previous users.

## Impact
**Severity**: High

Attackers can drain the entire ETH balance accumulated in the Router contract from users who overpaid on swaps. This is direct theft of user funds where any user's leftover ETH becomes available for subsequent attackers to consume through exact-output swaps without payment. The loss equals `min(required_eth_for_swap, router.balance)` per attack and can be repeated as long as the Router holds ETH.

## Finding Description

**Location:** `src/Router.sol:106-146`, function `handleLockData()`

**Intended Logic:** 
For swaps involving native ETH (token0 = NATIVE_TOKEN_ADDRESS), the Router should:
1. Forward the user's `msg.value` to Core for debt settlement
2. Refund excess ETH if user overpaid
3. Revert if user didn't send enough ETH

**Actual Logic:**
For exact-output swaps where token0 is ETH, the Router sets `value = 0` [1](#0-0) , meaning no ETH is forwarded to Core upfront. After the swap executes, when `valueDifference < 0` (user underpaid), the Router sends ETH from its own accumulated balance to the Accountant [2](#0-1)  without verifying this ETH came from the current user.

**Exploitation Path:**

1. **Setup - Victim Leaves ETH:**
   - Alice calls `Router.swap{value: 2 ETH}()` for exact-input swap needing 1 ETH
   - Router forwards 1 ETH to Core (via `value` parameter)
   - 1 ETH remains in Router's balance
   - Alice doesn't call `refundNativeToken()` [3](#0-2) 

2. **Attack - Steal Accumulated ETH:**
   - Bob calls `Router.swap{value: 0}()` for exact-output swap where token0 is ETH
   - Router sets `value = 0` because `isExactOut() = true`
   - Router calls `Core.swap{value: 0}()` (forwarding 0 ETH)
   - Core creates debt of 1 ETH (balanceUpdate.delta0() = 1)
   - Back in Router: `valueDifference = int256(0) - int256(1) = -1` [4](#0-3) 
   - Router sends 1 ETH from its balance to Accountant
   - Accountant reduces Bob's debt by 1 ETH [5](#0-4) 
   - Lock completes successfully with zero debt
   - Bob receives token1 output without paying any ETH

3. **Result:**
   - Bob received tokens worth 1 ETH
   - Bob paid 0 ETH
   - Alice's 1 ETH was stolen from Router's balance

**Security Property Broken:**
Users' ETH held in the Router contract should only be refundable to the original sender, not consumable by subsequent unrelated transactions. The Router acts as an unintended shared wallet where any user's funds can be stolen.

## Impact Explanation

**Affected Assets**: Native ETH (NATIVE_TOKEN_ADDRESS) accumulated in Router from users who sent excess `msg.value` and didn't immediately call `refundNativeToken()`.

**Damage Severity**:
- Attackers can drain the entire Router ETH balance in a single transaction
- Loss per attack: min(required_eth_for_swap, router.balance)
- Attack is repeatable and can be frontrun by multiple attackers
- All users who overpay on swaps are vulnerable unless they immediately call refund

**User Impact**: Any user sending excess ETH to Router becomes a victim. The vulnerability creates a race condition where the first attacker to execute an exact-output swap with zero payment steals accumulated ETH. Given Router is used by all protocol users, this affects a broad user base.

**Trigger Conditions**: Attacker can execute anytime Router.balance > 0, which occurs whenever users send more ETH than needed for their swaps.

## Likelihood Explanation

**Attacker Profile**: Any EOA or contract with no special permissions required.

**Preconditions**:
1. Router must have accumulated ETH balance (common - users frequently send rounded amounts like 1 ETH for swaps needing 0.9 ETH)
2. Pool with token0 = NATIVE_TOKEN_ADDRESS must exist (standard)
3. Pool must have sufficient liquidity for the swap (typical for active pools)

**Execution Complexity**: Single transaction calling `Router.swap()` with:
- `msg.value = 0`
- Exact-output swap parameters (negative amount)
- token0 = NATIVE_TOKEN_ADDRESS

**Economic Cost**: Only gas fees (~0.01 ETH), no capital required since attacker sends 0 ETH.

**Frequency**: Repeatable continuously as long as Router holds ETH. Multiple attackers can compete to drain the balance.

**Overall Likelihood**: HIGH - Simple to execute, common preconditions, significant financial incentive.

## Recommendation

**Primary Fix:**
The Router must never use its own accumulated balance to pay for user swaps. For exact-output swaps where ETH is required, the Router should revert when the user hasn't sent sufficient ETH:

```solidity
// In src/Router.sol, function handleLockData, lines 138-142:

// CURRENT (vulnerable):
} else if (valueDifference < 0) {
    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
}

// FIXED:
} else if (valueDifference < 0) {
    // User didn't send enough ETH - revert transaction
    // Do NOT use accumulated ETH from Router's balance
    revert InsufficientETHProvided(uint256(-valueDifference), value);
}
```

**Alternative Mitigation:**
For exact-output swaps where required ETH is unknown upfront:
1. Require users to send a maximum amount via `msg.value`
2. Always refund excess in the same transaction
3. Never accumulate ETH in the Router between transactions

**Additional Safeguard:**
Add a dedicated `msg.value` tracking mechanism per lock ID to ensure only the current user's ETH is consumed for their swap.

## Notes

The vulnerability stems from the Router treating its accumulated ETH balance as a shared pool rather than tracking per-user contributions. The root cause is at lines 106-110 where `value = 0` for exact-output swaps [1](#0-0) , combined with lines 140-142 where the Router unconditionally sends from its own balance when `valueDifference < 0` [2](#0-1) .

This vulnerability can be triggered in `CALL_TYPE_SINGLE_SWAP` flow and potentially in `CALL_TYPE_MULTIHOP_SWAP` where ETH is the input token. The design implicitly assumes users will immediately call `refundNativeToken()` after each transaction, but this is neither enforced nor guaranteed, creating a security vulnerability where user funds can be stolen.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L135-135)
```text
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
```

**File:** src/Router.sol (L140-142)
```text
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
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
