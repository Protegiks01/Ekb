# Audit Report

## Title
Unprotected `refundNativeToken()` Allows Theft of Accumulated ETH from Router, Orders, and BasePositions Contracts

## Summary
The `refundNativeToken()` function in `PayableMulticallable` has no access control and sends the entire contract balance to any caller. When users send excess ETH to Router, Orders, or BasePositions contracts, the surplus accumulates and can be stolen by any attacker calling `refundNativeToken()`. This represents direct theft of user funds.

## Impact
**Severity**: High - Direct theft of user funds

Any user who sends excess ETH to Router, Orders, or BasePositions contracts (more than needed for their operations) will have their surplus funds stolen by the first attacker to call `refundNativeToken()`. The vulnerability scales with protocol usage as more users accumulate excess ETH in these contracts.

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** 
The `refundNativeToken()` function is documented to "allow callers to recover ETH that was sent for transient payments but not fully consumed" when "exact payment amounts are difficult to calculate in advance." The documentation suggests it's intended for same-transaction refunds to the original sender.

**Actual Logic:**
The function has zero access control and unconditionally sends the **entire contract balance** to `msg.sender` without verifying ownership. [1](#0-0) 

Router's swap logic calculates ETH to forward based on `params.amount()`, not `msg.value`, causing excess to remain in the contract. [5](#0-4) 

The refund logic at lines 134-142 only handles differences between what was forwarded to Core and what Core used - it does NOT refund the difference between `msg.value` and the calculated forward amount. [6](#0-5) 

**Exploitation Path:**
1. **Accumulation**: User A calls `Router.swap{value: 100 ether}(...)` with `params.amount() = 80 ether`. Router calculates `value = 80 ether` and forwards only that amount to Core. 20 ETH remains in Router contract.
2. **More Accumulation**: User B calls `Router.swap{value: 50 ether}(...)` with `params.amount() = 40 ether`. 10 more ETH accumulates in Router. Total: 30 ETH.
3. **Theft**: Attacker calls `Router.refundNativeToken()` and receives all 30 ETH.
4. **Result**: Users A and B permanently lose their excess ETH.

**Security Property Broken:**
Direct theft of user funds - violates the fundamental principle that user assets should only be withdrawable by the rightful owner.

## Impact Explanation

**Affected Assets**: Native ETH sent to Router, Orders, or BasePositions contracts by any user who overpays for operations.

**Damage Severity**:
- Complete loss of all accumulated excess ETH
- Any address can drain the balance at any time
- Loss scales with protocol usage - more users = larger accumulated balances = bigger theft opportunity
- Affects Router swaps, Orders operations, and BasePositions deposits

**User Impact**: Any user who sends `msg.value` greater than the calculated operation amount. This includes users who:
- Intentionally send excess for gas efficiency in multicalls
- Accidentally overpay due to frontend issues or conservative slippage settings
- Don't understand they must call `refundNativeToken()` in the same transaction

## Likelihood Explanation

**Attacker Profile**: Any external address - zero special permissions required

**Preconditions**:
- At least one user has sent excess ETH to Router/Orders/BasePositions
- No minimum threshold - even small amounts are profitable to steal
- High probability given documentation encourages sending excess ("exact payment amounts are difficult to calculate")

**Execution Complexity**: Single transaction calling `refundNativeToken()` - trivial to execute and automate

**Economic Cost**: Only gas fees (~0.01 ETH), no capital lockup

**Frequency**: Continuous exploitation possible - attacker can monitor contract balances and immediately drain any accumulated ETH

**Overall Likelihood**: HIGH - Trivial to execute, affects any user who overpays

## Recommendation

**Primary Fix - Track Ownership:**
Implement a mapping to track which user's excess ETH remains in the contract. Modify `refundNativeToken()` to only refund the caller's tracked balance, and update the tracking after each operation that leaves excess ETH.

**Alternative Fix - Remove Function:**
Remove `refundNativeToken()` entirely and handle refunds within the specific operations (swap/deposit/order) that create excess, before the transaction completes.

**Alternative Fix - Strict Matching:**
Revert if `msg.value` doesn't exactly match the required amount. However, this reduces UX flexibility and contradicts the documented expectation that "exact payment amounts are difficult to calculate in advance."

## Proof of Concept

The provided PoC demonstrates:
1. VictimA sends 100 ETH, swap uses 80 ETH, 20 ETH remains in Router
2. VictimB sends 50 ETH, swap uses 40 ETH, 10 ETH remains in Router
3. Attacker calls `refundNativeToken()` and steals all 30 ETH
4. Router balance is drained to zero
5. Victims cannot recover their funds

**Expected Result if Vulnerable**: Attacker's balance increases by 30 ETH, Router balance becomes 0

**Expected Result if Fixed**: Transaction reverts or only refunds attacker's own tracked balance (0)

## Notes

**Cross-Contract Impact**: All three contracts (Router, Orders, BasePositions) inherit from PayableMulticallable and exhibit the same vulnerability through their payable functions.

**Root Cause**: Design mismatch between documentation (suggesting same-transaction "transient" refunds) and implementation (allowing cross-transaction theft with no access control).

**Core Contract Not Affected**: The FlashAccountant (Core contract) has a `receive()` function but does NOT inherit from PayableMulticallable, so it doesn't expose this vulnerability. [7](#0-6)

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
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

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
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
