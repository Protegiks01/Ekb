# Audit Report

## Title
Unprotected `refundNativeToken()` Allows Cross-Transaction Theft of Accumulated ETH from Router, Orders, and Positions Contracts

## Summary
The `refundNativeToken()` function in `PayableMulticallable` has zero access control and unconditionally sends the entire contract balance to any caller. When users send excess native ETH to Router, Orders, or Positions contracts (more than required for their operations), the surplus accumulates in these contracts and can be stolen by any attacker in a separate transaction. This represents direct, unauthorized theft of user funds. [1](#0-0) 

## Impact
**Severity**: High - Direct theft of user funds

Any user who sends `msg.value` exceeding the calculated operation amount to Router, Orders, or Positions contracts will have their excess ETH stolen by the first attacker who calls `refundNativeToken()`. The vulnerability scales with protocol usage as more users accumulate excess ETH in these contracts. Affected operations include Router swaps, Orders TWAMM operations, and Positions liquidity deposits where the contract calculates required amounts independently of `msg.value`.

## Finding Description

**Location:** `src/base/PayableMulticallable.sol:25-29`, function `refundNativeToken()`

**Affected Contracts:**
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** 
The documentation states the function should "allow callers to recover ETH that was sent for transient payments but not fully consumed" when "exact payment amounts are difficult to calculate in advance." The word "transient" suggests same-transaction refunds to the original sender within a multicall context.

**Actual Logic:**
The function is external with no access control and sends the **entire contract balance** to `msg.sender` without verifying ownership or tracking which user's ETH remains in the contract. [1](#0-0) 

**Root Cause - Router Example:**

Router's swap logic calculates the ETH amount to forward based on `params.amount()`, not `msg.value`: [5](#0-4) 

The refund logic at lines 134-142 only handles differences between what was forwarded to Core (`value`) and what Core actually consumed (`balanceUpdate.delta0()`). It does NOT refund the difference between `msg.value` and `value`: [6](#0-5) 

**Root Cause - Orders Example:**

Orders transfers the exact calculated amount when the sell token is native: [7](#0-6) 

**Root Cause - Positions Example:**

BasePositions transfers the exact calculated `amount0` when token0 is native: [8](#0-7) 

**Exploitation Path:**
1. **Accumulation**: Alice calls `Router.swap{value: 100 ether}(...)` with `params.amount() = 80 ether`. Router calculates `value = 80 ether` from params (not msg.value), forwards only 80 ETH to Core. 20 ETH remains in Router.
2. **More Accumulation**: Bob calls `Router.swap{value: 50 ether}(...)` with `params.amount() = 40 ether`. 10 more ETH accumulates. Total: 30 ETH in Router.
3. **Theft**: Attacker calls `Router.refundNativeToken()` in a separate transaction and receives all 30 ETH.
4. **Result**: Alice and Bob permanently lose their excess ETH to the attacker.

**Security Property Broken:**
Direct theft of user funds - violates the fundamental security principle that user assets should only be withdrawable by the rightful owner.

## Impact Explanation

**Affected Assets**: Native ETH (NATIVE_TOKEN_ADDRESS = address(0)) sent to Router, Orders, or Positions contracts.

**Damage Severity**:
- Complete and permanent loss of all accumulated excess ETH in the contract
- Any unprivileged address can drain the balance at any time
- Loss scales with protocol usage - more users sending excess = larger accumulated balances = bigger theft opportunity
- Affects all three major user-facing contracts

**User Impact**: Any user who sends `msg.value` greater than the calculated operation amount, including:
- Users intentionally sending excess for gas efficiency in multicalls
- Users accidentally overpaying due to frontend estimation errors or conservative settings
- Users unaware they must call `refundNativeToken()` in the same transaction via multicall

## Likelihood Explanation

**Attacker Profile**: Any external address with no special permissions required

**Preconditions**:
- At least one user has sent excess ETH to Router/Orders/Positions (high probability given documentation encourages sending excess: "exact payment amounts are difficult to calculate in advance")
- No minimum threshold - even dust amounts are profitable to steal
- Contract balance monitoring is trivial with standard blockchain explorers

**Execution Complexity**: Single transaction calling `refundNativeToken()` - completely trivial to execute and automate

**Economic Cost**: Only gas fees (~0.01 ETH on Ethereum mainnet), zero capital lockup

**Frequency**: Continuous exploitation possible - attacker can monitor contract balances and immediately drain any accumulated ETH after each user transaction

**Overall Likelihood**: HIGH - Trivial execution, affects any user who overpays, documentation encourages the vulnerable behavior

## Recommendation

**Primary Fix - Track Ownership:**
```solidity
mapping(address => uint256) private userRefunds;

function refundNativeToken() external payable {
    uint256 amount = userRefunds[msg.sender];
    if (amount != 0) {
        userRefunds[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }
}

// Update userRefunds after operations that leave excess ETH
```

**Alternative Fix - Remove Function:**
Remove `refundNativeToken()` entirely and handle refunds within the specific operations (swap/deposit/order) by comparing `msg.value` to the calculated required amount and immediately refunding the difference before the transaction completes.

**Alternative Fix - Strict Validation:**
Revert if `msg.value` doesn't exactly match the required amount:
```solidity
require(msg.value == calculatedAmount, "Exact payment required");
```
However, this reduces UX flexibility and contradicts the documented design that "exact payment amounts are difficult to calculate in advance."

## Proof of Concept

**Scenario:**
1. VictimA calls `Router.swap{value: 100 ether}(...)` where swap requires 80 ETH → 20 ETH remains in Router
2. VictimB calls `Router.swap{value: 50 ether}(...)` where swap requires 40 ETH → 10 ETH accumulates in Router (total: 30 ETH)
3. Attacker calls `Router.refundNativeToken()` → receives all 30 ETH
4. Router balance becomes 0
5. Victims cannot recover their funds

**Expected Result if Vulnerable**: 
- Attacker's balance increases by 30 ETH
- Router balance becomes 0
- Victims' excess ETH is permanently lost

**Expected Result if Fixed**: 
- Transaction reverts with "No balance to refund" OR
- Only attacker's own tracked balance (0) is refunded

## Notes

**Cross-Contract Impact**: All three major user-facing contracts inherit from PayableMulticallable and expose this vulnerability through their payable functions (Router swaps, Orders TWAMM operations, Positions deposits/withdrawals).

**Root Cause**: Fundamental design mismatch between documentation (suggesting same-transaction "transient" refunds within multicalls) and implementation (allowing cross-transaction theft with no access control or ownership tracking).

**Core Contract Safe**: FlashAccountant (Core contract) has a `receive()` function for native token handling but does NOT inherit from PayableMulticallable, so it doesn't expose this vulnerability. [9](#0-8) 

**Unused Function**: The `refundNativeToken()` function appears nowhere in the codebase tests or usage patterns, suggesting it was intended for a specific use case but lacks the necessary security controls to prevent misuse.

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

**File:** src/Orders.sol (L147-148)
```text
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L256-257)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
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
