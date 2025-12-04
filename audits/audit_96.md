# Audit Report

## Title
Unprotected `refundNativeToken` Allows Theft of User ETH Left in Router/Orders/BasePositions Contracts

## Summary
The `PayableMulticallable.refundNativeToken()` function lacks access control and refunds the entire contract balance to any caller. When users send excess native ETH for operations (particularly exact output swaps where input amounts are unknown), the unused ETH remains in Router/Orders/BasePositions contracts and can be stolen by any attacker in a subsequent transaction.

## Impact
**Severity**: High - Direct theft of user funds

Users who send more native ETH than required for their swap, order, or position operations will lose their excess funds to attackers. In exact output swaps, users cannot know the precise input amount needed in advance, making it reasonable to send extra ETH for safety. However, without calling `refundNativeToken()` in the same transaction via multicall, this excess ETH becomes vulnerable. MEV bots can easily monitor contract balances and immediately extract any leftover ETH, resulting in 100% loss of excess funds for affected users.

## Finding Description

**Location:** `src/base/PayableMulticallable.sol:25-29`, impacts `src/Router.sol`, `src/Orders.sol`, and `src/base/BasePositions.sol`

**Intended Logic:**
The function is designed to refund excess ETH sent for "transient payments" where exact amounts are difficult to calculate in advance. According to the comment, it "allows callers to recover ETH that was sent for transient payments but not fully consumed." [1](#0-0) 

**Actual Logic:**
The function has no access control mechanism and refunds the ENTIRE contract balance to ANY caller. There is no tracking of which address sent which ETH amount, creating a critical vulnerability. [2](#0-1) 

**Exploitation Path:**

1. **Victim Transaction:** Alice performs an exact output swap where she wants to receive a specific amount of tokens but doesn't know how much ETH input is required. For safety, she sends 1 ETH via `msg.value`.

2. **ETH Calculation:** In `Router.handleLockData()`, for exact output swaps, the `value` variable is set to 0 because the condition `!params.isExactOut()` evaluates to false: [3](#0-2) 

3. **ETH Forwarding:** The Router calls `_swap(value, ...)` with `value=0`, which through CoreLib forwards 0 ETH to Core: [4](#0-3) 

4. **Partial Payment:** After the swap completes, only the exact amount needed (e.g., 0.5 ETH stored in `balanceUpdate.delta0()`) is sent to ACCOUNTANT. The remaining 0.5 ETH stays in the Router contract: [5](#0-4) 

5. **Attacker Extraction:** Bob (or any MEV bot) calls `refundNativeToken()` and receives all of Alice's excess 0.5 ETH: [2](#0-1) 

**Security Guarantee Broken:**
Users should be able to safely recover their own excess payments. The current implementation allows any third party to steal these funds because the function refunds the entire balance without tracking or access control.

## Impact Explanation

**Affected Assets:** Native ETH (address(0)) sent to Router, Orders, or BasePositions contracts via `msg.value`

**Damage Severity:**
- Complete loss of excess ETH for affected users (100% of overpayment)
- Particularly impacts exact output swaps where input amounts cannot be known in advance
- Users sending 10-20% extra ETH for safety in volatile markets lose all excess
- Attackers can automate extraction via MEV bots monitoring contract balances
- Affects all three user-facing contracts: Router, Orders, and BasePositions

**User Impact:** 
- Users performing exact output swaps with native ETH
- Users who send more than the exact amount needed for any operation
- Users who don't use multicall to batch `refundNativeToken()` in the same transaction
- Users with transaction failures after payment but before refund
- Users calling single functions instead of multicall batches

## Likelihood Explanation

**Attacker Profile:** Any EOA or smart contract. No special permissions, positions, or capital required. MEV bots can trivially automate this attack.

**Preconditions:**
1. User sends more ETH than needed via `msg.value` (common for exact output swaps)
2. User doesn't call `refundNativeToken()` in the same transaction
3. Contract has non-zero ETH balance

**Execution Complexity:** Single external function call. Requires no setup, no specific market conditions, no timing requirements. Can be executed immediately after detecting contract ETH balance > 0.

**Economic Cost:** Only gas fees (~$0.50 at 20 gwei). No capital lockup, no slippage, no opportunity cost.

**Frequency:** Continuous exploitation possible. Every user transaction leaving excess ETH creates a new theft opportunity. Can target all affected contracts simultaneously.

**Overall Likelihood:** HIGH - Trivial to execute, affects common user behavior (exact output swaps), no barriers to entry.

## Recommendation

Implement proper tracking of ETH contributions per user:

```solidity
// In src/base/PayableMulticallable.sol

// Add transient storage (or use existing balance tracking)
mapping(address => uint256) private transientETHBalances;

function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    // Track sender's ETH contribution
    if (msg.value > 0) {
        transientETHBalances[msg.sender] += msg.value;
    }
    
    bytes[] memory results = _multicall(data);
    
    // Clean up after execution
    delete transientETHBalances[msg.sender];
    
    _multicallDirectReturn(results);
}

function refundNativeToken() external payable {
    uint256 refundAmount = transientETHBalances[msg.sender];
    if (refundAmount > 0 && address(this).balance >= refundAmount) {
        transientETHBalances[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Alternative Mitigation:** Automatically refund excess ETH at the end of each payable function, eliminating the need for manual refund calls. This would prevent ETH from ever remaining in the contract.

## Notes

- This vulnerability affects **three contracts** that inherit `PayableMulticallable`: Router, Orders, and BasePositions
- The issue is particularly severe for **exact output swaps** where users cannot calculate input amounts in advance
- No tests or documentation demonstrate the intended multicall + refund pattern, suggesting users may not be aware of this requirement
- The function is marked `external payable`, which is unusual for a refund function and may indicate incomplete implementation
- The comment mentions "transient payments" but there is no transient storage or per-user tracking implemented

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

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
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

**File:** src/libraries/CoreLib.sol (L139-139)
```text
            if iszero(call(gas(), core, value, free, 132, free, 64)) {
```
