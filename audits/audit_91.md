# Audit Report

## Title
ETH Theft via Unprotected refundNativeToken() Function When msg.value Sent to Non-Native Token Swaps

## Summary
The Router contract accepts ETH via `msg.value` for all swap operations but only forwards it to Core when specific conditions are met. When users send ETH with swaps involving non-native tokens, the ETH remains in the Router contract. The public `refundNativeToken()` function allows any attacker to steal this accumulated ETH by calling it and receiving the entire Router balance without access control.

## Impact
**Severity**: High

Direct theft of user funds. Any ETH accidentally sent to the Router during non-native token swaps becomes immediately vulnerable to theft by any unprivileged attacker through a single function call. Multiple victims' ETH can accumulate before being drained. This represents a 100% loss of user funds with no recovery mechanism.

## Finding Description

**Location:** `src/Router.sol` function `handleLockData` and `src/base/PayableMulticallable.sol` function `refundNativeToken`

**Intended Logic:**
The Router should either use ETH sent via `msg.value` for native token swaps or refund any unused ETH to the original sender. The design assumes a multicall pattern where `refundNativeToken()` is called by the same user within the same transaction.

**Actual Logic:**
The Router calculates whether to forward ETH to Core based on three conditions at lines 106-110. [1](#0-0)  When any condition fails (token0 is not native, swap is exact output, or swapping token1), `value` is set to 0 and no ETH is forwarded.

The refund logic only executes when `poolKey.token0 == NATIVE_TOKEN_ADDRESS`. [2](#0-1)  For non-native token swaps, the else branch executes without touching `msg.value`, leaving ETH in the Router contract.

The critical vulnerability is in `refundNativeToken()` which sends the entire contract balance to any caller without access control. [3](#0-2) 

**Exploitation Path:**
1. **Setup**: Victim initiates swap of non-native ERC20 tokens (token0 → token1) and mistakenly sends 1 ETH with the transaction
2. **Trigger**: Router receives 1 ETH but calculates `value = 0` because `poolKey.token0 != NATIVE_TOKEN_ADDRESS`
3. **State Change**: Swap executes successfully via `_swap(0, poolKey, params)` forwarding 0 ETH to Core, 1 ETH remains in Router
4. **Extraction**: Attacker monitors Router balance and calls `refundNativeToken()`
5. **Result**: Attacker receives the entire Router balance (1 ETH), victim's funds are permanently lost

**Security Guarantee Broken:**
User funds should never be directly stolen by unprivileged attackers. The contract accepts payable transactions without validation and provides an unprotected function to extract all accumulated value.

## Impact Explanation

**Affected Assets**: All ETH sent via `msg.value` to Router for swaps where token0 is not `NATIVE_TOKEN_ADDRESS`, or when `params.isToken1() == true`, or when `params.isExactOut() == true`

**Damage Severity**:
- Attacker can steal 100% of accumulated ETH in Router with a single function call
- Multiple victims' ETH can accumulate before being drained
- Complete and permanent loss for affected users
- No recovery mechanism exists

**User Impact**: Any user who sends ETH with a non-native token swap, including users who:
- Mistakenly believe ETH is needed for swap execution
- Confuse native token swaps with regular ERC20 swaps  
- Perform exact output swaps or token1 swaps with native token pools

**Trigger Conditions**: Any legitimate swap transaction where user accidentally includes `msg.value`

## Likelihood Explanation

**Attacker Profile**: Any EOA or contract, requires no special permissions or positions

**Preconditions**:
1. At least one user must have sent ETH with a swap where `poolKey.token0 != NATIVE_TOKEN_ADDRESS` OR swap parameters don't meet forwarding conditions
2. Router contract must have non-zero ETH balance (immediately true after victim transaction)

**Execution Complexity**: Single external function call `router.refundNativeToken()` with no parameters

**Economic Cost**: Only gas fees (~0.001 ETH), no capital requirements

**Frequency**: Continuously exploitable - can steal from every victim or wait for accumulation

**Overall Likelihood**: HIGH - Users commonly send ETH by mistake when interacting with DeFi protocols, and the exploit is trivial to execute

## Recommendation

**Primary Fix - Add validation in Router:**
```solidity
// In src/Router.sol, function handleLockData, after line 110:
// Add this check immediately after value calculation:
if (msg.value > 0 && value == 0) {
    revert UnexpectedMsgValue();
}
```

**Alternative Fix - Add access control tracking:**
Track ETH deposits per user in PayableMulticallable and only refund to the original depositor:
```solidity
mapping(address => uint256) private userEthBalance;

function refundNativeToken() external payable {
    uint256 refundAmount = userEthBalance[msg.sender];
    if (refundAmount != 0) {
        userEthBalance[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Additional Mitigations**:
- Document clearly that ETH should only be sent for native token swaps
- Consider making swap functions non-payable and using separate wrappers for native token swaps

## Notes

The vulnerability exists due to a design mismatch between the intended multicall pattern and the actual contract interface. While `refundNativeToken()` is designed for transient usage within a multicall batch, the Router's public payable swap functions allow direct calls that leave ETH vulnerable.

The BaseLocker's `lock()` function never forwards `msg.value` to the ACCOUNTANT, always calling with value=0. This architectural decision means any ETH sent to Router must be explicitly handled by the Router itself, which it fails to do for non-native token swaps.

The issue is particularly severe because:
1. All swap functions are marked `payable` enabling the vulnerability
2. No validation prevents incorrect usage
3. The refund function has no access control
4. No documentation warns users about this risk

### Citations

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

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
