# Audit Report

## Title
Unprotected `refundNativeToken()` Function Allows Theft of ETH Sent to Non-Native Token Orders

## Summary
The Orders contract inherits from PayableMulticallable, exposing a `refundNativeToken()` function with no access control that sends the entire contract's ETH balance to any caller. When users mistakenly send ETH while creating orders for non-native tokens (e.g., USDC/DAI pairs), the ETH accumulates in the Orders contract and becomes immediately claimable by any attacker or MEV bot through a single transaction.

## Impact
**Severity**: High

Direct theft of user funds. Any ETH mistakenly sent by users to non-native token order functions is permanently lost to the user and immediately stealable by any attacker. The vulnerability enables complete loss (100%) of the mistakenly sent ETH amount with zero recourse for victims. Common user mistakes (UI bugs, confusion about which orders require ETH, programmatic errors) result in immediate and irreversible theft.

## Finding Description

**Location:** Multiple files - `src/base/PayableMulticallable.sol`, `src/Orders.sol`, `src/base/BaseLocker.sol`

**Intended Logic:** 
The `refundNativeToken()` function is intended to allow users to recover excess ETH they sent during multicall transactions for native token orders. The design pattern assumes users will call this function themselves within the same transaction (via multicall) to reclaim their own surplus ETH.

**Actual Logic:**
The function sends the **entire contract balance** to **msg.sender** without any access control or tracking of who originally deposited the ETH. [1](#0-0)  When ETH is sent to non-native-token order functions, it accumulates in the Orders contract balance and becomes claimable by anyone, not just the original sender.

**Exploitation Path:**

1. **Victim sends ETH to non-native token order**: User calls `mintAndIncreaseSellAmount()` [2](#0-1)  with `msg.value = 1 ETH` but the `orderKey` specifies a non-native token pair (e.g., USDC/DAI where neither token is address(0)).

2. **ETH remains in Orders contract**: The internal `handleLockData()` function [3](#0-2)  checks if `sellToken == NATIVE_TOKEN_ADDRESS` at line 147. Since the sellToken is not address(0), the condition is false, and line 150 executes `ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount))`, which transfers the ERC20 token from the user but leaves the 1 ETH sitting in the Orders contract.

3. **BaseLocker.lock() does not forward ETH**: The lock mechanism [4](#0-3)  explicitly uses assembly instruction `call(gas(), target, 0, result, add(len, 4), 0, 0)` at line 61 with `0` as the value parameter, meaning no ETH is forwarded to the ACCOUNTANT during the lock callback.

4. **Attacker steals the ETH**: Any attacker (or MEV bot) monitoring for transactions that leave ETH in the Orders contract can immediately call `refundNativeToken()`, receiving the victim's 1 ETH.

**Security Property Broken:**
Direct theft of user funds - violates the fundamental property that users should not lose assets due to honest mistakes when the protocol has mechanisms that could prevent such loss. The Orders contract makes all functions payable to support native token orders but fails to protect accumulated ETH from unauthorized withdrawal.

## Impact Explanation

**Affected Assets**: Any ETH mistakenly sent by users to non-native-token order functions (mintAndIncreaseSellAmount, increaseSellAmount, decreaseSaleRate, collectProceeds).

**Damage Severity**:
- Victim loses 100% of the ETH amount sent in the mistaken transaction
- Attacker gains 100% of the victim's ETH with zero cost beyond gas fees
- Loss is permanent and irreversible - no mechanism for recovery

**User Impact**: Any user who accidentally includes ETH value when creating, modifying, or collecting proceeds from orders for non-native token pairs. This scenario is common due to:
- UI bugs that incorrectly set msg.value
- User confusion about which orders require ETH (only address(0) as sellToken)
- Programmatic interactions with incorrect msg.value parameters
- Copy-paste errors in transaction parameters

**Trigger Conditions**: Single mistaken transaction from victim, followed by single theft transaction from attacker. No special pool state, liquidity requirements, or timing windows needed.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or MEV bot monitoring mempool transactions. No special permissions, positions, or capital required.

**Preconditions**:
1. User sends ETH (msg.value > 0) to any payable Orders function while specifying a non-native token order (sellToken != address(0))
2. Common scenarios: UI bugs, user confusion, scripting errors, programmatic interactions

**Execution Complexity**: Single transaction calling `refundNativeToken()` on the Orders contract. Attacker can monitor mempool and back-run victim transactions, or periodically check Orders contract balance and front-run other potential claimants.

**Economic Cost**: Only gas fees (~0.01 ETH on mainnet). No capital lockup or risk to attacker.

**Frequency**: Can occur with every mistaken ETH transfer. Given the payable nature of all Orders functions and common user mistakes, this represents a persistent and repeatable threat vector.

**Overall Likelihood**: MEDIUM-HIGH - While requires user mistake, such mistakes are common in DeFi, and exploitation is trivial once ETH accumulates.

## Recommendation

**Primary Fix - Option 1: Revert on non-native token orders with msg.value**

Add validation in `handleLockData()` to prevent ETH being sent with non-native token orders:

```solidity
// In src/Orders.sol, handleLockData(), around line 146-151:
if (saleRateDelta > 0) {
    // NEW: Revert if ETH sent but token is not native
    if (sellToken != NATIVE_TOKEN_ADDRESS && msg.value != 0) {
        revert EthSentToNonNativeTokenOrder();
    }
    
    if (sellToken == NATIVE_TOKEN_ADDRESS) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
    } else {
        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
    }
}
```

**Alternative Fix - Option 2: Remove refundNativeToken() from Orders contract**

Since Orders handles native tokens explicitly by immediately transferring them to the ACCOUNTANT [5](#0-4) , there is no legitimate reason for ETH to accumulate in the Orders contract. Remove PayableMulticallable inheritance:

```solidity
// In src/Orders.sol line 24:
// CURRENT:
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken

// FIXED:
contract Orders is IOrders, UsesCore, BaseLocker, BaseNonfungibleToken
// Implement multicall directly without the refund function
```

**Additional Mitigation - Option 3: Track ETH deposits per sender**

If refunds are needed for legitimate multicall scenarios, implement proper accounting:

```solidity
// In PayableMulticallable.sol:
mapping(address => uint256) private _ethBalances;

function refundNativeToken() external payable {
    uint256 refundable = _ethBalances[msg.sender];
    if (refundable != 0) {
        _ethBalances[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundable);
    }
}

// Track deposits in receive() or modify multicall to track per-sender ETH
```

## Notes

The vulnerability exists because:

1. **All Orders functions are payable** [2](#0-1)  to support native token (ETH) orders where `sellToken == NATIVE_TOKEN_ADDRESS` (address(0)) [6](#0-5) .

2. **Native token handling is conditional** - only when `sellToken == NATIVE_TOKEN_ADDRESS` does the code transfer ETH to the ACCOUNTANT [7](#0-6) . For non-native tokens, the ERC20 is handled via `ACCOUNTANT.payFrom()` but the ETH value is ignored and accumulates.

3. **The refund mechanism has no access control** [1](#0-0)  - it was designed for users to recover their own excess ETH in multicall scenarios, but the implementation allows anyone to claim all accumulated ETH by calling it in a separate transaction.

4. **BaseLocker.lock() explicitly sends 0 value** [8](#0-7)  when calling the ACCOUNTANT, ensuring ETH never reaches the FlashAccountant in non-native token scenarios.

The ETH is not permanently locked, nor does it corrupt delta accounting - instead, it becomes immediately stealable by any attacker through the unprotected `refundNativeToken()` function. This represents a direct theft vector requiring immediate remediation.

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L43-49)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
```

**File:** src/Orders.sol (L134-175)
```text
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory result) {
        uint256 callType = abi.decode(data, (uint256));

        if (callType == CALL_TYPE_CHANGE_SALE_RATE) {
            (, address recipientOrPayer, uint256 id, OrderKey memory orderKey, int256 saleRateDelta) =
                abi.decode(data, (uint256, address, uint256, OrderKey, int256));

            int256 amount =
                CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));

            if (amount != 0) {
                address sellToken = orderKey.sellToken();
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
                } else {
                    unchecked {
                        // we know amount will never exceed the uint128 type because of limitations on sale rate (fixed point 80.32) and duration (uint32)
                        ACCOUNTANT.withdraw(sellToken, recipientOrPayer, uint128(uint256(-amount)));
                    }
                }
            }

            result = abi.encode(amount);
        } else if (callType == CALL_TYPE_COLLECT_PROCEEDS) {
            (, uint256 id, OrderKey memory orderKey, address recipient) =
                abi.decode(data, (uint256, uint256, OrderKey, address));

            uint128 proceeds = CORE.collectProceeds(TWAMM_EXTENSION, bytes32(id), orderKey);

            if (proceeds != 0) {
                ACCOUNTANT.withdraw(orderKey.buyToken(), recipient, proceeds);
            }

            result = abi.encode(proceeds);
        } else {
            revert();
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

**File:** src/math/constants.sol (L24-26)
```text
// Address used to represent the native token (ETH) within the protocol
// Using address(0) allows the protocol to handle native ETH alongside ERC20 tokens
address constant NATIVE_TOKEN_ADDRESS = address(0);
```
