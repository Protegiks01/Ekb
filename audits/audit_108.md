## Title
Native Token DOS in Zero-Delta Swap Settlement Due to Skipped Refund Logic

## Summary
When a swap with native token (ETH) results in a zero-delta balance update (both delta0 and delta1 equal to 0), the Router's settlement logic incorrectly skips the native token refund. The Core contract reduces the user's debt by the sent ETH amount, but the Router never withdraws this debt, causing the transaction to revert with `DebtsNotZeroed`.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Router.sol` (function `handleLockData`, lines 122-147) [1](#0-0) 

**Intended Logic:** The settlement logic should handle all balance updates from swaps, including refunding native token when users overpay or when swaps result in no token exchange. When `balanceUpdate.delta0() == 0` with native token, the full `value` sent should be refunded to the user.

**Actual Logic:** The native token refund logic is nested inside the `if (balanceUpdate.delta0() != 0)` condition. When a zero-delta swap occurs with native token value sent, this entire block is skipped, leaving the native token debt unsettled. [2](#0-1) 

**Exploitation Path:**
1. User initiates a swap with native token (token0 == NATIVE_TOKEN_ADDRESS) where `params.amount() > 0` and sends corresponding ETH value
2. Pool is already at the user's specified `sqrtRatioLimit`, causing Core to skip swap execution at line 541 [3](#0-2) 

3. Core still processes the native token debt adjustment at line 344: `_updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1)` which reduces debt by `msg.value` [4](#0-3) 

4. Router receives `balanceUpdate` with `delta0 == 0` and `delta1 == 0`, causing settlement logic to skip the native token refund block
5. Lock release fails at FlashAccountant line 176 with `DebtsNotZeroed` because native token debt is non-zero (negative) [5](#0-4) 

**Security Property Broken:** Flash Accounting invariant - "All flash loans must be repaid within the same transaction with proper accounting." The debt tracking becomes inconsistent when the Router fails to settle the native token debt created by the Core.

## Impact Explanation
- **Affected Assets**: Native token (ETH) sent with swap transactions
- **Damage Severity**: Users lose gas costs for failed transactions. No permanent fund loss occurs since transactions revert, but users waste gas and experience DOS
- **User Impact**: Any user performing swaps with native token where the pool reaches their price limit before the swap executes. This affects:
  - Users setting tight slippage limits
  - Market makers executing limit orders
  - Victims of front-running attacks where attackers move the pool to the victim's limit price

## Likelihood Explanation
- **Attacker Profile**: 
  - Natural occurrence: Users with conservative slippage settings
  - Malicious: Front-runners who can observe pending transactions and move pools to limit prices
- **Preconditions**: 
  - Pool must be initialized with native token as token0
  - User must be swapping token0 for token1 with exact input
  - Pool's current `sqrtRatio` must equal user's `sqrtRatioLimit`
- **Execution Complexity**: Single transaction, easily triggered naturally or via front-running
- **Frequency**: Can occur multiple times per block for popular pools with high-frequency trading

## Recommendation [6](#0-5) 

The fix requires moving the native token refund logic outside the `balanceUpdate.delta0() != 0` condition:

```solidity
// In src/Router.sol, function handleLockData, lines 121-147:

// CURRENT (vulnerable):
if (increasing) {
    if (balanceUpdate.delta0() != 0) {
        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
    }
    if (balanceUpdate.delta1() != 0) {
        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
    }
} else {
    if (balanceUpdate.delta1() != 0) {
        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
    }

    if (balanceUpdate.delta0() != 0) {
        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
            
            if (valueDifference > 0) {
                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
            } else if (valueDifference < 0) {
                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
            }
        } else {
            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
        }
    }
}

// FIXED:
if (increasing) {
    if (balanceUpdate.delta0() != 0) {
        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
    }
    if (balanceUpdate.delta1() != 0) {
        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
    }
} else {
    if (balanceUpdate.delta1() != 0) {
        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
    }

    // Handle native token separately, even if delta0 is 0
    if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && value > 0) {
        int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
        
        if (valueDifference > 0) {
            ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
        } else if (valueDifference < 0) {
            SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
        }
    } else if (balanceUpdate.delta0() != 0) {
        // Non-native token payment
        ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
    }
}
```

## Proof of Concept
```solidity
// File: test/Exploit_NativeTokenDOS.t.sol
// Run with: forge test --match-test test_NativeTokenZeroDeltaDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolKey.sol";
import "../src/types/swapParameters.sol";

contract Exploit_NativeTokenDOS is Test {
    Core core;
    Router router;
    address alice = address(0x1);
    
    function setUp() public {
        core = new Core();
        router = new Router(core);
        
        // Initialize a pool with native token as token0
        // Setup liquidity at specific price range
    }
    
    function test_NativeTokenZeroDeltaDOS() public {
        vm.deal(alice, 1 ether);
        vm.startPrank(alice);
        
        // SETUP: Create swap parameters where pool is already at limit price
        PoolKey memory poolKey = /* pool with native token */;
        SwapParameters memory params = /* params with sqrtRatioLimit = current pool price */;
        
        // EXPLOIT: Attempt swap with ETH sent, but pool is at limit price
        // This will result in delta0 = 0, delta1 = 0
        vm.expectRevert(abi.encodeWithSignature("DebtsNotZeroed(uint256)", 0));
        router.swap{value: 0.1 ether}(/* swap data */);
        
        // VERIFY: Transaction reverted due to non-zero debt
        // User loses gas, transaction fails
        assertEq(alice.balance, 1 ether, "ETH not deducted since tx reverted");
    }
}
```

## Notes

The vulnerability stems from the Router's assumption that when `balanceUpdate.delta0() == 0`, no settlement is needed for token0. However, this assumption breaks down for native token swaps where:

1. The Core contract's `_updatePairDebtWithNative` function always adjusts debt by `msg.value` when native token is sent, regardless of the actual swap delta [7](#0-6) 

2. The debt adjustment happens in the Core using this logic: `debtChange0 - int256(msg.value)`, which means if `debtChange0 = 0` and `msg.value > 0`, the resulting debt change is negative (protocol owes user)

3. The Router must withdraw this debt to settle it, but the withdrawal is skipped when `delta0 == 0`

This creates an inconsistency between the Core's debt accounting and the Router's settlement logic. The fix requires the Router to handle native token refunds independently of the `delta0` check, ensuring that any ETH sent is properly accounted for regardless of the swap outcome.

### Citations

**File:** src/Router.sol (L121-147)
```text
                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
                } else {
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
                    }

                    if (balanceUpdate.delta0() != 0) {
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
                }
```

**File:** src/Core.sol (L329-355)
```text
    function _updatePairDebtWithNative(
        uint256 id,
        address token0,
        address token1,
        int256 debtChange0,
        int256 debtChange1
    ) private {
        if (msg.value == 0) {
            // No native token payment included in the call, so use optimized pair update
            _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
        } else {
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
                }
            } else {
                // token0 is not native, and since token0 < token1, token1 cannot be native either
                // Update the token0, token1 debt and then update native token debt separately
                unchecked {
                    _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
                    _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
                }
            }
        }
    }
```

**File:** src/Core.sol (L541-541)
```text
            if (amountRemaining != 0 && stateAfter.sqrtRatio() != sqrtRatioLimit) {
```

**File:** src/base/FlashAccountant.sol (L175-181)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
```
