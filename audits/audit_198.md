## Title
DOS on Native Token Swaps When Delta0 is Zero Due to Missing Refund Logic

## Summary
The Router's payment logic contains a critical flaw where the ETH refund logic is only executed when `balanceUpdate.delta0() != 0`. When a swap results in zero delta but the user sent native ETH, the refund is skipped, leaving a negative debt in the FlashAccountant that causes legitimate user transactions to revert with `DebtsNotZeroed`.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Router.sol`, function `handleLockData`, lines 122-146 [1](#0-0) 

**Intended Logic:** When swapping native ETH as token0, the Router should handle payment and refunds by calculating the difference between the sent value and the actual amount required by the swap, then refund any excess ETH back to the swapper.

**Actual Logic:** The ETH refund logic is nested inside an `if (balanceUpdate.delta0() != 0)` check. When `delta0()` is zero but the user sent ETH (`value > 0`), this entire block is skipped. The Core contract has already credited the locker with negative debt (protocol owes ETH back), but the Router never withdraws it, causing the lock to fail validation.

**Exploitation Path:**
1. User calls `router.swap{value: 1000}()` with token0 = NATIVE_TOKEN_ADDRESS, amount = 1000, and sqrtRatioLimit set to the current pool price
2. Router calculates `value = 1000` and calls Core.swap with msg.value = 1000 [2](#0-1) 

3. Core.swap executes but line 541 condition fails (sqrtRatio == sqrtRatioLimit), resulting in a no-op swap with balanceUpdate = (0, 0) [3](#0-2) 

4. Core's `_updatePairDebtWithNative` adjusts debt by subtracting msg.value: `debtChange0 - msg.value = 0 - 1000 = -1000`, crediting the locker with -1000 native token debt [4](#0-3) 

5. Router checks `if (balanceUpdate.delta0() != 0)` which evaluates to FALSE, skipping the entire refund logic
6. Lock ends with nonzeroDebtCount > 0 (native token debt is -1000), causing revert with DebtsNotZeroed [5](#0-4) 

**Security Property Broken:** Flash Accounting invariant violated - all debts must be settled to zero before lock completion, but the negative debt (credit) from sent ETH remains unhandled.

## Impact Explanation
- **Affected Assets**: Native ETH sent by users attempting swaps that result in zero delta
- **Damage Severity**: Users lose gas fees on reverted transactions. No permanent fund loss, but creates a DOS condition preventing certain swap configurations
- **User Impact**: Any user who sends ETH with swap parameters that result in delta0() == 0 (most commonly when sqrtRatioLimit equals current price, causing no-op swap)

## Likelihood Explanation
- **Attacker Profile**: Not malicious - affects legitimate users making honest transactions
- **Preconditions**: 
  - Pool with native ETH as token0
  - User sends ETH (value > 0) with swap
  - Swap results in delta0() == 0 (e.g., sqrtRatioLimit equals current pool price, or pool has no liquidity in the specified range)
- **Execution Complexity**: Single transaction, can occur naturally when market conditions change between tx submission and execution
- **Frequency**: Occurs whenever the preconditions are met - more likely during high volatility when prices move to limits, or with user error in setting sqrtRatioLimit

## Recommendation

```solidity
// In src/Router.sol, function handleLockData, lines 128-147:

// CURRENT (vulnerable):
// The refund logic is only executed when delta0() != 0
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

// FIXED:
// Handle native token refund regardless of delta0() value
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    // Calculate refund amount based on value sent vs actual delta
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    if (valueDifference > 0) {
        // Refund excess ETH to swapper
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        // Send additional ETH to cover shortfall
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
    }
} else if (balanceUpdate.delta0() != 0) {
    // Only need to pay non-native token if delta is non-zero
    ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
}
```

The fix restructures the logic to always handle native token refunds when `value > 0`, regardless of whether `delta0()` is zero. For non-native tokens, the payment is only executed when `delta0() != 0` as before.

## Proof of Concept

```solidity
// File: test/Exploit_NativeTokenZeroDeltaDOS.t.sol
// Run with: forge test --match-test test_NativeTokenZeroDeltaDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";
import "../src/types/poolConfig.sol";
import "../src/math/constants.sol";
import "../src/math/ticks.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_NativeTokenZeroDeltaDOS is Test {
    Core core;
    Router router;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        router = new Router(core);
        
        // Create pool with native token as token0
        poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(0x1234), // some token
            config: createConcentratedPoolConfig(1 << 63, 100, address(0))
        });
        
        // Initialize pool at tick 0
        core.initializePool(poolKey, 0);
    }
    
    function test_NativeTokenZeroDeltaDOS() public {
        // SETUP: Get current pool price
        PoolState memory state = core.readPoolState(poolKey.toPoolId());
        SqrtRatio currentPrice = state.sqrtRatio();
        
        // EXPLOIT: User tries to swap with sqrtRatioLimit equal to current price
        // This will cause a no-op swap (delta0 = 0) but user sends ETH (value > 0)
        vm.deal(address(this), 1 ether);
        
        // This transaction will REVERT with DebtsNotZeroed because:
        // 1. Core receives 1000 wei ETH and credits locker -1000 debt
        // 2. Swap returns delta0() = 0 (no-op)
        // 3. Router skips refund logic because delta0() == 0
        // 4. Lock ends with non-zero debt, causing revert
        vm.expectRevert(abi.encodeWithSelector(IFlashAccountant.DebtsNotZeroed.selector, uint256(0)));
        router.swap{value: 1000}({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 1000,
                _sqrtRatioLimit: currentPrice, // Set limit to current price = no-op swap
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min
        });
        
        // VERIFY: Transaction reverted due to unhandled negative debt
        // The 1000 wei ETH sent by user is stuck in FlashAccountant as negative debt
        // User loses gas on failed transaction
    }
}
```

## Notes

This vulnerability specifically affects native token (ETH) swaps where the swap execution results in `delta0() == 0`. The most common scenario is when:

1. A user sets `sqrtRatioLimit` to exactly the current pool price, causing a no-op swap as documented in Core.sol line 540-541
2. Market conditions change between transaction submission and execution, moving the price to the user's limit
3. The pool has no liquidity in the specified tick range

The bug does NOT affect:
- Non-native token swaps (ERC20 tokens) - these are handled correctly even when delta is zero
- Swaps where delta0() is non-zero - the refund logic executes correctly
- The "increasing" branch (lines 121-127) - this only handles withdrawals and payments, not ETH refunds with msg.value

The fix is straightforward: move the native token refund logic outside the `if (balanceUpdate.delta0() != 0)` condition so it always executes when `value > 0`, ensuring any sent ETH is properly accounted for regardless of the swap outcome.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L122-146)
```text
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
```

**File:** src/Core.sol (L340-344)
```text
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
```

**File:** src/Core.sol (L540-541)
```text
            // 0 swap amount or sqrt ratio limit == sqrt ratio is no-op
            if (amountRemaining != 0 && stateAfter.sqrtRatio() != sqrtRatioLimit) {
```

**File:** src/base/FlashAccountant.sol (L175-180)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
```
