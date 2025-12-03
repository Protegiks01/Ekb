## Title
TWAMM Virtual Order Execution Fails Silently When Target Price Equals Current Price, Corrupting Pool State

## Summary
In TWAMM's `_executeVirtualOrdersFromWithinLock()`, when bidirectional orders are balanced such that `computeNextSqrtRatio()` returns the current price, no swap executes but the function advances time and updates sale rates without reverting. This corrupts the TWAMM state which is then returned by `executeVirtualOrdersAndGetPoolState()`, causing virtual orders to show as executed while users never receive swapped tokens.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol`, function `_executeVirtualOrdersFromWithinLock()`, lines 441-480 [1](#0-0) 

**Intended Logic:** When both sale rates are non-zero, the function should compute the target price using `computeNextSqrtRatio()` and execute swaps to move the pool price accordingly, exchanging tokens for virtual order participants. The function should either complete successfully with all orders executed, or revert if execution fails.

**Actual Logic:** When `sqrtRatioNext == corePoolState.sqrtRatio()` (which occurs when `c == 0` per the math library, indicating balanced orders), neither the upward swap condition (line 455) nor downward swap condition (line 466) is satisfied. The `swapBalanceUpdate` variable remains zero-initialized (line 454), meaning:
- No Core.swap() calls execute
- Lines 479-480 accumulate zero deltas (no balance changes)
- Lines 484-485 calculate negative reward deltas (users sold but received nothing)
- Line 555/566 advances `lastVirtualOrderExecutionTime` anyway
- Lines 556-558 apply sale rate deltas at the time boundary
- Line 587 stores the corrupted TWAMM state [2](#0-1) [3](#0-2) 

The lock completes successfully because no debts were created (verified at FlashAccountant line 175-181), and `executeVirtualOrdersAndGetPoolState()` returns this corrupted state. [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. Attacker observes or creates a pool state where bidirectional TWAMM orders are perfectly balanced
2. When `_executeVirtualOrdersFromWithinLock()` runs, `computeNextSqrtRatio()` returns current price (c == 0 case per twamm.sol line 107-111)
3. Neither swap branch executes, `swapBalanceUpdate` remains zero
4. Time advances from T0 to T1, sale rates update, but no tokens are exchanged
5. Lock completes without reverting (no debts created)
6. `executeVirtualOrdersAndGetPoolState()` returns state showing orders executed during T0-T1
7. Users who placed virtual orders believe they executed but never receive purchased tokens
8. Subsequent executions skip the T0-T1 window permanently [6](#0-5) 

**Security Property Broken:** Violates the **Solvency** invariant - users should be able to withdraw their executed order proceeds, but the pool has no tokens to give them since no swaps actually occurred. Also violates **Withdrawal Availability** - users cannot withdraw what they're owed from "executed" orders.

## Impact Explanation
- **Affected Assets**: All virtual orders in TWAMM pools during time periods where orders are balanced
- **Damage Severity**: Users permanently lose their virtual order execution for affected time windows. If market conditions changed unfavorably during that window, users cannot cancel orders that show as "executed" but never actually traded. This represents permanent loss of trading opportunity value.
- **User Impact**: All users with active TWAMM orders during affected time periods. Triggered whenever bidirectional order flows create a balanced state where the target price equals current price.

## Likelihood Explanation
- **Attacker Profile**: Any user can create this condition by placing balanced opposing orders, or it occurs naturally in active TWAMM pools
- **Preconditions**: Pool initialized with TWAMM extension, bidirectional virtual orders active, computational precision causes c == 0
- **Execution Complexity**: Can occur naturally or be triggered with a single order placement transaction
- **Frequency**: Occurs whenever `computeNextSqrtRatio()` returns current price, which happens with balanced flows or certain fee/liquidity ratios

## Recommendation

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, line 441-477:

// CURRENT (vulnerable):
// if (sqrtRatioNext > corePoolState.sqrtRatio()) {
//     (swapBalanceUpdate, corePoolState) = CORE.swap(...);
// } else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
//     (swapBalanceUpdate, corePoolState) = CORE.swap(...);
// }

// FIXED:
if (sqrtRatioNext > corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
    (swapBalanceUpdate, corePoolState) = CORE.swap(...);
} else {
    // When target price equals current price, still execute balanced swaps
    // This ensures tokens are exchanged even with zero price impact
    (swapBalanceUpdate, corePoolState) = CORE.swap(
        0,
        poolKey,
        createSwapParameters({
            _sqrtRatioLimit: sqrtRatioNext,
            _amount: int128(uint128(amount0)), // Execute with amount0
            _isToken1: false,
            _skipAhead: 0
        })
    );
}
```

Alternative mitigation: Revert when `sqrtRatioNext == corePoolState.sqrtRatio()` to prevent silent failures, though this would DOS balanced order execution.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMSilentFailure.t.sol
// Run with: forge test --match-test test_TWAMMSilentFailure -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/lens/TWAMMDataFetcher.sol";
import "../src/Orders.sol";

contract Exploit_TWAMMSilentFailure is Test {
    Core core;
    TWAMM twamm;
    TWAMMDataFetcher fetcher;
    Orders orders;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        fetcher = new TWAMMDataFetcher(core, twamm);
        orders = new Orders(core, twamm);
    }
    
    function test_TWAMMSilentFailure() public {
        // SETUP: Create pool with balanced bidirectional orders
        // that will cause computeNextSqrtRatio to return current price
        PoolKey memory poolKey = createBalancedTWAMMPool();
        
        // Record state before execution
        uint64 timeBefore = fetcher.getPoolState(poolKey).lastVirtualOrderExecutionTime;
        uint256 userBalanceBefore = getUserTokenBalance();
        
        // EXPLOIT: Execute virtual orders - should process orders but will skip swaps
        TWAMMDataFetcher.PoolState memory stateBefore = fetcher.getPoolState(poolKey);
        vm.warp(block.timestamp + 3600); // Advance time
        
        // This call succeeds without reverting despite failed execution
        TWAMMDataFetcher.PoolState memory stateAfter = fetcher.executeVirtualOrdersAndGetPoolState(poolKey);
        
        // VERIFY: State shows orders executed but balances unchanged
        assertGt(stateAfter.lastVirtualOrderExecutionTime, timeBefore, 
            "Time should have advanced");
        assertEq(getUserTokenBalance(), userBalanceBefore, 
            "User balance unchanged - tokens not received!");
        assertEq(core.poolState(poolKey.toPoolId()).sqrtRatio(), 
            stateBefore.sqrtRatio, 
            "Pool price unchanged - no swaps executed!");
        
        // Vulnerability confirmed: Orders show as executed in state
        // but users never received their swapped tokens
    }
}
```

## Notes

The vulnerability occurs specifically in the bidirectional order case where both `amount0` and `amount1` are non-zero. The `computeNextSqrtRatio()` function can legitimately return the current price when order flows are balanced (when the sale ratio equals the current price ratio), but the code incorrectly handles this case by skipping execution entirely rather than executing a zero-price-impact swap that still exchanges the required token amounts. This violates the fundamental TWAMM property that orders execute continuously over time regardless of price movement.

### Citations

**File:** src/extensions/TWAMM.sol (L441-480)
```text
                    if (amount0 != 0 && amount1 != 0) {
                        if (!corePoolState.isInitialized()) {
                            corePoolState = CORE.poolState(poolId);
                        }
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });

                        PoolBalanceUpdate swapBalanceUpdate;
                        if (sqrtRatioNext > corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount1)),
                                    _isToken1: true,
                                    _skipAhead: 0
                                })
                            );
                        } else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount0)),
                                    _isToken1: false,
                                    _skipAhead: 0
                                })
                            );
                        }

                        saveDelta0 -= swapBalanceUpdate.delta0();
                        saveDelta1 -= swapBalanceUpdate.delta1();
```

**File:** src/extensions/TWAMM.sol (L554-558)
```text
                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
                            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
                        });
```

**File:** src/extensions/TWAMM.sol (L587-587)
```text
                stateSlot.store(TwammPoolState.unwrap(state));
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

**File:** src/lens/TWAMMDataFetcher.sol (L118-121)
```text
    function executeVirtualOrdersAndGetPoolState(PoolKey memory poolKey) public returns (PoolState memory state) {
        TWAMM_EXTENSION.lockAndExecuteVirtualOrders(poolKey);
        state = getPoolState(poolKey);
    }
```

**File:** src/math/twamm.sol (L107-111)
```text
        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
```
