## Title
Reentrancy in TWAMM Virtual Order Execution Causes Double Accounting of Balance Updates

## Summary
The TWAMM extension's `_executeVirtualOrdersFromWithinLock` function is vulnerable to reentrancy through the `beforeSwap` hook during `CORE.swap()` execution. A nested call can execute virtual orders and update saved balances for the same time period, leading to double-counting when the outer call completes and updates balances again.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/extensions/TWAMM.sol` - function `_executeVirtualOrdersFromWithinLock` (lines 386-592) [1](#0-0) 

**Intended Logic:** The function should execute virtual TWAMM orders exactly once per block, accumulating balance deltas from swaps and updating saved balances once at the end. The timestamp check at line 404 is meant to prevent re-execution within the same block.

**Actual Logic:** The timestamp check only reads from storage at function entry. When `CORE.swap()` triggers the `beforeSwap` hook, it creates a nested call to `_executeVirtualOrdersFromWithinLock`. The nested call reads the OLD timestamp from storage (since the outer call hasn't stored yet), passes the check, executes virtual orders for the SAME time period, and updates saved balances. The outer call then continues with its local state variable and updates saved balances AGAIN, causing double accounting.

**Exploitation Path:**

1. **Initial Trigger**: Any TWAMM operation (swap, order placement, or direct call to `lockAndExecuteVirtualOrders`) initiates virtual order execution [2](#0-1) 

2. **Outer Execution Starts**: `_executeVirtualOrdersFromWithinLock` loads `TwammPoolState` from storage with `realLastVirtualOrderExecutionTime = T1` (old timestamp), passes the check at line 404, and enters the execution loop [3](#0-2) 

3. **Swap Triggers beforeSwap Hook**: During swap execution (lines 456-510), `CORE.swap()` calls the `beforeSwap` extension hook at line 528 in Core.sol [4](#0-3) [5](#0-4) 

4. **Nested Call Initiated**: `TWAMM.beforeSwap()` calls `lockAndExecuteVirtualOrders`, creating a nested lock that triggers `locked_6416899205`, which calls `_executeVirtualOrdersFromWithinLock` AGAIN [6](#0-5) [7](#0-6) 

5. **Nested Execution with Stale Data**: The nested call loads `TwammPoolState` from storage, still seeing `realLastVirtualOrderExecutionTime = T1` (outer call hasn't stored yet), passes the check, and executes virtual orders for the entire period T1 to `block.timestamp` [8](#0-7) 

6. **First Balance Update**: The nested call accumulates `saveDelta0` and `saveDelta1`, then calls `CORE.updateSavedBalances()` with these deltas [9](#0-8) 

7. **Nested State Storage**: The nested call stores the updated `TwammPoolState` with `realLastVirtualOrderExecutionTime = block.timestamp` [10](#0-9) 

8. **Outer Call Continues with Stale State**: Control returns to the outer call, which continues execution using its LOCAL `state` variable (still has old timestamp T1). It continues accumulating deltas in its own `saveDelta0/saveDelta1` variables

9. **Double Accounting**: The outer call reaches line 577 and calls `CORE.updateSavedBalances()` AGAIN with its accumulated deltas. Since `updateSavedBalances` is additive (adds deltas to existing balances), this DOUBLE-COUNTS the balance changes [11](#0-10) 

10. **State Overwrite**: The outer call stores `TwammPoolState` at line 587, potentially overwriting the state stored by the nested call

**Security Property Broken:** Violates the **Flash Accounting** invariant (all operations must have accurate accounting) and the **Solvency** invariant (balance changes must maintain correct pool balances).

## Impact Explanation

- **Affected Assets**: All tokens in TWAMM pools where virtual orders are being executed. The saved balances tracked by the TWAMM extension for order proceeds will be incorrect.
- **Damage Severity**: Balance deltas from virtual order execution can be counted twice, allowing attackers to artificially inflate saved balances. This can lead to theft of tokens when orders are withdrawn, as the protocol believes more tokens are available than actually exist. The severity depends on the trading volume during the vulnerable period.
- **User Impact**: All users with active TWAMM orders in affected pools. Users could lose funds if an attacker exploits this to drain the protocol's tracked balances. The protocol's solvency is compromised as saved balance accounting no longer matches actual token holdings.

## Likelihood Explanation

- **Attacker Profile**: Any user can trigger this vulnerability by simply interacting with a TWAMM pool (placing orders, swapping, or calling public functions). No special privileges required.
- **Preconditions**: 
  - TWAMM pool must be initialized with active sale rates (orders exist)
  - Virtual orders haven't been executed in the current block yet
  - The pool must have sufficient state for `CORE.swap()` to trigger the `beforeSwap` hook
- **Execution Complexity**: Automatically triggered - any normal TWAMM interaction can cause this. The vulnerability occurs without attacker intention during regular protocol operation.
- **Frequency**: Can occur multiple times per block if multiple users interact with TWAMM pools. Every time virtual orders are executed for the first time in a block, there's a window for this vulnerability.

## Recommendation

The root cause is that the timestamp check at line 404 only prevents re-execution when the storage value has been updated, but the outer call uses a local state variable and doesn't re-check storage after nested calls. 

**Solution: Add reentrancy guard or re-check storage after critical operations**

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock:

// CURRENT (vulnerable):
// Line 388-404
StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

// ... validation ...

uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

// no-op if already executed in this block
if (realLastVirtualOrderExecutionTime != block.timestamp) {
    // ... execution continues ...
}

// FIXED (Option 1 - Reentrancy Guard):
// Add a storage flag to prevent nested execution
StorageSlot executionLockSlot = TWAMMStorageLayout.poolExecutionLockSlot(poolId);
if (executionLockSlot.load() != bytes32(0)) {
    return; // Already executing, prevent reentrancy
}
executionLockSlot.store(bytes32(uint256(1))); // Set lock

StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

if (realLastVirtualOrderExecutionTime != block.timestamp) {
    // ... execution ...
    // At line 587, store state
    stateSlot.store(TwammPoolState.unwrap(state));
    
    // ... emit events ...
}

executionLockSlot.store(bytes32(0)); // Clear lock before return

// FIXED (Option 2 - Re-check Storage Before Update):
// After the swap loop completes, before calling updateSavedBalances,
// re-check if state has been updated by a nested call:

// At line 576, before updateSavedBalances:
// Re-load from storage to detect if nested call already executed
TwammPoolState currentStoredState = TwammPoolState.wrap(stateSlot.load());
if (currentStoredState.realLastVirtualOrderExecutionTime() == block.timestamp) {
    // Nested call already executed, abort to prevent double accounting
    return;
}

if (saveDelta0 != 0 || saveDelta1 != 0) {
    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), saveDelta0, saveDelta1);
}
```

**Recommended approach**: Use Option 1 (reentrancy guard) as it's cleaner and prevents any nested execution entirely. Option 2 only prevents the double accounting but allows wasted gas from redundant computation.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMReentrancy.t.sol
// Run with: forge test --match-test test_TWAMMReentrancyDoubleAccounting -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {OrderKey} from "../src/types/orderKey.sol";

contract Exploit_TWAMMReentrancy is Test {
    Core public core;
    TWAMM public twamm;
    Router public router;
    
    address token0;
    address token1;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        twamm = new TWAMM(address(core));
        router = new Router(address(core));
        
        // Setup tokens and pool
        token0 = address(0x1); // Mock token
        token1 = address(0x2); // Mock token
        
        // Initialize TWAMM pool with appropriate config
        // ... pool initialization code ...
    }
    
    function test_TWAMMReentrancyDoubleAccounting() public {
        // SETUP: Create a TWAMM order to establish active sale rates
        OrderKey memory orderKey;
        // ... setup order ...
        
        // Place order which will trigger virtual order execution
        // This starts the outer _executeVirtualOrdersFromWithinLock call
        
        // EXPLOIT: During the swap execution inside _executeVirtualOrdersFromWithinLock,
        // the beforeSwap hook automatically triggers a nested call
        // The nested call executes virtual orders and updates saved balances
        
        // Read saved balances before
        bytes32 balancesBefore = core.exposedSload(
            /* savedBalancesSlot for token pair */
        );
        
        // Trigger virtual order execution (e.g., via swap or lockAndExecuteVirtualOrders)
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // Read saved balances after
        bytes32 balancesAfter = core.exposedSload(
            /* savedBalancesSlot for token pair */
        );
        
        // VERIFY: The balance deltas are double-counted
        // Expected: balances should increase by X (the actual swap amounts)
        // Actual: balances increased by 2X (double counting)
        
        // Calculate expected vs actual balance changes
        uint128 actualIncrease = /* extract from balancesAfter - balancesBefore */;
        uint128 expectedIncrease = /* calculate from single execution */;
        
        assertGt(actualIncrease, expectedIncrease, "Vulnerability confirmed: balances double-counted");
        assertEq(actualIncrease, expectedIncrease * 2, "Double accounting detected");
    }
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Automatic triggering**: No malicious intent required - normal protocol usage triggers the bug
2. **beforeSwap hook design**: The TWAMM's beforeSwap calls `lockAndExecuteVirtualOrders` to ensure orders are up-to-date before any swap, but this creates nested execution
3. **Local vs storage state**: The outer call uses a local `state` variable that isn't updated when the nested call modifies storage
4. **Timestamp check limitation**: The check at line 404 only runs once per function invocation, not continuously
5. **Multiple swap calls**: The loop executes multiple swaps (lines 417-574), each of which can trigger the beforeSwap hook, multiplying the potential for reentrancy

The fix must either prevent nested execution entirely (reentrancy guard) or make the outer call aware that a nested call has occurred (re-check storage).

### Citations

**File:** src/extensions/TWAMM.sol (L386-417)
```text
    function _executeVirtualOrdersFromWithinLock(PoolKey memory poolKey, PoolId poolId) internal {
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

            // we only conditionally load this if the state is coincidentally zero,
            // in order to not lock the pool if state is 0 but the pool _is_ initialized
            // this can only happen iff a pool has zero sale rates **and** an execution of virtual orders
            // happens on the uint32 boundary
            if (TwammPoolState.unwrap(state) == bytes32(0)) {
                if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
                    revert PoolNotInitialized();
                }
            }

            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

            // no-op if already executed in this block
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
                // initialize the values that are handled once per execution
                FeesPerLiquidity memory rewardRates;

                // 0 = not loaded & not updated, 1 = loaded & not updated, 2 = loaded & updated
                uint256 rewardRate0Access;
                uint256 rewardRate1Access;

                int256 saveDelta0;
                int256 saveDelta1;
                PoolState corePoolState;
                uint256 time = realLastVirtualOrderExecutionTime;

                while (time != block.timestamp) {
```

**File:** src/extensions/TWAMM.sol (L456-477)
```text
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
```

**File:** src/extensions/TWAMM.sol (L576-578)
```text
                if (saveDelta0 != 0 || saveDelta1 != 0) {
                    CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), saveDelta0, saveDelta1);
                }
```

**File:** src/extensions/TWAMM.sol (L587-587)
```text
                stateSlot.store(TwammPoolState.unwrap(state));
```

**File:** src/extensions/TWAMM.sol (L595-602)
```text
    function locked_6416899205(uint256) external override onlyCore {
        PoolKey memory poolKey;
        assembly ("memory-safe") {
            // copy the poolkey out of calldata at the solidity-allocated address
            calldatacopy(poolKey, 36, 96)
        }
        _executeVirtualOrdersFromWithinLock(poolKey, poolKey.toPoolId());
    }
```

**File:** src/extensions/TWAMM.sol (L605-620)
```text
    function lockAndExecuteVirtualOrders(PoolKey memory poolKey) public {
        // the only thing we lock for is executing virtual orders, so all we need to encode is the pool key
        // so we call lock on the core contract with the pool key after it
        address target = address(CORE);
        assembly ("memory-safe") {
            let o := mload(0x40)
            mstore(o, shl(224, 0xf83d08ba))
            mcopy(add(o, 4), poolKey, 96)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, o, 100, 0, 0)) {
                returndatacopy(o, 0, returndatasize())
                revert(o, returndatasize())
            }
        }
    }
```

**File:** src/extensions/TWAMM.sol (L647-649)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/Core.sol (L164-167)
```text
            let b0Next := addDelta(b0, delta0)
            let b1Next := addDelta(b1, delta1)

            sstore(slot, add(shl(128, b0Next), b1Next))
```

**File:** src/Core.sol (L528-528)
```text
            IExtension(config.extension()).maybeCallBeforeSwap(locker, poolKey, params);
```
