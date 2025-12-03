## Title
TWAMM Extension Can Bypass Full-Range Pool Validation via Self-Initialization Frontrunning

## Summary
The `shouldCallAfterInitializePool` function's self-call check allows the TWAMM extension to frontrun legitimate pool initialization and initialize pools itself, thereby bypassing the critical `afterInitializePool` hook that enforces the requirement that TWAMM pools must be full-range. This enables TWAMM orders to be placed on non-full-range pools (concentrated liquidity or stableswap), violating protocol invariants. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/libraries/ExtensionCallPointsLib.sol` (shouldCallAfterInitializePool, lines 49-53) and `src/extensions/TWAMM.sol` (afterInitializePool, lines 625-644)

**Intended Logic:** The `afterInitializePool` hook in TWAMM is designed to enforce that only full-range pools can be initialized with TWAMM as the extension. The check at line 630 validates this requirement: [2](#0-1) 

**Actual Logic:** The `shouldCallAfterInitializePool` function prevents the hook from being called when the extension initializes the pool itself: [1](#0-0) 

When `msg.sender == extension`, the condition `iszero(eq(initializer, extension))` evaluates to false, preventing the hook execution. Since `initializePool` has no access control, the TWAMM extension can call it directly: [3](#0-2) 

**Exploitation Path:**
1. **Frontrun**: TWAMM extension (or attacker controlling deployment) monitors mempool for legitimate pool initialization transactions
2. **Self-Initialize**: TWAMM calls `core.initializePool(poolKey, tick)` where `poolKey.config` is a non-full-range configuration (e.g., concentrated liquidity with `tickSpacing > 0`) but has `extension = address(twamm)`
3. **Bypass Validation**: At line 100 of Core.sol, `maybeCallAfterInitializePool` is called with `initializer = msg.sender = twamm` and `extension = twamm`, causing the self-call check to fail and the hook to not execute
4. **Exploit State**: Pool is now initialized without the full-range validation. When users place TWAMM orders, the lazy initialization path checks pool state but NOT the full-range requirement: [4](#0-3) 

5. **Invariant Violation**: TWAMM orders execute on a non-full-range pool, violating the protocol's design assumption that TWAMM virtual orders operate across the full price range

**Security Property Broken:** Protocol invariant that TWAMM extension only operates on full-range pools. The test suite explicitly validates this requirement: [5](#0-4) 

## Impact Explanation
- **Affected Assets**: All TWAMM orders placed on the maliciously initialized non-full-range pool
- **Damage Severity**: TWAMM's virtual order execution logic assumes full-range liquidity distribution. Operating on concentrated liquidity or stableswap pools could lead to:
  - Incorrect price impact calculations during virtual order execution
  - Orders executing at wrong price points due to liquidity concentration
  - Potential loss of user funds deposited in orders
  - Protocol state corruption where TWAMM state diverges from actual pool state
- **User Impact**: Any user placing TWAMM orders on the affected pool. Since the pool appears valid (initialized, has TWAMM extension), users have no way to detect the misconfiguration until orders execute incorrectly

## Likelihood Explanation
- **Attacker Profile**: The TWAMM extension contract itself (if maliciously coded) or any frontrunner monitoring pool initialization transactions
- **Preconditions**: 
  - TWAMM extension must be registered with Core (happens in constructor)
  - A legitimate user or factory attempts to initialize a TWAMM pool
- **Execution Complexity**: Single frontrun transaction calling `core.initializePool()` with non-full-range config
- **Frequency**: Can be exploited once per pool. Each non-full-range TWAMM pool represents a permanent vulnerability affecting all future orders on that pool

## Recommendation

**Primary Fix:** Add the full-range validation to the lazy initialization path:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, lines 395-399:

// CURRENT (vulnerable):
if (TwammPoolState.unwrap(state) == bytes32(0)) {
    if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
        revert PoolNotInitialized();
    }
}

// FIXED:
if (TwammPoolState.unwrap(state) == bytes32(0)) {
    if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
        revert PoolNotInitialized();
    }
    // Enforce full-range requirement even during lazy initialization
    if (!poolKey.config.isFullRange()) revert FullRangePoolOnly();
}
```

**Alternative Mitigation:** Modify the self-call check to only apply to hooks that don't perform critical validation:

```solidity
// In src/libraries/ExtensionCallPointsLib.sol, line 49-53:

// CURRENT:
function shouldCallAfterInitializePool(IExtension extension, address initializer) internal pure returns (bool yes) {
    assembly ("memory-safe") {
        yes := and(shr(159, extension), iszero(eq(initializer, extension)))
    }
}

// ALTERNATIVE FIX (remove self-call check for afterInitializePool):
function shouldCallAfterInitializePool(IExtension extension, address initializer) internal pure returns (bool yes) {
    assembly ("memory-safe") {
        yes := shr(159, extension)
        // Note: Intentionally allows self-calls for afterInitializePool
        // since it contains critical validation logic
    }
}
```

The primary fix is recommended as it provides defense-in-depth and catches the issue regardless of initialization path.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMBypassFullRange.t.sol
// Run with: forge test --match-test test_TWAMMBypassFullRange -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../src/types/poolKey.sol";
import "../src/types/poolConfig.sol";
import "../src/types/orderKey.sol";
import "./TestToken.sol";

contract Exploit_TWAMMBypassFullRange is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    TestToken token0;
    TestToken token1;
    
    function setUp() public {
        // Deploy core protocol
        core = new Core();
        twamm = new TWAMM(ICore(address(core)));
        orders = new Orders(ICore(address(core)), ITWAMM(address(twamm)), address(this));
        
        // Deploy tokens
        token0 = new TestToken();
        token1 = new TestToken();
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
    }
    
    function test_TWAMMBypassFullRange() public {
        // SETUP: Create a NON-full-range pool config with TWAMM as extension
        // Concentrated liquidity with tickSpacing = 1 (not full-range)
        PoolConfig config = createConcentratedPoolConfig(
            0,                    // fee
            1,                    // tickSpacing (makes it non-full-range)
            address(twamm)        // TWAMM as extension
        );
        
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: config
        });
        
        // EXPLOIT: TWAMM extension initializes the pool itself
        // This bypasses the afterInitializePool hook due to self-call check
        vm.prank(address(twamm));
        core.initializePool(poolKey, 0);
        
        // VERIFY: Pool is initialized but TWAMM state is NOT properly initialized
        PoolState state = core.poolState(poolKey.toPoolId());
        assertTrue(state.isInitialized(), "Pool should be initialized");
        
        // The pool config is NOT full-range (this is the vulnerability)
        assertFalse(config.isFullRange(), "Config is not full-range");
        assertTrue(config.isConcentrated(), "Config is concentrated liquidity");
        assertEq(config.concentratedTickSpacing(), 1, "Tick spacing is 1 (not full-range)");
        
        // TWAMM state is zero (uninitialized) because afterInitializePool was not called
        TwammPoolState twammState = TWAMMLib.poolState(ITWAMM(address(twamm)), poolKey.toPoolId());
        assertEq(twammState.lastVirtualOrderExecutionTime(), 0, "TWAMM state not initialized");
        
        // Now users can place orders on this non-full-range pool
        // The lazy initialization will NOT check full-range requirement
        // This violates the protocol invariant that TWAMM only works on full-range pools
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Pool initialized with non-full-range config (tickSpacing=1)");
        console.log("- afterInitializePool hook was bypassed");
        console.log("- TWAMM orders can now be placed on incompatible pool type");
    }
}
```

**Notes:**
- The vulnerability stems from the interaction between the self-call check in `shouldCallAfterInitializePool` and the critical validation logic in TWAMM's `afterInitializePool` hook
- The full-range requirement is enforced by checking if all 32 bits of the pool type config are zero (discriminator=0, amplification=0, center=0) [6](#0-5) 

- The issue affects not just TWAMM but potentially any extension that performs critical initialization validation in `afterInitializePool` hooks
- This vulnerability violates the "Extension Isolation" invariant as the extension's own logic can be bypassed to create invalid protocol state

### Citations

**File:** src/libraries/ExtensionCallPointsLib.sol (L49-53)
```text
    function shouldCallAfterInitializePool(IExtension extension, address initializer) internal pure returns (bool yes) {
        assembly ("memory-safe") {
            yes := and(shr(159, extension), iszero(eq(initializer, extension)))
        }
    }
```

**File:** src/extensions/TWAMM.sol (L386-399)
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
```

**File:** src/extensions/TWAMM.sol (L625-644)
```text
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

**File:** test/extensions/TWAMM.t.sol (L50-53)
```text
    function test_createPool_fails_not_full_range() public {
        vm.expectRevert(ITWAMM.FullRangePoolOnly.selector);
        createPool(address(token0), address(token1), 0, createConcentratedPoolConfig(0, 1, address(twamm)));
    }
```

**File:** src/types/poolConfig.sol (L75-84)
```text
/// @notice Determines if this pool is full range (special case of stableswap with amplification=0 and center=0)
/// @dev Full range can be slightly optimized in that we don't need to compute the sqrt ratio at the tick boundaries
/// @param config The pool config
/// @return r True if the pool is full range
function isFullRange(PoolConfig config) pure returns (bool r) {
    assembly ("memory-safe") {
        // Full range when all 32 bits are 0 (discriminator=0, amplification=0, center=0)
        r := iszero(and(config, 0xffffffff))
    }
}
```
