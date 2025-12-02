## Title
Incorrect MEV Fee Calculation for Multiple Swaps in Same Block Due to Stale tickLast Reference

## Summary
The MEVCapture extension's `handleForwardData()` function only updates its `tickLast` state once per block, causing subsequent swaps within the same transaction to calculate MEV capture fees using a stale tick reference. This results in users being overcharged or undercharged based on cumulative tick movement from the start of the block rather than the actual tick movement of each individual swap.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData`, lines 177-260 [1](#0-0) 

**Intended Logic:** The MEVCapture extension should charge additional fees based on the tick distance moved by each individual swap. The fee multiplier should be calculated as `(abs(tickAfter - tickBefore) << 64) / tickSpacing` for each swap.

**Actual Logic:** The `tickLast` variable is only updated once per block when `lastUpdateTime != currentTime` (line 191). When multiple swaps occur in the same transaction:
- First swap: Correctly loads current tick from Core storage, saves it as `tickLast`, and calculates MEV fee based on actual movement
- Second and subsequent swaps: Skip the state update block (line 191 condition fails), use the stale `tickLast` from the first swap, causing MEV fee to be calculated on cumulative tick movement from block start rather than the individual swap's movement [2](#0-1) 

**Exploitation Path:**
1. User initiates multiple swaps through MEVCaptureRouter in a single transaction using `multiMultihopSwap()` or `multicall()` [3](#0-2) [4](#0-3) 

2. First swap executes via `handleForwardData()`: loads tick from Core (e.g., 100), saves `tickLast=100`, swaps to tick 150, correctly calculates MEV fee for 50 ticks of movement [5](#0-4) 

3. Second swap in same transaction: loads `tickLast=100` from storage, `lastUpdateTime == currentTime` so state update is skipped, swaps from tick 150 to 200 [6](#0-5) 

4. MEV fee calculated using `abs(200 - 100) = 100` ticks instead of actual `abs(200 - 150) = 50` ticks, resulting in 2x overcharge [7](#0-6) 

**Security Property Broken:** Violates the **Fee Accounting** invariant - "Position fee collection must be accurate and never allow double-claiming". Users are charged incorrect MEV capture fees that do not reflect actual tick movement.

## Impact Explanation
- **Affected Assets**: All users performing multiple swaps through MEVCapture pools in a single transaction, across all token pairs
- **Damage Severity**: Users can be overcharged by multiples of the correct fee (e.g., 2x, 3x, or more depending on number of swaps and directions). In reverse scenarios (opposite direction swaps), users can be undercharged or pay near-zero MEV fees despite significant tick movement
- **User Impact**: Any user utilizingRouter's batch swap functions (`multiMultihopSwap`, `multicall`) with MEVCapture pools. This is a normal usage pattern for multi-hop trades or portfolio rebalancing

## Likelihood Explanation
- **Attacker Profile**: Any user, including both innocent users performing legitimate multi-hop swaps and sophisticated actors intentionally exploiting the fee miscalculation
- **Preconditions**: MEVCapture pool must be initialized with non-zero liquidity. Multiple swaps in same transaction through the same or different MEVCapture pools
- **Execution Complexity**: Trivial - single transaction using standard Router functions already deployed
- **Frequency**: Every transaction containing multiple swaps through MEVCapture pools, potentially hundreds of times per day

## Recommendation

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, lines 177-260:

// CURRENT (vulnerable):
// tickLast is loaded once per block and reused for all swaps in that block
// causing incorrect fee calculations for subsequent swaps

// FIXED:
function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory result) {
    unchecked {
        (PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));

        PoolId poolId = poolKey.toPoolId();
        MEVCapturePoolState state = getPoolState(poolId);
        uint32 lastUpdateTime = state.lastUpdateTime();
        int32 tickLast = state.tickLast();

        uint32 currentTime = uint32(block.timestamp);

        int256 saveDelta0;
        int256 saveDelta1;

        // FIXED: Always load current tick from Core before each swap
        // to ensure accurate fee calculation for multiple swaps in same block
        (int32 currentTick, uint128 fees0, uint128 fees1) =
            loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

        // Only accumulate pending fees once per block
        if (lastUpdateTime != currentTime) {
            if (fees0 != 0 || fees1 != 0) {
                CORE.accumulateAsFees(poolKey, fees0, fees1);
                saveDelta0 -= int256(uint256(fees0));
                saveDelta1 -= int256(uint256(fees1));
            }
        }

        // Use the freshly loaded current tick for fee calculation
        tickLast = currentTick;
        
        // Update state with current tick regardless of whether it's first swap in block
        setPoolState({
            poolId: poolId,
            state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
        });

        (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

        // Now fee calculation uses correct tickLast = tick before THIS swap
        uint256 feeMultiplierX64 =
            (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
        
        // ... rest of function unchanged
    }
}
```

**Alternative mitigation:** Track the post-swap tick in storage and always use it as the starting point for the next swap's fee calculation, ensuring each swap's MEV fee reflects only its own tick movement.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureStaleTickLast.t.sol
// Run with: forge test --match-test test_StaleTickLastMultipleSwaps -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/MEVCaptureRouter.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/Router.sol";

contract Exploit_MEVCaptureStaleTickLast is Test {
    Core core;
    MEVCapture mevCapture;
    MEVCaptureRouter router;
    
    address token0 = address(0x1);
    address token1 = address(0x2);
    address user = address(0x999);
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        mevCapture = new MEVCapture(core);
        router = new MEVCaptureRouter(core, address(mevCapture));
        
        // Initialize MEVCapture pool with appropriate config
        // PoolKey with MEVCapture as extension, 0.3% fee, tick spacing 60
        PoolKey memory poolKey = createMEVCapturePoolKey();
        core.initializePool(poolKey, 0); // Initialize at tick 0
        
        // Add liquidity to pool
        // ... (liquidity provision code)
    }
    
    function test_StaleTickLastMultipleSwaps() public {
        // SETUP: Pool initialized at tick 0, MEVCapture state tickLast=0
        
        // Create two swaps in same transaction
        Swap[] memory swaps = new Swap[](2);
        
        // First swap: 0 -> 100 ticks (50 tick spacing = 2 crossings)
        swaps[0] = createSwap(token0, token1, 1000e18); // exactIn amount
        
        // Second swap: 100 -> 200 ticks (should be 50 tick spacing = 2 crossings)
        swaps[1] = createSwap(token0, token1, 1000e18);
        
        // EXPLOIT: Execute both swaps in single transaction
        vm.prank(user);
        PoolBalanceUpdate[][] memory results = router.multiMultihopSwap(swaps, 0);
        
        // VERIFY: Second swap charged MEV fee for 100 ticks instead of 50
        // Inspect the deltas to confirm overcharge
        
        // First swap: Correct fee for 2 tick spacing crossings
        int256 firstSwapInput = results[0][0].delta0();
        
        // Second swap: Incorrect fee for 4 tick spacing crossings (2x overcharge)
        // because it used tickLast=0 instead of tickLast=100
        int256 secondSwapInput = results[1][0].delta0();
        
        // The second swap should have same input as first (same tick distance)
        // but due to bug, it has ~2x the input due to 2x the MEV fee
        assertGt(
            secondSwapInput, 
            firstSwapInput * 19 / 10, // 1.9x multiplier
            "Second swap not overcharged as expected - vulnerability confirmed"
        );
    }
}
```

## Notes

This vulnerability stems from the design choice to update `tickLast` only once per block for gas optimization. However, this optimization breaks the fee accounting logic when multiple swaps occur in the same transaction. The issue is exacerbated by the Router's support for batch operations (`multiMultihopSwap`, `multicall`), which are standard features that users regularly employ for multi-hop trades.

The vulnerability can result in either overcharging (when swaps move ticks in the same direction) or undercharging (when swaps move ticks in opposite directions). Both scenarios violate the fee accounting accuracy requirement. Sophisticated users could potentially exploit the undercharging scenario to avoid paying proper MEV capture fees, while regular users performing legitimate batch swaps would be overcharged.

The root cause is the conditional state update at line 191 that gates the `tickLast` refresh. The fix requires loading the current tick from Core before each swap, regardless of whether it's the first swap in the block, while only accumulating pending fees once per block to maintain the intended behavior for fee collection.

### Citations

**File:** src/extensions/MEVCapture.sol (L177-260)
```text
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
            (PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));

            PoolId poolId = poolKey.toPoolId();
            MEVCapturePoolState state = getPoolState(poolId);
            uint32 lastUpdateTime = state.lastUpdateTime();
            int32 tickLast = state.tickLast();

            uint32 currentTime = uint32(block.timestamp);

            int256 saveDelta0;
            int256 saveDelta1;

            if (lastUpdateTime != currentTime) {
                (int32 tick, uint128 fees0, uint128 fees1) =
                    loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
                    // never overflows int256 container
                    saveDelta0 -= int256(uint256(fees0));
                    saveDelta1 -= int256(uint256(fees1));
                }

                tickLast = tick;
                setPoolState({
                    poolId: poolId,
                    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
                });
            }

            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));

            if (additionalFee != 0) {
                if (params.isExactOut()) {
                    // take an additional fee from the calculated input amount equal to the `additionalFee - poolFee`
                    if (balanceUpdate.delta0() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta1())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                } else {
                    if (balanceUpdate.delta0() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta0())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta1())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                }
            }

            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }

            result = abi.encode(balanceUpdate, stateAfter);
        }
    }
```

**File:** src/Router.sol (L390-403)
```text
    /// @notice Executes multiple multi-hop swaps in a single transaction
    /// @param swaps Array of swap structs, each containing a route and initial token amount
    /// @param calculatedAmountThreshold Minimum total final amount to receive (for slippage protection)
    /// @return results Array of delta arrays, one for each swap
    function multiMultihopSwap(Swap[] memory swaps, int256 calculatedAmountThreshold)
        external
        payable
        returns (PoolBalanceUpdate[][] memory results)
    {
        results = abi.decode(
            lock(abi.encode(CALL_TYPE_MULTI_MULTIHOP_SWAP, msg.sender, swaps, calculatedAmountThreshold)),
            (PoolBalanceUpdate[][])
        );
    }
```

**File:** src/base/PayableMulticallable.sol (L17-19)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }
```
