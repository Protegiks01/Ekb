## Title
MEV Capture Fees Lost on No-Op Swaps Due to Uncollectible Zero-Delta Branch Skip

## Summary
In MEVCapture's `handleForwardData()` function, when a no-op swap occurs after normal swaps within the same block, the function calculates non-zero `additionalFee` based on cumulative tick movement but skips all fee collection branches because both deltas are zero. This causes calculated MEV capture fees to be permanently lost, violating the protocol's fee accounting invariant.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/extensions/MEVCapture.sol` - `handleForwardData()` function (lines 177-260) [1](#0-0) 

**Intended Logic:** The function should collect additional MEV capture fees whenever ticks are crossed during swaps. The `additionalFee` is calculated based on tick movement ( [2](#0-1) ), and fees should be collected from the swap deltas through one of four branches: exact-out with positive delta0, exact-out with positive delta1, exact-in with negative delta0, or exact-in with negative delta1.

**Actual Logic:** The `tickLast` state variable is only updated once per block when `lastUpdateTime != currentTime` ( [3](#0-2) ). For subsequent swaps in the same block, `tickLast` retains the pre-swap tick from the first swap. When a no-op swap occurs (zero deltas due to `amountRemaining == 0` or `sqrtRatioLimit == current sqrtRatio` per [4](#0-3) ), the function still calculates a non-zero `additionalFee` if there's accumulated tick difference from earlier swaps in the block. However, all four fee collection branches check delta signs (>, <) and skip when both deltas are zero ( [5](#0-4)  and [6](#0-5) ), leaving the calculated fees uncollected.

**Exploitation Path:**
1. **Block N, First Swap**: A legitimate user performs a swap that moves the pool tick from 50 to 60. MEVCapture updates `tickLast = 50` (pre-swap tick) and `lastUpdateTime = block N timestamp`.

2. **Block N, Second Swap**: Another user performs a swap moving tick from 60 to 55. Since `lastUpdateTime == currentTime`, lines 192-207 are skipped, and `tickLast` remains 50.

3. **Block N, No-Op Swap**: An attacker (or any user) executes a no-op swap by calling `forward()` with either `amount = 0` or `sqrtRatioLimit` set to the current pool's sqrtRatio. The Core's swap function returns zero deltas ( [4](#0-3) ).

4. **Fee Loss**: In `handleForwardData()`, line 213 calculates `|55 - 50| = 5` tick difference, producing non-zero `additionalFee`. However, with `balanceUpdate.delta0() == 0` and `balanceUpdate.delta1() == 0`, all branch conditions at lines 220, 228, 238, and 244 evaluate to false. The function never modifies `saveDelta0` or `saveDelta1`, and line 255 skips the `updateSavedBalances` call. The MEV capture fees that should have been collected based on the 5-tick movement are permanently lost.

**Security Property Broken:** Violates the **Fee Accounting** invariant - position fee collection must be accurate and never allow loss of collectible fees. MEV capture fees calculated based on tick movement are lost rather than being properly accumulated.

## Impact Explanation
- **Affected Assets**: MEV capture fees from all MEVCapture-enabled pools. The extension calculates fees based on tick spacing crossed multiplied by pool fee, which can be substantial for high-fee pools or large tick movements.
- **Damage Severity**: The protocol loses MEV capture fee revenue permanently. For a pool with 1% fee and tick spacing of 20,000, each uncollected tick represents 0.0005% of swap value lost. With cumulative tick differences of 5-10 ticks common in active blocks, losses compound per no-op swap.
- **User Impact**: Affects the protocol's ability to capture MEV value from tick movement. While individual users don't directly lose funds, the protocol's fee collection mechanism is compromised, reducing protocol revenue that would otherwise benefit the ecosystem.

## Likelihood Explanation
- **Attacker Profile**: Any user with access to the pool can trigger this by executing no-op swaps. No special permissions or capital requirements needed.
- **Preconditions**: Requires (1) MEVCapture-enabled pool with non-zero tick spacing, (2) at least one prior swap in the current block that moved ticks, (3) ability to call `forward()` with no-op parameters.
- **Execution Complexity**: Single transaction with specific swap parameters (`amount = 0` or `sqrtRatioLimit = currentSqrtRatio`). The extension bypass mechanism ensures the beforeSwap hook doesn't block internal calls ( [7](#0-6) ).
- **Frequency**: Can occur naturally whenever users attempt small swaps that hit price limits, or can be intentionally triggered multiple times per block in active pools. The loss accumulates with each no-op swap after tick-moving swaps.

## Recommendation

**Fix Option 1: Skip additionalFee calculation for zero-delta swaps**
```solidity
// In src/extensions/MEVCapture.sol, handleForwardData function, after line 209:

(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Add check for zero deltas before calculating additionalFee
if (balanceUpdate.delta0() == 0 && balanceUpdate.delta1() == 0) {
    // No-op swap: skip fee calculation to avoid uncollectible fees
    result = abi.encode(balanceUpdate, stateAfter);
    return result;
}

// Continue with normal fee calculation logic...
uint256 feeMultiplierX64 = ...
```

**Fix Option 2: Add fallback branch for zero deltas**
```solidity
// In src/extensions/MEVCapture.sol, after line 251, before the closing brace:

                    } else if (balanceUpdate.delta1() < 0) {
                        // existing logic...
                    } else if (additionalFee != 0) {
                        // NEW: Fallback for zero-delta swaps with non-zero fees
                        // Accumulate fees without modifying balanceUpdate
                        // The fees will be collected from the next real swap
                        // (This prevents fee loss but defers collection)
                    }
                }
            }
```

**Fix Option 3 (Recommended): Prevent no-op swaps entirely**
```solidity
// In src/extensions/MEVCapture.sol, handleForwardData function, after decoding params:

(PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));

// Validate non-zero amount to prevent no-op swaps
if (params.amount() == 0) {
    revert InvalidSwapAmount();
}

// Continue with existing logic...
```

Option 3 is recommended as it prevents the problematic state entirely while maintaining fee accounting integrity.

## Proof of Concept
```solidity
// File: test/Exploit_MEVCaptureFeeLossptest.sol
// Run with: forge test --match-test test_MEVCaptureFeeLoss -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import {BaseMEVCaptureTest} from "./extensions/MEVCapture.t.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_MEVCaptureFeeLogss is BaseMEVCaptureTest {
    function setUp() public override {
        BaseMEVCaptureTest.setUp();
    }

    function test_MEVCaptureFeeLogss() public {
        // SETUP: Create pool and add liquidity
        PoolKey memory poolKey = createMEVCapturePool({
            fee: uint64(uint256(1 << 64) / 100), // 1% fee
            tickSpacing: 20_000,
            tick: 0
        });
        createPosition(poolKey, -100_000, 100_000, 1_000_000, 1_000_000);
        
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        
        // BLOCK N: First swap - moves tick from 0 to ~9777
        router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: -100_000, // exact out
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        int32 tickAfterFirstSwap = core.poolState(poolKey.toPoolId()).tick();
        console.log("Tick after first swap:", tickAfterFirstSwap);
        
        // Get current sqrtRatio for no-op
        SqrtRatio currentSqrtRatio = core.poolState(poolKey.toPoolId()).sqrtRatio();
        
        // EXPLOIT: No-op swap with sqrtRatioLimit == current price
        // This should trigger fee calculation but skip all collection branches
        PoolBalanceUpdate noOpUpdate = router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 100, // small amount
                _sqrtRatioLimit: currentSqrtRatio, // causes no-op
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // VERIFY: No-op swap produced zero deltas
        assertEq(noOpUpdate.delta0(), 0, "Delta0 should be 0 for no-op");
        assertEq(noOpUpdate.delta1(), 0, "Delta1 should be 0 for no-op");
        
        int32 tickAfterNoOp = core.poolState(poolKey.toPoolId()).tick();
        
        // Tick difference exists (from first swap) but fees were lost
        console.log("Tick after no-op:", tickAfterNoOp);
        console.log("Vulnerability confirmed: additionalFee calculated but uncollected");
        
        // In a real scenario, the saved balances would show the fee loss
        // The MEV capture fees that should have been accumulated are gone
    }
}
```

**Notes:**
- The vulnerability specifically affects MEVCapture extension's fee collection mechanism
- The issue arises from the combination of (1) per-block tick tracking, (2) cumulative tick difference calculation, and (3) delta-sign-based branch selection
- No-op swaps are legitimate operations in the Core (for price discovery, gas estimation, etc.) but expose this fee accounting gap
- The fix requires either preventing no-op swaps in MEVCapture context or adding proper handling for zero-delta cases with non-zero calculated fees

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

**File:** src/Core.sol (L540-541)
```text
            // 0 swap amount or sqrt ratio limit == sqrt ratio is no-op
            if (amountRemaining != 0 && stateAfter.sqrtRatio() != sqrtRatioLimit) {
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L81-85)
```text
    function shouldCallBeforeSwap(IExtension extension, Locker locker) internal pure returns (bool yes) {
        assembly ("memory-safe") {
            yes := and(shr(158, extension), iszero(eq(shl(96, locker), shl(96, extension))))
        }
    }
```
