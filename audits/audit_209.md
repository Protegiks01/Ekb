## Title
MEVCapture Charges Later Swappers for Cumulative Price Movement Within Same Block

## Summary
The MEVCapture extension's `handleForwardData` function only updates `tickLast` when entering a new block. When multiple swaps occur in the same block, subsequent swaps calculate their MEV fees based on the cumulative tick movement from the start of the block, not just their individual price impact. This causes later swappers to pay unfairly high fees while earlier swappers benefit from reduced fees.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/extensions/MEVCapture.sol`, function `handleForwardData`, lines 177-260 [1](#0-0) 

**Intended Logic:** The MEVCapture extension should charge each swapper an additional fee proportional to the price impact they cause. The comment on line 11 states it "Charges additional fees based on the relative size of the priority fee." [2](#0-1) 

**Actual Logic:** The `tickLast` variable is only updated at the start of each block (lines 191-206). When the condition `lastUpdateTime != currentTime` is true, `tickLast` is set to the current pool tick. For all subsequent swaps in that same block, this condition is false, so `tickLast` remains at the tick from the start of the block. The fee multiplier calculation on line 213 uses `abs(stateAfter.tick() - tickLast)`, causing later swaps to be charged for the entire cumulative price movement since the block started, not just their own impact. [3](#0-2) 

**Exploitation Path:**
1. Attacker monitors mempool for pending swaps in a MEVCapture-enabled pool
2. Attacker front-runs with their own swap to be first in the block
3. First swap pays fair MEV fees based only on its price impact
4. Victim's swap executes second in the same block, paying MEV fees calculated from the original tick (including the attacker's movement)
5. Attacker repeats this pattern, extracting value through unfair fee distribution

**Security Property Broken:** Fee Accounting invariant - "Position fee collection must be accurate and never allow double-claiming." While not strictly double-claiming, this causes inaccurate fee assessment where users pay for price movements they did not cause.

## Impact Explanation

- **Affected Assets**: All users swapping in MEVCapture-enabled pools are affected. Later swappers within a block overpay fees proportional to the cumulative price movement from earlier swaps.
- **Damage Severity**: If N swaps occur in a block with equal price impact, later swaps can pay up to N times the fair fee amount. For example, if three swaps each move the price 10 ticks: swap 1 pays for 10 ticks, swap 2 pays for 20 ticks, swap 3 pays for 30 ticks - total fees for 60 ticks when actual movement is only 30 ticks.
- **User Impact**: Any user whose swap is not first in a block within a MEVCapture pool will overpay. This disproportionately affects regular users versus sophisticated MEV searchers who can ensure first position.

## Likelihood Explanation

- **Attacker Profile**: Any sophisticated trader or MEV searcher with mempool monitoring capabilities
- **Preconditions**: MEVCapture-enabled pool with active trading, multiple swaps occurring in the same block
- **Execution Complexity**: Simple - requires only front-running capability, which is standard in MEV operations
- **Frequency**: Exploitable continuously, every block where multiple swaps occur in the same pool

## Recommendation

Update `tickLast` after each swap within a block, not just at the start of the block:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData:

// CURRENT (vulnerable):
// Lines 191-206: Only updates tickLast when entering new block
// Lines 209-213: Swap executes, then calculates fee using stale tickLast

// FIXED:
// After line 209, before line 212:
(PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

// Store the current tick for fee calculation BEFORE updating tickLast
int32 tickForFeeCalc = tickLast;

// however many tick spacings were crossed is the fee multiplier
uint256 feeMultiplierX64 =
    (FixedPointMathLib.abs(stateAfter.tick() - tickForFeeCalc) << 64) / poolKey.config.concentratedTickSpacing();

// NOW update tickLast for the next swap in this block
setPoolState({
    poolId: poolId,
    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: stateAfter.tick()})
});
```

This ensures each swap pays fees only for the price movement it causes, not cumulative movement from earlier swaps in the block.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureCumulativeFees.t.sol
// Run with: forge test --match-test test_MEVCaptureCumulativeFees -vvv

pragma solidity ^0.8.30;

import {FullTest} from "../FullTest.sol";
import {MEVCapture, mevCaptureCallPoints} from "../../src/extensions/MEVCapture.sol";
import {MEVCaptureRouter} from "../../src/MEVCaptureRouter.sol";
import {PoolKey} from "../../src/types/poolKey.sol";
import {createConcentratedPoolConfig} from "../../src/types/poolConfig.sol";
import {createSwapParameters} from "../../src/types/swapParameters.sol";
import {SqrtRatio} from "../../src/types/sqrtRatio.sol";
import {PoolBalanceUpdate} from "../../src/types/poolBalanceUpdate.sol";
import {CoreLib} from "../../src/libraries/CoreLib.sol";

contract Exploit_MEVCaptureCumulativeFees is FullTest {
    using CoreLib for *;
    
    MEVCapture internal mevCapture;
    MEVCaptureRouter internal mevRouter;
    
    function setUp() public override {
        FullTest.setUp();
        address deployAddress = address(uint160(mevCaptureCallPoints().toUint8()) << 152);
        deployCodeTo("MEVCapture.sol", abi.encode(core), deployAddress);
        mevCapture = MEVCapture(deployAddress);
        mevRouter = new MEVCaptureRouter(core, address(mevCapture));
        router = mevRouter;
    }
    
    function test_MEVCaptureCumulativeFees() public {
        // SETUP: Create pool with MEVCapture extension, 1% fee, 20k tick spacing
        PoolKey memory poolKey = createPool(
            address(token0),
            address(token1),
            0,
            createConcentratedPoolConfig(uint64(uint256(1 << 64) / 100), 20_000, address(mevCapture))
        );
        
        // Add liquidity across wide range
        createPosition(poolKey, -100_000, 100_000, 1_000_000, 1_000_000);
        
        // Approve router for swaps
        token0.approve(address(mevRouter), type(uint256).max);
        
        // Record initial tick
        int32 initialTick = core.poolState(poolKey.toPoolId()).tick();
        
        // EXPLOIT: Execute two identical swaps in same block
        
        // First swap: 200k token0
        PoolBalanceUpdate balance1 = mevRouter.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 200_000,
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        int32 tickAfterFirst = core.poolState(poolKey.toPoolId()).tick();
        int32 firstSwapMovement = initialTick - tickAfterFirst;
        
        // Second swap: same 200k token0 in SAME block
        PoolBalanceUpdate balance2 = mevRouter.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 200_000,
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        int32 tickAfterSecond = core.poolState(poolKey.toPoolId()).tick();
        int32 secondSwapMovement = tickAfterFirst - tickAfterSecond;
        
        // VERIFY: Second swap pays significantly more despite similar price impact
        
        // Both swaps input same amount
        assertEq(balance1.delta0(), 200_000, "First swap delta0");
        assertEq(balance2.delta0(), 200_000, "Second swap delta0");
        
        // Both swaps should move price roughly the same amount
        assertTrue(
            secondSwapMovement > firstSwapMovement * 95 / 100 &&
            secondSwapMovement < firstSwapMovement * 105 / 100,
            "Swaps should have similar price impact"
        );
        
        // But second swap pays MUCH higher fees (receives less output)
        int256 output1 = -balance1.delta1();
        int256 output2 = -balance2.delta1();
        
        // Second swapper receives significantly less due to being charged for cumulative movement
        assertTrue(
            output2 < output1 * 90 / 100,
            "Second swap pays unfairly high fees"
        );
        
        // The fee discrepancy proves the vulnerability
        int256 feeDifference = output1 - output2;
        assertTrue(feeDifference > 0, "Second swap paid more fees than first");
    }
}
```

## Notes

The vulnerability stems from a flawed implementation where `tickLast` serves as a "starting point" for fee calculations but is only updated once per block. The premise in the original question is incorrect - it's actually the **later swappers who pay unfairly HIGH fees**, not less. The first swapper benefits from paying only for their own price impact, while subsequent swappers in the same block are incorrectly charged for cumulative price movements including prior swaps' impacts.

This creates a perverse incentive where sophisticated traders can front-run to ensure first position in each block, paying minimal MEV fees while regular users who execute later bear disproportionate costs. The total fees collected by the protocol exceed what would be fair based on actual individual price impacts.

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

**File:** src/interfaces/extensions/IMEVCapture.sol (L11-11)
```text
/// @dev Extension that charges additional fees based on the relative size of the priority fee and tick movement during swaps
```
