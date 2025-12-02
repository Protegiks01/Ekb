## Title
Staleswap Position Fee View Function Returns Catastrophically Incorrect Values When Tick Moves Outside Active Liquidity Range

## Summary
The `getPositionFeesAndLiquidity` view function in `BasePositions.sol` uses incorrect logic for non-full-range stableswap pools, causing it to report massively incorrect fee amounts (due to arithmetic underflow) when the pool's current tick moves outside the stableswap active liquidity range. This violates the Fee Accounting invariant as the view function returns values that differ drastically from what `collectFees` would actually return.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (function `getPositionFeesAndLiquidity`, lines 43-68) [1](#0-0) 

**Intended Logic:** The view function should return the accurate pending fees that would be collected if `collectFees` were called, allowing users and integrators to query position values without state changes.

**Actual Logic:** For non-full-range stableswap pools, the function incorrectly uses `getPoolFeesPerLiquidityInside` (which relies on tick boundary fee tracking) instead of global fees per liquidity. When the tick moves outside the stableswap active range, this causes the function to compute `feesPerLiquidityInside = 0`, leading to arithmetic underflow in the fee calculation that produces massively incorrect values.

**Exploitation Path:**

1. **Pool Creation**: A non-full-range stableswap pool is created with amplification > 0 (e.g., amplification=10, center=0), defining an active liquidity range `[lower, upper]`. [2](#0-1) 

2. **Position Creation**: User mints a position at the required boundaries `[lower, upper]` (all stableswap positions must be at these exact boundaries). [3](#0-2) 

3. **Fee Accrual**: Swaps occur within the active range, accumulating fees. The position's `feesPerLiquidityInsideLast` snapshot is set to the global fees value during position updates. [4](#0-3) 

4. **Tick Moves Outside Range**: A large swap pushes the tick above `upper` (or below `lower`). For stableswap pools, the swap logic allows the tick to move outside the active range with `stepLiquidity = 0`. [5](#0-4) 

5. **View Function Called**: When `getPositionFeesAndLiquidity` is called, it checks `isFullRange()` which returns false for non-full-range stableswap. [6](#0-5) 

6. **Incorrect Calculation**: The function calls `getPoolFeesPerLiquidityInside`, which computes fees based on tick boundaries. Since stableswap never initializes these tick boundary values (no `_updateTick` calls for stableswap), they remain at 0. When tick >= upper, the formula returns `feesPerLiquidityInside = upper0 - lower0 = 0 - 0 = 0`. [7](#0-6) 

7. **Arithmetic Underflow**: The `position.fees()` function computes `difference0 = 0 - positionSnapshot` in unchecked assembly, causing wraparound to `type(uint256).max - positionSnapshot + 1`, resulting in a massively inflated fee value. [8](#0-7) 

8. **Discrepancy**: Meanwhile, `collectFees` correctly uses global fees per liquidity for all stableswap pools, returning the accurate fee amount. [9](#0-8) 

**Security Property Broken:** The Fee Accounting invariant is violated - the view function returns catastrophically incorrect values that differ from actual collectible fees by many orders of magnitude.

## Impact Explanation
- **Affected Assets**: All non-full-range stableswap positions where the tick has moved outside the active liquidity range
- **Damage Severity**: While this is a view function that doesn't directly steal funds, integrators relying on this function for portfolio valuation, liquidation decisions, or UI displays will receive completely incorrect data (potentially showing fees in the quintillions when actual fees are in the thousands). This can lead to:
  - Incorrect liquidation decisions in lending protocols
  - Portfolio valuation errors in aggregators
  - User confusion and loss of trust
  - Smart contract logic errors in protocols integrating Ekubo
- **User Impact**: Any LP with a non-full-range stableswap position, any integrator querying position values. The issue occurs automatically when market conditions push the tick outside the active range.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a logic error that manifests under normal market conditions
- **Preconditions**: 
  1. Non-full-range stableswap pool exists (amplification > 0 or center ≠ 0)
  2. Position has been created and fees have accrued
  3. Tick has moved outside the active liquidity range (common during volatile markets or low liquidity)
- **Execution Complexity**: Automatic - occurs whenever the view function is called after the tick moves outside range
- **Frequency**: Persistent - once the tick moves outside the range, every call to the view function returns incorrect values until the tick moves back into range

## Recommendation

Fix the logic in `BasePositions.getPositionFeesAndLiquidity` to use the same calculation method as `collectFees` and `updatePosition`:

```solidity
// In src/base/BasePositions.sol, function getPositionFeesAndLiquidity, lines 64-67:

// CURRENT (vulnerable):
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
    ? CORE.getPoolFeesPerLiquidity(poolId)
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);

// FIXED:
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isStableswap()
    ? CORE.getPoolFeesPerLiquidity(poolId)  // Use global fees for ALL stableswap pools
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);  // Use tick-based for concentrated only
```

This change aligns the view function logic with both `Core.collectFees` and `Core.updatePosition`, ensuring consistency across all stableswap pools (both full-range and non-full-range).

## Proof of Concept

```solidity
// File: test/Exploit_StableswapFeeViewUnderflow.t.sol
// Run with: forge test --match-test test_StableswapFeeViewUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "./helpers/TestERC20.sol";
import {PoolKey, createPoolKey} from "../src/types/poolKey.sol";
import {PoolConfig, createStableswapPoolConfig} from "../src/types/poolConfig.sol";
import {SqrtRatio, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_StableswapFeeViewUnderflow is Test {
    Core core;
    Positions positions;
    Router router;
    TestERC20 token0;
    TestERC20 token1;
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        positions = new Positions(core, address(this), 0, 0);
        router = new Router(core, positions);
        
        // Deploy tokens
        token0 = new TestERC20();
        token1 = new TestERC20();
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        token0.mint(address(this), type(uint128).max);
        token1.mint(address(this), type(uint128).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_StableswapFeeViewUnderflow() public {
        // SETUP: Create non-full-range stableswap pool
        PoolConfig config = createStableswapPoolConfig(3000, 10, 0, address(0)); // amp=10, center=0
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        
        PoolKey memory poolKey = createPoolKey(address(token0), address(token1), config);
        core.initializePool(poolKey, 0); // Initialize at tick 0 (inside range)
        
        // Create position
        uint256 positionId = positions.mintAndDeposit(poolKey, lower, upper, 1e18, 1e18, 0);
        
        // Perform swaps to accumulate fees (inside range)
        router.swap(poolKey, false, 1e17, MAX_SQRT_RATIO, 0, type(int256).min);
        router.swap(poolKey, true, 1e17, SqrtRatio.wrap(0), 0, type(int256).min);
        
        // Get fees while in range (should be reasonable)
        (,,, uint128 fees0InRange, uint128 fees1InRange) = 
            positions.getPositionFeesAndLiquidity(positionId, poolKey, lower, upper);
        
        // EXPLOIT: Push tick outside active range with large swap
        router.swap(poolKey, false, 5e18, MAX_SQRT_RATIO, 0, type(int256).min);
        
        // Verify tick is now outside range
        (, int32 currentTick,) = core.poolState(poolKey.toPoolId()).parse();
        assertGe(currentTick, upper, "Tick should be >= upper");
        
        // VERIFY: getPositionFeesAndLiquidity returns catastrophically wrong value
        (,,, uint128 fees0OutsideRange, uint128 fees1OutsideRange) = 
            positions.getPositionFeesAndLiquidity(positionId, poolKey, lower, upper);
        
        // The view function will show massive wraparound values
        assertGt(fees0OutsideRange, 1e30, "Vulnerability confirmed: fees wrapped around to massive value");
        
        // Meanwhile, collectFees would return reasonable values (can't test directly without auth)
        // but we can verify the discrepancy is real by checking the values are wildly different
        assertGt(fees0OutsideRange / fees0InRange, 1e18, "View function shows >1e18x more fees than before");
    }
}
```

**Notes:**
- The root cause is the inconsistency between checking `isFullRange()` in the view function versus `isStableswap()` in `collectFees` and `updatePosition`
- For stableswap pools, tick boundary fees (`poolTickFeesPerLiquidityOutside`) are never updated because `_updateTick` is only called for concentrated liquidity pools
- When the tick moves outside the stableswap active range (which is allowed by the swap logic), the uninitialized boundary values cause `getPoolFeesPerLiquidityInside` to return 0
- This creates an arithmetic underflow in the unchecked assembly fee calculation, producing wraparound values orders of magnitude larger than the actual fees
- The fix is simple: use `isStableswap()` instead of `isFullRange()` to determine which calculation method to use, matching the logic in `Core.collectFees` and `Core.updatePosition`

### Citations

**File:** src/base/BasePositions.sol (L43-68)
```text
    function getPositionFeesAndLiquidity(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        external
        view
        returns (uint128 liquidity, uint128 principal0, uint128 principal1, uint128 fees0, uint128 fees1)
    {
        PoolId poolId = poolKey.toPoolId();
        SqrtRatio sqrtRatio = CORE.poolState(poolId).sqrtRatio();
        PositionId positionId =
            createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper});
        Position memory position = CORE.poolPositions(poolId, address(this), positionId);

        liquidity = position.liquidity;

        // the sqrt ratio may be 0 (because the pool is uninitialized) but this is
        // fine since amount0Delta isn't called with it in this case
        (int128 delta0, int128 delta1) = liquidityDeltaToAmountDelta(
            sqrtRatio, -SafeCastLib.toInt128(position.liquidity), tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper)
        );

        (principal0, principal1) = (uint128(-delta0), uint128(-delta1));

        FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
            ? CORE.getPoolFeesPerLiquidity(poolId)
            : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);
        (fees0, fees1) = position.fees(feesPerLiquidityInside);
    }
```

**File:** src/types/poolConfig.sol (L152-169)
```text
/// @notice Creates a PoolConfig for a stableswap pool
/// @param _fee The fee for the pool
/// @param _amplification The amplification factor (0-127)
/// @param _centerTick The center tick (will be divided by 16 and stored as 24-bit value)
/// @param _extension The extension address for the pool
/// @return c The packed configuration
function createStableswapPoolConfig(uint64 _fee, uint8 _amplification, int32 _centerTick, address _extension)
    pure
    returns (PoolConfig c)
{
    assembly ("memory-safe") {
        // Divide center tick by 16 to get 24-bit representation
        let stableswapCenterTick24 := sdiv(_centerTick, 16)
        // Pack: bit 31 = 0 (stableswap), bits 30-24 = amplification, bits 23-0 = center tick
        let typeConfig := or(shl(24, and(_amplification, 0x7f)), and(stableswapCenterTick24, 0xffffff))
        c := or(or(shl(96, _extension), shl(32, and(_fee, 0xffffffffffffffff))), typeConfig)
    }
}
```

**File:** src/types/positionId.sol (L47-57)
```text
function validate(PositionId positionId, PoolConfig config) pure {
    if (config.isConcentrated()) {
        if (positionId.tickLower() >= positionId.tickUpper()) revert BoundsOrder();
        if (positionId.tickLower() < MIN_TICK || positionId.tickUpper() > MAX_TICK) revert MinMaxBounds();
        int32 spacing = int32(config.concentratedTickSpacing());
        if (positionId.tickLower() % spacing != 0 || positionId.tickUpper() % spacing != 0) revert BoundsTickSpacing();
    } else {
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        // For stableswap pools, positions must be exactly min/max tick
        if (positionId.tickLower() != lower || positionId.tickUpper() != upper) revert StableswapMustBeFullRange();
    }
```

**File:** src/Core.sol (L180-216)
```text
    function _getPoolFeesPerLiquidityInside(PoolId poolId, int32 tick, int32 tickLower, int32 tickUpper)
        internal
        view
        returns (FeesPerLiquidity memory feesPerLiquidityInside)
    {
        uint256 lower0;
        uint256 lower1;
        uint256 upper0;
        uint256 upper1;
        {
            (StorageSlot l0, StorageSlot l1) = CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tickLower);
            (lower0, lower1) = (uint256(l0.load()), uint256(l1.load()));

            (StorageSlot u0, StorageSlot u1) = CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tickUpper);
            (upper0, upper1) = (uint256(u0.load()), uint256(u1.load()));
        }

        unchecked {
            if (tick < tickLower) {
                feesPerLiquidityInside.value0 = lower0 - upper0;
                feesPerLiquidityInside.value1 = lower1 - upper1;
            } else if (tick < tickUpper) {
                uint256 global0;
                uint256 global1;
                {
                    (bytes32 g0, bytes32 g1) = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).loadTwo();
                    (global0, global1) = (uint256(g0), uint256(g1));
                }

                feesPerLiquidityInside.value0 = global0 - upper0 - lower0;
                feesPerLiquidityInside.value1 = global1 - upper1 - lower1;
            } else {
                feesPerLiquidityInside.value0 = upper0 - lower0;
                feesPerLiquidityInside.value1 = upper1 - lower1;
            }
        }
    }
```

**File:** src/Core.sol (L417-428)
```text
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
```

**File:** src/Core.sol (L480-490)
```text
        if (poolKey.config.isStableswap()) {
            // Stableswap pools: use global fees per liquidity
            StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
            feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
            feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
        } else {
            // Concentrated pools: calculate fees per liquidity inside the position bounds
            feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                poolId, readPoolState(poolId).tick(), positionId.tickLower(), positionId.tickUpper()
            );
        }
```

**File:** src/Core.sol (L577-598)
```text
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
```

**File:** src/types/position.sol (L33-51)
```text
function fees(Position memory position, FeesPerLiquidity memory feesPerLiquidityInside)
    pure
    returns (uint128, uint128)
{
    uint128 liquidity;
    uint256 difference0;
    uint256 difference1;
    assembly ("memory-safe") {
        liquidity := mload(add(position, 0x20))
        // feesPerLiquidityInsideLast is now at offset 0x40 due to extraData field
        let positionFpl := mload(add(position, 0x40))
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
    }

    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
```
