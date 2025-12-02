# NoVulnerability found for this question.

After thorough analysis of the `_updateTick` function and the constraints in the Ekubo Protocol, the checked subtraction overflow scenario described in the security question **cannot occur** in practice.

## Analysis Summary

The security question asks whether the checked subtraction at line 294 can overflow when `currentLiquidityDelta = type(int128).max` and `liquidityDelta = type(int128).min`. [1](#0-0) 

**Key Findings:**

1. **currentLiquidityDelta Cannot Reach type(int128).max**
   - The `liquidityDelta` field stored in each tick is bounded by `±liquidityNet`
   - `liquidityNet` is enforced to never exceed `maxLiquidity` by the constraint at line 298 [2](#0-1) 

2. **maxLiquidity Bounds Calculation**
   - `maxLiquidity = type(uint128).max / numTicks` [3](#0-2) 
   
   - With minimum tick spacing (1): `numTicks = 177,445,671`, `maxLiquidity ≈ 1.918 × 10³³`
   - With maximum tick spacing (698,605): `numTicks = 253`, `maxLiquidity ≈ 1.345 × 10³⁶` [4](#0-3) 

3. **Overflow Impossibility**
   - `type(int128).max ≈ 1.701 × 10³⁸`
   - Worst-case arithmetic: `maxLiquidity - (-maxLiquidity) = 2 × maxLiquidity ≈ 2.69 × 10³⁶`
   - This is **approximately 0.00158%** of `type(int128).max`
   - Therefore: `2 × maxLiquidity << type(int128).max` for all valid pool configurations

## Conclusion

The `maxLiquidity` constraint acts as an effective safeguard that prevents the tick's `liquidityDelta` field from ever approaching values that could cause overflow in the checked arithmetic at line 294. The scenario posed in the security question is mathematically impossible under the protocol's invariants.

**Notes:**
- The relationship between `liquidityDelta` and `liquidityNet` ensures `|liquidityDelta| ≤ liquidityNet ≤ maxLiquidity`
- Both tick updates (lower and upper) are subject to the same `maxLiquidity` constraint
- The constraint is validated for every position operation before the arithmetic that could theoretically overflow

### Citations

**File:** src/Core.sol (L293-294)
```text
        int128 liquidityDeltaNext =
            isUpper ? currentLiquidityDelta - liquidityDelta : currentLiquidityDelta + liquidityDelta;
```

**File:** src/Core.sol (L297-300)
```text
        uint128 maxLiquidity = poolConfig.concentratedMaxLiquidityPerTick();
        if (liquidityNetNext > maxLiquidity) {
            revert MaxLiquidityPerTickExceeded(tick, liquidityNetNext, maxLiquidity);
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

**File:** src/math/constants.sol (L10-22)
```text
int32 constant MIN_TICK = -88722835;

// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;

// The maximum tick magnitude (absolute value of MAX_TICK)
// Used for validation and bounds checking in tick-related calculations
uint32 constant MAX_TICK_MAGNITUDE = uint32(MAX_TICK);

// The maximum allowed tick spacing for pools
// Defines the upper limit for tick spacing configuration in pool creation
uint32 constant MAX_TICK_SPACING = 698605;
```
