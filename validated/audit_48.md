# NoVulnerability found for this question.

## Validation Confirmation

After rigorous validation of the security claim against the Ekubo codebase, I **confirm the assessment is correct**. There is no arithmetic overflow vulnerability in the checked subtraction at `_updateTick`.

## Verified Analysis

**1. Code Location Accuracy**

The checked arithmetic operation is at: [1](#0-0) 

The comment explicitly states "this is checked math", confirming Solidity 0.8.x overflow protection is active.

**2. Triangle Inequality Invariant Verified**

Test evidence confirms the relationship between `liquidityDelta` and `liquidityNet`: [2](#0-1) 

At tick -100 with two overlapping positions: `liquidityDelta = liquidityA - liquidityB` while `liquidityNet = liquidityA + liquidityB`, proving |liquidityDelta| ≤ liquidityNet by mathematical necessity.

**3. Protocol Constraint Enforcement**

The maxLiquidity check occurs at: [3](#0-2) 

This ensures `liquidityNetNext ≤ maxLiquidity`, which by the invariant bounds `|liquidityDeltaNext| ≤ maxLiquidity`.

**4. Mathematical Bounds Verified**

Constants defined at: [4](#0-3) 

With MAX_TICK_SPACING = 698,605, the calculation at: [5](#0-4) 

Yields: maxLiquidity = (2^128 - 1) / 255 ≈ 1.334 × 10^36

Worst-case arithmetic: 2 × maxLiquidity ≈ 2.668 × 10^36, which is only **1.57%** of int128.max ≈ 1.701 × 10^38.

**Safety margin: >60x**

## Notes

The protocol's design ensures overflow is impossible through:
- Mathematical invariant: |liquidityDelta| ≤ liquidityNet ≤ maxLiquidity
- Individual position liquidity cannot exceed maxLiquidity (enforced when adding)
- Removing liquidity is bounded by position's existing liquidity
- Checked arithmetic provides additional safety layer

The validation report correctly identifies this as a non-issue. The protocol's constraints and type bounds provide overwhelming protection against the theoretical overflow scenario.

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

**File:** test/Positions.t.sol (L78-80)
```text
        (liquidityDelta, liquidityNet) = core.poolTicks(poolKey.toPoolId(), -100);
        assertEq(liquidityDelta, int128(liquidityA) - int128(liquidityB));
        assertEq(liquidityNet, liquidityB + liquidityA);
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
