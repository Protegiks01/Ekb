# NoVulnerability found for this question.

## Validation Summary

After thorough validation of the security claim against the Ekubo codebase, I confirm that the analysis is **mathematically and technically correct**. The checked subtraction overflow scenario cannot occur under the protocol's invariants.

## Verified Code Evidence

The analysis correctly identifies the key code locations:

**1. Checked Subtraction Location:** [1](#0-0) 

**2. MaxLiquidity Constraint Enforcement:** [2](#0-1) 

**3. MaxLiquidity Calculation:** [3](#0-2) 

**4. Protocol Constants:** [4](#0-3) 

## Mathematical Verification

The core mathematical relationship is sound:

**Triangle Inequality:** For any tick, `|liquidityDelta| ≤ liquidityNet` must hold because:
- `liquidityNet` represents the sum of absolute liquidity values: `Σ|L_i|`
- `liquidityDelta` (the stored field) represents the algebraic sum: `Σ(±L_i)`
- By triangle inequality: `|Σ(±L_i)| ≤ Σ|L_i|`

**Overflow Analysis:**
- Maximum possible value: `|currentLiquidityDelta| ≤ maxLiquidity`
- Worst-case operation: `maxLiquidity - (-maxLiquidity) = 2 × maxLiquidity`
- With minimum tick spacing (1): `maxLiquidity ≈ 1.918 × 10³³`
- With maximum tick spacing (698,605): `maxLiquidity ≈ 1.334 × 10³⁶`
- Compare to `type(int128).max ≈ 1.701 × 10³⁸`
- Worst case: `2 × 1.334 × 10³⁶ ≈ 2.668 × 10³⁶` which is only ~1.57% of `int128.max`

**Constraint Enforcement:** [5](#0-4) 

The protocol enforces `liquidityNetNext ≤ maxLiquidity` before the checked arithmetic, ensuring the overflow scenario is impossible.

## Notes

- The relationship between the two stored values (`liquidityDelta` and `liquidityNet` in the `TickInfo` structure) is defined in: [6](#0-5) 
- The `addLiquidityDelta` function that updates `liquidityNet` includes its own overflow protection: [7](#0-6) 
- Both lower and upper tick updates are subject to the same constraint check, maintaining the invariant across all position operations

The analysis correctly demonstrates that the protocol's design prevents the theoretical overflow scenario through multiple layers of protection.

### Citations

**File:** src/Core.sol (L291-291)
```text
        uint128 liquidityNetNext = addLiquidityDelta(currentLiquidityNet, liquidityDelta);
```

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

**File:** src/types/tickInfo.sol (L20-25)
```text
function parse(TickInfo info) pure returns (int128 delta, uint128 net) {
    assembly ("memory-safe") {
        delta := signextend(15, info)
        net := shr(128, info)
    }
}
```

**File:** src/math/liquidity.sol (L129-136)
```text
function addLiquidityDelta(uint128 liquidity, int128 liquidityDelta) pure returns (uint128 result) {
    assembly ("memory-safe") {
        result := add(liquidity, liquidityDelta)
        if and(result, shl(128, 0xffffffffffffffffffffffffffffffff)) {
            mstore(0, shl(224, 0x6d862c50))
            revert(0, 4)
        }
    }
```
