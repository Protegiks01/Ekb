# NoVulnerability found for this question.

## Critical Analysis

After extensive code validation, this claim fails multiple checks from the validation framework:

### 1. **Mischaracterization of "Inactive Liquidity"**

For stableswap pools, ALL positions must be at exactly `[lower, upper]` boundaries from `stableswapActiveLiquidityTickRange()`. [1](#0-0)  This validation is enforced on EVERY `updatePosition` call. [2](#0-1) 

When tick moves outside `[lower, upper]`:
- Alice's liquidity at `[lower, upper]` is inactive
- Bob's liquidity at `[lower, upper]` is ALSO inactive
- **Both LPs have identical position bounds and identical inactive status**

The claim frames this as "inactive liquidity stealing from active liquidity" but this is fundamentally **misleading** - Alice's liquidity is also inactive when tick is outside the range.

### 2. **No Tick-Crossing Mechanism for Stableswap Pools**

Unlike concentrated pools which update `state.liquidity` conditionally based on tick position [3](#0-2) , stableswap pools have **NO mechanism** to adjust `state.liquidity` when tick crosses range boundaries.

If the design intended `state.liquidity` to represent "currently active liquidity", there would need to be code that:
- Sets `state.liquidity = 0` when tick exits `[lower, upper]`
- Restores `state.liquidity` when tick re-enters the range

**This code does not exist.** The only way `state.liquidity` changes for stableswap pools is through `updatePosition` calls. This strongly indicates the current behavior is **intentional design**, not a bug.

### 3. **Intentional Simpler Design for Stableswap Pools**

The codebase shows stableswap pools use a simpler global fee accounting model by design. During swaps, `state.liquidity` is read and then **conditionally used** by setting `stepLiquidity = 0` when outside range. [4](#0-3) 

This pattern (store total liquidity, conditionally use it) is consistent throughout the swap logic. For fee collection, stableswap pools similarly use global fees per liquidity without tick-range considerations. [5](#0-4) 

### 4. **Normal LP Behavior, Not an Exploit**

The scenario described is standard AMM behavior:
- Bob deposits real capital (token0 and token1) to provide liquidity
- Bob becomes a legitimate LP at the same position bounds as Alice
- Fees are distributed proportionally to LP shares
- Bob can add/remove liquidity at any time

The temporal argument ("Alice was there first when liquidity was active") does not create a security vulnerability. In all AMMs, fees are distributed based on **current LP share**, not historical contribution.

### 5. **Comment Ambiguity vs. Implementation Intent**

The comment "we store the active liquidity" [6](#0-5)  is ambiguous but likely means "the liquidity FOR the pool's active range configuration" (i.e., liquidity deposited at the designated [lower, upper] range), not "liquidity that is currently being used for trading".

The absence of tick-crossing updates is the strongest evidence that the implementation matches the intended design.

### 6. **No Security Invariant Violated**

The README and documentation do not specify that extension fees must only be distributed to "currently active" LPs. The protocol's fee distribution model for stableswap pools distributes proportionally to all deposited liquidity, which is a valid design choice.

## Notes

This claim confuses **design differences between pool types** with a security vulnerability. Concentrated pools use complex tick-based accounting that updates `state.liquidity` conditionally. Stableswap pools use simpler global accounting where `state.liquidity` stores total deposited liquidity. Both are valid design patterns for different use cases. The lack of a tick-crossing mechanism to adjust stableswap `state.liquidity` is the definitive proof this is intentional design, not an oversight.

### Citations

**File:** src/types/positionId.sol (L54-56)
```text
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        // For stableswap pools, positions must be exactly min/max tick
        if (positionId.tickLower() != lower || positionId.tickUpper() != upper) revert StableswapMustBeFullRange();
```

**File:** src/Core.sol (L363-363)
```text
        positionId.validate(poolKey.config);
```

**File:** src/Core.sol (L409-416)
```text
                if (state.tick() >= positionId.tickLower() && state.tick() < positionId.tickUpper()) {
                    state = createPoolState({
                        _sqrtRatio: state.sqrtRatio(),
                        _tick: state.tick(),
                        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                    });
                    writePoolState(poolId, state);
                }
```

**File:** src/Core.sol (L418-418)
```text
                // we store the active liquidity in the liquidity slot for stableswap pools
```

**File:** src/Core.sol (L480-484)
```text
        if (poolKey.config.isStableswap()) {
            // Stableswap pools: use global fees per liquidity
            StorageSlot fplFirstSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
            feesPerLiquidityInside.value0 = uint256(fplFirstSlot.load());
            feesPerLiquidityInside.value1 = uint256(fplFirstSlot.next().load());
```

**File:** src/Core.sol (L570-596)
```text
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
```
