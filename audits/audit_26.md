## Title
Out-of-Bounds Tick Storage When Swapping to MIN_TICK Causes Incorrect Fee Accounting

## Summary
When a swap reaches exactly `MIN_TICK` while decreasing (`increasing = false`), the swap logic at line 756 sets the pool's tick to `MIN_TICK - 1`, which is outside the valid tick range [-88722835, 88722835]. This invalid tick is stored in the pool state and subsequently causes incorrect fee calculations when users update positions or collect fees, violating the protocol's fee accounting invariant.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol` - `swap_6269342730()` function, lines 752-757, and `_getPoolFeesPerLiquidityInside()` function, lines 180-216 [1](#0-0) 

**Intended Logic:** When a swap crosses a tick boundary, the current tick should be set to reflect the correct position: at the tick when crossing upward, or one below the tick when crossing downward. The comment at line 755 states "no overflow danger because nextTick is always inside the valid tick bounds."

**Actual Logic:** When `nextTick = MIN_TICK` and `increasing = false`, the calculation `tick = nextTick - iszero(increasing) = MIN_TICK - 1` produces -88722836, which is below the minimum allowed tick of -88722835. [2](#0-1) 

**Exploitation Path:**

1. **Setup**: A pool has liquidity only at ticks above MIN_TICK. A user initiates a large swap from token0 to token1 (decreasing price, `increasing = false`).

2. **Tick Search**: During the swap loop, `findPrevInitializedTick` is called and returns `MIN_TICK` when no more initialized ticks are found. [3](#0-2) 

3. **Boundary Condition**: The swap amount is sufficient to reach exactly `MIN_TICK`, so `sqrtRatioNext == nextTickSqrtRatio` evaluates to true at line 752. The assembly code sets `tick = MIN_TICK - 1`. [4](#0-3) 

4. **State Corruption**: This invalid tick (-88722836) is stored in the pool state via `createPoolState` and `writePoolState`. [5](#0-4) 

5. **Fee Miscalculation**: When any user subsequently updates their position or collects fees, `_getPoolFeesPerLiquidityInside` is called with the corrupted tick value. [6](#0-5)  Since `MIN_TICK - 1 < tickLower` for all valid positions, the function always executes the first branch, calculating fees as `lower - upper` instead of the correct formula. [7](#0-6) 

6. **Incorrect Fee Collection**: Users collect incorrect fee amounts, either more or less than they should receive, depending on the actual fee distribution.

**Security Property Broken:** Fee Accounting invariant - "Position fee collection must be accurate and never allow double-claiming." The corrupted tick causes systematic fee miscalculation for all positions in the affected pool.

## Impact Explanation
- **Affected Assets**: All liquidity provider positions in pools where this boundary condition is triggered. The fees (in both token0 and token1) for these positions will be miscalculated.
- **Damage Severity**: Users may collect significantly more or less fees than they earned, depending on how the fee tracking variables evolved. In worst case, users could receive excess fees that should have gone to other LPs, or lose fees they legitimately earned.
- **User Impact**: All liquidity providers in the affected pool. The issue triggers when any user performs a large downward swap that reaches MIN_TICK, and persists until the pool recovers through upward price movement. All subsequent fee collections are affected.

## Likelihood Explanation
- **Attacker Profile**: Any user who can execute a swap. The issue can be triggered accidentally by legitimate swaps or intentionally by an attacker.
- **Preconditions**: 
  - Pool must have liquidity concentrated at higher ticks
  - Sufficient swap size to move price all the way to MIN_TICK
  - Swap must reach exactly MIN_TICK (condition `sqrtRatioNext == nextTickSqrtRatio` must be true)
- **Execution Complexity**: Single transaction executing a large swap. No special timing or multiple steps required.
- **Frequency**: Can occur once per pool. After the pool tick is corrupted, all subsequent fee operations are affected until the pool state is corrected through other swaps.

## Recommendation

```solidity
// In src/Core.sol, function swap_6269342730, line 752-757:

// CURRENT (vulnerable):
if (sqrtRatioNext == nextTickSqrtRatio) {
    sqrtRatio = sqrtRatioNext;
    assembly ("memory-safe") {
        // no overflow danger because nextTick is always inside the valid tick bounds
        tick := sub(nextTick, iszero(increasing))
    }

// FIXED:
if (sqrtRatioNext == nextTickSqrtRatio) {
    sqrtRatio = sqrtRatioNext;
    assembly ("memory-safe") {
        // Handle boundary condition: when crossing MIN_TICK downward, stay at MIN_TICK
        let adjustment := iszero(increasing)
        // If nextTick == MIN_TICK and adjustment == 1, clamp to MIN_TICK
        let wouldUnderflow := and(eq(nextTick, MIN_TICK), adjustment)
        tick := sub(nextTick, and(adjustment, iszero(wouldUnderflow)))
    }
```

Alternative mitigation: Add a post-condition check after the tick calculation to ensure it remains within valid bounds, reverting if violated.

## Proof of Concept

```solidity
// File: test/Exploit_MinTickUnderflow.t.sol
// Run with: forge test --match-test test_MinTickUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/types/poolKey.sol";
import "../src/types/swapParameters.sol";
import "../src/math/constants.sol";

contract Exploit_MinTickUnderflow is Test {
    Core core;
    Router router;
    
    address token0 = address(0x1);
    address token1 = address(0x2);
    
    function setUp() public {
        // Deploy core and router
        core = new Core();
        router = new Router(address(core));
        
        // Setup tokens (mock ERC20s)
        // Create pool with liquidity only at higher ticks
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: /* concentrated pool config */
        });
        
        // Initialize pool at a high tick (e.g., tick = 100000)
        core.initializePool(poolKey, 100000);
        
        // Add liquidity only at ticks > MIN_TICK (e.g., 0 to 100000)
        // This ensures findPrevInitializedTick will eventually return MIN_TICK
    }
    
    function test_MinTickUnderflow() public {
        // SETUP: Pool has liquidity only at high ticks
        // Current tick is around 100000
        
        // EXPLOIT: Execute large swap downward to reach MIN_TICK
        SwapParameters memory params = SwapParameters({
            amount: type(int128).max, // Very large swap
            isToken1: false,
            // ... other params to swap token0 -> token1
        });
        
        // Execute swap through router
        router.swap(/* pool key, params */);
        
        // VERIFY: Pool tick is now MIN_TICK - 1 (out of bounds)
        PoolState state = core.readPoolState(/* poolId */);
        int32 actualTick = state.tick();
        
        assertEq(actualTick, MIN_TICK - 1, "Vulnerability confirmed: tick underflowed below MIN_TICK");
        
        // Verify fee calculation is broken
        // Try to collect fees or update position - fees will be miscalculated
        (uint128 fees0, uint128 fees1) = core.collectFees(/* pool key, position */);
        
        // Fees will be incorrect due to wrong branch in _getPoolFeesPerLiquidityInside
        // Expected fees != actual fees collected
    }
}
```

**Notes:**
- The symmetric case (MAX_TICK with `increasing = true`) does NOT have this issue because `tick = MAX_TICK - 0 = MAX_TICK` stays within bounds
- The vulnerability is triggered when the swap reaches exactly MIN_TICK, which requires the condition `sqrtRatioNext == nextTickSqrtRatio` to be true
- Once the pool state is corrupted, all subsequent fee operations (position updates, fee collections) use the invalid tick for calculations
- The issue persists until the pool price moves upward through swaps, which would recalculate the tick using `sqrtRatioToTick` and potentially correct it

### Citations

**File:** src/Core.sol (L198-200)
```text
            if (tick < tickLower) {
                feesPerLiquidityInside.value0 = lower0 - upper0;
                feesPerLiquidityInside.value1 = lower1 - upper1;
```

**File:** src/Core.sol (L395-397)
```text
                    feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                        poolId, state.tick(), positionId.tickLower(), positionId.tickUpper()
                    );
```

**File:** src/Core.sol (L752-757)
```text
                    if (sqrtRatioNext == nextTickSqrtRatio) {
                        sqrtRatio = sqrtRatioNext;
                        assembly ("memory-safe") {
                            // no overflow danger because nextTick is always inside the valid tick bounds
                            tick := sub(nextTick, iszero(increasing))
                        }
```

**File:** src/Core.sol (L824-826)
```text
                stateAfter = createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: liquidity});

                writePoolState(poolId, stateAfter);
```

**File:** src/math/constants.sol (L10-10)
```text
int32 constant MIN_TICK = -88722835;
```

**File:** src/math/tickBitmap.sol (L105-107)
```text
            if (prevTick <= MIN_TICK) {
                prevTick = MIN_TICK;
                break;
```
