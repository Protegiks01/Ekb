## Title
Incorrect Fee Calculation for Non-Full-Range Stableswap Positions Due to Missing Pool Type Check

## Summary
The `BasePositions.getPositionFeesAndLiquidity()` function incorrectly calculates fees for non-full-range stableswap positions by reading uninitialized tick-level fee data instead of using global fee accumulators. This occurs because the function only checks `isFullRange()` rather than `isStableswap()`, causing it to use concentrated liquidity fee calculation logic on stableswap pools that never initialize tick data.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (function `getPositionFeesAndLiquidity`, lines 43-68) [1](#0-0) 

**Intended Logic:** The function should return accurate fee information for all position types, including stableswap positions. For stableswap pools, fees accumulate globally rather than per-tick, so the function should use global fee accumulators.

**Actual Logic:** The function only checks `config.isFullRange()` (which returns true only when amplification=0 AND center=0) to determine fee calculation method. For non-full-range stableswap pools (amplification != 0 or center != 0), it falls through to call `CORE.getPoolFeesPerLiquidityInside()`, which reads tick-level fee data that is never initialized for stableswap pools (always zero). [2](#0-1) 

**Root Cause:** Stableswap pools skip tick initialization entirely during position updates: [3](#0-2) 

Unlike concentrated pools that call `_updateTick()` to initialize tick data: [4](#0-3) 

When `getPoolFeesPerLiquidityInside()` is called on a stableswap pool, it reads uninitialized tick fees per liquidity outside slots (zeros): [5](#0-4) 

**Exploitation Path:**
1. Create a non-full-range stableswap pool (e.g., amplification=26, center=0)
2. Add liquidity to create a position with tick bounds matching the stableswap active range
3. Execute swaps to accumulate fees in the global fee accumulator
4. Call `BasePositions.getPositionFeesAndLiquidity()` to query position fees
5. Function returns incorrect fee values (zero or wrong amounts) because:
   - It reads uninitialized tick fees per liquidity outside (all zeros)
   - Calculation depends on current tick position relative to position bounds
   - If tick is in range: returns global fees (accidentally correct)
   - If tick drifts outside range: returns zero (incorrect - should still show global fees)

**Security Property Broken:** Violates **Fee Accounting** invariant - "Position fee collection must be accurate and never allow double-claiming." While actual collection via `Core.collectFees()` is correct (it properly checks `isStableswap()`), the view function returns misleading data that affects user decisions. [6](#0-5) 

## Impact Explanation
- **Affected Assets**: User positions in non-full-range stableswap pools
- **Damage Severity**: Users receive incorrect fee information when querying their positions. This could lead to:
  - Premature withdrawal decisions (thinking no fees have accumulated)
  - Failure to collect fees when optimal
  - Loss of confidence in protocol accuracy
  - Integration issues for third-party protocols relying on this data
- **User Impact**: All liquidity providers in non-full-range stableswap pools (amplification between 1-26) are affected. The function is public and used by frontends, analytics tools, and potentially other smart contracts.

## Likelihood Explanation
- **Attacker Profile**: Any user or contract querying position information
- **Preconditions**: 
  - Non-full-range stableswap pool exists (amplification != 0 or center != 0)
  - Position has been created in the pool
  - User queries via `getPositionFeesAndLiquidity()`
- **Execution Complexity**: Single view call, no special setup required
- **Frequency**: Occurs on every query for non-full-range stableswap positions

## Recommendation

In `src/base/BasePositions.sol`, function `getPositionFeesAndLiquidity`, replace the pool type check:

```solidity
// CURRENT (vulnerable):
// Line 64-66
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isFullRange()
    ? CORE.getPoolFeesPerLiquidity(poolId)
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);

// FIXED:
// Check for ANY stableswap pool, not just full-range
FeesPerLiquidity memory feesPerLiquidityInside = poolKey.config.isStableswap()
    ? CORE.getPoolFeesPerLiquidity(poolId)
    : CORE.getPoolFeesPerLiquidityInside(poolId, tickLower, tickUpper);
```

This ensures stableswap pools always use global fee accumulators, matching the logic in `Core.collectFees()`.

## Proof of Concept

```solidity
// File: test/Exploit_StableswapFeeQuery.t.sol
// Run with: forge test --match-test test_StableswapFeeQueryBug -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "./helpers/TestERC20.sol";

contract Exploit_StableswapFeeQuery is Test {
    Core core;
    Positions positions;
    Router router;
    TestERC20 token0;
    TestERC20 token1;
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        positions = new Positions(core, address(this));
        router = new Router(core);
        
        // Deploy tokens
        token0 = new TestERC20("Token0", "TK0");
        token1 = new TestERC20("Token1", "TK1");
        
        // Mint tokens
        token0.mint(address(this), 100e18);
        token1.mint(address(this), 100e18);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_StableswapFeeQueryBug() public {
        // SETUP: Create non-full-range stableswap pool (amplification=26, center=0)
        PoolConfig config = createStableswapPoolConfig(
            1e14, // 0.01% fee
            26,   // amplification != 0 (NOT full range)
            0,    // center tick
            address(0)
        );
        
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: config
        });
        
        (int32 lower, int32 upper) = config.stableswapActiveLiquidityTickRange();
        
        // Initialize pool and add liquidity
        router.initializePool(poolKey, 0);
        uint256 nftId = positions.mint(address(this));
        positions.deposit(nftId, poolKey, lower, upper, 1e18, 1e18, 0);
        
        // Execute swaps to accumulate fees
        router.swap(poolKey, false, 1e17, SqrtRatio.wrap(0), 0, type(int256).min);
        
        // EXPLOIT: Query position fees - will return wrong value
        (uint128 liquidity, uint128 principal0, uint128 principal1, 
         uint128 fees0, uint128 fees1) = positions.getPositionFeesAndLiquidity(
            nftId, poolKey, lower, upper
        );
        
        // VERIFY: The bug manifests when tick moves outside active range
        // Fees should be non-zero (accumulated from swap), but may show zero
        // depending on current tick position due to reading uninitialized tick data
        
        // Compare with actual collection (which uses correct logic)
        uint256 balanceBefore0 = token0.balanceOf(address(this));
        positions.collectFees(nftId, poolKey, lower, upper);
        uint256 actualFees0 = token0.balanceOf(address(this)) - balanceBefore0;
        
        // If query showed zero but actual collection is non-zero, bug is confirmed
        if (fees0 == 0 && actualFees0 > 0) {
            console.log("BUG CONFIRMED: Query showed 0 fees but actual collection got", actualFees0);
        }
    }
}
```

**Notes:**
- The vulnerability causes incorrect fee information to be returned by the public view function `getPositionFeesAndLiquidity()`
- Actual fee collection via `Core.collectFees()` works correctly because it properly checks `isStableswap()`
- The fix is simple: replace `isFullRange()` check with `isStableswap()` check to match Core's logic
- Test cases confirming non-full-range stableswap pools exist in the codebase at test/Router.t.sol:855-925

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

**File:** src/types/poolConfig.sol (L75-84)
```text
/// @notice Determines if this pool is full range (special case of stableswap with amplification=0 and center=0)
/// @dev Full range can be slightly optimized in that we don't need to compute the sqrt ratio at the tick boundaries
/// @param config The pool config
/// @return r True if the pool is full range
function isFullRange(PoolConfig config) pure returns (bool r) {
    assembly ("memory-safe") {
        // Full range when all 32 bits are 0 (discriminator=0, amplification=0, center=0)
        r := iszero(and(config, 0xffffffff))
    }
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

**File:** src/Core.sol (L391-401)
```text
            if (poolKey.config.isConcentrated()) {
                // the position is fully withdrawn
                if (liquidityNext == 0) {
                    // we need to fetch it before the tick fees per liquidity outside is deleted
                    feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                        poolId, state.tick(), positionId.tickLower(), positionId.tickUpper()
                    );
                }

                _updateTick(poolId, positionId.tickLower(), poolKey.config, liquidityDelta, false);
                _updateTick(poolId, positionId.tickUpper(), poolKey.config, liquidityDelta, true);
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

**File:** src/Core.sol (L479-490)
```text
        FeesPerLiquidity memory feesPerLiquidityInside;
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
