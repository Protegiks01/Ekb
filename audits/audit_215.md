## Title
Fee Reversal Error in MEVCapture Causes Systematic Overcharging on Multi-Step Exact-Out Swaps

## Summary
The `handleForwardData()` function in MEVCapture incorrectly reverses the pool fee on line 223 when processing exact-out swaps. [1](#0-0)  The Core contract applies `amountBeforeFee()` separately to each step of a multi-tick swap and sums the results, but MEVCapture reverses this with a single `computeFee()` subtraction, causing accumulated rounding errors that inflate the base amount used for calculating additional MEV fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/extensions/MEVCapture.sol` - `handleForwardData()` function, line 223

**Intended Logic:** When processing exact-out swaps, MEVCapture should remove the pool fee from the input amount to obtain the original amount before fees, then apply the additional MEV capture fee to this original amount. The comment on line 222 states: "first remove the fee to get the original input amount before we compute the additional fee". [2](#0-1) 

**Actual Logic:** The Core contract applies fees using `amountBeforeFee()` separately for each step when a swap crosses multiple ticks. [3](#0-2)  Each application rounds UP, and these fee-inclusive amounts are summed to create the total input amount. [4](#0-3)  However, MEVCapture attempts to reverse this entire accumulated fee structure with a single `inputAmount -= computeFee(inputAmount, poolFee)` operation, which mathematically fails to account for multiple independent rounding operations.

**Mathematical Demonstration:**
The `amountBeforeFee()` function rounds UP when dividing: [5](#0-4) 

For a swap crossing two steps with amounts `a1` and `a2`, and fee rate `f`:
- Core calculates: `b1 = ceil(a1 << 64 / (2^64 - f))` and `b2 = ceil(a2 << 64 / (2^64 - f))`
- Core returns: `total = b1 + b2` as the input amount
- MEVCapture reverses: `reversed = total - computeFee(total, f)`

Due to double rounding up (once for each step), `reversed > a1 + a2`.

**Concrete Example** (fee = 25% = 1<<62):
- Step amounts: a1 = 1, a2 = 1
- Core calculation: b1 = ceil(4/3) = 2, b2 = ceil(4/3) = 2
- Total returned: 4
- MEVCapture reversal: 4 - computeFee(4, 1<<62) = 4 - 1 = 3
- Expected original: a1 + a2 = 2
- **Error: 3 - 2 = 1 (50% inflation)**

**Exploitation Path:**
1. User initiates exact-out swap through MEVCapture that crosses multiple ticks (common for large swaps)
2. Core contract processes swap, applying `amountBeforeFee()` at each tick boundary and accumulating results
3. MEVCapture receives total input amount with compounded rounding errors from line 209 [6](#0-5) 
4. Line 223 incorrectly reverses the fee, producing an inflated base amount
5. Line 224 calculates additional MEV fee on this inflated amount [7](#0-6) 
6. User is charged excess MEV capture fees proportional to the number of ticks crossed

**Security Property Broken:** Violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming". While not double-claiming, this creates systematic inaccurate fee collection that overcharges users.

## Impact Explanation
- **Affected Assets**: All users performing exact-out swaps through MEVCapture extension, particularly large swaps that cross multiple ticks
- **Damage Severity**: The overcharge scales with (1) the pool fee rate, (2) the number of ticks crossed during the swap, and (3) the additional MEV fee multiplier. In the mathematical example above, a 25% pool fee with 2 steps caused a 50% inflation of the base amount. For a swap with 10% additional MEV fee, this would result in charging `10% * 3 = 0.3` instead of `10% * 2 = 0.2`, a 50% overcharge on the MEV fee component.
- **User Impact**: Any user performing exact-out swaps through MEVCapture pools is affected. The error is systematic and affects every multi-tick exact-out swap, with losses accumulating over time for active traders.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a systematic bug affecting normal protocol operations. All users performing exact-out swaps through MEVCapture are victims.
- **Preconditions**: 
  1. Pool must use MEVCapture extension
  2. Pool must have non-zero fee [8](#0-7) 
  3. Swap must be exact-out (specified output amount)
  4. Swap must cross multiple ticks (larger swaps or sparse liquidity)
  5. Additional MEV fee must be non-zero (price must have moved since last update) [9](#0-8) 
- **Execution Complexity**: Automatic - occurs during normal swap execution without any special actions
- **Frequency**: Every exact-out swap that crosses multiple ticks in MEVCapture pools

## Recommendation

The issue stems from trying to reverse a sum of multiple `amountBeforeFee()` operations with a single `computeFee()` subtraction. MEVCapture should track the pre-fee amounts directly from the Core contract rather than attempting mathematical reversal, or the Core contract should return both the fee-inclusive and fee-exclusive amounts.

**Option 1 - Track original amounts in Core:**
Modify the Core contract to return both the calculated amount (with fees) and the sum of original amounts (without fees) in the swap return data, so extensions don't need to perform error-prone reversal calculations.

**Option 2 - Remove fee reversal attempt:**
If the goal is to charge MEV fees on the full input amount (including pool fees), remove the reversal step entirely:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, lines 220-224:

// CURRENT (vulnerable):
uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
// first remove the fee to get the original input amount before we compute the additional fee
inputAmount -= computeFee(inputAmount, poolFee);
int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

// FIXED (charge MEV fee on total amount including pool fee):
uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
// Apply MEV fee to the full input amount (which includes pool fee)
int128 fee = SafeCastLib.toInt128(computeFee(inputAmount, additionalFee));
```

However, this changes the fee semantics. The preferred solution is Option 1, which requires Core contract modifications to expose the necessary data.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureFeeReversal.t.sol
// Run with: forge test --match-test test_MEVCaptureFeeReversalError -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/math/fee.sol";

contract Exploit_MEVCaptureFeeReversal is Test {
    
    function test_MEVCaptureFeeReversalError() public pure {
        // Demonstrate the mathematical error in fee reversal
        
        // Setup: 25% fee (1<<62)
        uint64 fee = uint64(1 << 62);
        
        // Two amounts that would be calculated separately in a multi-tick swap
        uint128 amount1 = 1;
        uint128 amount2 = 1;
        
        // Core contract applies amountBeforeFee to each amount separately
        uint128 beforeFee1 = amountBeforeFee(amount1, fee);
        uint128 beforeFee2 = amountBeforeFee(amount2, fee);
        
        // Core returns the sum as the total input amount
        uint128 totalInput = beforeFee1 + beforeFee2;
        
        // MEVCapture attempts to reverse the fee with a single operation
        uint128 reversed = totalInput - computeFee(totalInput, fee);
        
        // The original sum should be recovered
        uint128 expectedOriginal = amount1 + amount2;
        
        // VERIFY: Confirm the reversal error
        console.log("Original amount1:", amount1);
        console.log("Original amount2:", amount2);
        console.log("Expected sum:", expectedOriginal);
        console.log("BeforeFee1:", beforeFee1);
        console.log("BeforeFee2:", beforeFee2);
        console.log("Total input:", totalInput);
        console.log("Reversed amount:", reversed);
        console.log("Error:", reversed - expectedOriginal);
        
        // The reversed amount should equal the original sum, but it doesn't
        assertGt(reversed, expectedOriginal, "Vulnerability confirmed: Reversed amount exceeds original due to rounding accumulation");
        assertEq(reversed, 3, "Reversed amount is 3");
        assertEq(expectedOriginal, 2, "Expected original is 2");
        assertEq(reversed - expectedOriginal, 1, "Error is 1 (50% inflation)");
    }
    
    function test_MEVCaptureFeeReversalScaling() public pure {
        // Show the error scales with number of steps
        uint64 fee = uint64(1 << 62); // 25%
        uint8 numSteps = 10;
        
        uint128 totalReversed = 0;
        uint128 totalOriginal = 0;
        uint128 totalInput = 0;
        
        // Simulate 10 steps, each with amount = 1
        for (uint8 i = 0; i < numSteps; i++) {
            uint128 amount = 1;
            totalOriginal += amount;
            totalInput += amountBeforeFee(amount, fee);
        }
        
        // MEVCapture reversal
        totalReversed = totalInput - computeFee(totalInput, fee);
        
        console.log("Steps:", numSteps);
        console.log("Total original:", totalOriginal);
        console.log("Total input:", totalInput);
        console.log("Total reversed:", totalReversed);
        console.log("Error:", totalReversed - totalOriginal);
        console.log("Error percentage:", (totalReversed - totalOriginal) * 100 / totalOriginal, "%");
        
        assertGt(totalReversed, totalOriginal, "Error accumulates with more steps");
    }
}
```

## Notes

The vulnerability is rooted in the mathematical properties of the `amountBeforeFee()` and `computeFee()` functions. [10](#0-9) [11](#0-10) 

While the test file `test/math/fee.t.sol` proves that single fee applications can be correctly reversed, [12](#0-11)  it doesn't test the scenario where multiple `amountBeforeFee()` operations are summed before reversal. This is the critical edge case that MEVCapture encounters with multi-tick swaps.

The impact is proportional to the pool fee rate, the number of swap steps, and the additional MEV fee multiplier, making it more severe for large swaps in high-fee pools with significant price movement.

### Citations

**File:** src/extensions/MEVCapture.sol (L112-118)
```text
            assembly ("memory-safe") {
                let o := mload(0x40)
                mstore(o, shl(224, 0xf83d08ba))
                mcopy(add(o, 4), poolKey, 96)
                mstore(add(o, 100), poolId)

                // If the call failed, pass through the revert
```

**File:** src/extensions/MEVCapture.sol (L209-209)
```text
            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);
```

**File:** src/extensions/MEVCapture.sol (L212-217)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));

            if (additionalFee != 0) {
```

**File:** src/extensions/MEVCapture.sol (L222-223)
```text
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
```

**File:** src/extensions/MEVCapture.sol (L224-224)
```text
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);
```

**File:** src/Core.sol (L704-706)
```text
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
```

**File:** src/Core.sol (L811-822)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));

                int128 specifiedAmountDelta;
                int128 specifiedAmount = params.amount();
                assembly ("memory-safe") {
                    specifiedAmountDelta := sub(specifiedAmount, amountRemaining)
                }

                balanceUpdate = isToken1
                    ? createPoolBalanceUpdate(calculatedAmountDelta, specifiedAmountDelta)
                    : createPoolBalanceUpdate(specifiedAmountDelta, calculatedAmountDelta);
```

**File:** src/math/fee.sol (L6-10)
```text
function computeFee(uint128 amount, uint64 fee) pure returns (uint128 result) {
    assembly ("memory-safe") {
        result := shr(64, add(mul(amount, fee), 0xffffffffffffffff))
    }
}
```

**File:** src/math/fee.sol (L15-24)
```text
function amountBeforeFee(uint128 afterFee, uint64 fee) pure returns (uint128 result) {
    assembly ("memory-safe") {
        let v := shl(64, afterFee)
        let d := sub(0x10000000000000000, fee)
        result := add(iszero(iszero(mod(v, d))), div(v, d))
        if shr(128, result) {
            mstore(0, 0x0d88f526)
            revert(0x1c, 0x04)
        }
    }
```

**File:** test/math/fee.t.sol (L24-32)
```text
    function test_amountBeforeFee_computeFee(uint128 amount, uint64 fee) public view {
        vm.assumeNoRevert();

        uint128 before = this.abf(amount, fee);
        assertGe(before, amount);

        uint128 aft = before - computeFee(before, fee);
        assertEq(aft, amount);
    }
```
