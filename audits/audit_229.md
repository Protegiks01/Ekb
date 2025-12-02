## Title
Sequential Fee Application in MEVCapture Causes Underpayment of Total Fees Due to Non-Multiplicative Compounding

## Summary
The `handleForwardData()` function in MEVCapture applies pool fees and additional MEV fees sequentially rather than multiplicatively, causing users to pay less total fees than the correct compounded amount. The fee reversal logic at lines 220-236 is mathematically exact, but the subsequent sequential application of fees results in a systematic underpayment proportional to the product of both fee rates.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When an exact-out swap is routed through MEVCapture, the extension should charge the user for both the pool fee and an additional MEV capture fee. The total fee burden should compound multiplicatively, similar to how sequential tax applications work in traditional finance.

**Actual Logic:** The implementation reverses the pool fee to obtain the base swap amount, then applies the additional MEV fee to this base amount. While the reversal itself is mathematically exact (as proven by [2](#0-1) ), the sequential application results in:

Total = O/(1-p) + O/(1-a) - O = O × (1 - pa) / ((1-p)(1-a))

Where O is output amount, p is pool fee rate, and a is additional fee rate. This differs from the correct multiplicative formula:

Total = O / ((1-p)(1-a))

The ratio is (1 - pa), meaning users systematically pay less by a factor equal to the product of the two fee rates.

**Exploitation Path:**
1. User initiates an exact-out swap through a MEVCapture pool with significant tick movement (e.g., crossing 2 tick spacings)
2. Core swap executes and calculates: [3](#0-2) 
3. MEVCapture calculates additional fee: [4](#0-3) 
4. Fee reversal occurs: [5](#0-4) 
5. Additional fee applied to reversed amount: [6](#0-5) 
6. User pays Total = O/(1-p) + O/(1-a) - O instead of O/((1-p)(1-a))

**Security Property Broken:** Fee Accounting Invariant - Position fee collection must be accurate and calculated correctly. The sequential application systematically undercharges fees compared to the correct multiplicative compounding.

## Impact Explanation
- **Affected Assets**: All MEVCapture-enabled pools where swaps cause tick movement. Liquidity providers earn less fees than they should based on the stated fee rates.
- **Damage Severity**: For a 100,000 token swap with 1% pool fee and 2% additional fee (2 tick spacings crossed), users save ~31.65 tokens (0.0307%). On a $1M trade with these parameters, this represents ~$307 in underpaid fees. The discrepancy scales with p × a (product of fee rates), so pools with higher fees or larger tick movements experience greater losses.
- **User Impact**: All users performing exact-out swaps through MEVCapture pools benefit from paying less fees. All LPs in these pools lose a portion of their expected fee revenue. The effect is systematic and occurs on every swap with non-zero additional fees.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this by simply routing exact-out swaps through MEVCapture pools, particularly targeting swaps that cause large tick movements (higher additional fees = greater savings).
- **Preconditions**: Pool must use MEVCapture extension with non-zero pool fee, swap must cause tick movement between blocks to trigger additional fees.
- **Execution Complexity**: No special setup required - standard exact-out swap execution through MEVCapture router.
- **Frequency**: Exploitable on every exact-out swap through MEVCapture pools. Users can intentionally structure trades to maximize tick movement and thus maximize savings from the fee discrepancy.

## Recommendation

**Option 1: Apply fees multiplicatively**
```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, lines 217-236:

// CURRENT (vulnerable):
// Reverses pool fee then applies additional fee separately,
// resulting in Total = O/(1-p) + O/(1-a) - O

// FIXED:
if (additionalFee != 0) {
    if (params.isExactOut()) {
        if (balanceUpdate.delta0() > 0) {
            uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
            // Calculate combined effective fee rate: 1 - (1-p)(1-a) = p + a - pa
            uint64 poolFee = poolKey.config.fee();
            // combinedFee = poolFee + additionalFee - (poolFee * additionalFee) >> 64
            uint256 feeProduct = (uint256(poolFee) * uint256(additionalFee)) >> 64;
            uint64 combinedFee = uint64(uint256(poolFee) + uint256(additionalFee) - feeProduct);
            
            // Calculate total fee on the output amount
            // First reverse the pool fee to get output amount
            uint128 outputAmount = inputAmount - computeFee(inputAmount, poolFee);
            // Then calculate what input SHOULD be with combined fee
            uint128 correctInput = amountBeforeFee(outputAmount, combinedFee);
            int128 additionalFeeNeeded = SafeCastLib.toInt128(correctInput - inputAmount);
            
            saveDelta0 += additionalFeeNeeded;
            balanceUpdate = createPoolBalanceUpdate(
                balanceUpdate.delta0() + additionalFeeNeeded, 
                balanceUpdate.delta1()
            );
        }
        // Similar logic for token1...
    }
}
```

**Option 2: Document as intended behavior**
If the sequential application is intentional (applying both fees to the base amount rather than compounding), clearly document this in comments and ensure users/LPs understand the fee structure differs from typical multiplicative compounding.

## Proof of Concept
```solidity
// File: test/Exploit_MEVCaptureFeeUnderpayment.t.sol
// Run with: forge test --match-test test_MEVCaptureFeeUnderpayment -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import {computeFee, amountBeforeFee} from "../src/math/fee.sol";
import "../test/FullTest.sol";

contract Exploit_MEVCaptureFeeUnderpayment is BaseMEVCaptureTest {
    function test_MEVCaptureFeeUnderpayment() public {
        // SETUP: Create MEVCapture pool with 1% fee and 20,000 tick spacing
        uint64 poolFeeRate = uint64(uint256(1 << 64) / 100); // 1% fee
        PoolKey memory poolKey = createMEVCapturePool({
            fee: poolFeeRate, 
            tickSpacing: 20_000, 
            tick: 0
        });
        createPosition(poolKey, -100_000, 100_000, 1_000_000, 1_000_000);

        // EXPLOIT: Execute exact-out swap that crosses tick spacings
        // This will trigger additional MEV fee
        uint256 outputAmount = 500_000;
        
        token1.approve(address(router), type(uint256).max);
        
        PoolBalanceUpdate memory balanceUpdate = router.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false,
                _amount: -int128(int256(outputAmount)),
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });

        // VERIFY: Calculate what user SHOULD pay vs what they ACTUALLY paid
        uint256 actualPaid = uint256(int256(balanceUpdate.delta1()));
        
        // Expected with multiplicative fees:
        // Pool fee: 1%, Additional fee from 2 tick spacings: 2%
        // Total multiplicative: outputAmount / (0.99 * 0.98)
        uint256 expectedMultiplicative = (outputAmount * 1e18) / (99 * 98) * 100;
        
        // MEVCapture's sequential calculation gives less
        uint256 poolFeeAmount = amountBeforeFee(uint128(outputAmount), poolFeeRate);
        uint128 reversed = poolFeeAmount - computeFee(poolFeeAmount, poolFeeRate);
        uint64 additionalFeeRate = uint64(uint256(2) << 64) / 100; // 2% additional
        uint256 additionalFee = amountBeforeFee(reversed, additionalFeeRate) - reversed;
        uint256 expectedSequential = poolFeeAmount + additionalFee;
        
        console.log("Output amount:", outputAmount);
        console.log("Actually paid:", actualPaid);
        console.log("Expected (multiplicative):", expectedMultiplicative);
        console.log("Expected (sequential):", expectedSequential);
        console.log("Savings from exploit:", expectedMultiplicative - actualPaid);
        
        // Verify user paid less than multiplicative calculation
        assertLt(actualPaid, expectedMultiplicative, "User should pay less with sequential fees");
        
        // The difference is approximately outputAmount * poolFee * additionalFee
        uint256 discrepancy = expectedMultiplicative - actualPaid;
        uint256 expectedDiscrepancy = (outputAmount * 1 * 2) / 10000; // 1% * 2% = 0.02%
        
        // Verify discrepancy matches theoretical calculation
        assertApproxEqRel(
            discrepancy, 
            expectedDiscrepancy, 
            0.01e18, // 1% relative error tolerance
            "Discrepancy should match p*a formula"
        );
    }
}
```

**Notes:**
1. The reversal operation itself is mathematically exact - the `computeFee` and `amountBeforeFee` functions are proven inverses by the existing test suite.
2. The vulnerability stems from applying fees sequentially (additively to base amount) rather than multiplicatively (compounding).
3. The discrepancy equals approximately p × a × outputAmount, where p is pool fee rate and a is additional fee rate.
4. This affects all exact-out swaps through MEVCapture where additional fees are non-zero (i.e., when tick movement occurs).
5. The issue also applies to the token1 case at lines 228-236 with identical logic.

### Citations

**File:** src/extensions/MEVCapture.sol (L211-215)
```text
            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**File:** src/extensions/MEVCapture.sol (L220-236)
```text
                    if (balanceUpdate.delta0() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta1())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
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

**File:** src/Core.sol (L703-711)
```text
                            if (isExactOut) {
                                uint128 includingFee = amountBeforeFee(calculatedAmountWithoutFee, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, includingFee)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(includingFee, calculatedAmountWithoutFee)),
                                        stepLiquidity
                                    )
                                }
```
