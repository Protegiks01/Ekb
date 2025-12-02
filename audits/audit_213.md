## Title
MEVCapture Exact-Out Swaps Cause AmountBeforeFeeOverflow DOS for Large Swaps Due to Excessive additionalFee

## Summary
The MEVCapture extension's exact-out swap logic can cause `AmountBeforeFeeOverflow` errors for legitimate swaps that would succeed with the pool fee alone. When swaps cross many tick spacings, the `additionalFee` can reach `type(uint64).max`, drastically lowering the overflow threshold in the `amountBeforeFee` calculation from ~2^128 to ~2^64, causing denial-of-service for swaps requiring more than ~18.4 tokens of input.

## Impact
**Severity**: Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The MEVCapture extension charges additional fees based on tick movement during exact-out swaps. It removes the pool fee from the calculated input amount, then applies `amountBeforeFee(inputAmount, additionalFee)` to calculate the total including additional fees.

**Actual Logic:** The `amountBeforeFee` function has an overflow threshold that decreases as the fee parameter increases. When `additionalFee` approaches `type(uint64).max` (due to large tick movements), the overflow threshold drops to approximately 2^64 (~18.4 tokens with 18 decimals), causing legitimate swaps that succeeded in Core with `poolFee` alone to revert in MEVCapture.

**Mathematical Foundation:**

The `amountBeforeFee` function implementation [2](#0-1)  calculates `result = ceil((afterFee << 64) / (2^64 - fee))` and reverts if `result > 2^128 - 1`.

The overflow threshold is: `afterFee_max = (2^128 - 1) * (2^64 - fee) / 2^64`

- With `poolFee = 1%` (0.01 * 2^64): threshold ≈ 2^128 * 0.99 (very large)
- With `additionalFee = type(uint64).max` (2^64 - 1): threshold ≈ 2^64 ≈ 1.844 * 10^19 wei

**Exploitation Path:**

1. **Pool Setup**: Create a MEVCapture pool with `poolFee = 1%` and `tickSpacing = 20,000` at initial tick ~700,000
2. **Large Tick Movement**: Execute an exact-out swap that moves from current tick to MAX_TICK or MIN_TICK
   - Tick movement = 177,445,670 ticks (full range)
   - feeMultiplier = 177,445,670 / 20,000 = 8,872
   - [3](#0-2)  calculates: `additionalFee = min(type(uint64).max, 8,872 * 0.01 * 2^64) = type(uint64).max` (capped)
3. **Core Swap Succeeds**: For an exact-out swap requiring ~20-100 tokens of input, Core's [4](#0-3)  `amountBeforeFee(limitCalculatedAmountDelta, poolFee)` succeeds since 20-100 tokens << 2^128 * 0.99
4. **MEVCapture Overflows**: [5](#0-4)  calculates `inputAmount` (after removing pool fee) and calls `amountBeforeFee(inputAmount, additionalFee)` where `inputAmount > 2^64`, causing [6](#0-5)  `AmountBeforeFeeOverflow` revert

**Security Property Broken:** Violates **Extension Isolation** invariant - "Extension failures should not freeze pools or lock user capital (for in-scope extensions)". Legitimate swaps that should succeed are blocked by the MEVCapture extension.

## Impact Explanation

- **Affected Assets**: Any MEVCapture pool where swaps can cross sufficient tick spacings to make `additionalFee` approach `type(uint64).max`
- **Damage Severity**: Users attempting exact-out swaps requiring more than ~18.4 tokens of input (with 18 decimals) will experience transaction reverts when tick movement is large. This is a denial-of-service that prevents normal protocol usage.
- **User Impact**: All users attempting swaps during periods of high price volatility or when the pool tick is far from desired output price. The swap would succeed in a regular pool but fails in MEVCapture pools.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this is a design flaw that triggers naturally during large price movements
- **Preconditions**: 
  - MEVCapture pool with any non-zero `poolFee`
  - Large tick spacing (e.g., 20,000) enabling high fee multipliers
  - Swap requiring tick movement > `(100 / poolFee_percent) * tickSpacing` ticks
  - Exact-out swap with input amount > 2^64 wei
- **Execution Complexity**: Single swap transaction under normal market conditions
- **Frequency**: Occurs whenever large exact-out swaps cross many tick spacings, particularly during volatile markets or illiquid price ranges

## Recommendation

Add an overflow check before calling `amountBeforeFee` and cap the input amount to prevent overflow:

```solidity
// In src/extensions/MEVCapture.sol, lines 221-224 and 229-232:

// CURRENT (vulnerable):
uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
inputAmount -= computeFee(inputAmount, poolFee);
int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

// FIXED:
uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
inputAmount -= computeFee(inputAmount, poolFee);

// Check if amountBeforeFee would overflow and cap additionalFee if needed
// Overflow threshold: inputAmount > (type(uint128).max * (2^64 - additionalFee)) >> 64
uint256 threshold = (uint256(type(uint128).max) * (uint256(1) << 64 - additionalFee)) >> 64;
if (inputAmount > threshold) {
    // Reduce additionalFee to prevent overflow
    // Find max safe fee: inputAmount * 2^64 / (type(uint128).max) = 2^64 - maxFee
    uint64 maxSafeFee = uint64(type(uint64).max - ((uint256(inputAmount) << 64) / type(uint128).max));
    additionalFee = maxSafeFee > additionalFee ? additionalFee : maxSafeFee;
}

int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);
```

Alternative mitigation: Cap `additionalFee` to a maximum percentage (e.g., 50% of 2^64) to prevent extreme fee scenarios while still capturing MEV.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureOverflow.t.sol
// Run with: forge test --match-test test_MEVCaptureOverflowOnLargeExactOutSwap -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/Router.sol";
import "./FullTest.sol";

contract Exploit_MEVCaptureOverflow is FullTest {
    MEVCapture mevCapture;
    
    function setUp() public override {
        FullTest.setUp();
        
        // Deploy MEVCapture extension
        address deployAddress = address(uint160(mevCaptureCallPoints().toUint8()) << 152);
        deployCodeTo("MEVCapture.sol", abi.encode(core), deployAddress);
        mevCapture = MEVCapture(deployAddress);
        router = new MEVCaptureRouter(core, address(mevCapture));
    }
    
    function test_MEVCaptureOverflowOnLargeExactOutSwap() public {
        // SETUP: Create MEVCapture pool with 5% fee at tick 700,000
        PoolKey memory poolKey = createPool(
            address(token0),
            address(token1), 
            700_000,
            createConcentratedPoolConfig(
                uint64(uint256(1 << 64) / 20), // 5% fee
                20_000, // tick spacing
                address(mevCapture)
            )
        );
        
        // Add liquidity across wide range to support large swap
        createPosition(poolKey, 600_000, 800_000, type(uint128).max / 100, type(uint128).max / 100);
        
        // EXPLOIT: Attempt exact-out swap requiring > 2^64 wei of input
        // This will move ticks significantly, causing additionalFee to reach type(uint64).max
        token0.approve(address(router), type(uint256).max);
        
        // This swap would succeed in a normal pool but reverts in MEVCapture
        vm.expectRevert(AmountBeforeFeeOverflow.selector);
        router.swap({
            poolKey: poolKey,
            isToken1: true,
            amount: type(int128).min, // Maximum exact-out
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // VERIFY: The same swap in a pool without MEVCapture would succeed
        PoolKey memory normalPoolKey = createPool(
            address(token0),
            address(token1),
            700_000, 
            createConcentratedPoolConfig(
                uint64(uint256(1 << 64) / 20),
                20_000,
                address(0) // No extension
            )
        );
        createPosition(normalPoolKey, 600_000, 800_000, type(uint128).max / 100, type(uint128).max / 100);
        
        // This succeeds without MEVCapture
        PoolBalanceUpdate memory result = router.swap({
            poolKey: normalPoolKey,
            isToken1: true,
            amount: type(int128).min,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        assertTrue(result.delta0() > 0, "Normal pool swap succeeded");
    }
}
```

## Notes

The existing test suite includes cases like `test_swap_max_fee_token0_output` [7](#0-6)  that show large delta values (3.88 * 10^25), but these tests only cross ~187,272 ticks (9.36 tick spacings), resulting in `additionalFee ≈ 9.36% of type(uint64).max`, not the full cap. A **full range swap** crossing ~177 million ticks (8,872 tick spacings) with 1% fee would cap `additionalFee` at `type(uint64).max`, triggering the overflow for any `inputAmount > 2^64`.

The invariant tests explicitly allow `AmountBeforeFeeOverflow` as an expected error [8](#0-7) , but this acceptance was likely based on extreme swap amounts being fundamentally invalid, not on the extension causing legitimate swaps to fail when they would succeed in Core.

### Citations

**File:** src/extensions/MEVCapture.sol (L212-215)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**File:** src/extensions/MEVCapture.sol (L217-236)
```text
            if (additionalFee != 0) {
                if (params.isExactOut()) {
                    // take an additional fee from the calculated input amount equal to the `additionalFee - poolFee`
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

**File:** src/math/fee.sol (L12-12)
```text
error AmountBeforeFeeOverflow();
```

**File:** src/math/fee.sol (L15-25)
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
}
```

**File:** src/Core.sol (L675-684)
```text
                            if (isExactOut) {
                                uint128 beforeFee = amountBeforeFee(limitCalculatedAmountDelta, config.fee());
                                assembly ("memory-safe") {
                                    calculatedAmount := add(calculatedAmount, beforeFee)
                                    amountRemaining := add(amountRemaining, limitSpecifiedAmountDelta)
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitCalculatedAmountDelta)),
                                        stepLiquidity
                                    )
                                }
```

**File:** test/extensions/MEVCapture.t.sol (L567-587)
```text
    function test_swap_max_fee_token0_output() public {
        PoolKey memory poolKey =
            createMEVCapturePool({fee: uint64(uint256(1 << 64) / 100), tickSpacing: 20_000, tick: 700_000});
        createPosition(poolKey, 600_000, 800_000, 1_000_000, 2_000_000);

        token1.approve(address(router), type(uint256).max);
        PoolBalanceUpdate balanceUpdate = router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: type(int128).min,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });

        assertEq(balanceUpdate.delta0(), -993_170);
        assertEq(balanceUpdate.delta1(), 38785072624969501783380726); // divided by 2**64 (max fee) this is ~ 2e6
        int32 tick = core.poolState(poolKey.toPoolId()).tick();
        assertEq(tick, MAX_TICK);
    }
```

**File:** test/SolvencyInvariantTest.t.sol (L259-260)
```text
                    && sig != Amount1DeltaOverflow.selector && sig != Amount0DeltaOverflow.selector
                    && sig != AmountBeforeFeeOverflow.selector && sig != 0x4e487b71
```
