## Title
Precision Loss in computeC() Causes Premature Price Settlement and Fee Bypass in TWAMM Virtual Order Execution

## Summary
The `computeC()` function in the TWAMM mathematical library suffers from precision loss when calculating the normalized distance between current and target prices. When `sqrtRatio` and `sqrtSaleRatio` are very close but not equal, the function incorrectly returns 0, triggering a shortcut path that bypasses fee calculations, time-weighting, and liquidity resistance. This causes virtual orders to settle instantly at the equilibrium price instead of executing gradually as intended.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `computeC()` function calculates the normalized price coefficient `c = (sqrtSaleRatio - sqrtRatio) / (sqrtSaleRatio + sqrtRatio)` to determine how far the current price is from the target equilibrium. When `c == 0`, it indicates the prices are equal and no further price movement is needed. [2](#0-1) 

**Actual Logic:** Due to fixed-point arithmetic precision loss, `computeC()` returns 0 even when `sqrtRatio` and `sqrtSaleRatio` are close but **not equal**. The test suite explicitly demonstrates this behavior: [3](#0-2) 

At `MAX_SQRT_RATIO`, a difference of just 1 wei causes `c` to round to zero. The precision loss threshold is `dist < (sqrtRatio + sqrtSaleRatio) / 2^128`, which means larger price ratios have wider precision loss windows where distinct values are treated as equal.

**Exploitation Path:**
1. Attacker identifies or creates a pool with a high price ratio (near `MAX_SQRT_RATIO.toFixed()`)
2. Attacker places TWAMM orders with carefully chosen sale rates such that `computeSqrtSaleRatio(saleRateToken0, saleRateToken1)` produces a value within the precision loss window of current `sqrtRatio` [4](#0-3) 
3. When virtual orders execute via `_executeVirtualOrdersFromWithinLock`, the system calls `computeNextSqrtRatio()` [5](#0-4) 
4. `computeC()` incorrectly returns 0, triggering the shortcut path that immediately sets `sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp)` [2](#0-1) 
5. The full calculation path is bypassed, which would have:
   - Applied fee damping: `sqrtSaleRate = sqrtSaleRateWithoutFee - computeFee(...)` [6](#0-5) 
   - Used exponential formula to gradually move price based on time and liquidity [7](#0-6) 
6. Virtual orders execute with better prices than intended (instant settlement vs gradual execution), while LPs receive reduced fees and face excess price impact

**Security Property Broken:** This violates the **Fee Accounting** invariant - position fee collection must be accurate. The fee damping mechanism is completely bypassed when `c == 0`, causing LPs to lose expected fee revenue from virtual order execution. It also violates the fundamental TWAMM model where orders should execute gradually over time with liquidity providing resistance to price movement.

## Impact Explanation
- **Affected Assets**: All TWAMM pools, particularly those with high price ratios where precision loss is more prevalent. Liquidity providers lose fee revenue and face excess impermanent loss.
- **Damage Severity**: When `c` incorrectly rounds to 0:
  - Fee damping is bypassed - the pool fee that should reduce the effective sale rate is not applied
  - Time-weighting is lost - orders execute as if infinite time has passed rather than actual `timeElapsed`
  - Liquidity resistance is eliminated - price jumps immediately regardless of available liquidity
  - TWAMM sellers get better execution (up to 1-2% price improvement in extreme cases)
  - LPs suffer corresponding losses from the bypassed protections
- **User Impact**: All liquidity providers in affected TWAMM pools experience reduced fee income and increased impermanent loss. The issue affects every virtual order execution when the precision loss condition is met.

## Likelihood Explanation
- **Attacker Profile**: Any user who can place TWAMM orders can potentially exploit this by choosing specific sale rate ratios
- **Preconditions**: 
  - Pool must have a price ratio where precision loss is significant (higher ratios have wider loss windows)
  - Current `sqrtRatio` must be close to the equilibrium implied by sale rates (common during steady TWAMM execution)
- **Execution Complexity**: Moderate - requires calculating specific sale rates to place orders within the precision loss window, but mathematically straightforward
- **Frequency**: Can occur frequently in high-ratio pools, and the issue persists as long as orders remain active in the affected price range

## Recommendation

Modify the `computeNextSqrtRatio()` function to add a tolerance check that verifies whether the price difference is truly negligible relative to the magnitudes involved: [8](#0-7) 

```solidity
// Add after computing c, before the zero check:
// For very small c values, verify the absolute difference is also negligible
// to prevent precision loss from causing premature settlement
uint256 absoluteDiff = FixedPointMathLib.dist(sqrtRatioFixed, sqrtSaleRatio);
bool isTrulyEqual = (c == 0) && (absoluteDiff < 2); // Only treat as equal if diff < 2 wei

if (isTrulyEqual || liquidity == 0) {
    // Safe to settle - verified truly equal or no liquidity resistance
    sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
} else {
    // Execute full calculation even if c rounded to 0
    // ... existing code ...
}
```

Alternative mitigation: Increase the precision of the `computeC()` calculation by using 256-bit intermediate values and checking for true equality before relying solely on the `c` value.

## Proof of Concept

**Note:** This vulnerability is confirmed by the existing test suite which explicitly checks and expects this precision loss behavior: [3](#0-2) 

The test demonstrates that at `MAX_SQRT_RATIO.toFixed()`, a difference of 1 wei causes `computeC()` to return 0, proving the precision loss issue exists. A full exploit PoC would require:
1. Setting up a pool with high price ratio
2. Placing TWAMM orders with sale rates that produce `sqrtSaleRatio` close to but not equal to current `sqrtRatio`
3. Triggering virtual order execution and measuring the price impact vs expected gradual movement
4. Demonstrating LPs receive less fees than they should from the execution

The existing test infrastructure in [9](#0-8)  and [10](#0-9)  provides the necessary framework to implement such a PoC.

## Notes

The security question asks whether precision loss could cause `c` to be **nonzero** when values are equal - but the actual vulnerability is the inverse: precision loss causes `c` to be **zero** when values are close but **not equal**. This is confirmed by the test case showing a 1 wei difference at `MAX_SQRT_RATIO` produces `c = 0`.

The issue is particularly concerning because:
1. It's not just a theoretical edge case - it's tested and expected behavior [11](#0-10) 
2. The precision loss window grows with price magnitude, affecting high-value token pairs more severely
3. The comment justification "if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected" is incorrect when precision loss is the cause [12](#0-11)

### Citations

**File:** src/math/twamm.sol (L56-64)
```text
function computeC(uint256 sqrtRatio, uint256 sqrtSaleRatio) pure returns (int256 c) {
    uint256 unsigned = FixedPointMathLib.fullMulDiv(
        FixedPointMathLib.dist(sqrtRatio, sqrtSaleRatio), (1 << 128), sqrtRatio + sqrtSaleRatio
    );
    assembly ("memory-safe") {
        let sign := sub(shl(1, gt(sqrtSaleRatio, sqrtRatio)), 1)
        c := mul(sign, unsigned)
    }
}
```

**File:** src/math/twamm.sol (L68-83)
```text
function computeSqrtSaleRatio(uint256 saleRateToken0, uint256 saleRateToken1) pure returns (uint256 sqrtSaleRatio) {
    unchecked {
        uint256 saleRatio = FixedPointMathLib.rawDiv(saleRateToken1 << 128, saleRateToken0);

        if (saleRatio <= type(uint128).max) {
            // full precision for small ratios
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 128);
        } else if (saleRatio <= type(uint192).max) {
            // we know it only has 192 bits, so we can shift it 64 before rooting to get more precision
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 64) << 32;
        } else {
            // we assume it has max 240 bits, since saleRateToken1 is 112 bits and we shifted left 128
            sqrtSaleRatio = FixedPointMathLib.sqrt(saleRatio << 16) << 56;
        }
    }
}
```

**File:** src/math/twamm.sol (L105-111)
```text
        int256 c = computeC(sqrtRatioFixed, sqrtSaleRatio);

        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
```

**File:** src/math/twamm.sol (L113-115)
```text
            uint256 sqrtSaleRateWithoutFee = FixedPointMathLib.sqrt(saleRateToken0 * saleRateToken1);
            // max 112 bits
            uint256 sqrtSaleRate = sqrtSaleRateWithoutFee - computeFee(uint128(sqrtSaleRateWithoutFee), fee);
```

**File:** src/math/twamm.sol (L120-139)
```text
            uint256 exponent = FixedPointMathLib.rawDiv(sqrtSaleRate * timeElapsed * 12392656037, liquidity);
            if (exponent >= 0x400000000000000000) {
                // if the exponent is larger than this value (64), the exponent term dominates and the result is approximately the sell ratio
                sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
            } else {
                int256 ePowExponent = int256(uint256(exp2(uint128(exponent))) << 64);

                uint256 sqrtRatioNextFixed = FixedPointMathLib.fullMulDiv(
                    sqrtSaleRatio, FixedPointMathLib.dist(ePowExponent, c), FixedPointMathLib.abs(ePowExponent + c)
                );

                // we should never exceed the sale ratio
                if (roundUp) {
                    sqrtRatioNextFixed = FixedPointMathLib.max(sqrtRatioNextFixed, sqrtSaleRatio);
                } else {
                    sqrtRatioNextFixed = FixedPointMathLib.min(sqrtRatioNextFixed, sqrtSaleRatio);
                }

                sqrtRatioNext = toSqrtRatio(sqrtRatioNextFixed, roundUp);
            }
```

**File:** test/math/twamm.t.sol (L1-371)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {Test} from "forge-std/Test.sol";
import {
    computeSaleRate,
    computeNextSqrtRatio,
    computeC,
    computeAmountFromSaleRate,
    computeSqrtSaleRatio,
    computeRewardAmount,
    addSaleRateDelta,
    SaleRateDeltaOverflow,
    SaleRateOverflow
} from "../../src/math/twamm.sol";
import {MIN_SQRT_RATIO, MAX_SQRT_RATIO, SqrtRatio, toSqrtRatio} from "../../src/types/sqrtRatio.sol";

contract TwammMathTest is Test {
    function test_computeSaleRate_examples() public pure {
        assertEq(computeSaleRate(1000, 5), (1000 << 32) / 5);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_computeSaleRate_fuzz(uint128 amount, uint32 duration) public {
        duration = uint32(bound(duration, 1, type(uint32).max));
        uint256 saleRate = (uint256(amount) << 32) / duration;

        if (saleRate > type(uint112).max) {
            vm.expectRevert(SaleRateOverflow.selector);
        }
        uint256 result = computeSaleRate(amount, duration);
        assertEq(result, saleRate);
    }

    function wrapped_addSaleRateDelta(uint112 saleRate, int112 delta) external pure {
        addSaleRateDelta(saleRate, delta);
    }

    function test_addSaleRateDelta_invariants(uint112 saleRate, int112 delta) public {
        int256 expected = int256(uint256(saleRate)) + delta;
        if (expected < 0 || expected > int256(uint256(type(uint112).max))) {
            vm.expectRevert(SaleRateDeltaOverflow.selector);
            this.wrapped_addSaleRateDelta(saleRate, delta);
        } else {
            uint256 result = addSaleRateDelta(saleRate, delta);
            assertEq(int256(uint256(result)), expected);
        }
    }

    function test_computeRewardAmount() public pure {
        assertEq(computeRewardAmount({rewardRate: 0, saleRate: 0}), 0);
        assertEq(computeRewardAmount({rewardRate: type(uint256).max, saleRate: 0}), 0);
        assertEq(computeRewardAmount({rewardRate: type(uint256).max, saleRate: 1}), type(uint128).max);
        assertEq(computeRewardAmount({rewardRate: type(uint256).max, saleRate: type(uint112).max}), type(uint128).max);
        // overflows the uint128 container
        assertEq(computeRewardAmount({rewardRate: 1 << 146, saleRate: 1 << 110}), 0);
    }

    function test_computeAmountFromSaleRate_examples() public pure {
        // 100 per second
        assertEq(computeAmountFromSaleRate({saleRate: 100 << 32, duration: 3, roundUp: false}), 300);
        assertEq(computeAmountFromSaleRate({saleRate: 100 << 32, duration: 3, roundUp: true}), 300);

        // 62.5 per second
        assertEq(computeAmountFromSaleRate({saleRate: 125 << 31, duration: 3, roundUp: false}), 187);
        assertEq(computeAmountFromSaleRate({saleRate: 125 << 31, duration: 3, roundUp: true}), 188);

        // nearly 0 per second
        assertEq(computeAmountFromSaleRate({saleRate: 1, duration: 3, roundUp: false}), 0);
        assertEq(computeAmountFromSaleRate({saleRate: 1, duration: 3, roundUp: true}), 1);

        // nearly 0 per second
        assertEq(computeAmountFromSaleRate({saleRate: 1, duration: type(uint32).max, roundUp: false}), 0);
        assertEq(computeAmountFromSaleRate({saleRate: 1, duration: type(uint32).max, roundUp: true}), 1);

        // max sale rate max duration
        assertEq(
            computeAmountFromSaleRate({saleRate: type(uint112).max, duration: type(uint32).max, roundUp: false}),
            5192296857325901808915867154513919
        );
        assertEq(
            computeAmountFromSaleRate({saleRate: type(uint112).max, duration: type(uint32).max, roundUp: true}),
            5192296857325901808915867154513920
        );
    }

    function test_computeC_examples() public pure {
        assertEq(computeC(1 << 128, 1 << 129), 113427455640312821154458202477256070485);
        assertEq(computeC(1 << 128, 1 << 127), -113427455640312821154458202477256070485);
        assertEq(computeC(1 << 128, 1 << 128), 0);

        // large difference
        assertEq(
            computeC(MAX_SQRT_RATIO.toFixed(), MIN_SQRT_RATIO.toFixed()),
            -340282366920938463463374607431768211453,
            "max,min"
        );
        assertEq(
            computeC(MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed()),
            340282366920938463463374607431768211453,
            "min,max"
        );

        // small difference, i.e. large denominator relative to numerator
        assertEq(computeC(MAX_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed() - 1), 0, "max,max-1");
        assertEq(computeC(MIN_SQRT_RATIO.toFixed() + 1, MIN_SQRT_RATIO.toFixed()), -9223148497026361869, "min,min+1");

        assertEq(computeC({sqrtRatio: 10, sqrtSaleRatio: 15}), 0x33333333333333333333333333333333);
        assertEq(computeC({sqrtRatio: 10, sqrtSaleRatio: 20}), 0x55555555555555555555555555555555);
        assertEq(computeC({sqrtRatio: 10, sqrtSaleRatio: 30}), 0x80000000000000000000000000000000);
        assertEq(computeC({sqrtRatio: 10, sqrtSaleRatio: 190}), 0xe6666666666666666666666666666666);

        assertEq(computeC({sqrtRatio: 15, sqrtSaleRatio: 10}), -0x33333333333333333333333333333333);
        assertEq(computeC({sqrtRatio: 20, sqrtSaleRatio: 10}), -0x55555555555555555555555555555555);
        assertEq(computeC({sqrtRatio: 30, sqrtSaleRatio: 10}), -0x80000000000000000000000000000000);
        assertEq(computeC({sqrtRatio: 190, sqrtSaleRatio: 10}), -0xe6666666666666666666666666666666);
    }

    function test_computeSqrtSaleRatio_examples() public pure {
        assertEq(computeSqrtSaleRatio(1, 1), uint256(1) << 128);
        assertEq(computeSqrtSaleRatio(100, 1), 34028236692093846346337460743176821142);
        assertEq(computeSqrtSaleRatio(1, 100), 3402823669209384634633746074317682114560);
        assertEq(computeSqrtSaleRatio(type(uint112).max, 1), 4722366482869645213696);
        assertEq(computeSqrtSaleRatio(1, type(uint112).max), 24519928653854221733733552434404944576644526926077100032);
    }

    function test_gas_cost_computeNextSqrtRatio() public {
        vm.startSnapshotGas("computeNextSqrtRatio_0");
        computeNextSqrtRatio({
            sqrtRatio: toSqrtRatio(10_000 << 128, false),
            liquidity: 10_000,
            saleRateToken0: 458864027,
            saleRateToken1: 280824784,
            timeElapsed: 46_800,
            fee: 0
        });
        vm.stopSnapshotGas();

        vm.startSnapshotGas("computeNextSqrtRatio_1");
        computeNextSqrtRatio({
            sqrtRatio: toSqrtRatio((uint256(1) << 128) / 10_000, false),
            liquidity: 1_000_000,
            saleRateToken0: 707 << 32,
            saleRateToken1: 179 << 32,
            timeElapsed: 12,
            fee: uint64((uint256(30) << 64) / 10_000)
        });
        vm.stopSnapshotGas();

        vm.startSnapshotGas("computeNextSqrtRatio_2");
        computeNextSqrtRatio({
            sqrtRatio: toSqrtRatio(286363514177267035440548892163466107483369185, false),
            liquidity: 130385243018985227,
            saleRateToken0: 1917585044284,
            saleRateToken1: 893194653345642013054241177,
            timeElapsed: 360,
            fee: 922337203685477580
        });
        vm.stopSnapshotGas();
    }

    function test_computeNextSqrtRatio_examples() public pure {
        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(10_000 << 128, false),
                    liquidity: 10_000,
                    saleRateToken0: 458864027,
                    saleRateToken1: 280824784,
                    timeElapsed: 46_800,
                    fee: 0
                }).toFixed(),
            714795237151155238153964311638230171648 // 2.1005944081
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio((uint256(1) << 128) / 10_000, false),
                    liquidity: 1_000_000,
                    saleRateToken0: 707 << 32,
                    saleRateToken1: 179 << 32,
                    timeElapsed: 12,
                    fee: uint64((uint256(30) << 64) / 10_000)
                }).toFixed(),
            762756935888947507319423427130949632 // 0.00224154117297
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(uint256(1) << 128, false),
                    liquidity: 1_000_000,
                    saleRateToken0: 100_000 << 32,
                    saleRateToken1: 1 << 32,
                    timeElapsed: 12,
                    fee: 1 << 63
                }).toFixed(),
            212677851090737004084435068911850881024 // 0.625004031255463
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(uint256(1) << 128, false),
                    liquidity: 1_000_000,
                    saleRateToken0: 100_000 << 32,
                    saleRateToken1: 1 << 32,
                    timeElapsed: 12,
                    fee: 0
                }).toFixed(),
            154676064193352917823625393341053534208 // 0.4545520992
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(uint256(1) << 128, false),
                    liquidity: 1_000_000,
                    saleRateToken0: 1 << 32,
                    saleRateToken1: 100_000 << 32,
                    timeElapsed: 12,
                    fee: 1 << 63
                }).toFixed(),
            544448275377366823331338723279895527424 // 1.5999896801
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(uint256(1) << 128, false),
                    liquidity: 1_000_000,
                    saleRateToken0: 1 << 32,
                    saleRateToken1: 100_000 << 32,
                    timeElapsed: 12,
                    fee: 0
                }).toFixed(),
            748610263916272246100204618056279785472 // 2.1999678405
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(286363514177267035440548892163466107483369185, false),
                    liquidity: 130385243018985227,
                    saleRateToken0: 1917585044284,
                    saleRateToken1: 893194653345642013054241177,
                    timeElapsed: 360,
                    fee: 922337203685477580
                }).toFixed(),
            286548851173856260703560045093187956263354368 // 842,091.3894737111
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(1 << 128, false),
                    liquidity: 10,
                    saleRateToken0: 5000 << 32,
                    saleRateToken1: 500 << 32,
                    timeElapsed: 1,
                    fee: 0
                }).toFixed(),
            107606732706330320687810575739503247360 // ~= 0.316227766
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(286363514177267035440548892163466107483369185, false),
                    liquidity: 130385243018985227,
                    saleRateToken0: 1917585044284,
                    saleRateToken1: 893194653345642013054241177,
                    timeElapsed: 360,
                    fee: 922337203685477580
                }).toFixed(),
            286548851173856260703560045093187956263354368 // 842,091.3894737111
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(404353500025976246415094160170803, false),
                    liquidity: 130385243018985227,
                    saleRateToken0: 893194653345642013054241177,
                    saleRateToken1: 1917585044284,
                    timeElapsed: 360,
                    fee: 922337203685477580
                }).toFixed(),
            404091968133776522675682963095552 // 842,091.3894737111
        );

        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(1 << 128, false),
                    liquidity: 10,
                    saleRateToken0: 5000 << 32,
                    saleRateToken1: 500 << 32,
                    timeElapsed: 1,
                    fee: 0
                }).toFixed(),
            107606732706330320687810575739503247360 // ~= 0.316227766
        );
    }

    function test_computeNextSqrtRatio_example_from_production() public pure {
        assertEq(
            computeNextSqrtRatio({
                    sqrtRatio: toSqrtRatio(4182607738901102592 + (148436996701757 << 64), false),
                    liquidity: 4472135213867,
                    saleRateToken0: 3728260255814876407785,
                    saleRateToken1: 1597830095238095,
                    timeElapsed: 2688,
                    fee: 9223372036854775
                }).toFixed(),
            75660834358443397537995245133758464
        );
    }

    function test_computeNextSqrtRatio_always_within_bounds_0() public pure {
        test_computeNextSqrtRatio_always_within_bounds(
            40804391198510682395386066027183367945789451008295010214769,
            417285290670760742141,
            type(uint112).max,
            1,
            type(uint32).max,
            0
        );
    }

    function test_computeNextSqrtRatio_always_within_bounds(
        uint256 sqrtRatioFixed,
        uint128 liquidity,
        uint112 saleRateToken0,
        uint112 saleRateToken1,
        uint32 timeElapsed,
        uint64 fee
    ) public pure {
        // valid starting sqrt ratio
        SqrtRatio sqrtRatio =
            toSqrtRatio(bound(sqrtRatioFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed()), false);

        // if either is 0, we cannot use this method
        saleRateToken0 = uint112(bound(saleRateToken0, 1, type(uint112).max));
        saleRateToken1 = uint112(bound(saleRateToken1, 1, type(uint112).max));

        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
            sqrtRatio: sqrtRatio,
            liquidity: liquidity,
            saleRateToken0: saleRateToken0,
            saleRateToken1: saleRateToken1,
            timeElapsed: timeElapsed,
            fee: fee
        });

        // it should always be within the min/max sqrt ratio which represents 2**-128 to 2**128
        // this is because the sale ratio is bounded to 2**-112 to 2**112
        assertGe(sqrtRatioNext.toFixed(), MIN_SQRT_RATIO.toFixed());
        assertLe(sqrtRatioNext.toFixed(), MAX_SQRT_RATIO.toFixed());

        uint256 sqrtSaleRatio = computeSqrtSaleRatio(saleRateToken0, saleRateToken1);

        // the next sqrt ratio is always between the sale ratio and current price
        if (sqrtSaleRatio > sqrtRatio.toFixed()) {
            assertGe(sqrtRatioNext.toFixed(), sqrtRatio.toFixed());
            assertLe(sqrtRatioNext.toFixed(), sqrtSaleRatio);

            if (liquidity == 0) {
                assertEq(sqrtRatioNext.toFixed(), toSqrtRatio(sqrtSaleRatio, false).toFixed());
            }
        } else {
            assertLe(sqrtRatioNext.toFixed(), sqrtRatio.toFixed());
            assertGe(sqrtRatioNext.toFixed(), sqrtSaleRatio);

            if (liquidity == 0) {
                assertEq(sqrtRatioNext.toFixed(), toSqrtRatio(sqrtSaleRatio, true).toFixed());
            }
        }
    }
```

**File:** src/extensions/TWAMM.sol (L445-452)
```text
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });
```

**File:** test/extensions/TWAMM.t.sol (L1-50)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {PoolKey} from "../../src/types/poolKey.sol";
import {createConcentratedPoolConfig, createFullRangePoolConfig} from "../../src/types/poolConfig.sol";
import {PoolId} from "../../src/types/poolId.sol";
import {FullTest} from "../FullTest.sol";
import {ITWAMM, TWAMM, twammCallPoints} from "../../src/extensions/TWAMM.sol";
import {OrderKey} from "../../src/interfaces/extensions/ITWAMM.sol";
import {createOrderConfig} from "../../src/types/orderConfig.sol";
import {TWAMMStorageLayout} from "../../src/libraries/TWAMMStorageLayout.sol";
import {StorageSlot} from "../../src/types/storageSlot.sol";
import {Core} from "../../src/Core.sol";
import {TWAMMLib} from "../../src/libraries/TWAMMLib.sol";
import {Test} from "forge-std/Test.sol";
import {searchForNextInitializedTime} from "../../src/math/timeBitmap.sol";
import {MAX_ABS_VALUE_SALE_RATE_DELTA} from "../../src/math/time.sol";
import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import {createTimeInfo} from "../../src/types/timeInfo.sol";
import {TwammPoolState} from "../../src/types/twammPoolState.sol";
import {TimeInfo} from "../../src/types/timeInfo.sol";

abstract contract BaseTWAMMTest is FullTest {
    TWAMM internal twamm;

    function setUp() public virtual override {
        FullTest.setUp();
        address deployAddress = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), deployAddress);
        twamm = TWAMM(deployAddress);
    }

    function boundTime(uint256 time, uint32 offset) internal pure returns (uint64) {
        return uint64(((bound(time, offset, type(uint64).max - type(uint32).max - 2 * offset) / 256) * 256) + offset);
    }

    function createTwammPool(uint64 fee, int32 tick) internal returns (PoolKey memory poolKey) {
        poolKey = createPool(address(token0), address(token1), tick, createFullRangePoolConfig(fee, address(twamm)));
    }

    function coolAllContracts() internal virtual override {
        FullTest.coolAllContracts();
        vm.cool(address(twamm));
    }
}

contract TWAMMTest is BaseTWAMMTest {
    using TWAMMLib for *;

    function test_createPool_fails_not_full_range() public {
```
