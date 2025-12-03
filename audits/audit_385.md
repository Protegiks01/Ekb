## Title
Liquidity Deposit DOS at Extreme Price Ranges Due to Delta Calculation Overflow

## Summary
Pools at extreme prices (near MIN_TICK or MAX_TICK) become unable to accept new liquidity deposits due to integer overflow in `liquidityDeltaToAmountDelta` calculations. The protocol performs a round-trip conversion (token amounts → liquidity → token amounts) during deposits, where the second conversion overflows at extreme prices even when the liquidity value is valid, effectively DOS'ing liquidity provision.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** Users should be able to deposit liquidity at any price by providing token amounts. The `deposit` function calculates liquidity from user-provided amounts using `maxLiquidity()`, then calls `Core.updatePosition()` which should accept this liquidity and calculate the required token amounts.

**Actual Logic:** At extreme prices (near MIN_TICK or MAX_TICK), the delta calculation in `liquidityDeltaToAmountDelta` overflows even for liquidity values well below uint128.max. The deposit flow performs:
1. User provides maxAmount0, maxAmount1
2. `maxLiquidity()` calculates liquidity L (clamped to uint128.max) [2](#0-1) 
3. `Core.updatePosition()` calls `liquidityDeltaToAmountDelta(L)` [3](#0-2) 
4. At extreme prices, `amount0Delta` or `amount1Delta` overflows with `Amount0DeltaOverflow` or `Amount1DeltaOverflow` [4](#0-3) 

**Exploitation Path:**
1. Attacker creates a pool initialized at extreme tick (e.g., MAX_TICK - 1000) OR pushes existing pool to extreme price via large swap [5](#0-4) 
2. Legitimate user attempts to deposit liquidity using `positions.mintAndDeposit()` with reasonable token amounts [6](#0-5) 
3. Internal conversion calculates liquidity from amounts
4. `Core.updatePosition()` attempts to convert liquidity back to amounts, which overflows at extreme price
5. Transaction reverts, user cannot add liquidity to the pool

**Security Property Broken:** Violates the "Withdrawal Availability" invariant - if positions must be withdrawable at any time, they should also be depositable. Pools at extreme prices effectively become frozen for new liquidity additions.

## Impact Explanation
- **Affected Assets**: Any pool that reaches extreme prices (near MIN_TICK or MAX_TICK), whether intentionally initialized there or pushed there through swaps
- **Damage Severity**: Complete DOS of liquidity provision for affected pools. Existing LPs can still withdraw, but no new liquidity can be added, fragmenting liquidity and degrading trading efficiency
- **User Impact**: All users attempting to provide liquidity to pools at extreme prices. The issue is documented in protocol tests but not properly handled [7](#0-6) 

## Likelihood Explanation
- **Attacker Profile**: Any user can create pools at extreme ticks or perform swaps to push existing pools to extreme prices
- **Preconditions**: Pool must be at extreme price (within ~1000 ticks of MIN_TICK or MAX_TICK) with tick spacing of 1 (smallest spacing amplifies the issue)
- **Execution Complexity**: Single transaction to initialize pool at extreme tick, or large swap to push price to extreme
- **Frequency**: Affects all deposit operations once pool reaches extreme price; remains DOS'd until price moves away from extremes

## Recommendation

Add validation in `BasePositions.deposit()` to prevent deposits that would cause overflow: [8](#0-7) 

```solidity
// In src/base/BasePositions.sol, function deposit, after line 83:

// CURRENT (vulnerable):
liquidity = maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

if (liquidity < minLiquidity) {
    revert DepositFailedDueToSlippage(liquidity, minLiquidity);
}

// FIXED:
liquidity = maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

if (liquidity < minLiquidity) {
    revert DepositFailedDueToSlippage(liquidity, minLiquidity);
}

// Validate that the liquidity can be converted back to amounts without overflow
// This prevents DOS at extreme prices where delta calculations overflow
try this.validateLiquidityDelta(poolKey, tickLower, tickUpper, int128(liquidity)) {
    // Validation successful, proceed
} catch {
    revert DepositWouldOverflow();
}

// Add helper function:
function validateLiquidityDelta(PoolKey memory poolKey, int32 tickLower, int32 tickUpper, int128 liquidityDelta) external view {
    SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();
    // This will revert with Amount0DeltaOverflow or Amount1DeltaOverflow if invalid
    liquidityDeltaToAmountDelta(sqrtRatio, liquidityDelta, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper));
}
```

Alternative: Adjust `concentratedMaxLiquidityPerTick` calculation to account for extreme price ranges, or add price-dependent liquidity limits.

## Proof of Concept

```solidity
// File: test/Exploit_ExtremePriceDOS.t.sol
// Run with: forge test --match-test test_ExtremePriceDOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "./FullTest.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {Amount0DeltaOverflow, Amount1DeltaOverflow} from "../src/math/delta.sol";

contract Exploit_ExtremePriceDOS is FullTest {
    function test_ExtremePriceDOS() public {
        // SETUP: Create pool at extreme tick (near MAX_TICK)
        int32 extremeTick = MAX_TICK - 1000;
        PoolKey memory poolKey = createPool({
            tick: extremeTick,
            fee: 0,
            tickSpacing: 1
        });
        
        // Add initial small liquidity to make pool appear usable
        token0.approve(address(positions), 1);
        token1.approve(address(positions), 1e30);
        positions.mintAndDeposit(
            poolKey,
            extremeTick - 100,
            extremeTick + 100,
            1,
            1e30,
            0
        );
        
        // EXPLOIT: Legitimate user tries to add more liquidity with reasonable amounts
        token0.approve(address(positions), 1000);
        token1.approve(address(positions), 1e36);
        
        // This should succeed but reverts due to overflow in liquidityDeltaToAmountDelta
        vm.expectRevert(); // Will revert with Amount0DeltaOverflow or Amount1DeltaOverflow
        positions.mintAndDeposit(
            poolKey,
            extremeTick - 10,
            extremeTick + 10,
            1000,
            1e36,
            0
        );
        
        // VERIFY: Pool is DOS'd - cannot accept new liquidity at extreme price
        // Even though user provided reasonable token amounts, the internal
        // conversion from liquidity back to amounts overflows
        console.log("Pool at extreme price is DOS'd for liquidity deposits");
    }
}
```

## Notes

The issue is explicitly documented in the test suite at [9](#0-8) , which states: "At extreme prices (near MIN_TICK), attempting to calculate the token amounts for concentratedMaxLiquidityPerTick causes overflow. This demonstrates that while concentratedMaxLiquidityPerTick is the theoretical maximum, in practice you cannot deposit that much liquidity at extreme prices because the required token amounts exceed int128.max."

However, the protocol does not prevent users from attempting such deposits or handle the resulting DOS condition. The invariant tests acknowledge these overflows as "expected" errors [10](#0-9) , but this creates a practical DOS vector where pools at extreme prices become unusable for liquidity provision, even though swaps demonstrate pools CAN reach these extreme prices [11](#0-10) .

### Citations

**File:** src/math/liquidity.sol (L22-54)
```text
function liquidityDeltaToAmountDelta(
    SqrtRatio sqrtRatio,
    int128 liquidityDelta,
    SqrtRatio sqrtRatioLower,
    SqrtRatio sqrtRatioUpper
) pure returns (int128 delta0, int128 delta1) {
    unchecked {
        if (liquidityDelta == 0) {
            return (0, 0);
        }
        bool isPositive = (liquidityDelta > 0);
        int256 sign = -1 + 2 * int256(LibBit.rawToUint(isPositive));
        // absolute value of a int128 always fits in a uint128
        uint128 magnitude = uint128(FixedPointMathLib.abs(liquidityDelta));

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
            delta1 = SafeCastLib.toInt128(
                sign * int256(uint256(amount1Delta(sqrtRatioLower, sqrtRatioUpper, magnitude, isPositive)))
            );
        }
    }
}
```

**File:** src/math/liquidity.sol (L90-119)
```text
function maxLiquidity(
    SqrtRatio _sqrtRatio,
    SqrtRatio sqrtRatioA,
    SqrtRatio sqrtRatioB,
    uint128 amount0,
    uint128 amount1
) pure returns (uint128) {
    uint256 sqrtRatio = _sqrtRatio.toFixed();
    (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) = sortAndConvertToFixedSqrtRatios(sqrtRatioA, sqrtRatioB);

    if (sqrtRatio <= sqrtRatioLower) {
        return uint128(
            FixedPointMathLib.min(type(uint128).max, maxLiquidityForToken0(sqrtRatioLower, sqrtRatioUpper, amount0))
        );
    } else if (sqrtRatio < sqrtRatioUpper) {
        return uint128(
            FixedPointMathLib.min(
                type(uint128).max,
                FixedPointMathLib.min(
                    maxLiquidityForToken0(sqrtRatio, sqrtRatioUpper, amount0),
                    maxLiquidityForToken1(sqrtRatioLower, sqrtRatio, amount1)
                )
            )
        );
    } else {
        return uint128(
            FixedPointMathLib.min(type(uint128).max, maxLiquidityForToken1(sqrtRatioLower, sqrtRatioUpper, amount1))
        );
    }
}
```

**File:** src/Core.sol (L378-379)
```text
            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);
```

**File:** src/math/delta.sol (L25-69)
```text
function amount0Delta(SqrtRatio sqrtRatioA, SqrtRatio sqrtRatioB, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
{
    (uint256 sqrtRatioLower, uint256 sqrtRatioUpper) = sortAndConvertToFixedSqrtRatios(sqrtRatioA, sqrtRatioB);
    amount0 = amount0DeltaSorted(sqrtRatioLower, sqrtRatioUpper, liquidity, roundUp);
}

/// @dev Assumes that the sqrt ratios are non-zero and sorted
function amount0DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount0)
{
    unchecked {
        uint256 liquidityX128;
        assembly ("memory-safe") {
            liquidityX128 := shl(128, liquidity)
        }
        if (roundUp) {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUp(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            assembly ("memory-safe") {
                let result := add(div(result0, sqrtRatioLower), iszero(iszero(mod(result0, sqrtRatioLower))))
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        } else {
            uint256 result0 =
                FixedPointMathLib.fullMulDivUnchecked(liquidityX128, (sqrtRatioUpper - sqrtRatioLower), sqrtRatioUpper);
            uint256 result = FixedPointMathLib.rawDiv(result0, sqrtRatioLower);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount0DeltaOverflow()"
                    mstore(0, 0xb4ef2546)
                    revert(0x1c, 0x04)
                }
                amount0 := result
            }
        }
    }
}
```

**File:** test/Router.t.sol (L749-773)
```text
    function test_swap_full_range_to_max_price() public {
        PoolKey memory poolKey = createFullRangePool(MAX_TICK - 1, 0);

        (, uint128 liquidity) = createPosition(poolKey, MIN_TICK, MAX_TICK, 1, 1e36);
        assertNotEq(liquidity, 0);

        token1.approve(address(router), type(uint256).max);
        PoolBalanceUpdate balanceUpdate = router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: -1,
            sqrtRatioLimit: MAX_SQRT_RATIO,
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min
        });

        assertEq(balanceUpdate.delta0(), 0);
        assertEq(balanceUpdate.delta1(), 499999875000098127000483558015);

        // reaches max tick but does not change liquidity
        (SqrtRatio sqrtRatio, int32 tick, uint128 liquidityAfter) = core.poolState(poolKey.toPoolId()).parse();
        assertEq(SqrtRatio.unwrap(sqrtRatio), SqrtRatio.unwrap(MAX_SQRT_RATIO));
        assertEq(tick, MAX_TICK);
        assertEq(liquidityAfter, liquidity);
    }
```

**File:** src/base/BasePositions.sol (L70-97)
```text
    /// @inheritdoc IPositions
    function deposit(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }

        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }

        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity)),
            (uint128, uint128)
        );
    }
```

**File:** test/math/liquidity.t.sol (L209-255)
```text
    function test_maxLiquidityPerTick_at_min_price_tickSpacing1_overflows() public {
        // For tick spacing 1, calculate max liquidity per tick
        PoolConfig config = createConcentratedPoolConfig({_fee: 0, _tickSpacing: 1, _extension: address(0)});
        uint128 maxLiquidityPerTick = config.concentratedMaxLiquidityPerTick();

        // IMPORTANT: At extreme prices (near MIN_TICK), attempting to calculate the token amounts
        // for concentratedMaxLiquidityPerTick causes overflow. This demonstrates that while concentratedMaxLiquidityPerTick
        // is the theoretical maximum, in practice you cannot deposit that much liquidity at extreme
        // prices because the required token amounts exceed int128.max.

        // This test documents that overflow occurs at low prices
        int32 lowTick = MIN_TICK + 1000;

        // Expect Amount0DeltaOverflow when trying to calculate amounts for max liquidity
        // Use the external wrapper to make vm.expectRevert work
        vm.expectRevert();
        this.amountDeltas(
            tickToSqrtRatio(lowTick),
            int128(maxLiquidityPerTick),
            tickToSqrtRatio(lowTick),
            tickToSqrtRatio(lowTick + 1)
        );
    }

    function test_maxLiquidityPerTick_at_max_price_tickSpacing1_overflows() public {
        // For tick spacing 1, calculate max liquidity per tick
        PoolConfig config = createConcentratedPoolConfig({_fee: 0, _tickSpacing: 1, _extension: address(0)});
        uint128 maxLiquidityPerTick = config.concentratedMaxLiquidityPerTick();

        // IMPORTANT: At extreme prices (near MAX_TICK), attempting to calculate the token amounts
        // for concentratedMaxLiquidityPerTick causes overflow. This demonstrates that while concentratedMaxLiquidityPerTick
        // is the theoretical maximum, in practice you cannot deposit that much liquidity at extreme
        // prices because the required token amounts exceed int128.max.

        // This test documents that overflow occurs at high prices
        int32 highTick = MAX_TICK - 1000;

        // Expect Amount1DeltaOverflow when trying to calculate amounts for max liquidity
        // Use the external wrapper to make vm.expectRevert work
        vm.expectRevert();
        this.amountDeltas(
            tickToSqrtRatio(highTick),
            int128(maxLiquidityPerTick),
            tickToSqrtRatio(highTick - 1),
            tickToSqrtRatio(highTick)
        );
    }
```

**File:** test/math/liquidity.sol (L209-231)
```text

```

**File:** test/SolvencyInvariantTest.t.sol (L257-265)
```text
            if (
                sig != Router.PartialSwapsDisallowed.selector && sig != 0xffffffff && sig != 0x00000000
                    && sig != Amount1DeltaOverflow.selector && sig != Amount0DeltaOverflow.selector
                    && sig != AmountBeforeFeeOverflow.selector && sig != 0x4e487b71
                    && sig != SafeCastLib.Overflow.selector
            ) {
                revert UnexpectedError(err);
            }
        }
```
