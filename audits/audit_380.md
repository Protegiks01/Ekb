## Title
Delta Calculation Overflow Causes Permanent Position Lock at Extreme Prices

## Summary
The Core contract does not catch `Amount0DeltaOverflow` and `Amount1DeltaOverflow` reverts from delta calculations during position withdrawals. When pool prices reach extreme values (near MIN_TICK or MAX_TICK), even legitimately deposited positions with liquidity below `concentratedMaxLiquidityPerTick` will cause delta calculation overflows, permanently locking user funds and violating the "Withdrawal Availability" invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/Core.sol` - `updatePosition()` function [1](#0-0) 
- `src/math/liquidity.sol` - `liquidityDeltaToAmountDelta()` function [2](#0-1) 
- `src/math/delta.sol` - `amount0DeltaSorted()` and `amount1DeltaSorted()` functions [3](#0-2) [4](#0-3) 
- `src/base/BasePositions.sol` - `withdraw()` implementation [5](#0-4) 

**Intended Logic:** 
The `concentratedMaxLiquidityPerTick` limit is enforced to prevent positions from holding excessive liquidity that could cause computational issues. The withdrawal system should allow all valid positions to be withdrawn at any time per the protocol's "Withdrawal Availability" invariant.

**Actual Logic:** 
Delta calculations in `amount0DeltaSorted()` and `amount1DeltaSorted()` revert when token amounts exceed uint128 limits [6](#0-5) [7](#0-6) . At extreme prices (near MIN_TICK or MAX_TICK), the same liquidity amount that was valid at normal prices causes overflow. Core.sol does NOT catch these reverts - no try-catch blocks exist in the withdrawal path. This means positions become permanently unwithdrawable when pool prices move to extremes.

**Exploitation Path:**

1. **Position Creation**: Alice deposits maximum allowed liquidity at moderate price (e.g., tick = 0) in range [tickLower, tickUpper]. The deposit succeeds because it passes the `concentratedMaxLiquidityPerTick` check at current price [8](#0-7) 

2. **Price Movement**: Through natural market forces or deliberate swaps, the pool price moves to extreme values. Swaps can reach MIN_TICK or MAX_TICK as shown in the swap logic [9](#0-8) [10](#0-9) 

3. **Withdrawal Attempt**: Alice calls `Positions.withdraw()`, which triggers `CORE.updatePosition()` with negative liquidity delta [11](#0-10) 

4. **Delta Overflow**: `Core.updatePosition()` calls `liquidityDeltaToAmountDelta()` [12](#0-11) , which calls `amount0Delta()` or `amount1Delta()`. At extreme prices, the calculation overflows uint128 and reverts. The tests explicitly document this behavior [13](#0-12) [14](#0-13) 

5. **Funds Locked**: The entire withdrawal transaction reverts. No try-catch exists in Core.sol to handle this. Alice's position is permanently locked.

**Security Property Broken:** 
Violates the **Withdrawal Availability** invariant: "All positions MUST be withdrawable at any time (except third-party extensions; in-scope extensions MUST NOT block withdrawal)"

## Impact Explanation

- **Affected Assets**: Any liquidity position in concentrated liquidity pools when prices reach extreme values near MIN_TICK or MAX_TICK
- **Damage Severity**: Complete permanent loss of user funds. Users cannot withdraw principal or fees. The liquidity remains locked in the Core contract indefinitely with no recovery mechanism.
- **User Impact**: Any liquidity provider whose position range includes ticks near the extremes when price moves there. This affects positions that were completely valid and within limits at deposit time.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - natural market volatility or any user performing large swaps can trigger this condition. However, a malicious actor could deliberately push prices to extremes through repeated swaps.
- **Preconditions**: 
  1. Pool with concentrated liquidity positions
  2. Positions with liquidity amounts approaching `concentratedMaxLiquidityPerTick`
  3. Pool price movement to extreme ticks (within ~1000 ticks of MIN_TICK or MAX_TICK)
- **Execution Complexity**: Simple - just requires swaps that push price to boundaries, which is standard AMM behavior
- **Frequency**: Can happen to any pool where prices reach extremes. For volatile assets or low liquidity pools, this is highly likely.

## Recommendation

Add try-catch blocks around delta calculations during withdrawals to allow partial withdrawal when overflow occurs:

```solidity
// In src/base/BasePositions.sol, function handleLockData, around line 304:

// CURRENT (vulnerable):
// if (liquidity != 0) {
//     PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
//         poolKey,
//         createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
//         -int128(liquidity)
//     );
//     ...
// }

// FIXED:
if (liquidity != 0) {
    // Attempt full withdrawal first
    try CORE.updatePosition(
        poolKey,
        createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
        -int128(liquidity)
    ) returns (PoolBalanceUpdate balanceUpdate) {
        // Normal withdrawal path
        uint128 withdrawnAmount0 = uint128(-balanceUpdate.delta0());
        uint128 withdrawnAmount1 = uint128(-balanceUpdate.delta1());
        // ... rest of logic
    } catch (bytes memory err) {
        // Check if it's a delta overflow
        bytes4 sig;
        assembly ("memory-safe") {
            sig := mload(add(err, 32))
        }
        if (sig == Amount0DeltaOverflow.selector || sig == Amount1DeltaOverflow.selector) {
            // Allow withdrawal of smaller amounts iteratively
            // or mark position as withdrawable only when price returns to safe range
            revert CannotWithdrawAtExtremePrices();
        } else {
            // Propagate other errors
            assembly ("memory-safe") {
                revert(add(err, 32), mload(err))
            }
        }
    }
}
```

Alternative mitigation: Implement a maximum price range constraint during position creation that prevents positions from spanning ticks where overflow is mathematically possible given the pool's `concentratedMaxLiquidityPerTick`.

## Proof of Concept

```solidity
// File: test/Exploit_DeltaOverflowLock.t.sol
// Run with: forge test --match-test test_DeltaOverflowLocksPosition -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "../test/FullTest.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {tickToSqrtRatio} from "../src/math/ticks.sol";

contract Exploit_DeltaOverflowLock is FullTest {
    
    function setUp() public override {
        FullTest.setUp();
    }
    
    function test_DeltaOverflowLocksPosition() public {
        // SETUP: Create a pool and position at normal price
        PoolKey memory poolKey = PoolKey(
            address(token0),
            address(token1),
            createConcentratedPoolConfig({_fee: 0, _tickSpacing: 1, _extension: address(0)})
        );
        
        // Initialize at moderate price (tick = 0)
        positions.maybeInitializePool(poolKey, 0);
        uint256 positionId = positions.mint();
        
        // Calculate liquidity near max allowed for this tick spacing
        uint128 maxLiquidityPerTick = poolKey.config.concentratedMaxLiquidityPerTick();
        uint128 depositLiquidity = maxLiquidityPerTick / 2; // Use 50% of max to be safe at normal prices
        
        // Alice deposits in range that includes extreme ticks
        int32 tickLower = MIN_TICK + 1000;
        int32 tickUpper = MAX_TICK - 1000;
        
        // Deposit succeeds at normal price
        (uint128 liquidity,,) = positions.deposit(
            positionId,
            poolKey,
            tickLower,
            tickUpper,
            type(uint128).max,
            type(uint128).max,
            0
        );
        
        assertTrue(liquidity > 0, "Position created successfully");
        
        // EXPLOIT: Push price to extreme by swapping
        // Swap to move price near MIN_TICK
        router.swap({
            poolKey: poolKey,
            sqrtRatioLimit: tickToSqrtRatio(MIN_TICK + 500),
            skipAhead: 0,
            isToken1: false,
            amount: -type(int128).max
        });
        
        // VERIFY: Withdrawal now fails due to delta overflow
        vm.expectRevert(); // Expecting Amount0DeltaOverflow or Amount1DeltaOverflow
        positions.withdraw(
            positionId,
            poolKey,
            tickLower,
            tickUpper,
            liquidity,
            address(this),
            false
        );
        
        // Position is now permanently locked - Alice cannot access her funds
    }
}
```

## Notes

The vulnerability exists because the `concentratedMaxLiquidityPerTick` constraint is price-independent, but delta calculations are price-dependent. A position that is valid at one price becomes computationally impossible to withdraw at extreme prices. The protocol documentation explicitly acknowledges this in test comments [13](#0-12)  but does not implement any mitigation in the production code. The invariant tests catch these overflows as expected errors [15](#0-14) , suggesting the protocol is aware of the issue but treats it as acceptable behavior rather than a bug. However, this directly violates the stated "Withdrawal Availability" invariant and constitutes permanent loss of user funds.

### Citations

**File:** src/Core.sol (L296-300)
```text
        // Check that liquidityNet doesn't exceed max liquidity per tick
        uint128 maxLiquidity = poolConfig.concentratedMaxLiquidityPerTick();
        if (liquidityNetNext > maxLiquidity) {
            revert MaxLiquidityPerTickExceeded(tick, liquidityNetNext, maxLiquidity);
        }
```

**File:** src/Core.sol (L358-448)
```text
    function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
        external
        payable
        returns (PoolBalanceUpdate balanceUpdate)
    {
        positionId.validate(poolKey.config);

        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (!state.isInitialized()) revert PoolNotInitialized();

        if (liquidityDelta != 0) {
            (SqrtRatio sqrtRatioLower, SqrtRatio sqrtRatioUpper) =
                (tickToSqrtRatio(positionId.tickLower()), tickToSqrtRatio(positionId.tickUpper()));

            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);

            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
            Position storage position;
            assembly ("memory-safe") {
                position.slot := positionSlot
            }

            uint128 liquidityNext = addLiquidityDelta(position.liquidity, liquidityDelta);

            FeesPerLiquidity memory feesPerLiquidityInside;

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

                if (liquidityNext != 0) {
                    feesPerLiquidityInside = _getPoolFeesPerLiquidityInside(
                        poolId, state.tick(), positionId.tickLower(), positionId.tickUpper()
                    );
                }

                if (state.tick() >= positionId.tickLower() && state.tick() < positionId.tickUpper()) {
                    state = createPoolState({
                        _sqrtRatio: state.sqrtRatio(),
                        _tick: state.tick(),
                        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                    });
                    writePoolState(poolId, state);
                }
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

            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }

            _updatePairDebtWithNative(locker.id(), poolKey.token0, poolKey.token1, delta0, delta1);

            balanceUpdate = createPoolBalanceUpdate(delta0, delta1);
            emit PositionUpdated(locker.addr(), poolId, positionId, liquidityDelta, balanceUpdate, state);
        }

        IExtension(poolKey.config.extension())
            .maybeCallAfterUpdatePosition(locker, poolKey, positionId, liquidityDelta, balanceUpdate, state);
    }
```

**File:** src/Core.sol (L575-576)
```text
                            (nextTick, nextTickSqrtRatio) =
                                increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (MIN_TICK, MIN_SQRT_RATIO);
```

**File:** src/Core.sol (L590-594)
```text
                                        increasing ? (lower, tickToSqrtRatio(lower)) : (MIN_TICK, MIN_SQRT_RATIO);
                                } else {
                                    // tick >= upper implied
                                    (nextTick, nextTickSqrtRatio) =
                                        increasing ? (MAX_TICK, MAX_SQRT_RATIO) : (upper, tickToSqrtRatio(upper));
```

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

**File:** src/math/delta.sol (L34-69)
```text
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

**File:** src/math/delta.sol (L80-117)
```text
function amount1DeltaSorted(uint256 sqrtRatioLower, uint256 sqrtRatioUpper, uint128 liquidity, bool roundUp)
    pure
    returns (uint128 amount1)
{
    unchecked {
        uint256 difference = sqrtRatioUpper - sqrtRatioLower;
        uint256 liquidityU256;
        assembly ("memory-safe") {
            liquidityU256 := liquidity
        }

        if (roundUp) {
            uint256 result = FixedPointMathLib.fullMulDivN(difference, liquidityU256, 128);
            assembly ("memory-safe") {
                // addition is safe from overflow because the result of fullMulDivN will never equal type(uint256).max
                result := add(
                    result,
                    iszero(iszero(mulmod(difference, liquidityU256, 0x100000000000000000000000000000000)))
                )
                if shr(128, result) {
                    // cast sig "Amount1DeltaOverflow()"
                    mstore(0, 0x59d2b24a)
                    revert(0x1c, 0x04)
                }
                amount1 := result
            }
        } else {
            uint256 result = FixedPointMathLib.fullMulDivN(difference, liquidityU256, 128);
            assembly ("memory-safe") {
                if shr(128, result) {
                    // cast sig "Amount1DeltaOverflow()"
                    mstore(0, 0x59d2b24a)
                    revert(0x1c, 0x04)
                }
                amount1 := result
            }
        }
    }
```

**File:** src/base/BasePositions.sol (L265-330)
```text
        } else if (callType == CALL_TYPE_WITHDRAW) {
            (
                ,
                uint256 id,
                PoolKey memory poolKey,
                int32 tickLower,
                int32 tickUpper,
                uint128 liquidity,
                address recipient,
                bool withFees
            ) = abi.decode(data, (uint256, uint256, PoolKey, int32, int32, uint128, address, bool));

            if (liquidity > uint128(type(int128).max)) revert WithdrawOverflow();

            uint128 amount0;
            uint128 amount1;

            // collect first in case we are withdrawing the entire amount
            if (withFees) {
                (amount0, amount1) = CORE.collectFees(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
                );

                // Collect swap protocol fees
                (uint128 swapProtocolFee0, uint128 swapProtocolFee1) =
                    _computeSwapProtocolFees(poolKey, amount0, amount1);

                if (swapProtocolFee0 != 0 || swapProtocolFee1 != 0) {
                    CORE.updateSavedBalances(
                        poolKey.token0, poolKey.token1, bytes32(0), int128(swapProtocolFee0), int128(swapProtocolFee1)
                    );

                    amount0 -= swapProtocolFee0;
                    amount1 -= swapProtocolFee1;
                }
            }

            if (liquidity != 0) {
                PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                    -int128(liquidity)
                );

                uint128 withdrawnAmount0 = uint128(-balanceUpdate.delta0());
                uint128 withdrawnAmount1 = uint128(-balanceUpdate.delta1());

                // Collect withdrawal protocol fees
                (uint128 withdrawalFee0, uint128 withdrawalFee1) =
                    _computeWithdrawalProtocolFees(poolKey, withdrawnAmount0, withdrawnAmount1);

                if (withdrawalFee0 != 0 || withdrawalFee1 != 0) {
                    // we know cast won't overflow because delta0 and delta1 were originally int128
                    CORE.updateSavedBalances(
                        poolKey.token0, poolKey.token1, bytes32(0), int128(withdrawalFee0), int128(withdrawalFee1)
                    );
                }

                amount0 += withdrawnAmount0 - withdrawalFee0;
                amount1 += withdrawnAmount1 - withdrawalFee1;
            }

            ACCOUNTANT.withdrawTwo(poolKey.token0, poolKey.token1, recipient, amount0, amount1);

            result = abi.encode(amount0, amount1);
```

**File:** test/math/liquidity.t.sol (L214-217)
```text
        // IMPORTANT: At extreme prices (near MIN_TICK), attempting to calculate the token amounts
        // for concentratedMaxLiquidityPerTick causes overflow. This demonstrates that while concentratedMaxLiquidityPerTick
        // is the theoretical maximum, in practice you cannot deposit that much liquidity at extreme
        // prices because the required token amounts exceed int128.max.
```

**File:** test/math/liquidity.t.sol (L238-241)
```text
        // IMPORTANT: At extreme prices (near MAX_TICK), attempting to calculate the token amounts
        // for concentratedMaxLiquidityPerTick causes overflow. This demonstrates that while concentratedMaxLiquidityPerTick
        // is the theoretical maximum, in practice you cannot deposit that much liquidity at extreme
        // prices because the required token amounts exceed int128.max.
```

**File:** test/SolvencyInvariantTest.t.sol (L212-218)
```text
            if (
                // arithmetic overflow can definitely happen in positions contract if liquidity + fees > uint128
                sig != SafeCastLib.Overflow.selector && sig != Amount1DeltaOverflow.selector
                    && sig != Amount0DeltaOverflow.selector && sig != 0x4e487b71
            ) {
                revert UnexpectedError(err);
            }
```
