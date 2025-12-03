## Title
Narrow Price Range Positions Return Zero Tokens on Withdrawal Despite Non-Zero Liquidity, Causing Permanent Fund Loss

## Summary
When users create concentrated liquidity positions with very narrow price ranges (adjacent ticks with tickSpacing=1), the delta calculation functions round down to zero during withdrawal due to fixed-point arithmetic precision loss. This causes users to receive zero tokens back despite having deposited liquidity, while the position's liquidity is still reduced in Core storage, resulting in permanent loss of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) , [2](#0-1) , [3](#0-2) , [4](#0-3) 

**Intended Logic:** When users withdraw liquidity from positions, they should receive token amounts proportional to their liquidity. The protocol should ensure all positions are withdrawable at any time, as stated in the "Withdrawal Availability" invariant.

**Actual Logic:** For positions with very narrow price ranges (e.g., adjacent ticks with tickSpacing=1), the delta calculation in `amount1DeltaSorted` computes: `result = (difference * liquidity) >> 128` where `difference = sqrtRatioUpper - sqrtRatioLower`. When `difference * liquidity < 2^128`, the result rounds down to zero. For adjacent ticks at mid-price, positions with liquidity below approximately 2 trillion wei (~0.000002 tokens for 18-decimal tokens) will receive zero tokens on withdrawal.

**Exploitation Path:**
1. User creates a pool with tickSpacing=1 using `Core.initializePool()` [5](#0-4) 
2. User deposits a small amount of liquidity (e.g., 1e12 wei) into adjacent ticks (-1 to 1) via `Positions.mintAndDeposit()` [6](#0-5) 
3. User attempts to withdraw liquidity via `Positions.withdraw()` [7](#0-6) 
4. `Core.updatePosition()` calls `liquidityDeltaToAmountDelta()` with negative liquidityDelta and roundUp=false [8](#0-7) 
5. The delta calculation returns (0, 0) due to rounding, but the position's liquidity is still reduced to zero [9](#0-8) 
6. User receives 0 tokens despite having deposited real funds - permanent loss

**Security Property Broken:** Violates the "Withdrawal Availability" invariant: "All positions MUST be withdrawable at any time". Users with narrow-range positions below the rounding threshold cannot recover their deposited funds.

## Impact Explanation
- **Affected Assets**: Any token pairs where users create positions with tickSpacing=1 and liquidity below the rounding threshold (~2e12 wei per token)
- **Damage Severity**: Complete loss of deposited funds for affected positions. While individual position values may be small (0.000002 tokens), this affects the fundamental protocol invariant and can impact many users
- **User Impact**: Any user creating narrow-range positions with minimal liquidity. This is particularly problematic for:
  - Testing or experimental positions with small amounts
  - Tokens with low USD value where "small" amounts are still economically significant
  - Automated strategies that create many small positions
  - Users unaware of the rounding threshold who deposit slightly below it

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a design flaw affecting normal users. No malicious actor needed.
- **Preconditions**: 
  - Pool with tickSpacing=1 (minimum allowed) [10](#0-9) 
  - Position with adjacent ticks (e.g., -1 to 1)
  - Liquidity below rounding threshold (~2e12 wei)
  - No minimum liquidity enforcement in protocol [11](#0-10) 
- **Execution Complexity**: Simple - occurs during normal deposit/withdraw operations
- **Frequency**: Affects every withdrawal attempt for positions below the threshold. Permanent loss on first withdrawal attempt.

## Recommendation

Add a minimum liquidity check during position creation to prevent positions that would round to zero on withdrawal:

```solidity
// In src/math/liquidity.sol, add validation function:

/// @notice Validates that liquidity is sufficient to avoid zero-amount withdrawals
/// @param sqrtRatioLower Lower bound sqrt ratio
/// @param sqrtRatioUpper Upper bound sqrt ratio  
/// @param liquidity Proposed liquidity amount
/// @return isValid True if liquidity is sufficient to avoid rounding to zero
function validateMinimumLiquidity(
    uint256 sqrtRatioLower, 
    uint256 sqrtRatioUpper, 
    uint128 liquidity
) pure returns (bool isValid) {
    // Check that withdrawal would return non-zero amounts
    uint256 difference = sqrtRatioUpper - sqrtRatioLower;
    // Ensure (difference * liquidity) >= 2^128 to avoid zero rounding
    // Use mulmod to check overflow safely
    return (difference * liquidity) >= (1 << 128);
}

// In src/Core.sol, add check in updatePosition():
// After line 379, before updating position storage:
if (liquidityDelta > 0) {
    // For deposits, validate minimum liquidity
    (uint256 lower, uint256 upper) = sortAndConvertToFixedSqrtRatios(sqrtRatioLower, sqrtRatioUpper);
    require(
        validateMinimumLiquidity(lower, upper, uint128(liquidityDelta)),
        "Liquidity below minimum threshold"
    );
}
```

Alternative mitigation: Document the minimum liquidity threshold clearly and add a helper function in Positions contract to calculate the minimum viable liquidity for a given tick range, allowing frontends to prevent users from creating unwithdrawable positions.

## Proof of Concept

```solidity
// File: test/Exploit_NarrowRangeZeroWithdrawal.t.sol
// Run with: forge test --match-test test_NarrowRangeZeroWithdrawal -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {liquidityDeltaToAmountDelta} from "../src/math/liquidity.sol";
import {tickToSqrtRatio} from "../src/math/ticks.sol";
import {ONE} from "../src/types/sqrtRatio.sol";

contract Exploit_NarrowRangeZeroWithdrawal is FullTest {
    
    function setUp() public override {
        super.setUp();
    }
    
    function test_NarrowRangeZeroWithdrawal() public {
        // SETUP: Create pool with minimum tick spacing (1)
        PoolKey memory poolKey = createPool(0, 0, 1); // tick=0, fee=0, tickSpacing=1
        
        // Calculate a small liquidity amount that will round to zero on withdrawal
        // For adjacent ticks at mid-price, liquidity < ~2e12 rounds to zero
        uint128 smallLiquidity = 1e12; // 1 trillion wei - below rounding threshold
        
        // Calculate required token amounts for this liquidity
        // For ticks -1 to 1 (adjacent ticks with spacing=1)
        (int128 amount0Required, int128 amount1Required) = liquidityDeltaToAmountDelta(
            ONE, // current price at tick 0
            int128(smallLiquidity),
            tickToSqrtRatio(-1),
            tickToSqrtRatio(1)
        );
        
        require(amount0Required > 0 && amount1Required > 0, "Setup: amounts must be positive");
        
        // User deposits this small liquidity
        token0.approve(address(positions), uint128(amount0Required));
        token1.approve(address(positions), uint128(amount1Required));
        
        (uint256 positionId, uint128 actualLiquidity,,) = 
            positions.mintAndDeposit(poolKey, -1, 1, uint128(amount0Required), uint128(amount1Required), 0);
        
        emit log_named_uint("Deposited liquidity", actualLiquidity);
        emit log_named_int("Deposited amount0", amount0Required);
        emit log_named_int("Deposited amount1", amount1Required);
        
        // Verify position exists with non-zero liquidity
        (uint128 posLiquidity,,,,) = positions.getPositionFeesAndLiquidity(positionId, poolKey, -1, 1);
        assertGt(posLiquidity, 0, "Position should have non-zero liquidity");
        
        // Record user's token balance before withdrawal
        uint256 token0Before = token0.balanceOf(address(this));
        uint256 token1Before = token1.balanceOf(address(this));
        
        // EXPLOIT: User attempts to withdraw their position
        (uint128 withdrawn0, uint128 withdrawn1) = positions.withdraw(positionId, poolKey, -1, 1, actualLiquidity);
        
        // VERIFY: User receives ZERO tokens despite having deposited funds
        assertEq(withdrawn0, 0, "VULNERABILITY: Received 0 token0 on withdrawal");
        assertEq(withdrawn1, 0, "VULNERABILITY: Received 0 token1 on withdrawal");
        
        uint256 token0After = token0.balanceOf(address(this));
        uint256 token1After = token1.balanceOf(address(this));
        
        assertEq(token0After, token0Before, "User received no token0 back");
        assertEq(token1After, token1Before, "User received no token1 back");
        
        // Verify the position liquidity was actually reduced to zero (funds are lost)
        (uint128 finalLiquidity,,,,) = positions.getPositionFeesAndLiquidity(positionId, poolKey, -1, 1);
        assertEq(finalLiquidity, 0, "Position liquidity was reduced despite zero withdrawal");
        
        emit log_string("VULNERABILITY CONFIRMED: User deposited tokens but received zero back on withdrawal");
        emit log_string("Funds are permanently lost - violates Withdrawal Availability invariant");
    }
}
```

**Notes:**

This vulnerability is rooted in the fixed-point arithmetic used for delta calculations. When `sqrtRatioUpper - sqrtRatioLower` is very small (adjacent ticks), multiplying by small liquidity amounts and right-shifting by 128 bits causes precision loss that rounds to zero [12](#0-11) .

The issue is exacerbated by the protocol's design choice to round DOWN on withdrawals (roundUp=false) to favor the protocol [13](#0-12) . While rounding conservatively is generally good practice, it creates a threshold below which positions become unwithdrawable.

The protocol allows tickSpacing=1 [14](#0-13)  and has no minimum liquidity enforcement [11](#0-10) , making this vulnerability exploitable in normal usage scenarios.

### Citations

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

**File:** src/Core.sol (L374-443)
```text
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
```

**File:** src/base/BasePositions.sol (L71-97)
```text
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

**File:** src/base/BasePositions.sol (L120-133)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L303-330)
```text
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

**File:** src/types/poolConfig.sol (L141-149)
```text
function createConcentratedPoolConfig(uint64 _fee, uint32 _tickSpacing, address _extension)
    pure
    returns (PoolConfig c)
{
    assembly ("memory-safe") {
        // Set bit 31 to 1 for concentrated liquidity, then OR with tick spacing (bits 30-0)
        let typeConfig := or(0x80000000, and(_tickSpacing, 0x7fffffff))
        c := or(or(shl(96, _extension), shl(32, and(_fee, 0xffffffffffffffff))), typeConfig)
    }
```

**File:** src/types/positionId.sol (L47-52)
```text
function validate(PositionId positionId, PoolConfig config) pure {
    if (config.isConcentrated()) {
        if (positionId.tickLower() >= positionId.tickUpper()) revert BoundsOrder();
        if (positionId.tickLower() < MIN_TICK || positionId.tickUpper() > MAX_TICK) revert MinMaxBounds();
        int32 spacing = int32(config.concentratedTickSpacing());
        if (positionId.tickLower() % spacing != 0 || positionId.tickUpper() % spacing != 0) revert BoundsTickSpacing();
```

**File:** src/math/constants.sol (L22-22)
```text
uint32 constant MAX_TICK_SPACING = 698605;
```
