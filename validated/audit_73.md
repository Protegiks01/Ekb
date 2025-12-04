After performing rigorous validation through all phases of the Ekubo Protocol Validation Framework, I have determined this claim is **VALID**.

# Audit Report

## Title
TWAMM Virtual Order Execution Causes Users to Exceed maxAmount Limits in BasePositions.deposit()

## Summary
The `BasePositions.deposit()` function contains a Time-Of-Check-Time-Of-Use (TOCTOU) vulnerability where the pool price is read twice during execution. Between these reads, the TWAMM extension's `beforeUpdatePosition` hook executes virtual orders that change the price. This causes users to be charged token amounts exceeding their explicitly set `maxAmount0` and `maxAmount1` parameters, violating the fundamental safety guarantee these parameters provide.

## Impact
**Severity**: High - Direct financial loss to users, violation of core safety guarantee

Users depositing liquidity into TWAMM pools can be forced to deposit significantly more tokens than their specified maximum limits. When liquidity is calculated at price P1 but executed at price P2 (after TWAMM virtual order execution), the same liquidity amount can require substantially different token ratios. If the price movement pushes a position out of its range, the required amounts can exceed the user's maxAmount parameters by multiples (e.g., 2x-3x or more depending on price movement). This affects all TWAMM pools with pending virtual orders and breaks user trust in the maxAmount safety mechanism.

## Finding Description

**Location:** `src/base/BasePositions.sol`, function `deposit()` and `handleLockData()`

**Intended Logic:** 
The `maxAmount0` and `maxAmount1` parameters serve as hard upper bounds on token amounts a user authorizes for deposit. The function calculates liquidity at the current price to ensure amounts stay within these limits. [1](#0-0) 

**Actual Logic:**
The vulnerability occurs through this execution sequence:

1. **First price read** at line 80 calculates liquidity based on price P1 [2](#0-1) 

2. **TWAMM hook execution** occurs in `Core.updatePosition()` before the second price read [3](#0-2) 

3. **TWAMM executes swaps** that change the pool price from P1 to P2 [4](#0-3) [5](#0-4) 

4. **Second price read** and amount calculation happen at the NEW price P2, but liquidity L was calculated for price P1

5. **No validation** occurs before charging the user the potentially excessive amounts [6](#0-5) 

**Exploitation Path:**
1. **Setup**: TWAMM pool exists with pending virtual orders that will move price significantly
2. **Trigger**: User calls `deposit()` with `maxAmount0 = X`, `maxAmount1 = Y` at current price P1
3. **Price Fetch 1**: Line 80 fetches price P1; lines 82-83 calculate liquidity L for amounts ≤ X, Y at P1
4. **Lock Entry**: Line 93 enters lock, triggering `handleLockData` → `Core.updatePosition()`
5. **Hook Execution**: Lines 367-368 call `TWAMM.beforeUpdatePosition()` which executes virtual orders via `CORE.swap()`
6. **Price Change**: Pool price moves from P1 to P2 due to TWAMM swaps
7. **Price Fetch 2**: Line 371 reads NEW price P2; lines 378-379 calculate amounts for liquidity L at price P2
8. **Excess Charge**: Lines 249-254 charge user amounts that can exceed X or Y without validation

**Security Property Broken:**
The maxAmount parameters are designed to protect users from depositing more than intended. This protection is completely bypassed when TWAMM execution changes the price between calculation and execution.

**Mathematical Proof:**
For a position with range [PL, PU] and initial price P1 (in range):
- Liquidity L = maxAmount1 / (√P1 - √PL)
- If price moves to P2 > PU (above range), required amount1 = L × (√PU - √PL)
- Substituting: amount1 = maxAmount1 × (√PU - √PL) / (√P1 - √PL)
- Since √PU > √P1, this ratio is always > 1, proving amounts can exceed maxAmount

## Impact Explanation

**Affected Assets**: All user funds (token0 and token1) deposited into TWAMM pools

**Damage Severity**:
- Users can deposit 2x-3x or more beyond their maxAmount limits depending on price movement magnitude
- Example: User sets maxAmount0=1000, maxAmount1=1000 but deposits 0 token0 and 2400 token1 after TWAMM execution moves price significantly
- No way for users to protect themselves as TWAMM execution is automatic and unpredictable
- Breaks fundamental trust in the protocol's safety mechanisms

**User Impact**: Any user depositing into TWAMM pools (in-scope extension). Given TWAMM's design to continuously execute orders, this is a systemic issue affecting all TWAMM pool interactions.

**Trigger Conditions**: Occurs naturally whenever anyone deposits into a TWAMM pool with unexecuted virtual orders.

## Likelihood Explanation

**Attacker Profile**: Any user can trigger this, intentionally or unintentionally. No special permissions required.

**Preconditions**:
1. TWAMM pool with pending virtual orders (very common - this is TWAMM's purpose)
2. Virtual orders cause price movement when executed (typical behavior)
3. User deposits with position range affected by price movement (common scenario)

**Execution Complexity**: Single transaction calling `deposit()`. The vulnerability triggers automatically due to TWAMM's design.

**Economic Cost**: Only standard gas fees. No capital requirements beyond the deposit itself.

**Frequency**: Continuously exploitable on all TWAMM pools with active orders. TWAMM orders execute automatically on any pool interaction.

**Overall Likelihood**: HIGH - Trivial to trigger, affects all TWAMM users, continuous exposure.

## Recommendation

**Primary Fix: Validate actual amounts against maxAmount limits**

In `src/base/BasePositions.sol`, function `handleLockData`, add validation after line 250:

```solidity
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Decode maxAmount parameters from calldata
(, , , , , , uint128 maxAmount0, uint128 maxAmount1) = 
    abi.decode(data, (uint256, address, uint256, PoolKey, int32, int32, uint128, uint128));

// Validate amounts don't exceed user-specified maximums
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceedsMaxAmount(amount0, amount1, maxAmount0, maxAmount1);
}

ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
```

Add error definition:
```solidity
error DepositExceedsMaxAmount(uint128 amount0, uint128 amount1, uint128 maxAmount0, uint128 maxAmount1);
```

**Alternative Fix: Fetch price atomically within lock**

Move the price fetch and liquidity calculation into `handleLockData` where it executes atomically with the position update, eliminating the TOCTOU window entirely.

## Notes

**Key Technical Details:**

1. **TOCTOU Window**: The vulnerability exists in the temporal gap between BasePositions.sol:80 (first price read) and Core.sol:371 (second price read), with TWAMM hook execution occurring between them.

2. **No Validation Layer**: Complete code trace confirms zero validation exists checking `amount0 ≤ maxAmount0` or `amount1 ≤ maxAmount1` before charging users.

3. **In-Scope Extension**: TWAMM is explicitly listed in scope.txt line 22. This behavior is not a "misconfiguration" but TWAMM's intended design to execute virtual orders on any pool interaction.

4. **Not a Known Issue**: The README mentions TWAMM order execution price variance (lines 52-62), which concerns TWAMM order holders receiving bad prices. This is a completely different issue about deposit() users exceeding their maxAmount limits.

5. **Not Standard CLMM Behavior**: Uniswap v3 and other CLMMs don't have extension hooks that can modify price between calculation and execution. This is unique to Ekubo's extension architecture.

6. **Mathematical Certainty**: This is not a probabilistic vulnerability. The mathematical proof demonstrates amounts WILL exceed limits when specific (common) conditions occur.

### Citations

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

**File:** src/Core.sol (L358-385)
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
```

**File:** src/extensions/TWAMM.sol (L386-490)
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

                        // this cannot overflow or underflow because swapDelta0 is constrained to int128,
                        // and amounts computed from uint112 sale rates cannot exceed uint112.max
                        rewardDelta0 = swapBalanceUpdate.delta0() - int256(uint256(amount0));
                        rewardDelta1 = swapBalanceUpdate.delta1() - int256(uint256(amount1));
                    } else if (amount0 != 0 || amount1 != 0) {
                        PoolBalanceUpdate swapBalanceUpdate;
                        if (amount0 != 0) {
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
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
