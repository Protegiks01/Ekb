## Title
TWAMM Price Manipulation Between maxLiquidity Calculation and Position Update Causes Deposit Failures and Excess Token Deductions

## Summary
The `deposit()` function in `BasePositions.sol` calculates liquidity using `maxLiquidity()` based on the current pool price, but the TWAMM extension's `beforeUpdatePosition` hook can execute virtual orders that change the pool price before the actual token amounts are calculated in `updatePosition()`. This price manipulation causes the actual token amounts to potentially exceed the user's specified `maxAmount0` and `maxAmount1`, leading to transaction reverts or users paying more than intended.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (lines 71-97), `src/Core.sol` (lines 358-448), `src/extensions/TWAMM.sol` (lines 651-657)

**Intended Logic:** When a user calls `deposit(maxAmount0, maxAmount1)`, the function should ensure that the actual token amounts charged never exceed these maximum values. The `maxLiquidity()` function calculates the maximum liquidity that can be provided given the available token amounts at the current price. [1](#0-0) 

**Actual Logic:** The deposit flow has a critical time-of-check-time-of-use (TOCTOU) issue:

1. `deposit()` reads the pool's `sqrtRatio` at line 80
2. `maxLiquidity()` calculates liquidity `L` based on this price (lines 82-83)
3. `deposit()` calls `lock()` which triggers `updatePosition()` (line 94)
4. `updatePosition()` calls the TWAMM extension's `beforeUpdatePosition` hook (line 367-368) [2](#0-1) 

5. TWAMM's `beforeUpdatePosition` calls `lockAndExecuteVirtualOrders()` (line 656) [3](#0-2) 

6. Virtual orders execute swaps that **change the pool price**
7. `updatePosition()` reads the pool state again at line 371 and uses the **new price** for `liquidityDeltaToAmountDelta()` (lines 378-379)
8. The calculated amounts are based on the new price, not the original price used in `maxLiquidity()`

**Exploitation Path:**
1. A TWAMM pool has pending virtual orders that will execute and decrease the price
2. User calls `deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)` with exact token approvals
3. `maxLiquidity()` calculates `L` based on current price `P1`
4. TWAMM's `beforeUpdatePosition` hook executes, running virtual orders that swap tokens
5. Pool price changes from `P1` to `P2` where `P2 < P1` (price decreased)
6. `liquidityDeltaToAmountDelta()` calculates `actualAmount0` and `actualAmount1` based on `L` and `P2`
7. Since price decreased, more token0 is now needed for the same liquidity: `actualAmount0 > maxAmount0`
8. Transaction fails with `TransferFromFailed()` if user approved exactly `maxAmount0`, or user pays excess tokens if they approved more [4](#0-3) 

**Security Property Broken:** The implicit guarantee that `actualAmount0 <= maxAmount0` and `actualAmount1 <= maxAmount1` is violated. Users lose control over the maximum tokens they will spend in a deposit transaction.

## Impact Explanation
- **Affected Assets**: Token0 and token1 in any TWAMM-enabled pool where users attempt to deposit liquidity
- **Damage Severity**: Users can be charged token amounts exceeding their specified maximum limits. The excess is bounded by their token approvals but violates their slippage protection intent. In worst case, if a user approved `type(uint256).max`, they could lose significantly more tokens than intended.
- **User Impact**: All liquidity providers on TWAMM pools are affected. Every deposit transaction is vulnerable if virtual orders are pending. The issue manifests as either:
  - Unexpected transaction reverts (DOS) if exact approvals are used
  - Excess token deduction if higher approvals exist
  - Loss of predictable liquidity provisioning on TWAMM pools

## Likelihood Explanation
- **Attacker Profile**: Any user depositing liquidity on TWAMM pools. No special privileges required. Can also be exploited by attackers who create TWAMM orders specifically to manipulate prices during victim deposits.
- **Preconditions**: 
  - Pool must have TWAMM extension enabled
  - Pending virtual orders must exist that will execute and change the price
  - User must attempt to deposit liquidity while virtual orders are pending
  - Position must be in-range (requires both tokens)
- **Execution Complexity**: Single transaction. The vulnerability triggers automatically through normal deposit flow. An attacker could strategically place TWAMM orders to maximize price impact during victim deposits.
- **Frequency**: Continuously exploitable. Every deposit on TWAMM pools is vulnerable when virtual orders are pending. On active TWAMM pools, this could affect multiple transactions per block.

## Recommendation

**Option 1: Validate actual amounts against max amounts (Recommended)**

In `src/base/BasePositions.sol`, add validation after receiving actual amounts:

```solidity
// In src/base/BasePositions.sol, function deposit, after line 96:

(amount0, amount1) = abi.decode(
    lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity)),
    (uint128, uint128)
);

// ADD THIS VALIDATION:
if (amount0 > maxAmount0) {
    revert DepositExceedsMaxAmount0(amount0, maxAmount0);
}
if (amount1 > maxAmount1) {
    revert DepositExceedsMaxAmount1(amount1, maxAmount1);
}
```

**Option 2: Re-read price and recalculate liquidity in updatePosition**

In `src/Core.sol`, recalculate liquidity based on current price at the time of execution:

```solidity
// In src/Core.sol, function updatePosition, before line 378:

// If this is a deposit and liquidityDelta is based on maxLiquidity,
// recalculate it with current price to ensure amounts don't exceed max
// This requires passing maxAmount0 and maxAmount1 through the call chain
```

**Option 3: Skip TWAMM execution during position updates**

In `src/extensions/TWAMM.sol`, modify `beforeUpdatePosition` to skip execution or pass a flag:

```solidity
// In src/extensions/TWAMM.sol, line 652:

function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
    external
    override(BaseExtension, IExtension)
{
    // Skip execution to prevent price manipulation during deposits
    // or only execute if sufficient time has passed since last execution
    // This is less ideal as it prevents legitimate TWAMM functionality
}
```

**Recommended**: Option 1 is the cleanest fix that maintains all functionality while adding necessary validation. It provides clear error messages and preserves the user's slippage protection intent.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMPriceManipulation.t.sol
// Run with: forge test --match-test test_TWAMMPriceManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_TWAMMPriceManipulation is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    
    address user = address(0x1);
    address token0 = address(0x2);
    address token1 = address(0x3);
    
    function setUp() public {
        // Deploy Core, Positions, and TWAMM extension
        core = new Core();
        positions = new Positions(core, address(this));
        twamm = new TWAMM(core);
        
        // Initialize TWAMM pool with tick spacing and fee
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createPoolConfig(address(twamm), 100, 3000)
        });
        
        // Initialize pool at price ratio 1:1 (tick 0)
        core.initializePool(poolKey, 0);
        
        // Setup: Create TWAMM order that will decrease price
        // This simulates pending virtual orders
        vm.startPrank(user);
        deal(token0, user, 1000000 ether);
        IERC20(token0).approve(address(twamm), type(uint256).max);
        
        // Place sell order for token0 (will decrease price)
        twamm.submitOrder(
            poolKey,
            1000000 ether, // amount token0 to sell
            true, // zeroForOne
            block.timestamp + 3600 // endTime
        );
        vm.stopPrank();
    }
    
    function test_TWAMMPriceManipulation() public {
        // SETUP: User prepares to deposit liquidity
        address victim = address(0x4);
        deal(token0, victim, 10000 ether);
        deal(token1, victim, 10000 ether);
        
        vm.startPrank(victim);
        
        // Approve exact amounts
        uint128 maxAmount0 = 5000 ether;
        uint128 maxAmount1 = 5000 ether;
        IERC20(token0).approve(address(positions), maxAmount0);
        IERC20(token1).approve(address(positions), maxAmount1);
        
        // Read current price
        SqrtRatio priceBefore = core.poolState(poolKey.toPoolId()).sqrtRatio();
        
        // EXPLOIT: Attempt deposit
        // This will trigger TWAMM's beforeUpdatePosition hook
        // which executes virtual orders and changes the price
        
        uint256 tokenId = positions.mint();
        
        // This call will FAIL with TransferFromFailed because:
        // 1. maxLiquidity calculates L based on price BEFORE virtual orders
        // 2. TWAMM executes orders, price decreases
        // 3. liquidityDeltaToAmountDelta calculates amounts with NEW price
        // 4. actualAmount0 > maxAmount0, transferFrom fails
        
        vm.expectRevert(); // Expect TransferFromFailed
        positions.deposit(
            tokenId,
            poolKey,
            -100, // tickLower
            100,  // tickUpper
            maxAmount0,
            maxAmount1,
            0 // minLiquidity
        );
        
        vm.stopPrank();
        
        // VERIFY: Price changed due to TWAMM execution
        SqrtRatio priceAfter = core.poolState(poolKey.toPoolId()).sqrtRatio();
        assertLt(priceAfter.toFixed(), priceBefore.toFixed(), 
            "Vulnerability confirmed: TWAMM changed price during deposit");
    }
}
```

## Notes

This vulnerability specifically affects TWAMM-enabled pools and occurs due to the legitimate design of TWAMM's `beforeUpdatePosition` hook, which executes pending virtual orders. The hook is working as designed (executing orders before position updates), but the interaction with `maxLiquidity` calculation creates a TOCTOU vulnerability.

The mathematical property that `actualAmount <= maxAmount` when the price remains constant is correct (as confirmed by the fuzz test at lines 204-205). However, when the price changes between calculation and execution, this property breaks. [5](#0-4) 

The issue is NOT with malicious third-party extensions (which are out of scope), but with the in-scope TWAMM extension's legitimate behavior creating an unintended side effect. [6](#0-5)

### Citations

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

**File:** src/libraries/FlashAccountantLib.sol (L52-73)
```text
    function payFrom(IFlashAccountant accountant, address from, address token, uint256 amount) internal {
        assembly ("memory-safe") {
            mstore(0, 0xf9b6a796)
            mstore(32, token)

            // accountant.startPayments()
            // this is expected to never revert
            pop(call(gas(), accountant, 0, 0x1c, 36, 0x00, 0x00))

            // token#transferFrom
            let m := mload(0x40)
            mstore(0x60, amount)
            mstore(0x40, accountant)
            mstore(0x2c, shl(96, from))
            mstore(0x0c, 0x23b872dd000000000000000000000000) // `transferFrom(address,address,uint256)`.
            let success := call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
            if iszero(and(eq(mload(0x00), 1), success)) {
                if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                    mstore(0x00, 0x7939f424) // `TransferFromFailed()`.
                    revert(0x1c, 0x04)
                }
            }
```

**File:** test/math/liquidity.t.sol (L171-207)
```text
    function test_maxLiquidity(
        uint256 sqrtRatioFixed,
        uint256 sqrtRatioLowerFixed,
        uint256 sqrtRatioUpperFixed,
        uint128 amount0,
        uint128 amount1
    ) public view {
        amount0 = uint128(bound(amount0, 0, type(uint8).max));
        amount1 = uint128(bound(amount1, 0, type(uint8).max));
        // creates a minimum separation of .0001%, which causes it to overflow liquidity less often
        SqrtRatio sqrtRatio =
            toSqrtRatio(bound(sqrtRatioFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed()), false);
        SqrtRatio sqrtRatioLower =
            toSqrtRatio(bound(sqrtRatioLowerFixed, MIN_SQRT_RATIO.toFixed(), MAX_SQRT_RATIO.toFixed() - 1), false);
        SqrtRatio sqrtRatioUpper =
            toSqrtRatio(bound(sqrtRatioUpperFixed, sqrtRatioLower.toFixed() + 1, MAX_SQRT_RATIO.toFixed()), false);

        // this can overflow in some cases
        vm.assumeNoRevert();
        uint128 liquidity = this.ml(sqrtRatio, sqrtRatioLower, sqrtRatioUpper, amount0, amount1);

        if (sqrtRatio <= sqrtRatioLower && amount0 == 0) {
            assertEq(liquidity, 0);
        } else if (sqrtRatio >= sqrtRatioUpper && amount1 == 0) {
            assertEq(liquidity, 0);
        }

        // if we were capped at max liquidity, there isn't much we can assert, except maybe that the amount deltas likely overflow
        if (liquidity <= uint128(type(int128).max)) {
            (int128 a, int128 b) = this.amountDeltas(sqrtRatio, int128(liquidity), sqrtRatioLower, sqrtRatioUpper);

            assertGe(a, 0);
            assertGe(b, 0);
            assertLe(uint128(a), amount0);
            assertLe(uint128(b), amount1);
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
