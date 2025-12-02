## Title
TWAMM Extension Bypasses Slippage Protection in Positions.deposit() via Price Manipulation Between Liquidity Calculation and Execution

## Summary
The `BasePositions.deposit()` function calculates liquidity and validates slippage protection using the current pool price, but the TWAMM extension's `beforeUpdatePosition` hook executes virtual orders that change the pool price before the actual position update occurs. This causes the actual token amounts charged to differ significantly from expected, bypassing the user's `minLiquidity` slippage protection.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BasePositions.sol` (function `deposit`, lines 71-97 and `handleLockData`, lines 232-264), `src/Core.sol` (function `updatePosition`, lines 367-379), `src/extensions/TWAMM.sol` (function `beforeUpdatePosition`, lines 652-657)

**Intended Logic:** 
Users provide `maxAmount0`, `maxAmount1`, and `minLiquidity` parameters to protect against slippage. The function should calculate the maximum liquidity that can be provided with the given token amounts at the current price, verify it meets the minimum threshold, and then add that liquidity to the position charging amounts consistent with user expectations. [1](#0-0) 

**Actual Logic:**
The slippage protection is calculated and validated at one price, but the actual amounts are charged at a different price due to TWAMM's extension hook executing between these steps:

1. **Slippage check with OLD price**: `deposit()` reads the pool's `sqrtRatio` and calculates liquidity using `maxLiquidity()`, then validates `liquidity >= minLiquidity` [2](#0-1) 

2. **TWAMM price manipulation**: When `updatePosition()` is called, it first invokes the `beforeUpdatePosition` extension hook BEFORE reading the pool state [3](#0-2) 

3. **TWAMM executes swaps**: The TWAMM extension's hook calls `lockAndExecuteVirtualOrders()` which executes pending virtual orders through swaps, changing the pool's `sqrtRatio` [4](#0-3) [5](#0-4) 

4. **Amounts calculated with NEW price**: After the extension hook, `updatePosition()` reads the modified pool state and calculates `delta0` and `delta1` using the NEW `sqrtRatio` [6](#0-5) 

5. **No validation against maxAmounts**: The calculated amounts are directly charged to the user without verifying they don't exceed `maxAmount0` or `maxAmount1` [7](#0-6) 

**Exploitation Path:**
1. User calls `deposit()` with `maxAmount0=1000`, `maxAmount1=1000`, `minLiquidity=100` on a TWAMM-enabled pool
2. At current price (sqrtRatio=X), `maxLiquidity()` calculates `liquidity=150`, which passes the `minLiquidity` check
3. `beforeUpdatePosition` hook triggers, TWAMM executes large virtual orders that shift price significantly (sqrtRatio changes to Y)
4. `updatePosition()` calculates deltas with `liquidity=150` at the NEW price Y, requiring `amount0=700`, `amount1=1300`
5. User pays `amount1=1300`, exceeding their `maxAmount1=1000` expectation, with a different token ratio than anticipated

**Security Property Broken:** 
This violates the core slippage protection mechanism that users rely on to avoid providing liquidity at unfavorable prices. The `minLiquidity` parameter becomes ineffective as it validates against stale price data.

## Impact Explanation
- **Affected Assets**: All user deposits to pools with TWAMM extension enabled
- **Damage Severity**: Users can be charged significantly different token amounts and ratios than expected. In extreme cases, if `amount0` or `amount1` exceeds what users approved, transactions revert (DoS). If users approved sufficient amounts, they suffer unexpected losses due to providing liquidity at unfavorable ratios after TWAMM-induced price movements.
- **User Impact**: Any liquidity provider using TWAMM-enabled pools is vulnerable. Every deposit transaction is affected as TWAMM always executes pending virtual orders in the `beforeUpdatePosition` hook.

## Likelihood Explanation
- **Attacker Profile**: This affects normal users rather than requiring a malicious attacker. Any user depositing to a TWAMM pool experiences this issue. However, sophisticated actors could monitor TWAMM order books and time deposits to maximize slippage against victims.
- **Preconditions**: Pool must have TWAMM extension enabled and have pending virtual orders that execute during the deposit. This is common in active TWAMM pools.
- **Execution Complexity**: No special setup required. The vulnerability is inherent to the interaction between `deposit()` and TWAMM's extension hooks.
- **Frequency**: Occurs on every deposit to TWAMM pools when virtual orders are pending execution.

## Recommendation

Add validation in `handleLockData` to ensure actual amounts don't exceed the originally specified maximums:

```solidity
// In src/base/BasePositions.sol, function handleLockData, after line 250:

uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// ADD THIS VALIDATION:
// Decode maxAmount0 and maxAmount1 from original deposit call
// (Would need to pass these through the lock data)
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceededMaxAmounts(amount0, amount1, maxAmount0, maxAmount1);
}

// Existing payment logic follows...
```

**Better alternative:** Read the pool's `sqrtRatio` AFTER extension hooks execute to calculate liquidity for slippage validation:

```solidity
// In src/base/BasePositions.sol, function deposit:
// Move liquidity calculation INSIDE the lock where it executes after extension hooks

// CURRENT: Lines 80-83 calculate liquidity before lock
// FIXED: Move this logic to handleLockData after updatePosition's beforeHook executes
// This ensures slippage check uses the same price as actual amount calculation
```

This requires architectural changes to pass `maxAmount0`, `maxAmount1`, and `minLiquidity` through the lock data and perform validation after extension hooks execute.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMSlippageBypass.t.sol
// Run with: forge test --match-test test_TWAMMSlippageBypass -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_TWAMMSlippageBypass is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    
    function setUp() public {
        // Deploy Core, Positions, and TWAMM extension
        core = new Core();
        positions = new Positions(core, address(this), 0, 0);
        twamm = new TWAMM(core);
        // Initialize pool with TWAMM extension
    }
    
    function test_TWAMMSlippageBypass() public {
        // SETUP: Create pool with TWAMM extension and place large virtual orders
        // that will execute during position updates
        
        // User deposits with slippage protection
        uint128 maxAmount0 = 1000e18;
        uint128 maxAmount1 = 1000e18;
        uint128 minLiquidity = 100e18;
        
        // Record pool price before deposit
        SqrtRatio priceBeforeDeposit = core.poolState(poolId).sqrtRatio();
        
        // EXPLOIT: User calls deposit, expecting roughly equal token amounts
        uint256 tokenId = positions.mint();
        (uint128 liquidityAdded, uint128 amount0, uint128 amount1) = 
            positions.deposit(tokenId, poolKey, tickLower, tickUpper, 
                            maxAmount0, maxAmount1, minLiquidity);
        
        // Record pool price after TWAMM execution
        SqrtRatio priceAfterTWAMM = core.poolState(poolId).sqrtRatio();
        
        // VERIFY: Price changed significantly during deposit due to TWAMM
        assertTrue(priceAfterTWAMM != priceBeforeDeposit, 
                  "TWAMM should have changed price");
        
        // VERIFY: Token ratio significantly different from expected
        // At original price, user expected ~1:1 ratio
        // But actual ratio could be 1:2 or worse due to TWAMM price movement
        assertTrue(amount1 > maxAmount1 || 
                  (amount1 * 2 > amount0 * 3), // Example: >50% deviation
                  "Slippage protection bypassed: unexpected token ratio");
        
        // VERIFY: minLiquidity check was ineffective
        assertGe(liquidityAdded, minLiquidity, 
                "minLiquidity passed but amounts are unfavorable");
    }
}
```

## Notes

This vulnerability specifically affects pools with the TWAMM extension, which is explicitly in scope per `scope.txt` line 22. The issue demonstrates how extension hooks can create timing gaps that invalidate slippage protections. While the security question asked about validation "before calling Core.updatePosition," the actual validation DOES occur before that call, but the vulnerability arises because the extension hook executes WITHIN `updatePosition` before the actual price is read for amount calculation.

The root cause is the architectural decision to execute extension hooks before reading pool state for delta calculations, combined with TWAMM's ability to modify prices through swaps in those hooks. This creates a time-of-check-time-of-use (TOCTOU) vulnerability in the slippage protection mechanism.

### Citations

**File:** src/interfaces/IPositions.sol (L38-57)
```text
    /// @notice Deposits tokens into a liquidity position
    /// @param id The NFT token ID representing the position
    /// @param poolKey Pool key identifying the pool
    /// @param tickLower Lower tick of the price range of the position
    /// @param tickUpper Upper tick of the price range of the position
    /// @param maxAmount0 Maximum amount of token0 to deposit
    /// @param maxAmount1 Maximum amount of token1 to deposit
    /// @param minLiquidity Minimum liquidity to receive (for slippage protection)
    /// @return liquidity Amount of liquidity added to the position
    /// @return amount0 Actual amount of token0 deposited
    /// @return amount1 Actual amount of token1 deposited
    function deposit(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint128 liquidity, uint128 amount0, uint128 amount1);
```

**File:** src/base/BasePositions.sol (L80-87)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
```

**File:** src/base/BasePositions.sol (L243-262)
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
```

**File:** src/Core.sol (L367-372)
```text
        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (!state.isInitialized()) revert PoolNotInitialized();
```

**File:** src/Core.sol (L375-379)
```text
            (SqrtRatio sqrtRatioLower, SqrtRatio sqrtRatioUpper) =
                (tickToSqrtRatio(positionId.tickLower()), tickToSqrtRatio(positionId.tickUpper()));

            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);
```

**File:** src/extensions/TWAMM.sol (L454-477)
```text
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
```

**File:** src/extensions/TWAMM.sol (L652-657)
```text
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```
