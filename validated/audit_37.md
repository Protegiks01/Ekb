# Audit Report

## Title
TWAMM Extension Causes Price Change Between Liquidity Calculation and Deposit Execution, Violating maxAmount Interface Contract

## Summary
The `deposit()` function documents `maxAmount0` and `maxAmount1` as "Maximum amount ... to deposit" but fails to enforce these constraints. TWAMM's `beforeUpdatePosition` hook executes virtual orders that change the pool price between liquidity calculation and transfer execution, causing users to either experience unexpected `TransferFromFailed` reverts or pay amounts exceeding their documented maximums.

## Impact
**Severity**: Medium

Users depositing liquidity to TWAMM pools face two critical issues due to the unenforced maxAmount constraint: (1) transactions revert with `TransferFromFailed` despite passing slippage validation when users approve exactly the documented "maximum" amounts, causing gas loss and failed deposits, or (2) users who over-approve pay amounts exceeding their stated maximums (potentially 10-20%+ more of one token) as TWAMM virtual order execution changes the price deterministically within the transaction flow, violating the documented interface contract where `minLiquidity` only protects liquidity quantity, not token amounts.

## Finding Description

**Location:** `src/base/BasePositions.sol` (deposit function), `src/Core.sol` (updatePosition function), `src/extensions/TWAMM.sol` (beforeUpdatePosition hook)

**Intended Logic:**
The interface documentation explicitly states parameters are "Maximum amount of token0 to deposit" and "Maximum amount of token1 to deposit". [1](#0-0)  The deposit function should enforce these documented maximums and revert if actual amounts exceed them.

**Actual Logic:**
The implementation reads pool price and calculates liquidity outside the lock using `maxAmount0` and `maxAmount1`. [2](#0-1)  However, only the calculated liquidity value is passed into the lock, NOT the maxAmount parameters. [3](#0-2) 

Inside `updatePosition`, the TWAMM extension's `beforeUpdatePosition` hook executes BEFORE reading pool state. [4](#0-3)  The TWAMM hook calls `lockAndExecuteVirtualOrders` [5](#0-4)  which executes pending virtual orders via swaps [6](#0-5)  that change the pool price.

Token amounts are then calculated using the NEW post-TWAMM price with liquidity calculated from the OLD price. [7](#0-6)  These amounts are transferred directly without any validation against the documented `maxAmount0` or `maxAmount1` constraints. [8](#0-7) 

**Exploitation Path:**
1. Pool with TWAMM extension has pending virtual orders (normal operating state)
2. User calls `deposit(id, poolKey, tickLower, tickUpper, maxAmount0=100, maxAmount1=100, minLiquidity=95)`
3. Current pool price 1:1, liquidity calculated as 100 based on maxAmounts
4. Slippage check passes (100 ≥ 95)
5. During `updatePosition`, TWAMM executes virtual orders, price changes to 1.2:1
6. System calculates amount0=95, amount1=110 for liquidity=100 at new price
7. **Scenario A**: User approved exactly 100 of each → transfer fails with `TransferFromFailed` despite passing slippage validation
8. **Scenario B**: User over-approved → transfer succeeds with 110 of token1, exceeding documented "maximum" of 100

**Security Property Broken:**
The deposit function violates its documented interface contract stating `maxAmount0` and `maxAmount1` are "Maximum amount ... to deposit". The slippage protection on `minLiquidity` only validates liquidity quantity, not token amounts, leaving users without protection against token ratio changes induced by deterministic TWAMM execution within the transaction flow.

## Impact Explanation

**Affected Assets**: User tokens deposited to TWAMM pools, liquidity positions

**Damage Severity**:
- Users experience unexpected transaction reverts when deposits should succeed based on their documented parameter constraints, losing gas fees
- Users who over-approve tokens pay amounts exceeding their stated "maximum" (10-20%+ more of one token depending on TWAMM price movement)
- All deposits to TWAMM pools with pending virtual orders are affected (normal operating state for active TWAMM)
- Users cannot adequately protect themselves as price change occurs deterministically after parameter validation but before execution

**User Impact**: Every user attempting to deposit liquidity to TWAMM pools when virtual orders are pending

**Trigger Conditions**: Automatic on any deposit operation when TWAMM has pending virtual orders to execute (common scenario)

## Likelihood Explanation

**Attacker Profile**: No attacker required—this is an interface contract violation affecting normal user operations

**Preconditions**:
1. Pool uses TWAMM extension (in-scope)
2. TWAMM has pending virtual orders to execute (normal operating state for active TWAMM pools)

**Execution Complexity**: Happens automatically during normal deposit operations, no special setup required

**Economic Cost**: No additional cost—occurs during standard user deposits

**Frequency**: Every deposit to TWAMM pools when virtual orders are pending (high frequency for active pools)

**Overall Likelihood**: HIGH for TWAMM pools with active orders

**Supporting Evidence**: The test suite explicitly catches `TransferFromFailed` as expected behavior, indicating awareness of the issue without prevention.

## Recommendation

**Primary Fix (Recommended):**
Pass `maxAmount0` and `maxAmount1` into the lock and validate actual amounts against these documented maximums after `updatePosition` calculates required amounts. Add revert condition: `if (amount0 > maxAmount0 || amount1 > maxAmount1) revert DepositExceedsMaxAmounts(amount0, amount1, maxAmount0, maxAmount1);` before token transfers.

**Alternative Fix:**
Move liquidity calculation inside the lock after extension hooks execute, ensuring price reads and amount calculations occur at the same pool state, or recalculate liquidity based on post-hook price before calling `updatePosition`.

## Notes

This vulnerability is specific to pools using the TWAMM extension (in-scope, protocol-developed). The issue stems from the architectural decision to execute extension hooks that change pool state between price reading and position updates, combined with failure to enforce the documented "Maximum amount" interface contract.

The README mentions "TWAMM execution price degradation" (lines 52-62) regarding TWAMM order execution quality, not the impact of TWAMM execution on other operations. This is a distinct issue not covered by known issues.

The documented interface explicitly promises these are "Maximum" amounts, creating a contract with users that the implementation fails to honor. Users have no other mechanism to protect against paying more than their stated maximum when TWAMM deterministically changes the price during transaction execution.

### Citations

**File:** src/interfaces/IPositions.sol (L43-44)
```text
    /// @param maxAmount0 Maximum amount of token0 to deposit
    /// @param maxAmount1 Maximum amount of token1 to deposit
```

**File:** src/base/BasePositions.sol (L80-83)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
```

**File:** src/base/BasePositions.sol (L94-94)
```text
            lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity)),
```

**File:** src/base/BasePositions.sol (L249-254)
```text
            uint128 amount0 = uint128(balanceUpdate.delta0());
            uint128 amount1 = uint128(balanceUpdate.delta1());

            // Use multi-token payment for ERC20-only pools, fall back to individual payments for native token pools
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
```

**File:** src/Core.sol (L367-371)
```text
        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
```

**File:** src/Core.sol (L378-379)
```text
            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);
```

**File:** src/extensions/TWAMM.sol (L456-477)
```text
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

**File:** src/extensions/TWAMM.sol (L656-656)
```text
        lockAndExecuteVirtualOrders(poolKey);
```
