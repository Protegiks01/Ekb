# Audit Report

## Title
TWAMM Extension Causes Price Change Between Liquidity Calculation and Deposit Execution, Leading to Unexpected Reverts and Slippage Bypass

## Summary
The `deposit()` function in BasePositions reads the pool price and calculates liquidity outside the lock, but TWAMM's `beforeUpdatePosition` hook executes virtual orders that change the price before token amounts are calculated, causing users to either experience unexpected transaction reverts or pay significantly different token ratios than validated by their slippage checks.

## Impact
**Severity**: Medium

Users attempting to deposit liquidity to TWAMM pools face two critical issues: (1) transactions revert with `TransferFromFailed` despite passing slippage validation when users approve exact maxAmount values, causing gas loss and failed deposits, or (2) users who over-approve tokens pay substantially more than intended (potentially 10-20%+ more of one token) as the slippage protection on `minLiquidity` does not protect against token ratio changes induced by TWAMM virtual order execution between price validation and deposit execution.

## Finding Description

**Location:** `src/base/BasePositions.sol` (deposit function, lines 70-97), `src/Core.sol` (updatePosition function, lines 367-379)

**Intended Logic:**
The deposit function should calculate maximum liquidity based on current price, validate slippage protection, and execute the deposit at the expected price with the validated token amounts.

**Actual Logic:**
The critical flaw is that `maxAmount0` and `maxAmount1` are used to calculate liquidity outside the lock but are not passed into the lock or validated against actual amounts after TWAMM execution changes the price.

**Execution Flow:**

1. **Price Read Outside Lock**: At line 80, `sqrtRatio` is read from pool state [1](#0-0) 

2. **Liquidity Calculation**: Lines 82-83 calculate liquidity using this price and maxAmounts [2](#0-1) 

3. **Slippage Validation**: Lines 85-87 validate only that liquidity meets minimum [3](#0-2) 

4. **Lock Called Without maxAmounts**: Line 94 encodes only the calculated liquidity value, NOT the maxAmount parameters [4](#0-3) 

5. **Extension Hook Executes**: Inside `updatePosition`, the TWAMM extension's `beforeUpdatePosition` hook is called BEFORE reading pool state [5](#0-4) 

6. **TWAMM Execution**: The hook calls `lockAndExecuteVirtualOrders` [6](#0-5)  which executes pending virtual orders via swaps [7](#0-6)  changing the pool price

7. **Price Read After Hook**: Pool state is read AGAIN with the new post-TWAMM price [8](#0-7) 

8. **Amount Calculation at New Price**: Token amounts are calculated using the NEW price but with liquidity calculated from the OLD price [9](#0-8) 

9. **Unvalidated Transfers**: The calculated amounts are transferred without checking against maxAmount0 or maxAmount1 [10](#0-9) 

**Exploitation Path:**

1. Pool with TWAMM extension has pending virtual orders (normal operating state)
2. User calls `deposit(id, poolKey, tickLower, tickUpper, maxAmount0=100, maxAmount1=100, minLiquidity=95)`
3. Current pool price is 1:1, liquidity calculated as 100
4. Slippage check passes (100 ≥ 95)
5. During `updatePosition`, TWAMM executes virtual orders, changing price to 1.2:1
6. System now needs amount0=95, amount1=110 for liquidity=100 at new price
7. If user approved exactly 100 of each: transfer fails with `TransferFromFailed` despite passing slippage check
8. If user over-approved: transfer succeeds but user pays 110 instead of expected 100 (10% more)

**Security Property Broken:**
The deposit function violates the implicit guarantee that `maxAmount0` and `maxAmount1` represent maximum token amounts the user will pay. The slippage protection on `minLiquidity` is insufficient as it only validates the liquidity quantity, not the token ratio required to achieve that liquidity.

## Impact Explanation

**Affected Assets**: User tokens being deposited to TWAMM pools, liquidity positions

**Damage Severity**:
- Users experience unexpected transaction reverts when deposits should succeed based on slippage validation, losing gas fees and missing liquidity provision opportunities
- Users who over-approve tokens pay substantially more than intended (10-20%+ more of one token depending on price movement)
- All deposits to TWAMM pools with pending virtual orders are affected (normal operating state)

**User Impact**: Every user attempting to deposit liquidity to TWAMM pools when virtual orders are pending

**Trigger Conditions**: Automatic on any deposit operation when TWAMM has pending virtual orders to execute

## Likelihood Explanation

**Attacker Profile**: No attacker required—this is a design flaw affecting normal user operations

**Preconditions**:
1. Pool uses TWAMM extension (in-scope)
2. TWAMM has pending virtual orders to execute (normal operating state for TWAMM)

**Execution Complexity**: Happens automatically during normal deposit operations, no special setup required

**Economic Cost**: No additional cost—occurs during standard user deposits

**Frequency**: Every deposit to TWAMM pools when virtual orders are pending (common scenario for active TWAMM pools)

**Overall Likelihood**: HIGH for TWAMM pools with active orders

## Recommendation

**Primary Fix (Recommended):**
Pass `maxAmount0` and `maxAmount1` into the lock and validate actual amounts against these maxima after `updatePosition` calculates the required amounts:

```solidity
// In src/base/BasePositions.sol, line 94:
// CURRENT: lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity))
// FIXED: Include maxAmounts in encoded data
lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity, maxAmount0, maxAmount1))

// In handleLockData after line 250:
// Add validation before transfers
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceedsMaxAmounts(amount0, amount1, maxAmount0, maxAmount1);
}
```

**Alternative Fix:**
Move liquidity calculation inside the lock after extension hooks execute:

```solidity
// In deposit(), pass maxAmounts instead of pre-calculated liquidity
lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity))

// In handleLockData, call updatePosition first to let TWAMM execute
// Then read fresh pool state and calculate liquidity
// Then call updatePosition with the freshly calculated liquidity
```

## Notes

This vulnerability is specific to pools using the TWAMM extension, which is an in-scope extension developed by the protocol team (not third-party). The issue stems from the architectural decision to execute extension hooks (which can change pool state) between price reading and position updates.

The README mentions "TWAMM execution price degradation" (lines 52-62), but this refers to TWAMM order execution quality, not the impact of TWAMM execution on deposit operations. This is a distinct issue not covered by known issues.

The slippage protection on `minLiquidity` alone is insufficient because it only validates the liquidity amount, not the actual token ratio needed. Users cannot adequately protect themselves since the price change happens after their slippage check passes but before deposit execution, and the maxAmount parameters are not enforced at the critical point.

### Citations

**File:** src/base/BasePositions.sol (L80-80)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();
```

**File:** src/base/BasePositions.sol (L82-83)
```text
        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
```

**File:** src/base/BasePositions.sol (L85-87)
```text
        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
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

**File:** src/Core.sol (L367-368)
```text
        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);
```

**File:** src/Core.sol (L371-371)
```text
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
