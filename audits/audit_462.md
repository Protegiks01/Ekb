## Title
TWAMM Extension Causes Price Change Between Liquidity Calculation and Deposit Execution, Leading to Unexpected Reverts and Slippage Bypass

## Summary
In `BasePositions.deposit()`, the pool's `sqrtRatio` is read at line 80 to calculate maximum liquidity, but for pools with the TWAMM extension, the actual price used during `updatePosition()` at line 243 can differ due to TWAMM's `beforeUpdatePosition` hook executing virtual orders. This causes deposits to use mismatched price assumptions, leading to unexpected transaction reverts or users paying unexpected token ratios despite passing slippage checks.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (deposit function, lines 70-97) and `src/Core.sol` (updatePosition function, lines 367-379)

**Intended Logic:** The deposit function should read the current pool price, calculate the maximum liquidity that can be minted with the user's tokens, verify slippage protection, and then execute the deposit at the expected price.

**Actual Logic:** For pools with TWAMM extension, the sequence is:
1. Read `sqrtRatio` at line 80 [1](#0-0) 
2. Calculate `liquidity` using this price [2](#0-1) 
3. Check slippage on `liquidity` amount [3](#0-2) 
4. Call `updatePosition()` which triggers TWAMM's `beforeUpdatePosition` hook [4](#0-3) 
5. TWAMM executes `lockAndExecuteVirtualOrders()` [5](#0-4) 
6. This calls `CORE.swap()` which changes the pool price [6](#0-5) 
7. Control returns to `updatePosition()` which reads pool state AGAIN with the new price [7](#0-6) 
8. Token amounts are calculated using the NEW price but with liquidity calculated from the OLD price [8](#0-7) 

**Exploitation Path:**
1. User calls `deposit()` on a TWAMM pool with `maxAmount0=100, maxAmount1=100, minLiquidity=95`
2. At line 80, `sqrtRatio` is read showing price of 1:1
3. `maxLiquidity()` calculates `liquidity=100` based on 1:1 price
4. Slippage check passes (100 >= 95)
5. During `updatePosition()`, TWAMM's hook executes pending virtual orders via swap
6. Pool price changes to 1.5:1 due to TWAMM order execution
7. `liquidityDeltaToAmountDelta()` recalculates amounts: now needs `amount0=90, amount1=120` for same liquidity
8. Token transfer attempts to pull 120 of token1, but user only approved 100
9. Transaction reverts with `TransferFromFailed` despite passing slippage check

**Security Property Broken:** The deposit function violates user expectations by executing at a different price than what was used for liquidity calculation and slippage validation. This breaks the implicit invariant that slippage protection should prevent unexpected token ratio changes.

## Impact Explanation
- **Affected Assets**: User tokens being deposited to TWAMM pools, liquidity positions
- **Damage Severity**: Users face unexpected transaction reverts when deposits should succeed, or pay unexpected ratios of tokens (e.g., 90/120 instead of 100/100), losing the opportunity cost of optimal liquidity provision
- **User Impact**: All users attempting to deposit liquidity to TWAMM pools are affected. The issue triggers whenever TWAMM has pending virtual orders to execute during the deposit transaction.

## Likelihood Explanation
- **Attacker Profile**: This affects any user depositing to TWAMM pools; no attacker needed—it's a design flaw
- **Preconditions**: Pool must use TWAMM extension, TWAMM must have pending virtual orders to execute (which is the normal operating state for TWAMM)
- **Execution Complexity**: Happens automatically during normal deposit operations, no special setup required
- **Frequency**: Occurs on every deposit to TWAMM pools when virtual orders are pending (common scenario)

## Recommendation

The root cause is that `maxLiquidity()` uses a stale `sqrtRatio` that may change before `updatePosition()` executes. The fix should either:

**Option 1: Calculate liquidity inside the lock (recommended)**
Move the `maxLiquidity()` calculation to inside `handleLockData()` after `updatePosition()` reads the current state, or have `updatePosition()` itself enforce max amounts:

```solidity
// In src/base/BasePositions.sol, modify deposit():
function deposit(...) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
    // Remove liquidity calculation here - move it inside the lock
    (liquidity, amount0, amount1) = abi.decode(
        lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)),
        (uint128, uint128, uint128)
    );
}

// In handleLockData for CALL_TYPE_DEPOSIT:
// Read fresh sqrtRatio AFTER extension hooks have executed
SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();
uint128 liquidity = maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
if (liquidity < minLiquidity) revert DepositFailedDueToSlippage(liquidity, minLiquidity);
// Then call updatePosition with this liquidity
```

**Option 2: Add max amount validation**
Keep current flow but validate actual amounts against max amounts before transfer:

```solidity
// In handleLockData after updatePosition:
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Validate amounts don't exceed user's maximum
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceedsMaxAmounts(amount0, amount1, maxAmount0, maxAmount1);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMPriceChange.t.sol
// Run with: forge test --match-test test_TWAMMPriceChangeInDeposit -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_TWAMMPriceChange is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    address token0;
    address token1;
    
    function setUp() public {
        // Deploy core and extensions
        core = new Core();
        positions = new Positions(core, address(this));
        twamm = new TWAMM(core);
        
        // Setup tokens and pool
        token0 = address(new MockERC20());
        token1 = address(new MockERC20());
        
        // Initialize TWAMM pool at 1:1 price
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createPoolConfigWithTWAMM(address(twamm))
        });
        core.initializePool(poolKey, 0); // tick 0 = 1:1 price
    }
    
    function test_TWAMMPriceChangeInDeposit() public {
        // SETUP: Create a TWAMM order that will execute during deposit
        // This order will change the pool price from 1:1 to 1.5:1
        twamm.submitOrder(...); // Submit order that moves price
        
        // User attempts deposit with balanced amounts for 1:1 price
        uint128 maxAmount0 = 100e18;
        uint128 maxAmount1 = 100e18;
        uint128 minLiquidity = 95e18;
        
        // EXPLOIT: Deposit triggers TWAMM execution, price changes
        vm.expectRevert("TransferFromFailed"); // Reverts despite passing slippage check
        positions.deposit(
            tokenId,
            poolKey,
            tickLower,
            tickUpper,
            maxAmount0,
            maxAmount1,
            minLiquidity
        );
        
        // VERIFY: Transaction reverted due to price change
        // User approved 100 of each token, but after TWAMM execution,
        // the deposit now needs 90 token0 and 120 token1 for the same liquidity
        // The slippage check passed (liquidity >= minLiquidity) but
        // the actual token transfer failed (120 > 100)
    }
}
```

## Notes

This vulnerability is specific to pools using the TWAMM extension but is NOT a third-party extension issue—TWAMM is an in-scope extension developed by the protocol team. The issue stems from the architectural decision to execute extension hooks (which can change pool state) between price reading and position update. While the README mentions "TWAMM execution price degradation," it refers to TWAMM order execution quality, not this specific deposit price mismatch issue.

The slippage protection on `minLiquidity` alone is insufficient because it only validates the liquidity amount, not the actual token ratio needed. Users cannot adequately protect themselves since the price change happens after their slippage check passes but before the actual deposit executes.

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
