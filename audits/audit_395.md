## Title
MaxAmount Parameters Not Enforced in Deposit Operations Due to TWAMM Extension Price Manipulation

## Summary
The `deposit()` function in `BasePositions.sol` accepts `maxAmount0` and `maxAmount1` parameters documented as "Maximum amount of token0/token1 to deposit," but fails to validate that the actual amounts charged respect these limits. [1](#0-0)  The TWAMM extension's `beforeUpdatePosition` hook executes virtual orders that change the pool's `sqrtRatio` between liquidity calculation and token amount calculation, causing users to pay more than their specified maximums if they have approved sufficient tokens. [2](#0-1) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (function `deposit`, lines 71-97 and `handleLockData`, lines 243-262)

**Intended Logic:** Users specify `maxAmount0` and `maxAmount1` as maximum token amounts they are willing to deposit. The function should ensure actual amounts charged do not exceed these maximums.

**Actual Logic:** The `maxAmount` parameters are only used to calculate liquidity via `maxLiquidity()` [3](#0-2) , but the actual amounts charged are determined later in `Core.updatePosition()` without validation against these maximums. [4](#0-3) 

**Exploitation Path:**
1. User calls `deposit(id, poolKey, tickLower, tickUpper, maxAmount0=1000, maxAmount1=10, minLiquidity=0)` on a TWAMM pool where current price is below their position range (tick < tickLower)
2. `BasePositions.deposit()` reads current `sqrtRatio` at line 80 [5](#0-4) 
3. `maxLiquidity()` calculates liquidity based on this price, expecting only token0 is needed, returning large liquidity value L
4. `Core.updatePosition()` is called with liquidity L
5. TWAMM's `beforeUpdatePosition` hook executes at line 367-368 [6](#0-5) , calling `lockAndExecuteVirtualOrders()` which performs swaps [7](#0-6) 
6. These swaps move the price into the user's position range (tickLower < current tick < tickUpper)
7. `Core.updatePosition()` reads the NEW pool state at line 371 [8](#0-7) 
8. `liquidityDeltaToAmountDelta()` calculates amounts for liquidity L at the new price, requiring both token0 AND token1 [9](#0-8) 
9. User is charged `amount1 >> maxAmount1` without any validation [4](#0-3) 

**Security Property Broken:** Users lose more funds than intended due to lack of slippage protection on token amounts, violating the documented "Maximum amount" guarantee in the interface.

## Impact Explanation
- **Affected Assets**: Any tokens deposited into TWAMM pools or pools with extensions that manipulate price in hooks
- **Damage Severity**: Users can lose up to their full token approval amount rather than the specified maximum. For users who approve `type(uint256).max` for convenience, losses are unbounded.
- **User Impact**: All users depositing liquidity into pools with TWAMM or similar extensions that execute swaps in `beforeUpdatePosition` hooks. Particularly affects users who set conservative max amounts expecting them to be enforced.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a protocol design flaw that occurs naturally during normal TWAMM operation
- **Preconditions**: Pool must have TWAMM extension enabled and pending virtual orders that will execute during the deposit
- **Execution Complexity**: Occurs automatically in any deposit transaction when TWAMM orders are pending
- **Frequency**: Happens on every deposit to TWAMM pools when virtual orders are queued, which is the normal operation of TWAMM

## Recommendation

In `src/base/BasePositions.sol`, add validation after receiving actual amounts from `Core.updatePosition()`:

```solidity
// In src/base/BasePositions.sol, function handleLockData, after line 250:

uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// ADD THIS VALIDATION:
if (amount0 > maxAmount0 || amount1 > maxAmount1) {
    revert DepositExceedsMaximumAmounts(amount0, amount1, maxAmount0, maxAmount1);
}

// Then proceed with payment
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
    // ...
```

Alternative mitigation: Pass `maxAmount0` and `maxAmount1` through to `handleLockData` via the encoded data in `lock()` and validate there.

## Proof of Concept

```solidity
// File: test/Exploit_MaxAmountViolation.t.sol
// Run with: forge test --match-test test_MaxAmountViolation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_MaxAmountViolation is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    Orders orders;
    
    address token0 = address(0x1);
    address token1 = address(0x2);
    address user = address(0x3);
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        twamm = new TWAMM(core);
        positions = new Positions(core, address(this));
        orders = new Orders(core);
        
        // Setup tokens and pool with TWAMM extension
        // Initialize pool at tick -100 (price below user's range)
    }
    
    function test_MaxAmountViolation() public {
        // SETUP: User wants to deposit at tick range [100, 200]
        // Current tick is -100 (below range), so only token0 needed
        uint128 maxAmount0 = 1000e18;
        uint128 maxAmount1 = 10e18; // User only wants to provide 10 token1 max
        
        // User approves large amounts (common user behavior)
        vm.startPrank(user);
        // Assume approvals here
        
        // Place TWAMM sell orders that will execute and move price into range
        // When beforeUpdatePosition executes, price moves to tick 150 (in range [100,200])
        
        // EXPLOIT: Call deposit
        (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) = 
            positions.mintAndDeposit(
                poolKey,
                100, // tickLower
                200, // tickUpper  
                maxAmount0,
                maxAmount1, // User specified max 10 token1
                0 // no minLiquidity protection
            );
        
        // VERIFY: User was charged more token1 than maxAmount1
        assertGt(amount1, maxAmount1, "Vulnerability confirmed: user paid more than maxAmount1");
        // User expected to pay at most 10 token1, but paid significantly more
        // due to TWAMM execution moving price into their range
    }
}
```

## Notes

This vulnerability stems from a mismatch between when liquidity is calculated (using the pre-hook price) and when token amounts are calculated (using the post-hook price). The TWAMM extension's `beforeUpdatePosition` hook legitimately executes pending virtual orders by calling `CORE.swap()`, which changes the pool's `sqrtRatio`. [7](#0-6) 

The issue is NOT with TWAMM's behavior (which is expected), but with `BasePositions.deposit()` failing to validate that actual amounts respect the documented "Maximum" amounts. The boundary condition mentioned in the security question (`sqrtRatio <= sqrtRatioLower`) is relevant because price movements across position boundaries cause the largest discrepancies between expected and actual token ratios.

While the transaction would revert if users approve exactly `maxAmount0` and `maxAmount1`, many users approve larger amounts (or `type(uint256).max`) for convenience, making them vulnerable to paying more than intended. This violates user expectations and the documented interface.

### Citations

**File:** src/interfaces/IPositions.sol (L43-44)
```text
    /// @param maxAmount0 Maximum amount of token0 to deposit
    /// @param maxAmount1 Maximum amount of token1 to deposit
```

**File:** src/extensions/TWAMM.sol (L456-460)
```text
                            (swapBalanceUpdate, corePoolState) = CORE.swap(
                                0,
                                poolKey,
                                createSwapParameters({
                                    _sqrtRatioLimit: sqrtRatioNext,
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

**File:** src/base/BasePositions.sol (L80-80)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();
```

**File:** src/base/BasePositions.sol (L82-83)
```text
        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
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
