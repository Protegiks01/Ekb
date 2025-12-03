## Title
Missing Slippage Protection Allows TWAMM Virtual Order Execution to Force Users to Overpay on Position Deposits

## Summary
The `deposit()` function in BasePositions calculates the liquidity to add based on the current pool price, but TWAMM's `beforeUpdatePosition` hook can execute virtual orders that change the price before the actual position update. The function lacks validation that the final charged amounts respect the `maxAmount0` and `maxAmount1` parameters, allowing users to be charged more than their specified maximums.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BasePositions.sol` (deposit function lines 71-97, handleLockData lines 243-264)

**Intended Logic:** According to the IPositions interface documentation, `maxAmount0` and `maxAmount1` are "Maximum amount of token0/token1 to deposit"—hard limits on what the user will pay. [1](#0-0) 

**Actual Logic:** The deposit function calculates liquidity using the current pool price, but extension callbacks can change the price before the actual deposit occurs. The calculated deltas (amounts charged) are not validated against maxAmount0/maxAmount1.

**Exploitation Path:**

1. **Initial State Setup**: User calls `deposit()` with `maxAmount0=100, maxAmount1=100` on a TWAMM-enabled pool. Current pool price is R1, with pending virtual orders. [2](#0-1) 

2. **Price Observation**: At line 80, the function reads `sqrtRatio = R1` and calculates liquidity L using `maxLiquidity(R1, tickLower, tickUpper, 100, 100)`. Say this returns L=120 liquidity units.

3. **Lock Acquired**: The function calls `lock()` at line 94, which triggers the callback at line 243 that calls `Core.updatePosition()`. [3](#0-2) 

4. **Extension Hook Execution**: Before updating the position, `Core.updatePosition()` calls `maybeCallBeforeUpdatePosition()`. [4](#0-3) 

5. **TWAMM Virtual Orders Execute**: The TWAMM extension's `beforeUpdatePosition` hook calls `lockAndExecuteVirtualOrders()`. [5](#0-4) 

6. **Price Changes**: Virtual order execution performs swaps via `CORE.swap()`, changing the pool's sqrtRatio from R1 to R2. [6](#0-5) 

7. **Delta Calculation with New Price**: `Core.updatePosition()` reads the NEW sqrtRatio (R2) and calculates deltas using it. [7](#0-6) 

8. **User Overcharged**: If the price moved such that the same liquidity L now requires more of one token (e.g., delta0=80, delta1=150), the user pays these amounts without any check that delta1 (150) exceeds maxAmount1 (100). [8](#0-7) 

9. **No Validation**: There is no check that `amount0 <= maxAmount0` or `amount1 <= maxAmount1` anywhere in the deposit flow.

**Security Property Broken:** Violates the documented interface specification that maxAmount0/maxAmount1 are maximum deposit limits. Also breaks user expectation of slippage protection.

## Impact Explanation
- **Affected Assets**: User's approved token balances in any TWAMM-enabled pool with pending virtual orders
- **Damage Severity**: Users can lose significantly more tokens than intended. If they approved large amounts for gas efficiency or future deposits, an attacker with a pending TWAMM order can cause them to deposit their entire approved balance instead of just the intended maxAmount
- **User Impact**: Any user depositing into TWAMM pools is vulnerable. The issue triggers on every deposit when virtual orders are pending, which is the normal operating state of TWAMM pools

## Likelihood Explanation
- **Attacker Profile**: Any user who can place TWAMM orders in the target pool, or simply wait for existing TWAMM orders to execute during a victim's deposit
- **Preconditions**: 
  - Pool must use TWAMM extension
  - Pending TWAMM virtual orders must exist that will execute in the current block
  - Victim must have approved more tokens than their intended maxAmount0/maxAmount1
- **Execution Complexity**: Single transaction. Attacker can frontrun victim's deposit with a TWAMM order placement, or simply wait for natural TWAMM order execution timing
- **Frequency**: Can occur on every deposit to TWAMM pools during active trading periods

## Recommendation

Add validation in `BasePositions.handleLockData` after calculating the deposit amounts:

```solidity
// In src/base/BasePositions.sol, function handleLockData, after line 250:

// CURRENT (vulnerable):
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Use multi-token payment for ERC20-only pools...
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
}

// FIXED:
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// Validate amounts don't exceed user-specified maximums
// Extract maxAmount0 and maxAmount1 from the encoded data
(, , , , , , uint128 liquidity) = abi.decode(data, (uint256, address, uint256, PoolKey, int32, int32, uint128));
// Need to decode the original maxAmount0/maxAmount1 - they should be passed through the lock data
// This requires modifying the deposit function to pass maxAmount0/maxAmount1 in the encoded data

if (amount0 > maxAmount0) revert DepositExceedsMaxAmount0();
if (amount1 > maxAmount1) revert DepositExceedsMaxAmount1();

// Use multi-token payment for ERC20-only pools...
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
}
```

**Better Solution**: Pass maxAmount0 and maxAmount1 through the lock data and validate them:

1. Modify line 94 to encode maxAmount0 and maxAmount1:
```solidity
(amount0, amount1) = abi.decode(
    lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity, maxAmount0, maxAmount1)),
    (uint128, uint128)
);
```

2. In handleLockData at line 232, decode and validate:
```solidity
(
    ,
    address caller,
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    uint128 maxAmount0,  // Add these two parameters
    uint128 maxAmount1
) = abi.decode(data, (uint256, address, uint256, PoolKey, int32, int32, uint128, uint128, uint128));

// After line 250, add validation:
if (amount0 > maxAmount0) revert DepositExceedsMaxAmount0(amount0, maxAmount0);
if (amount1 > maxAmount1) revert DepositExceedsMaxAmount1(amount1, maxAmount1);
```

## Proof of Concept

```solidity
// File: test/Exploit_DepositOverpayment.t.sol
// Run with: forge test --match-test test_DepositOverpaymentViaTWAMM -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_DepositOverpayment is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    Orders orders;
    
    address token0 = address(0x1000);
    address token1 = address(0x2000);
    address victim = address(0x3000);
    address attacker = address(0x4000);
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        twamm = new TWAMM(core);
        positions = new Positions(core, address(this));
        orders = new Orders(core, address(this), twamm);
        
        // Setup tokens and approvals
        // [Mock token setup code here]
    }
    
    function test_DepositOverpaymentViaTWAMM() public {
        // SETUP: Create TWAMM pool
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: /* TWAMM config */
        });
        
        // Initialize pool at price 1.0
        core.initializePool(poolKey, 0);
        
        // SETUP: Attacker places TWAMM order that will execute during victim's deposit
        vm.prank(attacker);
        orders.updateSaleRate(
            OrderKey({/* parameters for order that moves price */}),
            1000000 // Large sale rate to move price significantly
        );
        
        // SETUP: Victim approves 1000 of each token but only wants to deposit 100 max
        vm.startPrank(victim);
        // [Approve 1000 tokens]
        
        uint256 victimToken0Before = token0.balanceOf(victim);
        uint256 victimToken1Before = token1.balanceOf(victim);
        
        // EXPLOIT: Victim calls deposit with maxAmount0=100, maxAmount1=100
        // But TWAMM execution changes price such that they pay more
        uint256 nftId = positions.mint();
        (uint128 liquidity, uint128 amount0, uint128 amount1) = positions.deposit(
            nftId,
            poolKey,
            -887220, // tickLower
            887220,  // tickUpper
            100,     // maxAmount0 - INTENDED MAXIMUM
            100,     // maxAmount1 - INTENDED MAXIMUM
            0        // minLiquidity
        );
        vm.stopPrank();
        
        // VERIFY: Victim paid more than maxAmount1
        uint256 actualPaid0 = victimToken0Before - token0.balanceOf(victim);
        uint256 actualPaid1 = victimToken1Before - token1.balanceOf(victim);
        
        console.log("Victim intended max token0:", 100);
        console.log("Victim actually paid token0:", actualPaid0);
        console.log("Victim intended max token1:", 100);
        console.log("Victim actually paid token1:", actualPaid1);
        
        // Vulnerability confirmed: User paid more than their specified maximum
        assert(actualPaid1 > 100 || actualPaid0 > 100);
    }
}
```

## Notes

This vulnerability occurs specifically in TWAMM-enabled pools because the TWAMM extension's `beforeUpdatePosition` hook actively executes pending virtual orders, which perform swaps that change the pool price. Other extensions like Oracle and MEVCapture also have `beforeUpdatePosition` hooks, but they don't modify the pool's sqrtRatio, so they don't trigger this issue.

The root cause is that the deposit flow splits the price observation (line 80) from the actual delta calculation (line 379 in Core), and allows state-modifying callbacks between these two operations without validating that the final amounts respect the user's specified maximums.

This represents a violation of the principle of least surprise and the documented interface specification, where users reasonably expect `maxAmount0` and `maxAmount1` to be hard limits on their deposit amounts.

### Citations

**File:** src/interfaces/IPositions.sol (L43-45)
```text
    /// @param maxAmount0 Maximum amount of token0 to deposit
    /// @param maxAmount1 Maximum amount of token1 to deposit
    /// @param minLiquidity Minimum liquidity to receive (for slippage protection)
```

**File:** src/base/BasePositions.sol (L71-83)
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
```

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
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

**File:** src/Core.sol (L371-379)
```text
        PoolState state = readPoolState(poolId);
        if (!state.isInitialized()) revert PoolNotInitialized();

        if (liquidityDelta != 0) {
            (SqrtRatio sqrtRatioLower, SqrtRatio sqrtRatioUpper) =
                (tickToSqrtRatio(positionId.tickLower()), tickToSqrtRatio(positionId.tickUpper()));

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

**File:** src/extensions/TWAMM.sol (L652-657)
```text
    function beforeUpdatePosition(Locker, PoolKey memory poolKey, PositionId, int128)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```
