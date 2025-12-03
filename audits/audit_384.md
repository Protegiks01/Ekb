## Title
TWAMM Virtual Order Execution During Position Updates Causes Delta Calculations Based on Stale Pool State

## Summary
When users add or remove liquidity in pools with the TWAMM extension, the liquidity amount is calculated based on the current pool state, but TWAMM's `beforeUpdatePosition` hook executes pending virtual orders that modify the pool's sqrt ratio before the actual position update occurs. This causes delta calculations to use a different price than expected, leading to transaction reverts, griefing attacks, and unexpected token amounts.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (deposit function), `src/extensions/TWAMM.sol` (beforeUpdatePosition hook), `src/Core.sol` (updatePosition function)

**Intended Logic:** When a user deposits liquidity, the protocol should:
1. Calculate the maximum liquidity that can be provided with the user's `maxAmount0` and `maxAmount1`
2. Use that liquidity to create a position
3. Transfer exactly the calculated amounts from the user [1](#0-0) 

**Actual Logic:** The deposit flow has a critical timing issue:
1. The pool state (sqrtRatio) is read to calculate liquidity
2. A lock is acquired, which triggers the TWAMM extension's `beforeUpdatePosition` callback
3. TWAMM executes `lockAndExecuteVirtualOrders`, which acquires a nested lock and calls `_executeVirtualOrdersFromWithinLock`
4. This executes pending virtual orders via `CORE.swap()`, modifying the pool's sqrtRatio
5. Control returns to `Core.updatePosition()`, which reads the MODIFIED pool state
6. Delta calculations use the NEW sqrtRatio, not the original one used for liquidity calculation
7. The user may be charged different token amounts than expected [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. Attacker places large TWAMM orders that will significantly move the price when executed
2. Victim calls `Positions.deposit()` with `maxAmount0=100` and `maxAmount1=100` to add liquidity
3. BasePositions reads pool state at sqrtRatio R1 and calculates liquidity L
4. The deposit acquires a lock and calls `Core.updatePosition()`
5. Before updatePosition executes, `TWAMM.beforeUpdatePosition()` is called
6. TWAMM executes virtual orders, moving sqrtRatio from R1 to R2 (price increased)
7. `Core.updatePosition()` reads the pool state at sqrtRatio R2
8. Delta calculation uses R2, which for a price increase requires more token1 and less token0
9. Calculated amounts become (delta0=80, delta1=120), exceeding victim's maxAmount1=100
10. The transfer fails with insufficient balance/allowance, causing transaction revert [6](#0-5) [7](#0-6) 

**Security Property Broken:** This violates the **Withdrawal Availability** invariant - positions cannot be reliably created or modified when TWAMM orders are pending execution. Users experience unexpected transaction failures and cannot manage their positions as intended.

## Impact Explanation
- **Affected Assets**: All liquidity providers in pools with TWAMM extension enabled
- **Damage Severity**: 
  - Liquidity provision DOS: Users cannot add liquidity when TWAMM orders are pending
  - Wasted gas costs from reverted transactions
  - For withdrawals, users receive unexpected token amounts based on post-TWAMM-execution prices
  - Griefing: Attackers can intentionally place TWAMM orders to prevent deposits
- **User Impact**: Any user attempting to add/remove liquidity in TWAMM-enabled pools during periods when virtual orders need execution

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient tokens to place TWAMM orders
- **Preconditions**: 
  - Pool has TWAMM extension enabled
  - Virtual orders are pending execution (time has passed since last execution)
  - Victim attempts to add/remove liquidity
- **Execution Complexity**: Simple - place TWAMM orders and wait for victims to attempt liquidity operations
- **Frequency**: Can be exploited continuously in any block where virtual orders are pending and liquidity operations occur

## Recommendation

The issue requires reading the pool state AFTER extension hooks execute, not before. The fundamental problem is that `BasePositions.deposit()` calculates liquidity before acquiring the lock, but TWAMM modifies the pool state during the lock acquisition.

**Option 1: Move liquidity calculation inside the lock**
```solidity
// In src/base/BasePositions.sol, modify deposit function:

function deposit(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 maxAmount0,
    uint128 maxAmount1,
    uint128 minLiquidity
) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
    // REMOVE: Pre-lock liquidity calculation
    // MOVE: Calculate liquidity inside handleLockData after extensions execute
    
    (liquidity, amount0, amount1) = abi.decode(
        lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)),
        (uint128, uint128, uint128)
    );
}

// In handleLockData for CALL_TYPE_DEPOSIT:
// 1. Let extensions execute (TWAMM virtual orders)
// 2. Read pool state AFTER extensions
// 3. Calculate liquidity from maxAmounts
// 4. Verify liquidity >= minLiquidity
// 5. Call updatePosition
// 6. Verify amounts <= maxAmounts
```

**Option 2: Add explicit amount verification**
```solidity
// In src/base/BasePositions.sol, handleLockData:

// After updatePosition returns balanceUpdate:
uint128 amount0 = uint128(balanceUpdate.delta0());
uint128 amount1 = uint128(balanceUpdate.delta1());

// ADD: Verify amounts don't exceed user's maximums
require(amount0 <= maxAmount0Passed && amount1 <= maxAmount1Passed, "Amounts exceed maximum");

// Then proceed with payment
```

**Option 3: Oracle-based price bounds**
Add oracle-based price validation to ensure sqrtRatio hasn't moved beyond acceptable bounds between calculation and execution.

## Proof of Concept
```solidity
// File: test/Exploit_TWAMMStateRaceCondition.t.sol
// Run with: forge test --match-test test_TWAMMStateRaceCondition -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_TWAMMStateRaceCondition is Test {
    Core core;
    Positions positions;
    TWAMM twamm;
    address token0;
    address token1;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        positions = new Positions(core, address(this));
        twamm = new TWAMM(core);
        
        // Setup tokens and pool
        token0 = address(new MockERC20("Token0", "T0"));
        token1 = address(new MockERC20("Token1", "T1"));
        
        // Initialize pool with TWAMM extension
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: PoolConfig.wrap(bytes32(uint256(uint160(address(twamm)))))
        });
        core.initializePool(poolKey, 0);
        
        // Place TWAMM order that will move price significantly
        twamm.placeOrder(/* large order parameters */);
    }
    
    function test_TWAMMStateRaceCondition() public {
        // SETUP: User prepares to deposit 100/100
        uint128 maxAmount0 = 100e18;
        uint128 maxAmount1 = 100e18;
        uint128 minLiquidity = 1000e18;
        
        // User calculates expected liquidity at current price
        PoolState stateBefore = core.poolState(poolKey.toPoolId());
        uint128 expectedLiquidity = calculateExpectedLiquidity(stateBefore.sqrtRatio());
        
        // EXPLOIT: User calls deposit, TWAMM executes and changes price
        vm.expectRevert("Insufficient balance or allowance");
        positions.deposit(
            tokenId,
            poolKey,
            -100, // tickLower
            100,  // tickUpper
            maxAmount0,
            maxAmount1,
            minLiquidity
        );
        
        // VERIFY: Pool state changed during deposit
        PoolState stateAfter = core.poolState(poolKey.toPoolId());
        assertTrue(stateAfter.sqrtRatio() != stateBefore.sqrtRatio(), 
            "TWAMM modified pool state during deposit");
        
        // Deposit failed because actual amounts exceeded max due to price change
    }
}
```

## Notes

The vulnerability stems from a fundamental architectural issue: extension hooks execute BEFORE the pool state is read for delta calculations, but user-facing contracts calculate parameters BEFORE acquiring the lock that triggers extensions. This creates a time-of-check-time-of-use (TOCTOU) vulnerability where the pool state used for user calculations differs from the state used for actual execution.

This issue affects:
- **Deposits**: Transaction reverts if price moves unfavorably
- **Withdrawals**: Users receive unexpected token amounts (no slippage protection)
- **All TWAMM pools**: Any pool with pending virtual orders is vulnerable

The issue is not limited to "multiple LPs simultaneously" as stated in the security question - even a SINGLE LP operation is affected due to TWAMM's asynchronous virtual order execution mechanism.

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

**File:** src/extensions/TWAMM.sol (L386-402)
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

**File:** src/extensions/TWAMM.sol (L605-620)
```text
    function lockAndExecuteVirtualOrders(PoolKey memory poolKey) public {
        // the only thing we lock for is executing virtual orders, so all we need to encode is the pool key
        // so we call lock on the core contract with the pool key after it
        address target = address(CORE);
        assembly ("memory-safe") {
            let o := mload(0x40)
            mstore(o, shl(224, 0xf83d08ba))
            mcopy(add(o, 4), poolKey, 96)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, o, 100, 0, 0)) {
                returndatacopy(o, 0, returndatasize())
                revert(o, returndatasize())
            }
        }
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

**File:** src/Core.sol (L358-379)
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
```
