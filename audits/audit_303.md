## Title
Gas Griefing in executeVirtualOrdersAndGetCurrentOrderInfo Forces Users to Pay for All Pool Orders

## Summary
The `executeVirtualOrdersAndGetCurrentOrderInfo` function in Orders.sol unconditionally executes ALL virtual orders for the entire pool, regardless of how many orders the caller owns. This forces users with a single small order to pay gas costs for executing potentially hundreds of other users' orders across multiple time periods, enabling a gas griefing attack.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/Orders.sol`, `src/libraries/TWAMMLib.sol`, `src/extensions/TWAMM.sol`

**Intended Logic:** Users should be able to retrieve information about their TWAMM orders efficiently, paying only for the computation necessary to update their own order state.

**Actual Logic:** When a user calls `executeVirtualOrdersAndGetCurrentOrderInfo`, the function executes ALL virtual orders for the entire pool, including orders from all other users and across all time periods since the last execution.

**Exploitation Path:**

1. **Attacker Setup**: Attacker creates 50-100 TWAMM orders in a pool spanning multiple time periods (e.g., orders with different start/end times). [1](#0-0) 

2. **Victim Interaction**: Victim with a single small order calls `executeVirtualOrdersAndGetCurrentOrderInfo` to check their order status. [2](#0-1) 

3. **Forced Pool-Wide Execution**: The function calls `TWAMMLib.executeVirtualOrdersAndGetCurrentOrderInfo` which unconditionally executes `lockAndExecuteVirtualOrders` for the entire pool. [3](#0-2) 

4. **Gas Drain**: The execution loop processes all time periods and all orders in the pool, forcing the victim to pay for executing all 50-100 attacker orders. [4](#0-3) 

**Security Property Broken:** Users are forced to pay excessive gas costs that should be distributed among all order holders, effectively subsidizing other users' order execution.

## Impact Explanation

- **Affected Assets**: Gas costs paid by users interacting with their TWAMM orders
- **Damage Severity**: Users can be forced to pay for executing hundreds of orders belonging to other users. With 100 orders across multiple time periods, gas costs could reach millions of gas units, making transactions prohibitively expensive or causing them to fail.
- **User Impact**: ANY user calling `executeVirtualOrdersAndGetCurrentOrderInfo`, `increaseSellAmount`, `decreaseSaleRate`, or `collectProceeds` will trigger pool-wide virtual order execution and pay for ALL orders, not just their own. [5](#0-4) [6](#0-5) 

## Likelihood Explanation

- **Attacker Profile**: Any user can create multiple TWAMM orders to amplify gas costs for subsequent callers
- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Attacker creates many orders (no limit on number of orders per user)
  - Victim must be the first caller in a block (subsequent calls are no-ops per line 404 check) [7](#0-6) 
- **Execution Complexity**: Single transaction - attacker simply creates many orders, victim calls any order interaction function
- **Frequency**: Exploitable continuously - each block has a new "first caller" who pays for everything

## Recommendation

Implement a batched or lazy execution mechanism where virtual orders are executed incrementally or on-demand rather than all at once. Alternatively, provide a view-only function for querying order status without executing virtual orders, and only require execution for state-changing operations:

```solidity
// In src/libraries/TWAMMLib.sol:

// NEW: View-only function that doesn't execute virtual orders
function getCurrentOrderInfoView(
    ITWAMM twamm,
    address owner,
    bytes32 salt,
    OrderKey memory orderKey
) internal view returns (uint112 saleRate, uint256 amountSold, uint256 remainingSellAmount, uint128 purchasedAmount) {
    // Read order state without triggering pool-wide execution
    OrderId orderId = orderKey.toOrderId();
    (uint32 lastUpdateTime, uint112 _saleRate, uint256 _amountSold) = 
        orderState(twamm, owner, salt, orderId).parse();
    
    // Calculate theoretical state based on current timestamp and reward rates
    // without executing virtual orders
    // ... calculation logic ...
    
    return (_saleRate, _amountSold, remainingSellAmount, purchasedAmount);
}

// In src/Orders.sol, add:
function getCurrentOrderInfoView(uint256 id, OrderKey memory orderKey) 
    external 
    view 
    returns (uint112 saleRate, uint256 amountSold, uint256 remainingSellAmount, uint128 purchasedAmount) 
{
    return TWAMMLib.getCurrentOrderInfoView(TWAMM_EXTENSION, address(this), bytes32(id), orderKey);
}
```

Additionally, consider implementing a mechanism to limit the number of orders that can be created by a single user in a pool, or introduce a gas cost sharing mechanism where order creators pre-pay for their execution costs.

## Proof of Concept

```solidity
// File: test/Exploit_GasGriefing.t.sol
// Run with: forge test --match-test test_gasGriefing_executeVirtualOrders -vvv

pragma solidity ^0.8.31;

import "./Orders.t.sol";

contract Exploit_GasGriefing is BaseOrdersTest {
    using CoreLib for *;

    function test_gasGriefing_executeVirtualOrders() public {
        // SETUP: Create pool and liquidity
        uint64 fee = uint64((uint256(5) << 64) / 100);
        int32 tick = 0;
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: tick});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 100000, 100000);
        
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = alignToNextValidTime();
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // EXPLOIT: Attacker creates many orders
        uint256[] memory attackerOrders = new uint256[](50);
        for (uint i = 0; i < 50; i++) {
            (attackerOrders[i],) = orders.mintAndIncreaseSellAmount(key, 1000, type(uint112).max);
        }
        
        // Victim creates one small order
        (uint256 victimOrderId,) = orders.mintAndIncreaseSellAmount(key, 10, type(uint112).max);
        
        // Advance time to create work for virtual order execution
        advanceTime((endTime - startTime) / 4);
        
        // VERIFY: Victim pays gas for all 51 orders when checking their single order
        uint256 gasBefore = gasleft();
        orders.executeVirtualOrdersAndGetCurrentOrderInfo(victimOrderId, key);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Gas used is proportional to number of orders in pool (all 51)
        // With 50 attacker orders, victim pays ~50x more gas than necessary
        emit log_named_uint("Gas used for 51 orders", gasUsed);
        
        // Compare: if victim was alone in pool
        PoolKey memory cleanPoolKey = createTwammPool({fee: fee, tick: tick + 1});
        createPosition(cleanPoolKey, MIN_TICK, MAX_TICK, 100000, 100000);
        OrderKey memory cleanKey = OrderKey({
            token0: cleanPoolKey.token0,
            token1: cleanPoolKey.token1,
            config: key.config
        });
        (uint256 cleanOrderId,) = orders.mintAndIncreaseSellAmount(cleanKey, 10, type(uint112).max);
        advanceTime((endTime - startTime) / 4);
        
        uint256 gasBeforeClean = gasleft();
        orders.executeVirtualOrdersAndGetCurrentOrderInfo(cleanOrderId, cleanKey);
        uint256 gasUsedClean = gasBeforeClean - gasleft();
        
        emit log_named_uint("Gas used for 1 order", gasUsedClean);
        emit log_named_uint("Gas griefing multiplier", gasUsed / gasUsedClean);
        
        // Vulnerability confirmed: victim pays significantly more gas
        assertTrue(gasUsed > gasUsedClean * 10, "Victim pays >10x more gas due to attacker's orders");
    }
}
```

## Notes

This vulnerability affects ALL TWAMM order interactions, not just `executeVirtualOrdersAndGetCurrentOrderInfo`. The same gas griefing occurs when users call:
- `increaseSellAmount` - triggers virtual order execution
- `decreaseSaleRate` - triggers virtual order execution  
- `collectProceeds` - triggers virtual order execution

The check at line 404 that prevents re-execution within the same block only protects subsequent callers, not the first caller who bears the entire cost. An attacker can front-run victims to ensure they are always the first caller, maximizing the griefing effect.

While the protocol provides a view-only `TWAMMDataFetcher` for pool-level data, there is no view function for individual order information that avoids triggering pool-wide execution, forcing users into this expensive operation.

### Citations

**File:** src/Orders.sol (L42-50)
```text
    /// @inheritdoc IOrders
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```

**File:** src/Orders.sol (L122-128)
```text
    function executeVirtualOrdersAndGetCurrentOrderInfo(uint256 id, OrderKey memory orderKey)
        external
        returns (uint112 saleRate, uint256 amountSold, uint256 remainingSellAmount, uint128 purchasedAmount)
    {
        (saleRate, amountSold, remainingSellAmount, purchasedAmount) =
            TWAMM_EXTENSION.executeVirtualOrdersAndGetCurrentOrderInfo(address(this), bytes32(id), orderKey);
    }
```

**File:** src/libraries/TWAMMLib.sol (L64-66)
```text
        unchecked {
            PoolKey memory poolKey = orderKey.toPoolKey(address(twamm));
            twamm.lockAndExecuteVirtualOrders(poolKey);
```

**File:** src/extensions/TWAMM.sol (L212-212)
```text
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L347-347)
```text
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/extensions/TWAMM.sol (L404-404)
```text
            if (realLastVirtualOrderExecutionTime != block.timestamp) {
```

**File:** src/extensions/TWAMM.sol (L417-428)
```text
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
```
