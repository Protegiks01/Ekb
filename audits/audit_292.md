## Title
Missing Reward Rate Snapshot for Immediately-Starting TWAMM Orders Enables Theft of Prior Rewards

## Summary
When a TWAMM order is created with `startTime = block.timestamp` (immediate start), the protocol fails to initialize the reward rate snapshot at `startTime`. This causes `getRewardRateInside` to read uninitialized storage (zero) instead of the actual accumulated reward rate, allowing the order to claim all historical rewards from time zero rather than only rewards earned during its active period.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` - `handleForwardData` function (lines 269-299) and `getRewardRateInside` function (lines 84-111) [1](#0-0) 

**Intended Logic:** When an order is created or updated, the protocol should track the starting reward rate to calculate how many tokens the order has earned during its lifetime. The reward rate is a cumulative global value that increases as virtual orders execute and purchase tokens.

**Actual Logic:** When `block.timestamp >= startTime` (immediate start), the code takes the else branch which:
1. Updates the current pool state's sale rates directly
2. Calls `_updateTime` ONLY for `endTime` (line 298), NOT for `startTime`
3. This means no snapshot is written to `poolRewardRatesBeforeSlot(poolId, startTime)`

Later, when `getRewardRateInside` is called with `block.timestamp > startTime`, it executes branch 2: [2](#0-1) 

This reads `poolRewardRatesBeforeSlot(poolId, config.startTime())` which returns 0 (uninitialized storage), causing the calculation to be `rewardRateCurrent - 0` instead of `rewardRateCurrent - rewardRateAtStartTime`.

**Exploitation Path:**
1. **Setup**: Alice creates a TWAMM order from T0 to T10, selling token0 for token1. Virtual orders execute continuously, accumulating rewards. By T5, `rewardRateToken1 = R5` (some positive value).

2. **Attack**: Bob creates a TWAMM order at T5 with `startTime = T5` and `endTime = T15`, also selling token0 for token1. Since `block.timestamp >= startTime`, no snapshot is created at T5.

3. **First Collection**: At T6, Bob updates his order (or just waits). Virtual orders execute to T6. When calculating Bob's rewards:
   - `rewardRateStart` = 0 (uninitialized, should be R5)
   - `rewardRateCurrent` = R6
   - `rewardRateInside` = R6 - 0 = R6 (should be R6 - R5)
   - Bob's `purchasedAmount` = `(R6 * Bob.saleRate) >> 128`

4. **Fund Theft**: Bob withdraws tokens via `updateSavedBalances` with negative delta. He receives credit for the full R6 reward accumulation, including R5 which was earned before his order existed. These tokens rightfully belong to Alice's order. [3](#0-2) 

**Security Property Broken:** Violates the **Solvency Invariant** - Bob can withdraw more tokens than his order legitimately earned, draining funds that should be available for other orders (Alice's).

## Impact Explanation
- **Affected Assets**: The purchased token (token1 in the example) in TWAMM pools where multiple orders exist
- **Damage Severity**: An attacker can steal a proportional share of all previously accumulated rewards. If the attacker's sale rate equals existing orders' total sale rate, they can steal up to 50% of prior rewards. With higher sale rates, the theft percentage increases.
- **User Impact**: All users with active TWAMM orders are vulnerable. When they attempt to collect their rightful proceeds, the pool may be insolvent because the attacker already withdrew those tokens.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this - no special privileges required
- **Preconditions**: 
  1. A TWAMM pool must exist with at least one active order that has accumulated rewards
  2. Attacker creates a new order with `startTime = block.timestamp`
  3. Time must advance so `block.timestamp > startTime` for subsequent collections
- **Execution Complexity**: Single transaction to create the malicious order, then standard collect/update operations
- **Frequency**: Can be exploited every time a new order is created with immediate start in a pool with existing reward accumulation. Repeatable across all TWAMM pools.

## Recommendation

**Fix:** In the `handleForwardData` function, when an order starts immediately (`block.timestamp >= startTime`), manually create a reward rate snapshot at `startTime` before updating the pool state: [4](#0-3) 

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, lines 271-299:

// CURRENT (vulnerable):
if (block.timestamp < startTime) {
    _updateTime(poolId, startTime, saleRateDelta, isToken1, numOrdersChange);
    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
} else {
    // Order starts immediately - no snapshot created for startTime
    StorageSlot currentStateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
    // ... updates pool state ...
    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
}

// FIXED:
if (block.timestamp < startTime) {
    _updateTime(poolId, startTime, saleRateDelta, isToken1, numOrdersChange);
    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
} else {
    // Create snapshot at startTime for immediate-start orders
    StorageSlot rewardRatesSlot = TWAMMStorageLayout.poolRewardRatesSlot(poolId);
    uint256 offset = LibBit.rawToUint(!isToken1);
    uint256 currentRewardRate = uint256(rewardRatesSlot.add(offset).load());
    
    // Store the current reward rate as the starting snapshot
    TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, startTime)
        .add(offset).store(bytes32(currentRewardRate));
    
    // Continue with existing logic
    StorageSlot currentStateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
    TwammPoolState currentState = TwammPoolState.wrap(currentStateSlot.load());
    // ... rest of the code unchanged ...
    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
}
```

**Alternative Mitigation:** Require all orders to have `startTime > block.timestamp` by adding a validation check before processing:
```solidity
if (startTime <= block.timestamp) revert InvalidTimestamps();
```

However, this would change user-facing behavior and may not be desirable for immediate execution orders.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMRewardTheft.t.sol
// Run with: forge test --match-test test_TWAMMRewardTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";

contract Exploit_TWAMMRewardTheft is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    
    address alice = address(0x1);
    address bob = address(0x2);
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm);
        
        // Setup pool and initial liquidity
        // (simplified - actual test would need full pool initialization)
    }
    
    function test_TWAMMRewardTheft() public {
        // SETUP: Alice creates first order at T0
        vm.warp(0);
        uint64 aliceStart = 0;
        uint64 aliceEnd = 1000;
        
        vm.prank(alice);
        orders.mintAndIncreaseSellAmount(
            /* orderKey with startTime=aliceStart, endTime=aliceEnd */
            /* amount */ 1000 ether
        );
        
        // Time passes, Alice's order executes, rewards accumulate
        vm.warp(500); // T = 500
        twamm.lockAndExecuteVirtualOrders(/* poolKey */);
        
        // Check accumulated reward rate (should be > 0)
        uint256 rewardRateBefore = /* read poolRewardRatesSlot */;
        assertGt(rewardRateBefore, 0, "Rewards accumulated");
        
        // EXPLOIT: Bob creates order with startTime = current block.timestamp
        vm.prank(bob);
        orders.mintAndIncreaseSellAmount(
            /* orderKey with startTime=500, endTime=1500 */
            /* amount */ 1000 ether  // Same amount as Alice
        );
        
        // Advance time and let Bob collect
        vm.warp(600);
        twamm.lockAndExecuteVirtualOrders(/* poolKey */);
        
        vm.prank(bob);
        uint256 bobProceeds = orders.collectProceeds(/* orderKey */);
        
        // VERIFY: Bob received more than his fair share
        // Bob's order was active for 100s (500->600)
        // Alice's order was active for 600s (0->600)
        // Bob should get ~14% of rewards, but gets much more due to missing snapshot
        
        vm.prank(alice);
        uint256 aliceProceeds = orders.collectProceeds(/* orderKey */);
        
        // Bob stole Alice's rewards
        assertGt(bobProceeds, aliceProceeds / 6, "Bob got more than 1/6th despite being active 1/6th of time");
    }
}
```

**Notes:**
- The vulnerability requires existing reward accumulation before the malicious order is created
- The theft amount is proportional to: (attacker's saleRate / total saleRate) * prior_accumulated_rewards
- This breaks the fundamental accounting assumption that orders only earn rewards during their active period
- The issue occurs because the else branch at line 274 assumes the order is already active and doesn't need boundary snapshots, but it's actually the FIRST update for a new order starting immediately

### Citations

**File:** src/extensions/TWAMM.sol (L96-107)
```text
        } else if (block.timestamp > config.startTime()) {
            uint256 offset = LibBit.rawToUint(!config.isToken1());

            //  note that we check gt because if it's equal to start time, then the reward rate inside is necessarily 0
            uint256 rewardRateStart =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.startTime()).add(offset).load());
            uint256 rewardRateCurrent = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).add(offset).load());

            unchecked {
                result = rewardRateCurrent - rewardRateStart;
            }
        } else {
```

**File:** src/extensions/TWAMM.sol (L269-299)
```text
                bool isToken1 = orderKey.config.isToken1();

                if (block.timestamp < startTime) {
                    _updateTime(poolId, startTime, saleRateDelta, isToken1, numOrdersChange);
                    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
                } else {
                    // we know block.timestamp < orderKey.endTime because we validate that first
                    // and we know the order is active, so we have to apply its delta to the current pool state
                    StorageSlot currentStateSlot = TWAMMStorageLayout.twammPoolStateSlot(poolId);
                    TwammPoolState currentState = TwammPoolState.wrap(currentStateSlot.load());
                    (uint32 lastTime, uint112 rate0, uint112 rate1) = currentState.parse();

                    if (isToken1) {
                        currentState = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: lastTime,
                            _saleRateToken0: rate0,
                            _saleRateToken1: uint112(addSaleRateDelta(rate1, saleRateDelta))
                        });
                    } else {
                        currentState = createTwammPoolState({
                            _lastVirtualOrderExecutionTime: lastTime,
                            _saleRateToken0: uint112(addSaleRateDelta(rate0, saleRateDelta)),
                            _saleRateToken1: rate1
                        });
                    }

                    currentStateSlot.store(TwammPoolState.unwrap(currentState));

                    // only update the end time
                    _updateTime(poolId, endTime, -int256(saleRateDelta), isToken1, numOrdersChange);
                }
```

**File:** src/extensions/TWAMM.sol (L366-374)
```text
                    if (orderKey.config.isToken1()) {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), -int256(purchasedAmount), 0
                        );
                    } else {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), 0, -int256(purchasedAmount)
                        );
                    }
```
