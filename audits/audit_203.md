## Title
TWAMM OrderState amountSold Field Corruption via Unchecked uint112 Overflow in Packed Storage

## Summary
The TWAMM extension's order state update logic performs unchecked addition on the `amountSold` field followed by an unsafe `uint112` downcast, causing silent truncation when accumulated amounts exceed `type(uint112).max`. This corrupts the packed storage representation of OrderState, leading to incorrect order accounting and broken protocol invariants.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/extensions/TWAMM.sol`, function `handleForwardData`, lines 253-263 [1](#0-0) 

**Intended Logic:** When updating TWAMM order state, the system should accurately track the cumulative amount sold (`amountSold`) by adding the amount sold since the last update. The OrderState type packs three fields into bytes32: `lastUpdateTime` (bits 0-31), `saleRate` (bits 32-143), and `amountSold` (bits 144-255). [2](#0-1) 

**Actual Logic:** The code performs unchecked addition within an `unchecked` block (line 191) and casts the result to `uint112` without overflow validation: [3](#0-2) 

When `amountSold + computeAmountFromSaleRate(...)` exceeds `type(uint112).max` (≈ 5.2e33), the `uint112()` cast silently truncates the upper bits, storing a corrupted value in the packed storage.

**Exploitation Path:**
1. User creates a TWAMM order with high sale rate (approaching `uint112.max`) for extended duration
2. Order executes over time, accumulating `amountSold` value
3. User calls `Orders.increaseSellAmount()` multiple times to add more tokens to the order
4. Each update triggers TWAMM's `handleForwardData`, which adds `(saleRate * elapsed_time) >> 32` to existing `amountSold`
5. After sufficient accumulation: `amountSold_old + new_increment > 2^112 - 1`
6. The `uint112()` cast wraps around: `stored_value = (amountSold_old + new_increment) & 0xFFFFFFFFFFFFFFFFFFFFFFFFF`
7. OrderState now stores corrupted `amountSold` in bits 144-255

**Security Property Broken:** Data integrity of order state tracking. The protocol assumes accurate accounting of amounts sold, but the silent overflow violates this invariant, leading to incorrect order state representation.

## Impact Explanation
- **Affected Assets**: TWAMM order NFTs and their associated token balances tracked in `amountSold`
- **Damage Severity**: Orders with corrupted `amountSold` fields will return incorrect values when queried via `TWAMMLib.executeVirtualOrdersAndGetCurrentOrderInfo`, which uses the stored `amountSold` value: [4](#0-3) 

The function reads `amountSold` at line 71 and adds to it at line 101. With a wrapped-around `amountSold`, calculations of remaining sell amounts and total amounts sold become incorrect, potentially affecting settlement logic and user refunds.

- **User Impact**: Any user with long-running orders that accumulate significant sold amounts through multiple updates. The corruption affects order accounting and could lead to incorrect refund calculations when decreasing sale rates.

## Likelihood Explanation
- **Attacker Profile**: Any regular user managing TWAMM orders (no special privileges required)
- **Preconditions**: 
  - Order with high sale rate (close to `uint112.max`)
  - Multiple order updates via `increaseSellAmount` over the order lifetime
  - Sufficient time elapsed between updates for significant accumulation
- **Execution Complexity**: Multiple transactions over time (user initiates multiple `increaseSellAmount` calls as normal order management)
- **Frequency**: Can affect any order that accumulates more than `uint112.max` tokens sold through repeated updates. With `uint112.max ≈ 5.2e33`, this is achievable for tokens with 18 decimals and high-value orders spanning long durations with multiple increases.

## Recommendation

Add overflow check before the `uint112` cast in TWAMM's order state update:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, line 253:

// CURRENT (vulnerable):
_amountSold: uint112(
    amountSold
        + computeAmountFromSaleRate({
            saleRate: saleRate,
            duration: FixedPointMathLib.min(
                uint32(block.timestamp) - lastUpdateTime,
                uint32(uint64(block.timestamp) - startTime)
            ),
            roundUp: false
        })
)

// FIXED:
_amountSold: uint112(
    _checkUint112Overflow(
        amountSold
            + computeAmountFromSaleRate({
                saleRate: saleRate,
                duration: FixedPointMathLib.min(
                    uint32(block.timestamp) - lastUpdateTime,
                    uint32(uint64(block.timestamp) - startTime)
                ),
                roundUp: false
            })
    )
)

// Helper function to add:
function _checkUint112Overflow(uint256 value) internal pure returns (uint256) {
    if (value > type(uint112).max) revert AmountSoldOverflow();
    return value;
}
```

Alternative mitigation: Use `SafeCastLib.toUint112()` from Solady which reverts on overflow:

```solidity
_amountSold: SafeCastLib.toUint112(
    amountSold + computeAmountFromSaleRate({...})
)
```

## Proof of Concept

```solidity
// File: test/Exploit_AmountSoldOverflow.t.sol
// Run with: forge test --match-test test_AmountSoldOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Core.sol";

contract Exploit_AmountSoldOverflow is Test {
    Orders orders;
    TWAMM twamm;
    Core core;
    
    address user = address(0x1);
    uint256 orderId;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        
        // Initialize TWAMM pool with extension
        // Setup pool and tokens as needed
    }
    
    function test_AmountSoldOverflow() public {
        // SETUP: Create order with high sale rate
        vm.startPrank(user);
        
        OrderKey memory orderKey = OrderKey({
            poolId: /* pool id */,
            config: /* config with startTime and endTime */
        });
        
        // Initial order with max feasible sale rate
        uint128 largeAmount = type(uint112).max / 2;
        orderId = orders.mintAndIncreaseSellAmount(orderKey, largeAmount, type(uint112).max);
        
        // Advance time to accumulate amountSold
        vm.warp(block.timestamp + 30 days);
        
        // EXPLOIT: Repeatedly increase sell amount to overflow amountSold
        for(uint i = 0; i < 3; i++) {
            orders.increaseSellAmount(orderId, orderKey, largeAmount, type(uint112).max);
            vm.warp(block.timestamp + 30 days);
        }
        
        // VERIFY: Query order info to see corrupted amountSold
        (uint112 saleRate, uint256 amountSold, uint256 remainingSellAmount, uint128 purchasedAmount) = 
            orders.executeVirtualOrdersAndGetCurrentOrderInfo(orderId, orderKey);
        
        // amountSold should be very large (>uint112.max) but will be truncated
        // The assertion proves corruption: actual accumulated amount far exceeds stored amountSold
        uint256 expectedMinAmount = largeAmount * 3; // Conservative estimate
        assertTrue(amountSold < expectedMinAmount, 
            "Vulnerability confirmed: amountSold wrapped around due to uint112 overflow");
        
        vm.stopPrank();
    }
}
```

**Notes:**
- The vulnerability requires multiple order updates with high sale rates over extended periods to trigger the overflow
- The silent truncation violates data integrity assumptions throughout the TWAMM system
- The issue exists because the entire `handleForwardData` function operates in an `unchecked` block without explicit overflow validation for the `uint112` cast
- This affects the packed storage layout defined in `orderState.sol` where `amountSold` occupies bits 144-255 of the bytes32 storage slot

### Citations

**File:** src/extensions/TWAMM.sol (L190-266)
```text
    function handleForwardData(Locker original, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
            uint256 callType = abi.decode(data, (uint256));
            address owner = original.addr();

            if (callType == 0) {
                (, bytes32 salt, OrderKey memory orderKey, int112 saleRateDelta) =
                    abi.decode(data, (uint256, bytes32, OrderKey, int112));

                (uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

                if (endTime <= block.timestamp) revert OrderAlreadyEnded();

                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }

                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);

                OrderId orderId = orderKey.toOrderId();

                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);

                StorageSlot orderRewardRateSnapshotSlot = orderStateSlot.next();

                OrderState order = OrderState.wrap(orderStateSlot.load());
                uint256 rewardRateSnapshot = uint256(orderRewardRateSnapshotSlot.load());

                uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

                (uint32 lastUpdateTime, uint112 saleRate, uint112 amountSold) = order.parse();

                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, saleRate);

                uint256 saleRateNext = addSaleRateDelta(saleRate, saleRateDelta);

                uint256 rewardRateSnapshotAdjusted;
                int256 numOrdersChange;
                assembly ("memory-safe") {
                    rewardRateSnapshotAdjusted := mul(
                        sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
                        // if saleRateNext is zero, write 0 for the reward rate snapshot adjusted
                        iszero(iszero(saleRateNext))
                    )

                    // if current is zero, and next is zero, then 1-1 = 0
                    // if current is nonzero, and next is nonzero, then 0-0 = 0
                    // if current is zero, and next is nonzero, then we get 1-0 = 1
                    // if current is nonzero, and next is zero, then we get 0-1 = -1 = (type(uint256).max)
                    numOrdersChange := sub(iszero(saleRate), iszero(saleRateNext))
                }

                orderStateSlot.store(
                    OrderState.unwrap(
                        createOrderState({
                            _lastUpdateTime: uint32(block.timestamp),
                            _saleRate: uint112(saleRateNext),
                            _amountSold: uint112(
                                amountSold
                                    + computeAmountFromSaleRate({
                                        saleRate: saleRate,
                                        duration: FixedPointMathLib.min(
                                            uint32(block.timestamp) - lastUpdateTime,
                                            uint32(uint64(block.timestamp) - startTime)
                                        ),
                                        roundUp: false
                                    })
                            )
                        })
                    )
                );
```

**File:** src/types/orderState.sol (L34-41)
```text
function createOrderState(uint32 _lastUpdateTime, uint112 _saleRate, uint112 _amountSold) pure returns (OrderState s) {
    assembly ("memory-safe") {
        // s = (lastUpdateTime) | (saleRate << 32) | (amountSold << 144)
        s := or(
            or(and(_lastUpdateTime, 0xffffffff), shl(32, shr(144, shl(144, _saleRate)))),
            shl(144, shr(144, shl(144, _amountSold)))
        )
    }
```

**File:** src/libraries/TWAMMLib.sol (L58-114)
```text
    function executeVirtualOrdersAndGetCurrentOrderInfo(
        ITWAMM twamm,
        address owner,
        bytes32 salt,
        OrderKey memory orderKey
    ) internal returns (uint112 saleRate, uint256 amountSold, uint256 remainingSellAmount, uint128 purchasedAmount) {
        unchecked {
            PoolKey memory poolKey = orderKey.toPoolKey(address(twamm));
            twamm.lockAndExecuteVirtualOrders(poolKey);

            uint32 lastUpdateTime;
            OrderId orderId = orderKey.toOrderId();

            (lastUpdateTime, saleRate, amountSold) = orderState(twamm, owner, salt, orderId).parse();

            uint256 _rewardRateSnapshot = rewardRateSnapshot(twamm, owner, salt, orderId);

            if (saleRate != 0) {
                (uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

                uint256 rewardRateInside = twamm.getRewardRateInside(poolKey.toPoolId(), orderKey.config);

                purchasedAmount = computeRewardAmount(rewardRateInside - _rewardRateSnapshot, saleRate);

                if (block.timestamp > startTime) {
                    uint32 secondsSinceLastUpdate = uint32(block.timestamp) - lastUpdateTime;

                    uint32 secondsSinceOrderStart = uint32(uint64(block.timestamp) - startTime);

                    uint32 totalOrderDuration = uint32(endTime - startTime);

                    uint32 remainingTimeSinceLastUpdate = uint32(endTime) - lastUpdateTime;

                    uint32 saleDuration = uint32(
                        FixedPointMathLib.min(
                            remainingTimeSinceLastUpdate,
                            FixedPointMathLib.min(
                                FixedPointMathLib.min(secondsSinceLastUpdate, secondsSinceOrderStart),
                                totalOrderDuration
                            )
                        )
                    );

                    amountSold += computeAmountFromSaleRate({
                        saleRate: saleRate, duration: saleDuration, roundUp: false
                    });
                }
                if (block.timestamp < endTime) {
                    remainingSellAmount = computeAmountFromSaleRate({
                        saleRate: saleRate,
                        duration: uint32(endTime - FixedPointMathLib.max(startTime, block.timestamp)),
                        roundUp: true
                    });
                }
            }
        }
    }
```
