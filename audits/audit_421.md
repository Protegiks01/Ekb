## Title
Front-Running configure() to Lock Protocol Fees in Unwanted TWAMM Orders

## Summary
The `RevenueBuybacks.configure()` function can be front-run by calling the permissionless `PositionsOwner.withdrawAndRoll()` function, which creates TWAMM orders using the old configuration parameters before the owner's configuration change takes effect. Since `RevenueBuybacks` has no mechanism to cancel orders, protocol fees become locked in potentially unwanted orders for their full duration.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (configure function), `src/PositionsOwner.sol` (withdrawAndRoll function) [1](#0-0) [2](#0-1) 

**Intended Logic:** The owner should be able to reconfigure or disable revenue buybacks by calling `configure()`, with changes taking effect immediately for future order creation. The `withdrawAndRoll()` function is designed to be permissionless to allow anyone to trigger revenue buybacks for configured tokens.

**Actual Logic:** An attacker can observe a pending `configure()` transaction in the mempool and front-run it by calling `withdrawAndRoll()`. This function:
1. Checks if both tokens are configured using the OLD state (line 53-56)
2. Withdraws accumulated protocol fees to the RevenueBuybacks contract
3. Calls `roll()` for both tokens, creating orders with OLD configuration parameters

After these orders are created, the owner's `configure()` executes, but the funds are already committed to orders using the previous (potentially undesired) parameters. Critically, RevenueBuybacks has no function to cancel orders—there is no wrapper for `Orders.decreaseSaleRate()`. [3](#0-2) 

**Exploitation Path:**
1. Owner submits `configure()` transaction to change `targetOrderDuration`, `minOrderDuration`, or `fee`, or to disable buybacks entirely (by setting both durations to 0)
2. Attacker observes the pending transaction in the mempool
3. Attacker front-runs with `withdrawAndRoll(token0, token1)` for configured token pairs
4. `withdrawAndRoll()` checks configuration (passes with old state), withdraws protocol fees, and calls `roll()`
5. `roll()` creates TWAMM orders using the OLD configuration that lasts for `targetOrderDuration` seconds (potentially hours or days)
6. The state is updated with `lastEndTime`, `lastOrderDuration`, and `lastFee` from the newly created order
7. Owner's `configure()` executes, loading this state and preserving the timing information
8. Protocol fees are now locked in orders for the full original duration
9. Owner cannot cancel these orders as RevenueBuybacks lacks a `decreaseSaleRate` wrapper function [4](#0-3) 

**Security Property Broken:** This violates the owner's ability to control when and how protocol revenue is used for buybacks, effectively creating a temporary fund lock scenario where the owner loses custody of protocol fees against their explicit intent.

## Impact Explanation
- **Affected Assets**: Protocol fees (token0 and token1) accumulated in the Positions contract that are withdrawn to RevenueBuybacks and committed to TWAMM orders
- **Damage Severity**: Protocol fees become locked in TWAMM orders for the duration specified in the old configuration (could be hours to days). While funds are not permanently lost (they execute as orders and owner receives proceeds), the owner loses immediate control. If the owner wanted to disable buybacks urgently (e.g., due to pool manipulation or unfavorable market conditions), they cannot retrieve the funds.
- **User Impact**: Affects protocol revenue management. The owner may receive unfavorable execution prices if market conditions deteriorate, or may be forced to participate in buybacks when they explicitly wanted to stop them.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged external actor monitoring the mempool can execute this attack. No special permissions or capital required.
- **Preconditions**: 
  1. Tokens must be configured for buybacks in RevenueBuybacks (minOrderDuration > 0)
  2. Protocol fees must be accumulated in the Positions contract
  3. Owner must submit a `configure()` transaction to change parameters
  4. Pool with the configured fee tier must exist and be initialized
- **Execution Complexity**: Single transaction front-running attack. Attacker simply calls `withdrawAndRoll()` before the owner's `configure()` transaction executes. No complex setup or multi-block coordination required.
- **Frequency**: Can be executed every time the owner attempts to reconfigure or disable buybacks, as long as protocol fees are available.

## Recommendation

Add a `decreaseSaleRate` wrapper function to RevenueBuybacks to allow the owner to cancel unwanted orders:

```solidity
// In src/RevenueBuybacks.sol, add new function:

/// @notice Allows owner to decrease or cancel an active buyback order
/// @param token The revenue token of the order to decrease
/// @param fee The fee tier of the pool
/// @param endTime The end time of the order
/// @param saleRateDecrease The amount to decrease the sale rate by
/// @return refund The amount of tokens refunded
function decreaseSaleRate(
    address token, 
    uint64 fee, 
    uint64 endTime, 
    uint112 saleRateDecrease
) external onlyOwner returns (uint112 refund) {
    OrderKey memory key = _createOrderKey(token, fee, 0, endTime);
    refund = ORDERS.decreaseSaleRate(NFT_ID, key, saleRateDecrease, owner());
}
```

Alternative mitigations:
1. Add access control to `PositionsOwner.withdrawAndRoll()` to make it owner-only, though this reduces permissionless automation
2. Add a timelock or cooldown period between configuration changes
3. Implement a two-step configuration process where changes are queued before taking effect

## Proof of Concept

```solidity
// File: test/Exploit_ConfigureFrontrun.t.sol
// Run with: forge test --match-test test_ConfigureFrontrun -vvv

pragma solidity ^0.8.31;

import {BaseOrdersTest} from "./Orders.t.sol";
import {RevenueBuybacks} from "../src/RevenueBuybacks.sol";
import {PositionsOwner} from "../src/PositionsOwner.sol";
import {IRevenueBuybacks} from "../src/interfaces/IRevenueBuybacks.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {TestToken} from "./TestToken.sol";
import {BuybacksState} from "../src/types/buybacksState.sol";

contract Exploit_ConfigureFrontrun is BaseOrdersTest {
    IRevenueBuybacks rb;
    PositionsOwner positionsOwner;
    TestToken buybacksToken;
    uint64 poolFee;

    function setUp() public override {
        BaseOrdersTest.setUp();
        buybacksToken = new TestToken(address(this));

        // Ensure buybacksToken > token1 > token0 for proper ordering
        if (address(buybacksToken) < address(token1)) {
            (token1, buybacksToken) = (buybacksToken, token1);
        }
        if (address(token1) < address(token0)) {
            (token0, token1) = (token1, token0);
        }

        // Deploy RevenueBuybacks and PositionsOwner
        rb = new RevenueBuybacks(address(this), orders, address(buybacksToken));
        positionsOwner = new PositionsOwner(address(this), positions, rb);
        
        // Transfer positions ownership to PositionsOwner
        positions.transferOwnership(address(positionsOwner));

        poolFee = uint64((uint256(1) << 64) / 100); // 1%
    }

    function test_ConfigureFrontrun() public {
        // SETUP: Configure tokens for buybacks with long duration
        uint32 longDuration = 86400; // 1 day
        uint32 minDuration = 43200; // 12 hours
        rb.configure({
            token: address(token0),
            targetOrderDuration: longDuration,
            minOrderDuration: minDuration,
            fee: poolFee
        });
        rb.configure({
            token: address(token1),
            targetOrderDuration: longDuration,
            minOrderDuration: minDuration,
            fee: poolFee
        });

        // Setup pool
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: poolFee})
        });
        positions.maybeInitializePool(poolKey, 0);
        token0.approve(address(positions), 1e18);
        buybacksToken.approve(address(positions), 1e18);
        positions.mintAndDeposit(poolKey, MIN_TICK, MAX_TICK, 1e18, 1e18, 0);

        // Accumulate protocol fees by doing some swaps
        token0.approve(address(router), 1e18);
        router.swapPermit2(poolKey, false, 1e17, address(this), 0, type(uint256).max, type(uint256).max, new bytes(0));

        rb.approveMax(address(token0));

        // Verify protocol fees exist
        (uint128 fees0Before,) = positions.getProtocolFees(address(token0), address(token1));
        assertGt(fees0Before, 0, "Should have accumulated protocol fees");

        // EXPLOIT: Owner wants to disable buybacks, attacker front-runs
        // Simulate attacker front-running by calling withdrawAndRoll BEFORE configure
        address attacker = address(0xBEEF);
        vm.prank(attacker);
        withdrawAndRoll(address(token0), address(token1));

        // Verify order was created with OLD configuration (long duration)
        BuybacksState state0 = rb.state(address(token0));
        uint32 orderEndTime = state0.lastEndTime();
        assertGt(orderEndTime, block.timestamp, "Order should extend into future");
        assertGe(orderEndTime - uint32(block.timestamp), minDuration, "Order duration should match old config");

        // Now owner's configure executes (attempting to disable)
        rb.configure({
            token: address(token0),
            targetOrderDuration: 0,
            minOrderDuration: 0,
            fee: poolFee
        });

        // VERIFY: Configuration updated but funds still locked in order
        BuybacksState stateAfter = rb.state(address(token0));
        assertEq(stateAfter.minOrderDuration(), 0, "Config should be disabled");
        assertEq(stateAfter.targetOrderDuration(), 0, "Config should be disabled");
        
        // The order still exists with the old endTime
        assertEq(stateAfter.lastEndTime(), orderEndTime, "Order endTime preserved in state");
        
        // Owner cannot call roll anymore (reverts with TokenNotConfigured)
        vm.expectRevert(abi.encodeWithSelector(IRevenueBuybacks.TokenNotConfigured.selector, address(token0)));
        rb.roll(address(token0));

        // Funds are locked in the order until orderEndTime
        // Owner has no way to cancel this order through RevenueBuybacks
        assertEq(rb.balanceOf(address(token0)), 0, "Funds committed to order, not in RevenueBuybacks");
    }

    function withdrawAndRoll(address token0, address token1) internal {
        positionsOwner.withdrawAndRoll(token0, token1);
    }
}
```

## Notes

The vulnerability stems from the combination of:
1. **Permissionless withdrawAndRoll()**: Allows anyone to trigger order creation at any time [5](#0-4) 
2. **Preserved state in configure()**: The function loads and preserves `lastEndTime`, `lastOrderDuration`, and `lastFee` from existing orders [6](#0-5) 
3. **No cancellation mechanism**: RevenueBuybacks lacks any function to call `Orders.decreaseSaleRate()` to cancel unwanted orders

This is particularly problematic when the owner needs to urgently disable buybacks (e.g., if a pool is being manipulated or market conditions deteriorate significantly), as the attacker can force protocol fees to remain committed to TWAMM orders for extended periods.

### Citations

**File:** src/RevenueBuybacks.sol (L90-139)
```text
    function roll(address token) public returns (uint64 endTime, uint112 saleRate) {
        unchecked {
            BuybacksState state;
            assembly ("memory-safe") {
                state := sload(token)
            }

            if (!state.isConfigured()) {
                revert TokenNotConfigured(token);
            }

            // minOrderDuration == 0 indicates the token is not configured
            bool isEth = token == NATIVE_TOKEN_ADDRESS;
            uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
            // if the fee changed, or the amount of time exceeds the min order duration
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
                // handles overflow
                endTime = uint64(block.timestamp + timeRemaining);
            } else {
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));

                state = createBuybacksState({
                    _targetOrderDuration: state.targetOrderDuration(),
                    _minOrderDuration: state.minOrderDuration(),
                    _fee: state.fee(),
                    _lastEndTime: uint32(endTime),
                    _lastOrderDuration: uint32(endTime - block.timestamp),
                    _lastFee: state.fee()
                });

                assembly ("memory-safe") {
                    sstore(token, state)
                }
            }

            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
            }
        }
    }
```

**File:** src/RevenueBuybacks.sol (L147-173)
```text
    function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
        external
        onlyOwner
    {
        if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
        if (minOrderDuration == 0 && targetOrderDuration != 0) {
            revert MinOrderDurationMustBeGreaterThanZero();
        }

        BuybacksState state;
        assembly ("memory-safe") {
            state := sload(token)
        }
        state = createBuybacksState({
            _targetOrderDuration: targetOrderDuration,
            _minOrderDuration: minOrderDuration,
            _fee: fee,
            _lastEndTime: state.lastEndTime(),
            _lastOrderDuration: state.lastOrderDuration(),
            _lastFee: state.lastFee()
        });
        assembly ("memory-safe") {
            sstore(token, state)
        }

        emit Configured(token, state);
    }
```

**File:** src/PositionsOwner.sol (L47-76)
```text
    /// @notice Withdraws protocol fees and transfers them to the buybacks contract, then calls roll for both tokens. Can be called by anyone to trigger revenue buybacks
    /// @dev Both tokens must be configured for buybacks in the buybacks contract
    /// @param token0 The first token of the pair to withdraw fees for
    /// @param token1 The second token of the pair to withdraw fees for
    function withdrawAndRoll(address token0, address token1) external {
        // Check if at least one token is configured for buybacks
        (BuybacksState s0, BuybacksState s1) = BUYBACKS.state(token0, token1);
        if (s0.minOrderDuration() == 0 || s1.minOrderDuration() == 0) {
            revert RevenueTokenNotConfigured();
        }

        // Get available protocol fees
        (uint128 amount0, uint128 amount1) = POSITIONS.getProtocolFees(token0, token1);

        assembly ("memory-safe") {
            // this makes sure we do not ever leave the positions contract with less than 1 wei of fees in both tokens
            // leaving those fees saves gas for when more protocol fees are accrued
            amount0 := sub(amount0, gt(amount0, 0))
            amount1 := sub(amount1, gt(amount1, 0))
        }

        // Withdraw fees to the buybacks contract if there are any
        if (amount0 != 0 || amount1 != 0) {
            POSITIONS.withdrawProtocolFees(token0, token1, uint128(amount0), uint128(amount1), address(BUYBACKS));
        }

        // Call roll for both tokens
        BUYBACKS.roll(token0);
        BUYBACKS.roll(token1);
    }
```

**File:** src/types/buybacksState.sol (L78-97)
```text
function createBuybacksState(
    uint32 _targetOrderDuration,
    uint32 _minOrderDuration,
    uint64 _fee,
    uint32 _lastEndTime,
    uint32 _lastOrderDuration,
    uint64 _lastFee
) pure returns (BuybacksState state) {
    assembly ("memory-safe") {
        state := or(
            or(
                or(and(_targetOrderDuration, 0xFFFFFFFF), shl(32, and(_minOrderDuration, 0xFFFFFFFF))),
                shl(64, and(_fee, 0xFFFFFFFFFFFFFFFF))
            ),
            or(
                or(shl(128, and(_lastEndTime, 0xFFFFFFFF)), shl(160, and(_lastOrderDuration, 0xFFFFFFFF))),
                shl(192, _lastFee)
            )
        )
    }
```
