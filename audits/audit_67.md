After systematic validation against the framework, I have completed my analysis.

# Audit Report

## Title
Front-Running configure() to Lock Protocol Fees in Unwanted TWAMM Orders

## Summary
The `RevenueBuybacks.configure()` function can be front-run by calling the permissionless `PositionsOwner.withdrawAndRoll()` function, which creates TWAMM orders using old configuration parameters before the owner's changes take effect. Since `RevenueBuybacks` lacks any mechanism to cancel orders, protocol fees become locked in potentially unwanted orders for their full duration.

## Impact
**Severity**: Medium - Temporary fund lock of protocol fees with potential financial harm

Protocol fees become locked in TWAMM orders for the duration specified in the old configuration (potentially hours to days). While funds are not permanently lost and the owner eventually receives buyback proceeds, this violates the owner's ability to control when and how protocol revenue is used. If the owner needs to urgently disable buybacks due to unfavorable market conditions, pool manipulation, or security concerns, they cannot retrieve the committed funds until orders complete.

## Finding Description

**Location:** [1](#0-0) , [2](#0-1) 

**Intended Logic:** 
The owner should be able to reconfigure or disable revenue buybacks by calling `configure()`, with changes taking effect immediately for future order creation. The README explicitly grants the RevenueBuybacks Owner the right to "configure buyback rules."

**Actual Logic:**
An attacker can observe a pending `configure()` transaction in the mempool and front-run it by calling the permissionless `withdrawAndRoll()` function. This function reads the current state from storage [3](#0-2)  to check if tokens are configured, withdraws accumulated protocol fees [4](#0-3) , and calls `roll()` for both tokens [5](#0-4) .

The `roll()` function creates TWAMM orders based on the state it reads from storage [6](#0-5) , calculates order duration using the old `targetOrderDuration` [7](#0-6) , and commits funds via `increaseSellAmount()` [8](#0-7) .

When the owner's `configure()` transaction subsequently executes, it preserves `lastEndTime`, `lastOrderDuration`, and `lastFee` from the existing state [9](#0-8) , effectively recording the order just created by the attacker. Critically, RevenueBuybacks provides no function to call `Orders.decreaseSaleRate()` to cancel unwanted orders.

**Exploitation Path:**
1. **Setup**: Tokens are configured for buybacks with specific durations (e.g., 86400 seconds). Protocol fees have accumulated in the Positions contract.
2. **Trigger**: Owner submits `configure(token, 0, 0, fee)` transaction to disable buybacks by setting both durations to 0.
3. **Front-run**: Attacker observes the pending transaction and submits `withdrawAndRoll(token0, token1)` with higher gas priority.
4. **State Change**: Attacker's transaction executes first, passing the configuration check with old state, withdrawing protocol fees, and creating TWAMM orders with the old `targetOrderDuration`.
5. **Configuration Update**: Owner's `configure()` executes, updating target and minimum durations to 0 but preserving `lastEndTime` from the order just created.
6. **Result**: Protocol fees are locked in TWAMM orders until `lastEndTime`. Owner cannot call `roll()` anymore (reverts with `TokenNotConfigured` since `minOrderDuration==0`), and cannot cancel the order through RevenueBuybacks.

**Security Property Broken:**
This violates the owner's documented ability to "configure buyback rules" and control protocol revenue timing. The owner explicitly intended to stop buybacks immediately but is forced to continue for the old duration.

## Impact Explanation

**Affected Assets**: Protocol fees (token0 and token1) accumulated in the Positions contract

**Damage Severity**:
- Protocol fees become locked in TWAMM orders for hours to days depending on the old `targetOrderDuration`
- Owner loses immediate control over protocol revenue despite explicit configuration change
- If market conditions deteriorate rapidly, the owner may suffer unfavorable execution prices
- If pool manipulation is detected, the owner cannot halt buybacks to protect protocol funds
- While funds are not stolen and owner eventually receives buyback proceeds, the timing loss can be financially significant

**User Impact**: Affects protocol revenue management and the owner's ability to respond to security or market events

**Trigger Conditions**: Can be executed with a single front-running transaction whenever the owner attempts to reconfigure buybacks and protocol fees are available

## Likelihood Explanation

**Attacker Profile**: Any unprivileged external actor monitoring the mempool. No special permissions or capital required.

**Preconditions**:
1. Tokens configured for buybacks (normal operational state)
2. Protocol fees accumulated (typical for active protocol)
3. Owner submits `configure()` transaction (governance action)
4. Pool with configured fee tier exists and is initialized (normal state)

**Execution Complexity**: Single transaction front-running attack using standard MEV infrastructure. Attacker simply calls `withdrawAndRoll()` with higher gas priority before owner's transaction executes.

**Economic Cost**: Only gas fees (~$10-50), no capital lockup required

**Frequency**: Can be executed every time the owner attempts to reconfigure or disable buybacks, as long as protocol fees are available

**Overall Likelihood**: MEDIUM-HIGH - Standard MEV attack with low barrier to entry, can occur on every reconfiguration attempt

## Recommendation

**Primary Fix:**
Add a `decreaseSaleRate` wrapper function to RevenueBuybacks to allow the owner to cancel unwanted orders:

```solidity
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

**Alternative Mitigations**:
1. Add access control to `PositionsOwner.withdrawAndRoll()` to make it owner-only (reduces permissionless automation benefit)
2. Implement a timelock or cooldown period between configuration changes
3. Use a two-step configuration process where changes are queued before taking effect
4. Allow owner to transfer NFT ownership to manually cancel orders in emergency situations

## Notes

The vulnerability stems from three design elements working in combination:
1. **Permissionless automation**: `withdrawAndRoll()` is callable by anyone to enable automated revenue collection [10](#0-9) 
2. **State preservation**: `configure()` preserves order history fields to track existing orders [11](#0-10) 
3. **Missing cancellation**: No wrapper function exists to call `Orders.decreaseSaleRate()` for emergency order cancellation

While the permissionless nature appears intentional for automation, the lack of cancellation mechanism is a clear security gap that prevents the owner from exercising urgent control over protocol revenue in response to market or security events.

### Citations

**File:** src/RevenueBuybacks.sol (L90-98)
```text
    function roll(address token) public returns (uint64 endTime, uint112 saleRate) {
        unchecked {
            BuybacksState state;
            assembly ("memory-safe") {
                state := sload(token)
            }

            if (!state.isConfigured()) {
                revert TokenNotConfigured(token);
```

**File:** src/RevenueBuybacks.sol (L116-130)
```text
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
```

**File:** src/RevenueBuybacks.sol (L133-137)
```text
            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
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
