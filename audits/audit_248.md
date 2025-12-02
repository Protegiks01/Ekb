# NoVulnerability found for this question.

## Analysis

The security question asks whether `computeRewardAmount` can produce non-zero results for cancelled orders (saleRate = 0) due to stale `rewardRateInside` values.

**Answer: NO** - This cannot happen due to the mathematical properties of the `computeRewardAmount` function.

### Key Findings:

**1. Order Cancellation Logic:**
When an order is cancelled (saleRate set to 0), the code correctly sets `rewardRateSnapshotAdjusted = 0`: [1](#0-0) 

The assembly code multiplies by `iszero(iszero(saleRateNext))`, which evaluates to 0 when `saleRateNext == 0`, forcing the entire `rewardRateSnapshotAdjusted` to 0.

**2. Proceeds Collection Logic:**
During proceeds withdrawal, the purchased amount is calculated as: [2](#0-1) 

For a cancelled order, this becomes: `computeRewardAmount(rewardRateInside - 0, 0)` where the second parameter is the order's saleRate (which is 0).

**3. Mathematical Guarantee:**
The `computeRewardAmount` function implementation guarantees zero output when saleRate is zero: [3](#0-2) 

The function computes `(rewardRate * saleRate) >> 128`. When `saleRate = 0`, the result is mathematically always 0, regardless of the `rewardRate` value.

### Conclusion:

The "staleness" of `rewardRateInside` is irrelevant because it gets multiplied by `saleRate = 0` in the formula. The code correctly returns zero proceeds for all cancelled orders. There is no exploitable vulnerability related to this question.

**Notes:**
- The rewardRateSnapshot being set to 0 during cancellation is correct behavior that prevents tracking rewards for inactive orders
- Even if rewardRateSnapshot were non-zero after cancellation, the multiplication by saleRate=0 would still guarantee zero proceeds
- This design ensures cancelled orders cannot extract any value from accumulated reward rates

### Citations

**File:** src/extensions/TWAMM.sol (L232-239)
```text
                uint256 rewardRateSnapshotAdjusted;
                int256 numOrdersChange;
                assembly ("memory-safe") {
                    rewardRateSnapshotAdjusted := mul(
                        sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
                        // if saleRateNext is zero, write 0 for the reward rate snapshot adjusted
                        iszero(iszero(saleRateNext))
                    )
```

**File:** src/extensions/TWAMM.sol (L356-363)
```text
                OrderState order = OrderState.wrap(orderStateSlot.load());
                uint256 rewardRateSnapshot = uint256(orderRewardRateSnapshotSlot.load());

                uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());

                orderRewardRateSnapshotSlot.store(bytes32(rewardRateInside));
```

**File:** src/math/twamm.sol (L48-52)
```text
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128) {
    return uint128(FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128));
}
```
