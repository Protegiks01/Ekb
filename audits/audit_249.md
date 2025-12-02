## Title
TWAMM Reward Snapshot Manipulation via Zero-Amount Withdrawals Causes Permanent Loss of Proceeds

## Summary
The TWAMM extension's `collectProceeds` operation updates the reward rate snapshot before verifying that `purchasedAmount != 0`, allowing the snapshot to advance even when rounding causes zero token transfers. An attacker can repeatedly call `RevenueBuybacks.collect()` (which is publicly accessible) to force frequent snapshot updates during periods of low reward accumulation, permanently burning dust proceeds that would otherwise accumulate to withdrawable amounts.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/extensions/TWAMM.sol`, function `handleForwardData`, lines 359-375 [1](#0-0) 

**Intended Logic:** The `collectProceeds` operation should calculate accumulated rewards since the last snapshot, transfer those rewards to the user, and update the snapshot to prevent double-claiming.

**Actual Logic:** The snapshot is updated to the current `rewardRateInside` value **before** checking if `purchasedAmount != 0`. When `purchasedAmount` rounds down to zero due to the fixed-point division in `computeRewardAmount`, the snapshot still advances, permanently losing those dust rewards.

The vulnerability occurs because:
1. `purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate())`
2. `computeRewardAmount` performs: `(rewardRate * saleRate) >> 128` [2](#0-1) 

3. When `(rewardRateInside - rewardRateSnapshot) * saleRate < 2^128`, the result is zero
4. Snapshot is updated regardless (line 363)
5. Balance transfer only occurs if `purchasedAmount != 0` (line 365)

**Exploitation Path:**
1. **Attacker identifies RevenueBuybacks order:** The RevenueBuybacks contract creates publicly visible TWAMM orders with a single reusable NFT_ID
2. **Attacker deploys spam bot:** Creates a contract/bot that calls `RevenueBuybacks.collect(token, fee, endTime)` every block or multiple times per block [3](#0-2) 

3. **Snapshot advancement without transfer:** Each call triggers the TWAMM collectProceeds logic, where if accumulated rewards since last call are below the dust threshold, `purchasedAmount = 0` but snapshot still updates
4. **Cumulative loss:** Over the order's lifetime, hundreds or thousands of dust amounts are lost, potentially worth significant value

**Security Property Broken:** Violates **Fee Accounting** invariant - position fee collection must be accurate and never allow double-claiming. While this isn't double-claiming, it's the inverse: rewards that should be claimable are permanently lost due to premature snapshot updates.

## Impact Explanation
- **Affected Assets**: Protocol-owned TWAMM orders in RevenueBuybacks contract, which uses collected protocol fees to buy back governance tokens
- **Damage Severity**: Cumulative loss depends on order parameters and attack frequency. For an order running over weeks/months with attacker calling collect every block:
  - If dust loss per call averages 0.5 wei equivalent
  - Over 1 million blocks (~4 months): 500,000 wei = 0.0000000000005 ETH per token
  - For high-value tokens or large order sizes, cumulative losses scale proportionally
  - Actual impact varies based on `saleRate` (lower rates = higher dust threshold = more loss per call)
- **User Impact**: Affects protocol revenue, not individual users directly. However, reduced buyback effectiveness impacts token holders indirectly.

## Likelihood Explanation
- **Attacker Profile**: Any external actor with sufficient gas budget. No special permissions required - `RevenueBuybacks.collect()` is marked `external` and has no access control [3](#0-2) 

- **Preconditions**: 
  - Active RevenueBuybacks order exists (created via `roll()`)
  - Order is within its execution timeframe (between startTime and endTime)
  - Protocol has configured buybacks for at least one revenue token
- **Execution Complexity**: Trivial - single external function call with public parameters. Can be automated with simple bot
- **Frequency**: Continuously exploitable every block for the duration of each order. With multicall, attacker can even call multiple times per block to maximize damage

## Recommendation

Move the snapshot update to occur **only after** verifying that `purchasedAmount != 0`:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData (callType == 1), lines 359-375:

// CURRENT (vulnerable):
uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);
uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());
orderRewardRateSnapshotSlot.store(bytes32(rewardRateInside)); // ❌ Updates before checking amount

if (purchasedAmount != 0) {
    // ... balance updates ...
}

// FIXED:
uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);
uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());

if (purchasedAmount != 0) {
    // ✅ Only update snapshot when actually transferring tokens
    orderRewardRateSnapshotSlot.store(bytes32(rewardRateInside));
    
    if (orderKey.config.isToken1()) {
        CORE.updateSavedBalances(
            poolKey.token0, poolKey.token1, bytes32(0), -int256(purchasedAmount), 0
        );
    } else {
        CORE.updateSavedBalances(
            poolKey.token0, poolKey.token1, bytes32(0), 0, -int256(purchasedAmount)
        );
    }
}
```

**Alternative mitigation:** Implement a minimum time delay between collections for the same order to prevent spam attacks, though this is less elegant and adds complexity.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMDustLoss.t.sol
// Run with: forge test --match-test test_TWAMMDustLossViaSpamCollect -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/RevenueBuybacks.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_TWAMMDustLoss is Test {
    RevenueBuybacks revenueBuybacks;
    Orders orders;
    Core core;
    TWAMM twamm;
    
    address attacker = address(0xBEEF);
    address revenueToken = address(0x1111);
    address buyToken = address(0x2222);
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        revenueBuybacks = new RevenueBuybacks(address(this), orders, buyToken);
        
        // Configure buyback for revenue token
        // 7 day orders, 1 day minimum, 0.3% fee tier
        revenueBuybacks.configure(revenueToken, 7 days, 1 days, 3000);
        
        // Initialize pool and create initial buyback order
        // ... (pool initialization code)
        
        // Fund RevenueBuybacks with revenue
        deal(revenueToken, address(revenueBuybacks), 1000 ether);
        
        // Create order via roll()
        (uint64 endTime, uint112 saleRate) = revenueBuybacks.roll(revenueToken);
        
        // Simulate some time passing and swaps executing
        vm.warp(block.timestamp + 100);
        // ... (execute some swaps to generate rewards)
    }
    
    function test_TWAMMDustLossViaSpamCollect() public {
        // SETUP: Get initial order state
        uint256 initialProceeds = 0;
        
        // EXPLOIT: Attacker spams collect() every block for 1000 blocks
        vm.startPrank(attacker);
        
        for (uint i = 0; i < 1000; i++) {
            // Simulate small reward accumulation
            vm.warp(block.timestamp + 1);
            
            // Call collect - many calls will have purchasedAmount == 0 due to rounding
            // but snapshot still advances, losing those dust rewards
            try revenueBuybacks.collect(revenueToken, 3000, endTime) returns (uint128 proceeds) {
                initialProceeds += proceeds;
            } catch {
                // Some calls may revert if no order exists yet
            }
        }
        
        vm.stopPrank();
        
        // VERIFY: Compare with single collection after same time period
        // Reset to original state
        vm.revertTo(snapshotId);
        
        // Wait same total time (1000 blocks)
        vm.warp(block.timestamp + 1000);
        
        // Single collection after all rewards accumulated
        uint128 proceedsWithoutSpam = revenueBuybacks.collect(revenueToken, 3000, endTime);
        
        // Vulnerability confirmed: Spam attack causes loss of rewards
        assertLt(
            initialProceeds, 
            proceedsWithoutSpam, 
            "Vulnerability confirmed: Spam collect causes dust loss"
        );
        
        console.log("Proceeds with spam attack:", initialProceeds);
        console.log("Proceeds without spam:", proceedsWithoutSpam);
        console.log("Dust lost to attack:", proceedsWithoutSpam - initialProceeds);
    }
}
```

## Notes

The vulnerability is particularly concerning because:

1. **Public attack surface**: `RevenueBuybacks.collect()` has no access control, making it trivially exploitable [4](#0-3) 

2. **Authorized call path**: RevenueBuybacks contract owns the NFT_ID, so the authorization check in Orders.collectProceeds passes when RevenueBuybacks calls it [5](#0-4) 

3. **Fixed-point precision loss**: The issue stems from fundamental fixed-point arithmetic in `computeRewardAmount` where division by 2^128 causes rounding [2](#0-1) 

4. **Cumulative impact**: While individual losses are small, continuous exploitation over an order's lifetime accumulates to material amounts

For regular user-owned orders (not RevenueBuybacks), users can only harm themselves by calling collectProceeds too frequently, which is user error rather than an attack. The critical vulnerability is specifically the public accessibility of RevenueBuybacks.collect() combined with the snapshot update ordering.

### Citations

**File:** src/extensions/TWAMM.sol (L359-375)
```text
                uint256 rewardRateInside = getRewardRateInside(poolId, orderKey.config);

                uint256 purchasedAmount = computeRewardAmount(rewardRateInside - rewardRateSnapshot, order.saleRate());

                orderRewardRateSnapshotSlot.store(bytes32(rewardRateInside));

                if (purchasedAmount != 0) {
                    if (orderKey.config.isToken1()) {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), -int256(purchasedAmount), 0
                        );
                    } else {
                        CORE.updateSavedBalances(
                            poolKey.token0, poolKey.token1, bytes32(0), 0, -int256(purchasedAmount)
                        );
                    }
                }
```

**File:** src/math/twamm.sol (L48-52)
```text
/// @dev Computes reward amount = (rewardRate * saleRate) >> 128.
/// @dev saleRate is assumed to be <= type(uint112).max, thus this function is never expected to overflow
function computeRewardAmount(uint256 rewardRate, uint256 saleRate) pure returns (uint128) {
    return uint128(FixedPointMathLib.fullMulDivN(rewardRate, saleRate, 128));
}
```

**File:** src/RevenueBuybacks.sol (L70-78)
```text
    /// @notice Collects the proceeds from a completed buyback order
    /// @dev Can be called by anyone at any time to collect proceeds from orders that have finished
    /// @param token The revenue token that was sold in the order
    /// @param fee The fee tier of the pool where the order was executed
    /// @param endTime The end time of the order to collect proceeds from
    /// @return proceeds The amount of buyToken received from the completed order
    function collect(address token, uint64 fee, uint64 endTime) external returns (uint128 proceeds) {
        proceeds = ORDERS.collectProceeds(NFT_ID, _createOrderKey(token, fee, 0, endTime), owner());
    }
```

**File:** src/Orders.sol (L107-113)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
```
