## Title
Type Boundary Overflow in `Orders.decreaseSaleRate` Prevents Full Cancellation of Large Orders

## Summary
The `Orders.decreaseSaleRate` function contains a critical type casting flaw at line 88 where `saleRateDecrease` (uint112) is negated and later cast to int112. When users attempt to cancel orders with sale rates exceeding `type(int112).max` (approximately 2.596×10³³), the transaction reverts due to SafeCastLib overflow protection, preventing full order cancellation in a single transaction.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** Users should be able to decrease their order's sale rate by any amount up to the current sale rate, including full cancellation. The function should handle all valid uint112 sale rate values since orders can have sale rates up to `type(uint112).max`.

**Actual Logic:** When `saleRateDecrease > type(int112).max`, the casting chain fails:
1. Line 88 creates: `-int256(uint256(saleRateDecrease))`
2. Line 142 attempts: `SafeCastLib.toInt112(saleRateDelta)` [2](#0-1) 
3. For values exceeding int112 range `[-2^111, 2^111-1]`, SafeCastLib reverts

**Exploitation Path:**
1. User creates a TWAMM order with large amount and short duration, resulting in sale rate `S` where `S > type(int112).max` (but `S ≤ type(uint112).max`)
2. Sale rate calculation passes validation [3](#0-2) 
3. User later attempts full cancellation via `decreaseSaleRate(id, key, S, recipient)`
4. Transaction reverts at SafeCastLib.toInt112() due to overflow, preventing withdrawal

**Security Property Broken:** Violates Critical Invariant #2: "All positions MUST be withdrawable at any time." Users with large orders cannot fully cancel their positions in a single transaction.

## Impact Explanation
- **Affected Assets**: TWAMM orders with sale rates between `type(int112).max` (2.596×10³³) and `type(uint112).max` (5.192×10³³) - representing approximately 50% of the valid sale rate range
- **Damage Severity**: Users cannot exit positions atomically, forcing partial cancellations that incur:
  - Additional gas costs for multiple transactions
  - Unwanted partial execution if time constraints prevent multiple transactions
  - Withdrawal fees on each partial cancellation [4](#0-3) 
- **User Impact**: Any user creating large orders (common for institutional traders or high-value positions) faces potential fund lock and forced execution

## Likelihood Explanation
- **Attacker Profile**: Any order owner creating large positions (not malicious, normal protocol usage)
- **Preconditions**: 
  - Order must have sale rate > `type(int112).max`
  - Achievable with: `amount > (type(int112).max * duration) >> 32`
  - Example: For minimum 256-second duration, amount > ~1.86×10²⁸ tokens (realistic for 18-decimal tokens)
- **Execution Complexity**: Single transaction, no special timing required
- **Frequency**: Affects every cancellation attempt for large orders; no per-block or per-pool limits

## Recommendation

**Root Cause:** Mismatch between uint112 storage type for sale rates and int112 casting in decrease logic.

**Fix Option 1 - Change parameter type to int112 (RECOMMENDED):** [1](#0-0) 

```solidity
// In src/Orders.sol, function decreaseSaleRate:

// CURRENT (vulnerable):
function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
    public payable authorizedForNft(id) returns (uint112 refund)
{
    refund = uint112(uint256(-abi.decode(
        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease)))),
        (int256)
    )));
}

// FIXED:
function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
    public payable authorizedForNft(id) returns (uint112 refund)
{
    // Validate saleRateDecrease fits in int112 to prevent SafeCastLib revert
    if (saleRateDecrease > uint112(type(int112).max)) {
        revert SaleRateDecreaseTooLarge();
    }
    
    refund = uint112(uint256(-abi.decode(
        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int112(int256(uint256(saleRateDecrease))))),
        (int256)
    )));
}
```

**Fix Option 2 - Support multi-step cancellation:**
Add a separate `fullCancelOrder` function that automatically handles large sale rates by splitting into multiple partial decreases up to `type(int112).max` each.

**Fix Option 3 - Change internal representation:**
Modify TWAMM.handleForwardData to accept int256 instead of int112 for sale rate deltas, removing the SafeCastLib bottleneck. However, this requires changes to TimeInfo storage layout [5](#0-4) , which may break existing state.

## Proof of Concept

```solidity
// File: test/Exploit_LargeSaleRateCancellation.t.sol
// Run with: forge test --match-test test_CannotCancelLargeSaleRate -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./Orders.t.sol";
import {SafeCastLib} from "solady/utils/SafeCastLib.sol";

contract Exploit_LargeSaleRateCancellation is BaseOrdersTest {
    using CoreLib for *;
    
    function test_CannotCancelLargeSaleRate() public {
        uint64 time = 1000;
        vm.warp(time);
        
        // Create TWAMM pool with liquidity
        uint64 fee = 0;
        int32 tick = 0;
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: tick});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 1e30, 1e30);
        
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = alignToNextValidTime();
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        uint32 duration = uint32(endTime - startTime); // Minimum 256 seconds
        
        // Calculate amount that will produce sale rate > type(int112).max
        // saleRate = (amount << 32) / duration
        // For saleRate > type(int112).max: amount > (type(int112).max * duration) >> 32
        uint256 threshold = (uint256(type(int112).max) * duration) >> 32;
        uint256 largeAmount = threshold + 1e18; // Exceed threshold
        
        // Mint tokens for test
        token0.mint(address(this), largeAmount);
        
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // SETUP: Create order with large sale rate
        (uint256 id, uint112 saleRate) = orders.mintAndIncreaseSellAmount(key, largeAmount, type(uint112).max);
        
        // VERIFY: Sale rate exceeds int112 boundary
        assertGt(saleRate, uint112(type(int112).max), "Sale rate must exceed int112.max");
        
        // EXPLOIT: Attempt to cancel entire order - this will revert
        vm.expectRevert(SafeCastLib.Overflow.selector);
        orders.decreaseSaleRate(id, key, saleRate, address(this));
        
        // WORKAROUND VERIFICATION: Can only cancel in chunks <= type(int112).max
        uint112 firstChunk = uint112(type(int112).max);
        orders.decreaseSaleRate(id, key, firstChunk, address(this));
        
        // Remaining amount still cannot be fully cancelled if it's also > type(int112).max
        uint112 remaining = saleRate - firstChunk;
        if (remaining > type(int112).max) {
            vm.expectRevert(SafeCastLib.Overflow.selector);
            orders.decreaseSaleRate(id, key, remaining, address(this));
        }
    }
}
```

**Notes:**
- This vulnerability stems from a design mismatch where sale rates are stored as uint112 but decrease operations require int112-bounded deltas
- The MAX_ABS_VALUE_SALE_RATE_DELTA constraint [6](#0-5)  applies to aggregated time-point deltas, not individual order cancellations
- While SafeCastLib prevents silent overflow, the revert blocks legitimate user operations
- Impact is amplified for tokens with large decimal places (e.g., 18 decimals) where realistic amounts easily exceed the threshold

### Citations

**File:** src/Orders.sol (L77-94)
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
```

**File:** src/Orders.sol (L138-142)
```text
            (, address recipientOrPayer, uint256 id, OrderKey memory orderKey, int256 saleRateDelta) =
                abi.decode(data, (uint256, address, uint256, OrderKey, int256));

            int256 amount =
                CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));
```

**File:** src/math/twamm.sol (L11-22)
```text
/// @dev Computes sale rate = (amount << 32) / duration and reverts if the result exceeds type(uint112).max.
/// @dev Assumes duration > 0 and amount <= type(uint224).max.
function computeSaleRate(uint256 amount, uint256 duration) pure returns (uint256 saleRate) {
    assembly ("memory-safe") {
        saleRate := div(shl(32, amount), duration)
        if shr(112, saleRate) {
            // cast sig "SaleRateOverflow()"
            mstore(0, shl(224, 0x83c87460))
            revert(0, 4)
        }
    }
}
```

**File:** src/extensions/TWAMM.sol (L196-197)
```text
                (, bytes32 salt, OrderKey memory orderKey, int112 saleRateDelta) =
                    abi.decode(data, (uint256, bytes32, OrderKey, int112));
```

**File:** src/extensions/TWAMM.sol (L318-330)
```text
                // user is withdrawing tokens, so they need to pay a fee to the liquidity providers
                if (amountDelta < 0) {
                    // negation and downcast will never overflow, since max sale rate times max duration is at most type(uint112).max
                    uint128 fee = computeFee(uint128(uint256(-amountDelta)), poolKey.config.fee());
                    if (isToken1) {
                        CORE.accumulateAsFees(poolKey, 0, fee);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), 0, amountDelta);
                    } else {
                        CORE.accumulateAsFees(poolKey, fee, 0);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), amountDelta, 0);
                    }

                    amountDelta += int128(fee);
```

**File:** src/math/time.sol (L9-10)
```text
// If we constrain the sale rate delta to this value, then the current sale rate will never overflow
uint256 constant MAX_ABS_VALUE_SALE_RATE_DELTA = type(uint112).max / MAX_NUM_VALID_TIMES;
```
