## Title
RevenueBuybacks DOS via Sale Rate Overflow When Reusing Orders with Minimal Time Remaining

## Summary
The `RevenueBuybacks.roll()` function can be permanently DOSed when a large revenue balance accumulates and the function attempts to reuse an existing order with minimal remaining duration (as low as 1 second). The sale rate calculation `(amount << 32) / duration` in `computeSaleRate` exceeds `type(uint112).max`, causing a revert that blocks all future automated buybacks for that token.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (function `roll`, lines 90-139) and `src/math/twamm.sol` (function `computeSaleRate`, lines 13-22)

**Intended Logic:** The `roll()` function should create automated buyback orders for accumulated protocol revenue. When conditions are met, it reuses an existing order's end time to batch multiple revenue accumulations efficiently. The sale rate is calculated as `(amount << 32) / duration` and must not exceed `type(uint112).max`. [1](#0-0) 

**Actual Logic:** When the reuse condition passes with `minOrderDuration = 1` and `timeRemaining = 1 second`, a large accumulated balance (> 2^80 wei ≈ 1.2 million tokens for 18-decimal tokens) causes the sale rate calculation to overflow. The `computeSaleRate` function reverts with `SaleRateOverflow()`, permanently blocking the `roll()` function for that token. [2](#0-1) 

**Exploitation Path:**
1. **Configuration:** Owner configures a revenue token with `minOrderDuration = 1` (minimum allowed per validation at line 152) and `targetOrderDuration = 256` (minimum time grid step). [3](#0-2) 

2. **Initial Order:** Someone calls `roll()` which creates an order with `lastEndTime` approximately 256 seconds in the future. The state is updated with this information. [4](#0-3) 

3. **Time Passes:** The blockchain advances to `block.timestamp = lastEndTime - 1`, so `timeRemaining = 1 second`.

4. **Large Revenue Accumulates:** Protocol collects substantial revenue (e.g., 2^80 wei = ~1,208,925,819,614,629,174,706,176 wei, or ~1.21 million tokens with 18 decimals). This is realistic for protocols processing significant trading volume.

5. **Second Roll Attempt:** Someone calls `roll()` again:
   - Line 103: `amountToSpend = 2^80` (the large balance)
   - Line 105: `timeRemaining = lastEndTime - block.timestamp = 1` (unchecked block allows this calculation)
   - Lines 110-111: Reuse condition PASSES:
     * `state.fee() == state.lastFee()` ✓ (fee unchanged)
     * `timeRemaining >= state.minOrderDuration()` ✓ (1 >= 1)
     * `timeRemaining <= state.lastOrderDuration()` ✓ (1 <= 256)
   - Line 114: `endTime = block.timestamp + 1`
   - Line 134: Calls `ORDERS.increaseSellAmount(NFT_ID, ..., uint128(2^80), type(uint112).max)` [5](#0-4) 

6. **Orders.increaseSellAmount:** 
   - Line 59: `realStart = max(block.timestamp, 0) = block.timestamp` (startTime is 0)
   - Line 66: Calls `computeSaleRate(2^80, uint32(endTime - block.timestamp))` where duration = 1 [6](#0-5) 

7. **computeSaleRate Overflow:**
   - Line 15: `saleRate = (2^80 << 32) / 1 = 2^112`
   - Line 16: Check `shr(112, saleRate)` evaluates to 1 (non-zero)
   - Lines 18-19: Reverts with `SaleRateOverflow()` [2](#0-1) 

8. **DOS Result:** The `roll()` function permanently fails for this token. Revenue continues accumulating but cannot be converted to automated buybacks. The only recovery is the owner manually calling `take()` to withdraw funds, defeating the automated mechanism.

**Security Property Broken:** This violates the protocol's automated revenue buyback functionality and temporarily locks revenue (recoverable only through owner intervention), which impacts protocol operation and requires manual remediation.

## Impact Explanation
- **Affected Assets:** All accumulated revenue tokens in the `RevenueBuybacks` contract for the configured token
- **Damage Severity:** Complete DOS of automated buyback functionality for that token. Revenue accumulates but cannot be used for its intended purpose until owner manually intervenes via `take()`. No permanent fund loss, but operational disruption and manual intervention required.
- **User Impact:** Protocol-wide impact. The automated buyback mechanism stops functioning, preventing the protocol from executing its tokenomics (buying back governance/utility tokens with revenue). Requires owner to notice the issue and manually withdraw funds.

## Likelihood Explanation
- **Attacker Profile:** No attacker needed - this occurs through normal protocol operation when conditions naturally align
- **Preconditions:** 
  * Token configured with `minOrderDuration = 1` (owner decision, but 1 is a valid minimum)
  * Existing order with ~1 second remaining (naturally occurs as orders expire)
  * Large revenue balance accumulates (> 2^80 wei, realistic for active protocols)
  * Someone calls `roll()` during this narrow window
- **Execution Complexity:** Passive - no attacker action required, just natural protocol operation
- **Frequency:** Depends on revenue accumulation rate and order timing. For high-volume protocols with frequent large revenue collections, this could occur regularly if `minOrderDuration` is set to 1.

## Recommendation

**Option 1: Enforce minimum duration on reuse path**

In `src/RevenueBuybacks.sol`, function `roll()`, modify the reuse condition to enforce a higher minimum duration:

```solidity
// Around line 110-111:

// CURRENT (vulnerable):
if (
    state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
        && timeRemaining <= state.lastOrderDuration()
) {

// FIXED:
uint32 SAFE_MIN_DURATION = 256; // Minimum time grid step
if (
    state.fee() == state.lastFee() && timeRemaining >= max(state.minOrderDuration(), SAFE_MIN_DURATION)
        && timeRemaining <= state.lastOrderDuration()
) {
```

This prevents reusing orders with dangerously short durations that could cause overflow with large balances.

**Option 2: Cap amount based on remaining duration**

In `src/RevenueBuybacks.sol`, function `roll()`, add amount limiting logic:

```solidity
// Around line 133-137:

// CURRENT (vulnerable):
if (amountToSpend != 0) {
    saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
        NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
    );
}

// FIXED:
if (amountToSpend != 0) {
    uint32 duration = uint32(endTime - block.timestamp);
    // Cap amount to prevent overflow: (amount << 32) / duration <= type(uint112).max
    // Rearranged: amount <= (type(uint112).max * duration) >> 32
    uint256 maxSafeAmount = (uint256(type(uint112).max) * duration) >> 32;
    uint128 safeAmount = uint128(amountToSpend > maxSafeAmount ? maxSafeAmount : amountToSpend);
    
    saleRate = ORDERS.increaseSellAmount{value: isEth ? safeAmount : 0}(
        NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), safeAmount, type(uint112).max
    );
    // Note: Remaining balance will be rolled in the next call
}
```

**Option 3: Use try-catch to fallback to new order**

```solidity
// Around line 133-137:

if (amountToSpend != 0) {
    try ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
        NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
    ) returns (uint112 _saleRate) {
        saleRate = _saleRate;
    } catch {
        // If overflow occurs, create a new order with fresh duration
        endTime = uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));
        saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
            NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
        );
    }
}
```

**Recommendation:** Option 1 is the simplest and most gas-efficient fix, as it prevents the problematic state from occurring in the first place.

## Proof of Concept

```solidity
// File: test/Exploit_RevenueBuybacksDOS.t.sol
// Run with: forge test --match-test test_RevenueBuybacksDOS_SaleRateOverflow -vvv

pragma solidity ^0.8.31;

import "./RevenueBuybacks.t.sol";

contract Exploit_RevenueBuybacksDOS is RevenueBuybacksTest {
    function test_RevenueBuybacksDOS_SaleRateOverflow() public {
        // SETUP: Configure with minOrderDuration = 1 (minimum allowed)
        uint32 targetDuration = 256; // Minimum valid time grid step
        uint32 minDuration = 1; // Minimum allowed by contract
        uint64 poolFee = uint64((uint256(1) << 64) / 100); // 1%
        
        rb.configure({
            token: address(token0),
            targetOrderDuration: targetDuration,
            minOrderDuration: minDuration,
            fee: poolFee
        });
        
        // Initialize pool
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: poolFee})
        });
        positions.maybeInitializePool(poolKey, 0);
        token0.approve(address(positions), 1e18);
        buybacksToken.approve(address(positions), 1e18);
        positions.mintAndDeposit(poolKey, MIN_TICK, MAX_TICK, 1e18, 1e18, 0);
        
        // Approve and initial roll with small amount
        rb.approveMax(address(token0));
        donate(address(token0), 1e15); // Small initial amount
        (uint64 firstEndTime,) = rb.roll(address(token0));
        
        // EXPLOIT: Advance time to 1 second before order ends
        vm.warp(firstEndTime - 1);
        
        // Accumulate large revenue: 2^80 wei (~1.21M tokens with 18 decimals)
        // For demonstration, we'll use a proportionally large amount that causes overflow
        uint256 largeAmount = (uint256(type(uint112).max) >> 32) + 1; // Just above overflow threshold for duration=1
        donate(address(token0), uint128(largeAmount));
        
        // VERIFY: Attempting to roll now should revert with SaleRateOverflow
        vm.expectRevert(); // Will catch the SaleRateOverflow error
        rb.roll(address(token0));
        
        // Demonstrate that roll() is permanently DOSed
        vm.expectRevert();
        rb.roll(address(token0));
        
        // Only recovery is owner withdrawing manually
        uint256 balanceBefore = token0.balanceOf(address(this));
        rb.take(address(token0), largeAmount + 1e15);
        assertEq(token0.balanceOf(address(this)) - balanceBefore, largeAmount + 1e15, "Owner must manually recover funds");
    }
}
```

## Notes

- The vulnerability requires `minOrderDuration = 1`, which is the minimum allowed value but represents a valid configuration choice by the owner
- The issue is not an attacker exploit but rather a design flaw in the reuse logic that doesn't account for extreme ratio between balance and remaining duration
- The threshold for overflow is `amount > (type(uint112).max * duration) >> 32`. For duration = 1 second, this is approximately 2^80 wei
- For an 18-decimal token, 2^80 wei ≈ 1.21 million tokens, which is achievable for protocols with significant trading volume
- The DOS is temporary (owner can call `take()` to recover) but defeats the automated buyback mechanism and requires manual intervention
- Impact is Medium rather than High because funds are not lost (recoverable by owner) and the issue requires specific timing conditions to manifest

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

**File:** src/math/twamm.sol (L13-22)
```text
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

**File:** src/Orders.sol (L53-74)
```text
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
        authorizedForNft(id)
        returns (uint112 saleRate)
    {
        uint256 realStart = FixedPointMathLib.max(block.timestamp, orderKey.config.startTime());

        unchecked {
            if (orderKey.config.endTime() <= realStart) {
                revert OrderAlreadyEnded();
            }

            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));

            if (saleRate > maxSaleRate) {
                revert MaxSaleRateExceeded();
            }
        }

        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
    }
```
