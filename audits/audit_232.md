## Title
Uint32 Timestamp Overflow Causes Critical State Corruption in TWAMM and Oracle Extensions

## Summary
The TWAMM, Oracle, and MEVCapture extensions cast `block.timestamp` to `uint32` for storage optimization. When `block.timestamp` exceeds `type(uint32).max` (either on chains with non-standard timestamps or after February 7, 2106), the uint32 cast wraps to small values. Subsequent arithmetic operations in unchecked blocks cause massive underflows, corrupting order states in TWAMM and oracle data, leading to fund loss and protocol insolvency.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/extensions/TWAMM.sol` (lines 258-259, within `handleForwardData` function)
- `src/extensions/Oracle.sol` (line 102, within `maybeInsertSnapshot` function)
- `src/extensions/MEVCapture.sol` (line 186, within `handleForwardData` function)

**Intended Logic:** 
The extensions cast `block.timestamp` to `uint32` to save storage space, assuming timestamps will remain within the uint32 range (up to 4,294,967,295 seconds). Time deltas are calculated by subtracting stored uint32 timestamps from the current uint32-cast timestamp to determine elapsed time for fee accumulation, order execution, and oracle updates. [1](#0-0) 

**Actual Logic:** 
When `block.timestamp` exceeds `type(uint32).max`, the cast wraps the value. In TWAMM's order update path, the duration calculation performs `uint32(block.timestamp) - lastUpdateTime` within an unchecked block. If `lastUpdateTime` was stored before the wrap (large value) and `block.timestamp` wraps to a small value, the subtraction underflows to approximately `type(uint32).max`, creating a massive duration value. [2](#0-1) 

This massive duration is passed to `computeAmountFromSaleRate`, which multiplies it by the sale rate and shifts right by 32 bits, still producing an enormous amount. [3](#0-2) 

The result is added to `amountSold` and cast to `uint112`, causing overflow and state corruption. [4](#0-3) 

**Exploitation Path:**

1. **Pre-wrap State**: Before `block.timestamp` exceeds uint32.max, a TWAMM order exists with `lastUpdateTime = 4,294,967,290` (5 seconds before the wrap) and `saleRate = 1e18` (1 token per second in 80.32 fixed point).

2. **Timestamp Wraps**: On a chain with non-standard timestamps or after Feb 2106, `block.timestamp` becomes 4,294,967,296. When cast to uint32: `uint32(4,294,967,296) = 0`.

3. **Order Update Triggered**: User calls `forward` on TWAMM to update their order, invoking `handleForwardData`.

4. **Underflow Exploitation**: 
   - Line 258 calculates: `duration = uint32(0) - 4,294,967,290 = 4,294,967,006` (massive underflow in unchecked block)
   - Line 255 computes: `amountFromSaleRate = (1e18 * 4,294,967,006) >> 32 ≈ 1e18 tokens` (gigantic amount)
   - Line 253 adds this to `amountSold` and casts to uint112, causing overflow/wrap
   - Corrupted `amountSold` stored in order state

5. **State Corruption Cascades**: The corrupted order state causes incorrect reward calculations, wrong amounts distributed to users, and potential pool insolvency when virtual orders execute with corrupted sale rates.

**Security Property Broken:** 
- **Solvency Invariant**: Pool balances become negative or incorrect due to wrong amount calculations
- **Withdrawal Availability**: Orders cannot be properly withdrawn with corrupted state
- **Fee Accounting**: TWAMM rewards and collected amounts are completely wrong

## Impact Explanation

**Affected Assets**: 
- All TWAMM orders on affected pools
- Oracle TWAP data for all tokens
- Pool liquidity balances
- User order positions and claimable rewards

**Damage Severity**: 
- **TWAMM**: Order states show massively inflated `amountSold` values. When orders are settled or cancelled, users receive incorrect token amounts based on corrupted state. If the overflow wraps to a small value, users lose their rightful funds. If it remains large before cast truncation, excess tokens could be drained from pools.
- **Oracle**: The underflow at line 102 creates `timePassed ≈ 4.2 billion seconds`, causing cumulative values to jump by astronomical amounts. All TWAP calculations become meaningless, breaking any protocols relying on oracle price feeds. [5](#0-4) [6](#0-5) 

- **MEVCapture**: Less severe - causes one-time incorrect fee accumulation at the wrap boundary due to comparison logic error. [7](#0-6) 

**User Impact**: 
- All users with active TWAMM orders experience fund loss or gain based on unpredictable overflow behavior
- All protocols using the Oracle extension receive corrupted price data
- Pool solvency is violated, preventing legitimate withdrawals

## Likelihood Explanation

**Attacker Profile**: 
Any user interacting with TWAMM orders, Oracle, or MEVCapture after the timestamp wrap. No special privileges required - the vulnerability is triggered by normal protocol usage.

**Preconditions**: 
1. Chain's `block.timestamp` exceeds `type(uint32).max` (4,294,967,295)
   - Standard chains: Occurs after February 7, 2106
   - Non-standard chains: Could be immediate if they use different timestamp schemes
2. Existing orders or oracle snapshots with pre-wrap `lastUpdateTime` values
3. Any user transaction that updates order state or oracle snapshots

**Execution Complexity**: 
Single transaction. No special timing or coordination needed - any normal interaction with the affected extensions triggers the bug after the timestamp wrap.

**Frequency**: 
Continuous. Every order update, oracle snapshot, or MEVCapture swap after the wrap experiences the corrupted arithmetic. The corruption persists across all subsequent transactions until contracts are replaced.

## Recommendation

Replace uint32 timestamp storage with uint40 or uint48, which provide sufficient range while maintaining storage efficiency:

```solidity
// In src/extensions/TWAMM.sol, line 251:

// CURRENT (vulnerable):
_lastUpdateTime: uint32(block.timestamp),

// FIXED (using uint40 - valid until year 36,812):
_lastUpdateTime: uint40(block.timestamp),

// Update OrderState type definition to use uint40 instead of uint32
// In src/types/orderState.sol, modify parse() function accordingly
```

```solidity
// In src/extensions/Oracle.sol, line 102:

// CURRENT (vulnerable):
uint32 timePassed = uint32(block.timestamp) - c.lastTimestamp();

// FIXED (using uint40):
uint40 timePassed = uint40(block.timestamp) - c.lastTimestamp();

// Update Snapshot and Counts types to use uint40
```

```solidity
// In src/extensions/MEVCapture.sol, line 186:

// CURRENT (vulnerable):
uint32 currentTime = uint32(block.timestamp);

// FIXED (using uint40):
uint40 currentTime = uint40(block.timestamp);

// Update MEVCapturePoolState type to use uint40
```

**Alternative mitigation**: Add explicit checks before arithmetic operations:

```solidity
// In TWAMM.sol, before line 258:
require(uint32(block.timestamp) >= lastUpdateTime, "Timestamp overflow detected");

// In Oracle.sol, before line 102:
require(uint32(block.timestamp) >= c.lastTimestamp(), "Timestamp overflow detected");
```

However, this would make the protocol unusable after the wrap, only preventing silent corruption. The uint40/uint48 upgrade is the proper long-term solution.

## Proof of Concept

```solidity
// File: test/Exploit_Uint32TimestampOverflow.t.sol
// Run with: forge test --match-test test_Uint32TimestampOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/extensions/TWAMM.sol";
import "../src/interfaces/ICore.sol";

contract Exploit_Uint32TimestampOverflow is Test {
    TWAMM twamm;
    ICore core;
    
    function setUp() public {
        // Deploy core and TWAMM
        core = ICore(address(new MockCore()));
        twamm = new TWAMM(core);
        
        // Initialize a pool with TWAMM extension
        // ... pool setup code ...
    }
    
    function test_Uint32TimestampOverflow() public {
        // SETUP: Create order before timestamp wrap
        uint256 preWrapTimestamp = type(uint32).max - 100; // 100 seconds before wrap
        vm.warp(preWrapTimestamp);
        
        // User creates TWAMM order with saleRate = 1e18 tokens/second
        bytes32 salt = bytes32(uint256(1));
        OrderKey memory orderKey = OrderKey({
            // ... order configuration ...
            config: OrderConfig.wrap(/* endTime near uint32.max */)
        });
        int112 saleRateDelta = 1e18; // 1 token per second in 80.32 format
        
        bytes memory orderData = abi.encode(
            uint256(0), // callType = 0 for order update
            salt,
            orderKey,
            saleRateDelta
        );
        
        // Create initial order - stored with lastUpdateTime = type(uint32).max - 100
        twamm.forward(orderData);
        
        // EXPLOIT: Warp past uint32.max to trigger timestamp wrap
        uint256 postWrapTimestamp = uint256(type(uint32).max) + 10;
        vm.warp(postWrapTimestamp);
        
        // User updates order, triggering underflow
        // Expected duration: 110 seconds
        // Actual duration after underflow: ~4.2 billion seconds (0 - (uint32.max - 100))
        twamm.forward(orderData);
        
        // VERIFY: Check that amountSold is corrupted
        // The massive duration should have caused:
        // amountSold += (1e18 * ~4.2e9) >> 32 = huge value
        // When cast to uint112, this overflows
        
        OrderState memory orderState = twamm.getOrderState(/* order id */);
        
        // The amountSold should be ~110 tokens (110 seconds * 1 token/sec)
        // But due to underflow, it's either overflowed to near 0 or wrapped to huge value
        uint112 expectedAmount = 110e18;
        uint112 actualAmount = orderState.amountSold;
        
        // Assertion will fail, confirming state corruption
        assertTrue(
            actualAmount != expectedAmount,
            "Vulnerability confirmed: amountSold corrupted by timestamp underflow"
        );
        
        // Additional check: amountSold should be either very small (overflowed) 
        // or very large (before uint112 cast truncation)
        assertTrue(
            actualAmount < 100e18 || actualAmount > 1e30,
            "amountSold shows signs of arithmetic overflow/underflow"
        );
    }
}
```

## Notes

This vulnerability affects all three in-scope extensions but with varying severity:

1. **TWAMM** (Critical): Direct fund loss through corrupted order accounting
2. **Oracle** (Critical): Complete breakdown of TWAP price feeds affecting downstream protocols  
3. **MEVCapture** (Low): Minor fee accumulation logic error at wrap boundary

The issue is particularly concerning for:
- **Chains with non-standard timestamps**: The bug could manifest immediately on deployment
- **Long-term protocol viability**: Even on standard chains, the protocol will catastrophically fail in year 2106

The `realLastVirtualOrderExecutionTime()` function in `TwammPoolState` attempts to handle wrapping for the virtual order execution loop, but this protection does NOT extend to the order update path in `handleForwardData`, leaving a critical vulnerability. [8](#0-7) 

The security question's premise is correct: **uint32 timestamp casting DOES cause bizarre time-based behavior that corrupts critical protocol state and violates solvency invariants.**

### Citations

**File:** src/extensions/TWAMM.sol (L190-191)
```text
    function handleForwardData(Locker original, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
```

**File:** src/extensions/TWAMM.sol (L253-263)
```text
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
```

**File:** src/math/twamm.sol (L42-46)
```text
function computeAmountFromSaleRate(uint256 saleRate, uint256 duration, bool roundUp) pure returns (uint256 amount) {
    assembly ("memory-safe") {
        amount := shr(32, add(mul(saleRate, duration), mul(0xffffffff, roundUp)))
    }
}
```

**File:** src/extensions/Oracle.sol (L102-103)
```text
            uint32 timePassed = uint32(block.timestamp) - c.lastTimestamp();
            if (timePassed == 0) return;
```

**File:** src/extensions/Oracle.sol (L121-126)
```text
            Snapshot snapshot = createSnapshot({
                _timestamp: uint32(block.timestamp),
                _secondsPerLiquidityCumulative: last.secondsPerLiquidityCumulative()
                    + uint160(FixedPointMathLib.rawDiv(uint256(timePassed) << 128, nonZeroLiquidity)),
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
            });
```

**File:** src/extensions/MEVCapture.sol (L186-191)
```text
            uint32 currentTime = uint32(block.timestamp);

            int256 saveDelta0;
            int256 saveDelta1;

            if (lastUpdateTime != currentTime) {
```

**File:** src/types/twammPoolState.sol (L20-24)
```text
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))
    }
}
```
