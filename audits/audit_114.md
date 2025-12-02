## Title
Integer Boundary Asymmetry in TokenWrapper Causes Permanent Token Lock for Amounts Above type(int128).max

## Summary
TokenWrapper.handleForwardData() allows wrapping amounts up to 2^127 (type(int128).max + 1) because the negation fits within int128 bounds, but unwrapping these tokens permanently fails as the positive value exceeds int128 limits. Users who wrap exactly 2^127 tokens lose them permanently, violating the "Withdrawal Availability" invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/TokenWrapper.sol` - `handleForwardData()` function [1](#0-0) 

**Intended Logic:** The TokenWrapper allows users to wrap underlying tokens into time-locked wrapper tokens. According to the comments, "the specified amount of this wrapper token will be credited to the locker and the same amount of underlying will be debited" for wrapping, and users should be able to unwrap after the unlock time.

**Actual Logic:** The function uses `SafeCastLib.toInt128(-amount)` at line 179 for both wrapping (positive amount) and unwrapping (negative amount). Due to two's complement representation:
- When wrapping with amount = 2^127: `-amount = -2^127 = type(int128).min` (valid int128) ✓
- When unwrapping with amount = -2^127: `-(-amount) = 2^127 > type(int128).max` (overflow) ✗

**Exploitation Path:**
1. User creates a locker contract and calls `ACCOUNTANT.forward(address(wrapper), abi.encode(int256(2^127)))` to wrap exactly 2^127 tokens
2. TokenWrapper.handleForwardData executes with amount = 2^127 (positive)
3. Line 171-177: `updateSavedBalances` succeeds as 2^127 fits in uint128
4. Line 179: `SafeCastLib.toInt128(-2^127)` succeeds as type(int128).min = -2^127 is valid
5. Wrap completes, user receives 2^127 wrapper tokens
6. After unlock time, user attempts to unwrap by calling `ACCOUNTANT.forward(address(wrapper), abi.encode(-int256(2^127)))`
7. Line 167-169: Unlock time check passes
8. Line 171-177: `updateSavedBalances` with delta0 = -2^127 would succeed
9. Line 179: `SafeCastLib.toInt128(-(-2^127))` = `SafeCastLib.toInt128(2^127)` REVERTS (2^127 > type(int128).max by 1)
10. Unwrap permanently fails - tokens locked forever

**Security Property Broken:** Violates the "Withdrawal Availability" invariant: "All positions MUST be withdrawable at any time"

## Impact Explanation
- **Affected Assets**: Any ERC20 token wrapped via TokenWrapper with amounts at the int128 boundary (2^127 = 170,141,183,460,469,231,731,687,303,715,884,105,728 units)
- **Damage Severity**: 100% permanent loss of wrapped tokens. Tokens become permanently locked in Core contract with no recovery mechanism even after unlock time expires
- **User Impact**: Any user (whether intentionally or accidentally) wrapping exactly 2^127 tokens loses them permanently. While the amount is large, for tokens with high decimals or low value, this could be a realistic scenario

## Likelihood Explanation
- **Attacker Profile**: Any user with tokens to wrap; no special privileges required. Can also be triggered accidentally by users dealing with large amounts
- **Preconditions**: 
  - TokenWrapper deployed with any underlying token
  - User has 2^127 units of the underlying token to wrap
  - For 18-decimal tokens, this is ~170 million tokens
- **Execution Complexity**: Single wrap transaction succeeds, but all subsequent unwrap attempts fail permanently
- **Frequency**: Can occur once per user who wraps this specific amount. The issue is deterministic and permanent

## Recommendation

Add explicit validation to enforce that amounts stay within safe int128 bounds:

```solidity
// In src/TokenWrapper.sol, function handleForwardData, add after line 164:

// CURRENT (vulnerable):
// (int256 amount) = abi.decode(data, (int256));
// 
// // unwrap
// if (amount < 0) {
//     if (block.timestamp < UNLOCK_TIME) revert TooEarly();
// }

// FIXED:
(int256 amount) = abi.decode(data, (int256));

// Enforce symmetric int128 bounds to ensure both wrap and unwrap can succeed
// For wrap (positive): -amount must fit in int128 → amount <= 2^127 - 1
// For unwrap (negative): -amount must fit in int128 → amount >= -(2^127 - 1)
if (amount > 0) {
    if (amount > uint256(uint128(type(int128).max))) revert AmountTooLarge();
} else if (amount < 0) {
    if (block.timestamp < UNLOCK_TIME) revert TooEarly();
    // Ensure -amount fits in int128 for unwrapping
    if (amount < -int256(uint256(uint128(type(int128).max)))) revert AmountTooLarge();
}
```

Add a new custom error:
```solidity
error AmountTooLarge();
```

Alternative mitigation: Use int256 for debt tracking instead of int128, but this would require changes to the FlashAccountant interface and is more complex.

## Proof of Concept

```solidity
// File: test/Exploit_TokenWrapperBoundary.t.sol
// Run with: forge test --match-test test_TokenWrapperBoundary -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/TokenWrapper.sol";
import "../src/TokenWrapperFactory.sol";
import "../src/Core.sol";
import "./TestToken.sol";
import "../src/base/BaseLocker.sol";
import {ICore} from "../src/interfaces/ICore.sol";
import {FlashAccountantLib} from "../src/libraries/FlashAccountantLib.sol";

contract ExploitLocker is BaseLocker {
    using FlashAccountantLib for *;
    
    TokenWrapper public wrapper;
    bool public wrapPhase;
    
    constructor(ICore core) BaseLocker(core) {}
    
    function setWrapper(TokenWrapper _wrapper) external {
        wrapper = _wrapper;
    }
    
    function wrapBoundary() external {
        wrapPhase = true;
        lock(abi.encode(int256(uint256(uint128(type(int128).max)) + 1)));
    }
    
    function unwrapBoundary() external {
        wrapPhase = false;
        lock(abi.encode(-int256(uint256(uint128(type(int128).max)) + 1)));
    }
    
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        int256 amount = abi.decode(data, (int256));
        
        if (wrapPhase) {
            // Wrap: forward to wrapper
            ACCOUNTANT.forward(address(wrapper), abi.encode(amount));
            // Withdraw wrapper tokens to this contract
            ACCOUNTANT.withdraw(address(wrapper), address(this), uint128(uint256(amount)));
            // Pay underlying tokens
            ACCOUNTANT.payFrom(address(this), address(wrapper.UNDERLYING_TOKEN()), uint256(amount));
        } else {
            // Unwrap: forward to wrapper
            ACCOUNTANT.forward(address(wrapper), abi.encode(amount));
            // Should fail here due to SafeCastLib overflow
        }
        
        return "";
    }
}

contract Exploit_TokenWrapperBoundary is Test {
    Core core;
    TokenWrapperFactory factory;
    TestToken underlying;
    TokenWrapper wrapper;
    ExploitLocker exploiter;
    
    function setUp() public {
        core = new Core();
        factory = new TokenWrapperFactory(core);
        underlying = new TestToken(address(this));
        wrapper = factory.deployWrapper(underlying, 0); // unlocked immediately
        exploiter = new ExploitLocker(core);
        exploiter.setWrapper(wrapper);
    }
    
    function test_TokenWrapperBoundary() public {
        // SETUP: Mint maximum boundary amount to exploiter
        uint256 boundaryAmount = uint256(uint128(type(int128).max)) + 1; // 2^127
        underlying.mint(address(exploiter), boundaryAmount);
        
        // Approve exploiter to spend
        vm.prank(address(exploiter));
        underlying.approve(address(core), boundaryAmount);
        
        // EXPLOIT: Wrap boundary amount succeeds
        exploiter.wrapBoundary();
        
        assertEq(wrapper.balanceOf(address(exploiter)), boundaryAmount, "Wrap succeeded");
        assertEq(underlying.balanceOf(address(core)), boundaryAmount, "Underlying transferred");
        
        // VERIFY: Unwrap fails permanently due to int128 overflow
        vm.expectRevert(); // SafeCastLib.Overflow() or similar
        exploiter.unwrapBoundary();
        
        // Tokens are permanently locked
        assertEq(wrapper.balanceOf(address(exploiter)), boundaryAmount, "Wrapper tokens still held");
        assertEq(underlying.balanceOf(address(core)), boundaryAmount, "Underlying still in Core");
        // No way to recover the underlying tokens
    }
}
```

### Citations

**File:** src/TokenWrapper.sol (L163-182)
```text
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory) {
        (int256 amount) = abi.decode(data, (int256));

        // unwrap
        if (amount < 0) {
            if (block.timestamp < UNLOCK_TIME) revert TooEarly();
        }

        CORE.updateSavedBalances({
            token0: address(UNDERLYING_TOKEN),
            token1: address(type(uint160).max),
            salt: bytes32(0),
            delta0: amount,
            delta1: 0
        });

        CORE.updateDebt(SafeCastLib.toInt128(-amount));

        return bytes("");
    }
```
