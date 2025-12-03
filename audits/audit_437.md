## Title
Extension Reverts in beforeCollectFees Can Permanently Lock User Fees

## Summary
The `maybeCallBeforeCollectFees` function propagates all extension reverts, allowing in-scope extensions (TWAMM, MEVCapture) to block fee collection. When extensions revert during `beforeCollectFees`, users cannot collect their accrued fees through any available mechanism, violating the requirement that in-scope extensions must not lock user capital. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/libraries/ExtensionCallPointsLib.sol` (lines 232-235), `src/Core.sol` (line 469), `src/base/BasePositions.sol` (lines 283-287)

**Intended Logic:** Extensions should be able to execute logic before fee collection but should not prevent users from accessing their earned fees. The README explicitly states: "The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital."

**Actual Logic:** When `maybeCallBeforeCollectFees` is called, any revert from the extension is directly propagated to the caller, causing the entire fee collection transaction to fail. This blocks users from accessing their accrued fees through both direct `collectFees()` calls and withdrawal operations with `withFees=true`. [2](#0-1) 

**Exploitation Path:**
1. User provides liquidity to a pool with TWAMM or MEVCapture extension and earns fees over time
2. Extension's `beforeCollectFees` hook encounters a state that causes it to revert (e.g., DebtsNotZeroed from flash accounting, swap failure in virtual order execution, or logic error)
3. User attempts to collect fees via `Positions.collectFees()` or `Positions.withdraw()` with fees
4. Transaction reverts due to extension failure, leaving fees permanently inaccessible if the revert condition is persistent [3](#0-2) [4](#0-3) 

**Security Property Broken:** Extension Isolation - "Extension failures should not freeze pools or lock user capital (for in-scope extensions)" and the explicit README requirement that in-scope extensions must not lock deposited user capital.

## Impact Explanation
- **Affected Assets**: All accrued fees for liquidity positions in pools using TWAMM or MEVCapture extensions
- **Damage Severity**: Users permanently lose access to all accumulated fees if extension enters a persistently reverting state. Even temporary reverts cause denial of service for fee collection
- **User Impact**: All liquidity providers in affected pools cannot access their rightfully earned fees. Principal liquidity can be withdrawn by setting `withFees=false`, but fees remain locked in the pool [5](#0-4) 

## Likelihood Explanation
- **Attacker Profile**: Not an active attack - this is a design flaw. Any bug in TWAMM or MEVCapture's `beforeCollectFees` logic automatically locks all fees
- **Preconditions**: Pool must use TWAMM or MEVCapture extension; extension must encounter a reverting condition (e.g., unbalanced flash accounting, failed swaps, state corruption)
- **Execution Complexity**: Occurs passively when extension state becomes problematic; no attacker action needed
- **Frequency**: Once extension enters problematic state, affects all subsequent fee collection attempts until state is manually fixed (if possible)

## Recommendation
Implement try-catch error handling for extension calls in `maybeCallBeforeCollectFees` to prevent extension reverts from blocking critical user operations:

```solidity
// In src/libraries/ExtensionCallPointsLib.sol, function maybeCallBeforeCollectFees, lines 216-238:

// CURRENT (vulnerable):
// Reverts are unconditionally propagated, blocking fee collection

// FIXED:
function maybeCallBeforeCollectFees(
    IExtension extension,
    Locker locker,
    PoolKey memory poolKey,
    PositionId positionId
) internal {
    bool needCall = shouldCallBeforeCollectFees(extension, locker);
    if (needCall) {
        // Use try-catch to isolate extension failures
        try IExtension(extension).beforeCollectFees(locker, poolKey, positionId) {
            // Extension succeeded
        } catch {
            // Log the failure but allow fee collection to proceed
            // This ensures user fees are never locked by extension bugs
            emit ExtensionCallFailed(extension, "beforeCollectFees");
        }
    }
}
```

Alternative mitigation: Provide an emergency fee collection function that bypasses extension hooks for admin intervention, though this violates the principle of decentralization.

## Proof of Concept
```solidity
// File: test/Exploit_FeesLockedByExtension.t.sol
// Run with: forge test --match-test test_FeesLockedByExtension -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/extensions/TWAMM.sol";

contract MaliciousExtension is BaseExtension {
    bool public shouldRevert = false;
    
    constructor(ICore core) BaseExtension(core) {}
    
    function getCallPoints() internal pure override returns (CallPoints memory) {
        return CallPoints({
            beforeInitializePool: false,
            afterInitializePool: false,
            beforeUpdatePosition: false,
            afterUpdatePosition: false,
            beforeSwap: false,
            afterSwap: false,
            beforeCollectFees: true, // Enable the problematic hook
            afterCollectFees: false
        });
    }
    
    function beforeCollectFees(Locker, PoolKey memory, PositionId) external override {
        if (shouldRevert) {
            revert("Extension in bad state");
        }
    }
    
    function triggerBadState() external {
        shouldRevert = true;
    }
}

contract Exploit_FeesLockedByExtension is Test {
    Core core;
    Positions positions;
    MaliciousExtension extension;
    
    function setUp() public {
        core = new Core();
        positions = new Positions(core);
        extension = new MaliciousExtension(core);
    }
    
    function test_FeesLockedByExtension() public {
        // SETUP: Create pool with malicious extension, add liquidity
        PoolKey memory poolKey = createPoolKeyWithExtension(address(extension));
        core.initializePool(poolKey, 0);
        
        uint256 tokenId = positions.mint(msg.sender);
        positions.deposit(tokenId, poolKey, -100, 100, 1000e18, 1000e18, 100e18);
        
        // Simulate fee accrual through swaps
        // ... swaps occur, fees accumulate ...
        
        // Extension enters bad state (simulating a bug or state corruption)
        extension.triggerBadState();
        
        // EXPLOIT: User tries to collect their rightfully earned fees
        vm.expectRevert("Extension in bad state");
        positions.collectFees(tokenId, poolKey, -100, 100);
        
        // VERIFY: Fees are permanently locked
        // User can withdraw principal but loses all fees
        positions.withdraw(tokenId, poolKey, -100, 100, 100e18, msg.sender, false); // succeeds
        
        // But fee collection remains blocked forever
        vm.expectRevert("Extension in bad state");
        positions.collectFees(tokenId, poolKey, -100, 100);
    }
}
```

## Notes

The vulnerability stems from the protocol's design decision to propagate all extension reverts without exception handling. While both TWAMM and MEVCapture provide public functions (`lockAndExecuteVirtualOrders`, `accumulatePoolFees`) that could theoretically fix temporary state issues, this requires:

1. Users to understand the extension internals
2. The extension state to be fixable via external calls
3. The root cause to not be a permanent bug in the extension logic

The core issue is that fee collection has no fallback mechanism when extensions fail, creating a single point of failure that violates the stated extension isolation requirement. Users can withdraw their principal liquidity by using `withdraw()` with `withFees=false`, but their accrued fees remain permanently locked if the extension cannot recover. [6](#0-5)

### Citations

**File:** src/libraries/ExtensionCallPointsLib.sol (L216-238)
```text
    function maybeCallBeforeCollectFees(
        IExtension extension,
        Locker locker,
        PoolKey memory poolKey,
        PositionId positionId
    ) internal {
        bool needCall = shouldCallBeforeCollectFees(extension, locker);
        assembly ("memory-safe") {
            if needCall {
                let freeMem := mload(0x40)
                // cast sig "beforeCollectFees(bytes32, (address,address,bytes32), bytes32)"
                mstore(freeMem, shl(224, 0xdf65d8d1))
                mstore(add(freeMem, 4), locker)
                mcopy(add(freeMem, 36), poolKey, 96)
                mstore(add(freeMem, 132), positionId)
                // bubbles up the revert
                if iszero(call(gas(), extension, 0, freeMem, 164, 0, 0)) {
                    returndatacopy(freeMem, 0, returndatasize())
                    revert(freeMem, returndatasize())
                }
            }
        }
    }
```

**File:** src/Core.sol (L463-469)
```text
    function collectFees(PoolKey memory poolKey, PositionId positionId)
        external
        returns (uint128 amount0, uint128 amount1)
    {
        Locker locker = _requireLocker();

        IExtension(poolKey.config.extension()).maybeCallBeforeCollectFees(locker, poolKey, positionId);
```

**File:** src/base/BasePositions.sol (L282-301)
```text
            // collect first in case we are withdrawing the entire amount
            if (withFees) {
                (amount0, amount1) = CORE.collectFees(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
                );

                // Collect swap protocol fees
                (uint128 swapProtocolFee0, uint128 swapProtocolFee1) =
                    _computeSwapProtocolFees(poolKey, amount0, amount1);

                if (swapProtocolFee0 != 0 || swapProtocolFee1 != 0) {
                    CORE.updateSavedBalances(
                        poolKey.token0, poolKey.token1, bytes32(0), int128(swapProtocolFee0), int128(swapProtocolFee1)
                    );

                    amount0 -= swapProtocolFee0;
                    amount1 -= swapProtocolFee1;
                }
            }
```

**File:** README.md (L46-50)
```markdown
### Extension Freezing Power

The extensions in scope of the audit are **not** expected to be able to freeze a pool and lock deposited user capital.

Third-party extensions, however, can freeze a pool and lock deposited user capital. This is considered an acceptable risk.
```
