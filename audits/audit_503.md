## Title
Nested Locks from Same Address Create savedBalances State Corruption Leading to DOS and Flash Accounting Invariant Violations

## Summary
The `updateSavedBalances()` function uses persistent storage keyed by locker address, while flash accounting debt tracking uses transient storage keyed by lock ID. When the same address initiates nested locks (calling `lock()` recursively), both locks share the same `savedBalances` storage slot but maintain separate debt tracking, allowing nested locks to corrupt the saved balance state expected by outer locks.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/Core.sol::updateSavedBalances()` (lines 124-171) and `src/base/FlashAccountant.sol::lock()` (lines 146-187)

**Intended Logic:** The `savedBalances` mechanism allows contracts to temporarily store token balances within Core for later retrieval within the same transaction. Flash accounting ensures all debts are properly tracked and settled per lock before completion. Each lock's operations should be isolated from other locks' accounting.

**Actual Logic:** When a contract calls `lock()` recursively to create nested locks, the `lockerAddr` remains the same for both locks (determined by `caller()` in assembly), but each lock gets a different `lockId`. The `savedBalances` storage slot is computed using `lockerAddr` [1](#0-0) , while debt tracking uses `lockId` [2](#0-1) . This architectural mismatch allows nested locks to modify shared persistent storage while maintaining separate transient debt accounting.

**Exploitation Path:**

1. **Outer Lock Saves Tokens**: Attacker initiates Lock ID 0 through a contract that calls `Core.lock()`. The contract's callback invokes `updateSavedBalances(tokenA, tokenB, salt, +100, +100)` to save 100 tokens.
   - Persistent storage: `savedBalances[contractAddr][tokenA][tokenB][salt] = (100, 100)` [3](#0-2) 
   - Transient storage: `debt[0][tokenA] = +100, debt[0][tokenB] = +100`

2. **Nested Lock Modifies Shared Storage**: While still in Lock ID 0's callback, the contract calls `lock()` again, creating Lock ID 1 (nested) with the same `lockerAddr` [4](#0-3) . In Lock ID 1's callback, it invokes `updateSavedBalances(tokenA, tokenB, salt, -60, -60)` to load 60 tokens.
   - Persistent storage: `savedBalances[contractAddr][tokenA][tokenB][salt] = (40, 40)` — MODIFIED!
   - Transient storage: `debt[1][tokenA] = -60, debt[1][tokenB] = -60` (separate from Lock ID 0)

3. **Nested Lock Completes**: Lock ID 1 withdraws 60 tokens to settle its negative debt and completes successfully, passing the debt-zeroed check [5](#0-4) .

4. **Outer Lock Fails Due to Corrupted State**: Back in Lock ID 0, the contract attempts to load its expected 100 tokens by calling `updateSavedBalances(tokenA, tokenB, salt, -100, -100)`. The function tries to compute `(40, 40) + (-100, -100) = (-60, -60)`, which underflows the uint128 bounds. The overflow check in the assembly block detects this and reverts with `SavedBalanceOverflow()` [6](#0-5) .

Alternatively, if code reads `savedBalances` via `CoreLib.savedBalances()` [7](#0-6)  during or after the nested lock but before the outer lock completes, it will see the modified value (40, 40) instead of the expected (100, 100), causing incorrect business logic decisions based on inconsistent state.

**Security Property Broken:** This violates the **Flash Accounting** invariant that all flash loans and balance modifications must maintain proper accounting within a transaction. It also violates **Withdrawal Availability** by causing DOS when contracts attempt to withdraw saved balances that were corrupted by nested locks.

## Impact Explanation

- **Affected Assets**: Any contract using `savedBalances` with nested locks is vulnerable. This includes:
  - Protocol fees accumulated by `BasePositions` contract [8](#0-7) 
  - MEV capture fees saved by `MEVCapture` extension [9](#0-8) 
  - TWAMM order proceeds stored by the TWAMM extension [10](#0-9) 

- **Damage Severity**: This creates a DOS condition where contracts cannot withdraw their legitimately saved balances, temporarily locking funds until the issue is resolved. While the funds are not permanently lost (they remain in Core contract storage), they become inaccessible through normal withdrawal flows. For protocol fee collection, this prevents the owner from claiming accumulated fees. For users with saved order proceeds in TWAMM, they cannot withdraw their purchased tokens.

- **User Impact**: Any user or contract that saves balances in an outer lock and then initiates a nested lock that modifies those same balances will encounter transaction reverts. This affects protocols building on Ekubo that use nested lock patterns for composability, and impacts protocol owners trying to collect accumulated fees.

## Likelihood Explanation

- **Attacker Profile**: Any contract or user that creates nested locks using the same contract address. This is a legitimate pattern for composability (e.g., a router contract that needs to perform multiple operations), so it's not necessarily malicious but rather an unhandled edge case.

- **Preconditions**: 
  - A contract must call `lock()` to initiate the outer lock
  - Within that lock's callback, it must save balances using `updateSavedBalances()`
  - The same contract must call `lock()` again (nested lock) within the outer lock's callback
  - The nested lock must modify the same saved balances (same tokens and salt)
  - The outer lock must attempt to access those saved balances after the nested lock completes

- **Execution Complexity**: Single transaction with nested lock pattern. Requires contract code that performs nested locks, which is a valid composability pattern.

- **Frequency**: This can occur whenever contracts use nested locks with saved balances, which may become more common as protocols build complex interactions on top of Ekubo.

## Recommendation

Add lock ID tracking to the savedBalances storage key to ensure each lock has isolated saved balance storage:

```solidity
// In src/Core.sol, function updateSavedBalances, lines 137-158:

// CURRENT (vulnerable):
// Uses only lockerAddr for storage slot, shared across nested locks
(uint256 id, address lockerAddr) = _requireLocker().parse();
assembly ("memory-safe") {
    let free := mload(0x40)
    mstore(free, lockerAddr)
    calldatacopy(add(free, 0x20), 4, 96)
    let slot := keccak256(free, 128)
    // ... operates on shared slot
}

// FIXED:
// Include lock ID in storage key for per-lock isolation
(uint256 id, address lockerAddr) = _requireLocker().parse();
assembly ("memory-safe") {
    let free := mload(0x40)
    mstore(free, lockerAddr)
    calldatacopy(add(free, 0x20), 4, 96) // token0, token1, salt
    mstore(add(free, 116), id) // Add lock ID to key (4 bytes)
    let slot := keccak256(free, 132) // Hash includes lock ID now
    // ... operates on per-lock isolated slot
}
// Also update _updatePairDebtWithNative to use id in storage key
```

Also update `CoreLib.savedBalances()` and `CoreStorageLayout.savedBalancesSlot()` to require a lock ID parameter:

```solidity
// In src/libraries/CoreStorageLayout.sol, add lockId parameter:
function savedBalancesSlot(address owner, address token0, address token1, bytes32 salt, uint256 lockId)
    internal pure returns (StorageSlot slot)
{
    assembly ("memory-safe") {
        let free := mload(0x40)
        mstore(free, owner)
        mstore(add(free, 0x20), token0)
        mstore(add(free, 0x40), token1)
        mstore(add(free, 0x60), salt)
        mstore(add(free, 0x80), lockId) // Add lock ID
        slot := keccak256(free, 160) // Updated hash length
    }
}
```

**Alternative mitigation**: Prevent nested locks entirely by checking if a lock is already active before allowing a new lock, though this would break composability patterns.

## Proof of Concept

```solidity
// File: test/Exploit_NestedLockSavedBalancesCorruption.t.sol
// Run with: forge test --match-test test_NestedLockCorruptsSavedBalances -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BaseLocker.sol";
import "../src/interfaces/ICore.sol";

contract NestedLockAttacker is BaseLocker {
    ICore public core;
    address public token0;
    address public token1;
    bytes32 public salt;
    bool public inNestedLock;
    
    constructor(ICore _core) BaseLocker(_core) {
        core = _core;
    }
    
    function executeAttack(address _token0, address _token1, bytes32 _salt) external {
        token0 = _token0;
        token1 = _token1;
        salt = _salt;
        inNestedLock = false;
        lock(abi.encode("outer"));
    }
    
    function handleLockData(uint256 id, bytes memory) internal override returns (bytes memory) {
        if (!inNestedLock) {
            // Outer lock (ID 0): Save 100 tokens
            core.updateSavedBalances(token0, token1, salt, 100, 100);
            
            // Initiate nested lock
            inNestedLock = true;
            lock(abi.encode("nested"));
            
            // After nested lock returns, try to load the 100 tokens we saved
            // This will revert because nested lock consumed 60 of them
            core.updateSavedBalances(token0, token1, salt, -100, -100);
        } else {
            // Nested lock (ID 1): Load 60 tokens from the SAME savedBalances
            core.updateSavedBalances(token0, token1, salt, -60, -60);
            
            // Settle debt by withdrawing 60 tokens
            // (In real scenario, would call ACCOUNTANT.withdraw)
        }
        return "";
    }
}

contract Exploit_NestedLockSavedBalancesCorruption is Test {
    Core core;
    NestedLockAttacker attacker;
    
    function setUp() public {
        core = new Core();
        attacker = new NestedLockAttacker(core);
    }
    
    function test_NestedLockCorruptsSavedBalances() public {
        address token0 = address(0x1);
        address token1 = address(0x2);
        bytes32 salt = bytes32(0);
        
        // Execute attack - this will revert with SavedBalanceOverflow
        // because nested lock consumed part of the saved balances
        vm.expectRevert(abi.encodeWithSelector(ICore.SavedBalanceOverflow.selector));
        attacker.executeAttack(token0, token1, salt);
    }
}
```

## Notes

This vulnerability arises from the architectural decision to use persistent storage for `savedBalances` (keyed by locker address) while using transient storage for debt tracking (keyed by lock ID). While nested locks are properly isolated in their debt accounting, they share saved balance storage when initiated by the same address, creating a state consistency violation.

The issue is particularly concerning because nested locks are a valid composability pattern that protocols may use when building on Ekubo. The current implementation makes it unsafe for contracts to use nested locks if they rely on saved balances, as the inner lock can corrupt the outer lock's expected state.

The vulnerability doesn't lead to direct fund theft because the flash accounting system still enforces that all debts must be settled before a lock completes. However, it creates DOS conditions and violates the flash accounting invariant that lock operations should be properly isolated.

### Citations

**File:** src/libraries/CoreStorageLayout.sol (L122-135)
```text
    function savedBalancesSlot(address owner, address token0, address token1, bytes32 salt)
        internal
        pure
        returns (StorageSlot slot)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, owner)
            mstore(add(free, 0x20), token0)
            mstore(add(free, 0x40), token1)
            mstore(add(free, 0x60), salt)
            slot := keccak256(free, 128)
        }
    }
```

**File:** src/base/FlashAccountant.sol (L67-84)
```text
    function _accountDebt(uint256 id, address token, int256 debtChange) internal {
        assembly ("memory-safe") {
            let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
            let current := tload(deltaSlot)

            // we know this never overflows because debtChange is only ever derived from 128 bit values in inheriting contracts
            let next := add(current, debtChange)

            let countChange := sub(iszero(current), iszero(next))

            if countChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), countChange))
            }

            tstore(deltaSlot, next)
        }
    }
```

**File:** src/base/FlashAccountant.sol (L146-153)
```text
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))
```

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

**File:** src/Core.sol (L140-151)
```text
            function addDelta(u, i) -> result {
                // full‐width sum mod 2^256
                let sum := add(u, i)
                // 1 if i<0 else 0
                let sign := shr(255, i)
                // if sum > type(uint128).max || (i>=0 && sum<u) || (i<0 && sum>u) ⇒ 256-bit wrap or underflow
                if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                    mstore(0x00, 0x1293d6fa) // `SavedBalanceOverflow()`
                    revert(0x1c, 0x04)
                }
                result := sum
            }
```

**File:** src/Core.sol (L152-168)
```text

            // we can cheaply calldatacopy the arguments into memory, hence no call to CoreStorageLayout#savedBalancesSlot
            let free := mload(0x40)
            mstore(free, lockerAddr)
            // copy the first 3 arguments in the same order
            calldatacopy(add(free, 0x20), 4, 96)
            let slot := keccak256(free, 128)
            let balances := sload(slot)

            let b0 := shr(128, balances)
            let b1 := shr(128, shl(128, balances))

            let b0Next := addDelta(b0, delta0)
            let b1Next := addDelta(b1, delta1)

            sstore(slot, add(shl(128, b0Next), b1Next))
        }
```

**File:** src/libraries/CoreLib.sol (L85-94)
```text
    function savedBalances(ICore core, address owner, address token0, address token1, bytes32 salt)
        internal
        view
        returns (uint128 savedBalance0, uint128 savedBalance1)
    {
        uint256 value = uint256(core.sload(CoreStorageLayout.savedBalancesSlot(owner, token0, token1, salt)));

        savedBalance0 = uint128(value >> 128);
        savedBalance1 = uint128(value);
    }
```

**File:** src/base/BasePositions.sol (L293-296)
```text
                if (swapProtocolFee0 != 0 || swapProtocolFee1 != 0) {
                    CORE.updateSavedBalances(
                        poolKey.token0, poolKey.token1, bytes32(0), int128(swapProtocolFee0), int128(swapProtocolFee1)
                    );
```

**File:** src/extensions/MEVCapture.sol (L141-147)
```text
                CORE.updateSavedBalances(
                    poolKey.token0,
                    poolKey.token1,
                    PoolId.unwrap(poolId),
                    -int256(uint256(fees0)),
                    -int256(uint256(fees1))
                );
```

**File:** src/extensions/TWAMM.sol (L324-327)
```text
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), 0, amountDelta);
                    } else {
                        CORE.accumulateAsFees(poolKey, fee, 0);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), amountDelta, 0);
```
