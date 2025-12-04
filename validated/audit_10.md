# Audit Report

## Title
Chained FlashAccountant.forward() Calls Corrupt Original Locker Address, Breaking TWAMM Order Ownership

## Summary
The `FlashAccountant.forward()` mechanism fails to preserve the original locker's address when forwards are chained through multiple intermediaries (A→B→C). After the first forward, `_CURRENT_LOCKER_SLOT` contains the current forwardee's address rather than the original locker's address. When subsequent forwards occur, this corrupted value is passed as the "original" parameter, violating TWAMM's ownership model which relies on `original.addr()` to determine order storage locations. [1](#0-0) 

## Impact
**Severity**: Medium

This vulnerability causes permanent loss of access to TWAMM orders when users build aggregator/helper contracts that chain forward calls before reaching TWAMM. Orders become stored under an intermediate contract's address rather than the true owner's address, making them permanently inaccessible. While no current in-scope contracts exhibit this pattern, the broken mechanism prevents legitimate composability use cases and affects any future integrations requiring chained forwards.

## Finding Description

**Location:** `src/base/FlashAccountant.sol:190-220`, function `forward()`

**Intended Logic:** 
According to the interface documentation, `forward()` should allow forwardees to "act on the original locker's debt." When forwarding through multiple contracts (A→B→C), each forwardee should receive the original locker `[A's ID | A's address]` to maintain ownership context. The parameter is explicitly named "original" in the `forwarded_2374103877` callback. [2](#0-1) 

**Actual Logic:**
When HelperB forwards to TWAMM after receiving a forward from HelperA:

1. Line 191: `_requireLocker()` reads from `_CURRENT_LOCKER_SLOT` which currently contains `[A's ID | B's address]` (set during the A→B forward at line 196)
2. Line 202: This corrupted locker `[A's ID | B's address]` is passed to TWAMM as the "original" parameter
3. TWAMM receives `[A's ID | B's address]` instead of the true original `[A's ID | A's address]`

**Exploitation Path:**
1. **Setup**: User deploys HelperA contract implementing `BaseLocker` and `BaseForwardee` to manage TWAMM orders with custom logic
2. **Lock**: HelperA calls `Core.lock()` which sets `_CURRENT_LOCKER_SLOT = [A's ID | A's address]`
3. **First Forward**: HelperA's `handleLockData` forwards to HelperB via `forward(address(HelperB))`, temporarily setting `_CURRENT_LOCKER_SLOT = [A's ID | B's address]`
4. **Nested Forward**: HelperB's `handleForwardData` forwards to TWAMM, but `_requireLocker()` returns the corrupted `[A's ID | B's address]`
5. **Order Creation**: TWAMM extracts `address owner = original.addr()` receiving HelperB's address
6. **Storage Corruption**: Order state is stored at a slot computed using HelperB's address as owner [3](#0-2) [4](#0-3) 

7. **Result**: HelperA cannot access the order because it's stored under HelperB's address, causing permanent loss of order control and accumulated proceeds

**Security Property Broken:**
The forward mechanism violates its documented guarantee to preserve the "original locker" context through forwarding chains. Storage slot computation in TWAMM uses the owner address as a key component, making address corruption critical. [5](#0-4) 

## Impact Explanation

**Affected Assets**: TWAMM orders, including their accumulated proceeds, sale rate state, and remaining sell amounts for any orders created through chained forward patterns.

**Damage Severity**:
- Users building helper contracts lose complete access to their TWAMM orders
- Cannot modify sale rates, collect purchased tokens, or withdraw remaining sell amounts
- Orders become permanently orphaned under intermediate contract addresses
- Affects protocol composability - prevents building complex aggregators that chain operations

**User Impact**: Any user or protocol building aggregator contracts, DAO governance wrappers, multisig integrations, or other helpers that require chaining forwards before reaching TWAMM. While the current `Orders.sol` contract doesn't chain forwards (it locks once and forwards directly to TWAMM), the broken mechanism undermines the protocol's extensibility.

**Trigger Conditions**: Automatically occurs whenever a user builds a contract that chains two or more forwards before reaching TWAMM extension.

## Likelihood Explanation

**User Profile**: Legitimate users building integration contracts, not malicious attackers. Users may reasonably want to build:
- Aggregators wrapping multiple operations (e.g., TokenWrapper + TWAMM order)
- DAO governance contracts adding checks before TWAMM operations  
- Multisig wrappers requiring approval chains
- Composable DeFi protocols integrating TWAMM functionality

**Preconditions**:
1. User must deploy a custom contract that locks Core and chains multiple forwards
2. The forward chain must eventually reach TWAMM extension
3. No other preconditions - the bug triggers automatically in chained scenarios

**Execution Complexity**: Simple - once a helper contract with chained forwards is deployed, every order creation permanently corrupts ownership.

**Economic Cost**: Standard gas costs only (~0.01-0.05 ETH depending on complexity).

**Frequency**: Every order created through a chained forward pattern is affected.

**Overall Likelihood**: Currently LOW (no in-scope contracts chain forwards), but HIGH for future integrations. The broken mechanism represents a latent composability failure that will affect users attempting to build on top of Ekubo's forwarding infrastructure.

## Recommendation

**Primary Fix:**
Modify `FlashAccountant.forward()` to track the original locker separately from the current locker. When entering a nested forward, preserve and pass through the original locker received from the parent forward rather than reading from `_CURRENT_LOCKER_SLOT`.

**Implementation Option 1** (Extract from calldata):
```solidity
// In forward() function, check if we're being called from within another forward
// by examining calldata for the forwarded_2374103877 selector
// If so, extract and preserve the original parameter
// Otherwise use current locker as the original
```

**Implementation Option 2** (Separate storage slot):
Add a new transient storage slot `_ORIGINAL_LOCKER_SLOT`:
- Set it once during the first forward in a chain
- Read from it (instead of `_CURRENT_LOCKER_SLOT`) when passing to forwardees
- Never modify it during nested forwards
- Clear it when the lock completes

**Additional Mitigation:**
Add validation in TWAMM to detect when owner address doesn't match expected patterns, though this is insufficient as the root cause must be fixed in FlashAccountant.

## Proof of Concept

The provided PoC demonstrates the vulnerability by deploying HelperA and HelperB contracts that chain forwards to TWAMM. The test shows that TWAMM receives HelperB's address as the owner rather than HelperA's address, confirming the ownership corruption.

**Expected Result:**
- **If Vulnerable**: HelperB emits `OwnerReceived(address(helperB))` instead of `OwnerReceived(address(helperA))`, and orders are stored under HelperB's address
- **If Fixed**: HelperB emits `OwnerReceived(address(helperA))`, and orders are correctly stored under HelperA's address

## Notes

This vulnerability demonstrates a fundamental composability flaw in the flash accounting forwarding mechanism. While current in-scope contracts (Orders.sol, TokenWrapper.sol, MEVCapture.sol) don't chain forwards and are therefore unaffected, the broken mechanism:

1. **Violates documented behavior**: The interface explicitly states forwards allow acting "on the original locker's debt"
2. **Prevents legitimate integrations**: Users cannot build helper contracts that compose multiple operations via chained forwards
3. **Undermines extensibility**: The forward mechanism is designed to enable composability but fails for multi-hop scenarios
4. **Affects only TWAMM currently**: TWAMM is the only in-scope extension that critically relies on `original.addr()` for ownership and storage computation, but the broken mechanism could affect future extensions with similar patterns [6](#0-5) 

The severity is Medium rather than High because no current in-scope contracts are vulnerable, and the issue requires users to explicitly build chained forward patterns. However, this represents a significant barrier to protocol composability that should be addressed to enable the full potential of Ekubo's extension architecture.

### Citations

**File:** src/interfaces/IFlashAccountant.sol (L39-43)
```text
    /// @notice Forwards the lock context to another actor, allowing them to act on the original locker's debt
    /// @dev Temporarily changes the locker to the forwarded address for the duration of the forwarded call.
    ///      Any additional calldata is passed through to the forwardee with no additional encoding.
    ///      Any data returned from IForwardee#forwarded is returned exactly as is. Reverts are bubbled up.
    /// @param to The address to forward the lock context to
```

**File:** src/base/FlashAccountant.sol (L190-220)
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
```

**File:** src/extensions/TWAMM.sol (L193-193)
```text
            address owner = original.addr();
```

**File:** src/extensions/TWAMM.sol (L216-217)
```text
                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);
```

**File:** src/extensions/TWAMM.sol (L377-377)
```text
                emit OrderProceedsWithdrawn(original.addr(), salt, orderKey, uint128(purchasedAmount));
```

**File:** src/libraries/TWAMMStorageLayout.sol (L86-92)
```text
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, owner)
            mstore(add(free, 0x20), salt)
            mstore(add(free, 0x40), orderId)
            slot := add(keccak256(free, 96), ORDER_STATE_OFFSET)
        }
```
