# NoVulnerability found for this question.

After conducting a thorough investigation of the security question regarding debt accumulation when multicall batches multiple lock calls with overlapping token operations, I have analyzed the complete execution flow from Router through FlashAccountant to Core and found no exploitable vulnerability.

## Investigation Summary

**Lock Mechanism Analysis:**
The `lock()` function creates isolated lock contexts with unique IDs for each lock cycle. [1](#0-0)  Each lock ID gets incremented for nested locks and is restored after completion, with mandatory debt settlement verification before returning.

**Debt Isolation Verification:**
Debts are tracked per (lockID, token) pair in transient storage using the formula `_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET + (id << 160) + token`. [2](#0-1)  This ensures complete isolation between different lock IDs, preventing debt leakage across lock cycles.

**Settlement Enforcement:**
At lock completion, the system checks that `nonzeroDebtCount` equals zero for that specific lock ID, ensuring all debts are properly settled. [3](#0-2)  This prevents any lock from completing with outstanding debts.

**msg.value Handling:**
When Router forwards ETH to Core via `CoreLib.swap()`, it uses the `call` opcode with a specific value parameter. [4](#0-3)  The msg.value inside Core.swap reflects only the ETH sent in that particular call, not the original multicall msg.value, preventing double-counting of native token payments.

**Multicall Execution Pattern:**
Router's multicall executes delegatecalls sequentially, not in parallel. [5](#0-4)  Each swap completes its entire lock cycle (including debt settlement) before the next swap begins, eliminating the possibility of concurrent debt accumulation issues.

**Lock ID Reuse Safety:**
While lock ID 0 is reused for sequential locks in a multicall, this is safe because the settlement check guarantees all debt values are zeroed before the lock completes. Transient storage slots are reused with clean (zero) values for the next lock cycle.

## Notes

The flash accounting system robustly enforces the critical invariant that "all flash loans must be repaid within the same transaction with proper accounting." The combination of isolated debt tracking per lock ID, mandatory settlement verification, and sequential execution in multicall prevents incorrect debt accumulation across multiple lock calls, even with overlapping token operations.

### Citations

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

**File:** src/base/FlashAccountant.sol (L146-187)
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
    }
```

**File:** src/libraries/CoreLib.sol (L123-148)
```text
    function swap(ICore core, uint256 value, PoolKey memory poolKey, SwapParameters params)
        internal
        returns (PoolBalanceUpdate balanceUpdate, PoolState stateAfter)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)

            // the function selector of swap is 0
            mstore(free, 0)

            // Copy PoolKey
            mcopy(add(free, 4), poolKey, 96)

            // Add SwapParameters
            mstore(add(free, 100), params)

            if iszero(call(gas(), core, value, free, 132, free, 64)) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Extract return values - balanceUpdate is packed (delta1 << 128 | delta0)
            balanceUpdate := mload(free)
            stateAfter := mload(add(free, 32))
        }
    }
```

**File:** src/base/PayableMulticallable.sol (L12-19)
```text
    /// @notice Executes multiple calls in a single transaction with native token support
    /// @dev Overrides the base multicall function to make it payable, allowing ETH to be sent
    ///      Uses direct return to avoid unnecessary memory copying for gas efficiency
    /// @param data Array of encoded function call data to execute
    /// @return results Array of return data from each function call
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }
```
