# NoVulnerability found for this question.

After deep investigation of the Router settlement logic, Core swap execution, flash accounting system, and extension interaction patterns, I found that **the flash accounting system cannot be bypassed** even if a malicious extension returns zero deltas.

## Key Findings

### 1. Flash Accounting Enforcement

The Router's settlement logic at lines 122-127 relies on the `balanceUpdate` returned from `_swap()`: [1](#0-0) 

However, even if a malicious extension using the forwarding pattern modifies this return value to zero deltas, the fundamental debt accounting is already recorded by `Core.swap()` via `_updatePairDebtWithNative()`: [2](#0-1) 

### 2. Lock Completion Check

The critical protection is in the lock completion logic, which verifies that all debts are zeroed: [3](#0-2) 

This check occurs **after** the callback returns, regardless of what the extension returns to the Router. If debt remains unsettled, the transaction reverts with `DebtsNotZeroed`.

### 3. Forwarding Mechanism

During forwarding, the extension temporarily becomes the locker with the **same lock ID** as the original caller: [4](#0-3) 

This means any debt accrued during the forwarded call (like from `Core.swap()`) is tracked under the same ID that will be checked at lock completion.

### 4. Attempted Bypass Scenarios Fail

- **Returning zero deltas**: Router doesn't settle, but debt remains → lock reverts
- **Using savedBalances**: Cannot make them negative (reverts with `SavedBalanceOverflow`): [5](#0-4) 
- **Fake payments**: `completePayments()` verifies actual token balance changes: [6](#0-5) 

## Conclusion

The protocol's defense-in-depth approach ensures that **flash accounting cannot be bypassed**. The lock completion check is the ultimate enforcement mechanism that validates all debts are settled, independent of what extensions return or how they manipulate intermediate states. The system correctly maintains the **Flash Accounting invariant** that all flash loans must be repaid within the same transaction.

### Citations

**File:** src/Router.sol (L121-127)
```text
                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
```

**File:** src/Core.sol (L146-148)
```text
                if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                    mstore(0x00, 0x1293d6fa) // `SavedBalanceOverflow()`
                    revert(0x1c, 0x04)
```

**File:** src/Core.sol (L834-834)
```text
                _updatePairDebtWithNative(locker.id(), token0, token1, balanceUpdate.delta0(), balanceUpdate.delta1());
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

**File:** src/base/FlashAccountant.sol (L195-196)
```text
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))
```

**File:** src/base/FlashAccountant.sol (L274-287)
```text
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
```
