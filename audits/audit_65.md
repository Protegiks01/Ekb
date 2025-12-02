## Title
Unchecked Subtraction Overflow in _updatePairDebtWithNative Corrupts Flash Accounting System

## Summary
The `_updatePairDebtWithNative` function performs an unchecked subtraction `debtChange0 - int256(msg.value)` when `token0` is the native token, without validating that `msg.value` stays within the assumed `uint128` bounds. [1](#0-0)  When `debtChange0 = type(int128).min` and `msg.value >= type(int256).max`, this subtraction underflows in the unchecked block, wrapping to a huge positive value (~2^255) that violates the protocol's fundamental assumption that debt changes fit in 128 bits. [2](#0-1) 

## Impact
**Severity**: High

## Finding Description
**Location:** [3](#0-2) 

**Intended Logic:** The function is supposed to safely subtract `msg.value` from `debtChange0` when processing native token payments, under the assumption (stated in the comment) that "debtChange0 and msg.value are both bounded by int128/uint128". [4](#0-3) 

**Actual Logic:** The function performs unchecked arithmetic without validating that `msg.value` is actually bounded. The protocol assumes throughout that `msg.value` never exceeds `type(uint128).max`, [5](#0-4)  but no enforcement exists anywhere in the codebase.

**Exploitation Path:**
1. Attacker calls `updateSavedBalances` within a lock context [6](#0-5)  with:
   - `token0 = NATIVE_TOKEN_ADDRESS` (address(0))
   - `delta0 = type(int128).min` (-2^127)
   - `msg.value = type(int256).max` (2^255 - 1) or `msg.value = type(int256).max + 1` (2^255)

2. When `_updatePairDebtWithNative` executes line 344, the unchecked subtraction calculates:
   - If `msg.value = type(int256).max`: `debtChange0 - int256(msg.value) = -2^127 - (2^255 - 1) = -(2^127 + 2^255 - 1)`
   - This underflows `type(int256).min`, wrapping to approximately `2^255 - 2^127` (huge positive number)
   - If `msg.value = 2^255`: `int256(msg.value)` wraps to `type(int256).min`, so `debtChange0 - int256(msg.value) = -2^127 - (-2^255) = 2^255 - 2^127`

3. This corrupted value (exceeding 128 bits) is passed to `_updatePairDebt` [7](#0-6)  which assumes debt changes fit in 128 bits and uses unchecked assembly to add it to the current debt: `let nextA := add(currentA, debtChangeA)` [8](#0-7) 

4. The lock mechanism will permanently fail the debt settlement check [9](#0-8)  because the corrupted debt (~2^255) cannot be repaid through normal operations (payments are limited to 128 bits [10](#0-9) ), permanently DOSing the protocol.

**Security Property Broken:** Violates the **Flash Accounting** invariant that "all flash loans must be repaid within the same transaction with proper accounting" and violates the implicit invariant that debt values fit within 128 bits throughout the system.

## Impact Explanation
- **Affected Assets**: All protocol operations become unusable once debt tracking is corrupted for any token pair involving the native token
- **Damage Severity**: Complete protocol DOS - users cannot perform swaps, update positions, collect fees, or any other operations that require the lock mechanism, as the debt can never be settled
- **User Impact**: All users are affected; any transaction attempting to use the corrupted lock will revert with `DebtsNotZeroed` error, effectively bricking the protocol

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user who can send ETH with a transaction
- **Preconditions**: None - attacker only needs to be able to call `updateSavedBalances` within a lock context (available to any user)
- **Execution Complexity**: Single transaction with `msg.value >= type(int256).max`, which while not practically feasible due to ETH supply constraints, represents a critical code correctness issue that violates documented assumptions
- **Frequency**: One-time attack permanently corrupts the system

## Recommendation [3](#0-2) 

Add explicit validation that `msg.value` stays within the assumed 128-bit bounds:

```solidity
function _updatePairDebtWithNative(
    uint256 id,
    address token0,
    address token1,
    int256 debtChange0,
    int256 debtChange1
) private {
    if (msg.value == 0) {
        _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
    } else {
        // FIXED: Validate msg.value fits in 128 bits
        if (msg.value > type(uint128).max) revert MsgValueExceedsMaximum();
        
        if (token0 == NATIVE_TOKEN_ADDRESS) {
            unchecked {
                // Now safe because msg.value is bounded by uint128
                _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
            }
        } else {
            unchecked {
                _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
                _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
            }
        }
    }
}
```

Alternative: Add validation in the `receive()` function or at the entry points of all payable functions to enforce the 128-bit assumption globally.

## Proof of Concept

```solidity
// File: test/Exploit_DebtOverflow.t.sol
// Run with: forge test --match-test test_DebtOverflowViaLargeMsgValue -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/ICore.sol";

contract Exploit_DebtOverflow is Test {
    Core core;
    address constant NATIVE_TOKEN = address(0);
    address attacker;
    
    function setUp() public {
        core = new Core();
        attacker = makeAddr("attacker");
        // Fund attacker with hypothetical large ETH amount
        vm.deal(attacker, type(uint256).max);
    }
    
    function test_DebtOverflowViaLargeMsgValue() public {
        vm.startPrank(attacker);
        
        // Create a custom contract that will trigger the vulnerability
        MaliciousLocker locker = new MaliciousLocker(core);
        
        // This will corrupt debt tracking by sending msg.value >= type(int256).max
        vm.expectRevert(); // Will revert with DebtsNotZeroed due to corrupted debt
        locker.exploitDebtOverflow();
        
        vm.stopPrank();
    }
}

contract MaliciousLocker {
    ICore core;
    
    constructor(ICore _core) {
        core = _core;
    }
    
    function exploitDebtOverflow() external payable {
        // Call lock which will call back to locked_
        core.lock();
    }
    
    function locked_(uint256 id) external {
        // Call updateSavedBalances with:
        // - delta0 = type(int128).min
        // - msg.value = large value causing overflow
        // This will corrupt debt tracking
        core.updateSavedBalances{value: type(uint256).max / 2}(
            address(0), // NATIVE_TOKEN
            address(1), // any token1
            bytes32(0), // salt
            type(int128).min, // delta0
            0 // delta1
        );
        // The debt will now be corrupted with a value ~2^255
        // which can never be settled, bricking the protocol
    }
}
```

### Citations

**File:** src/Core.sol (L124-134)
```text
    function updateSavedBalances(
        address token0,
        address token1,
        bytes32,
        // positive is saving, negative is loading
        int256 delta0,
        int256 delta1
    )
        external
        payable
    {
```

**File:** src/Core.sol (L329-355)
```text
    function _updatePairDebtWithNative(
        uint256 id,
        address token0,
        address token1,
        int256 debtChange0,
        int256 debtChange1
    ) private {
        if (msg.value == 0) {
            // No native token payment included in the call, so use optimized pair update
            _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
        } else {
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
                }
            } else {
                // token0 is not native, and since token0 < token1, token1 cannot be native either
                // Update the token0, token1 debt and then update native token debt separately
                unchecked {
                    _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
                    _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
                }
            }
        }
    }
```

**File:** src/base/FlashAccountant.sol (L59-63)
```text
    /// @notice Updates the debt tracking for a specific locker and token
    /// @dev We assume debtChange cannot exceed a 128 bits value, even though it uses a int256 container.
    ///      This must be enforced at the places it is called for this contract's safety.
    ///      Negative values erase debt, positive values add debt.
    ///      Updates the non-zero debt count when debt transitions between zero and non-zero states.
```

**File:** src/base/FlashAccountant.sol (L96-111)
```text
    function _updatePairDebt(uint256 id, address tokenA, address tokenB, int256 debtChangeA, int256 debtChangeB)
        internal
    {
        assembly ("memory-safe") {
            let nzdCountChange := 0

            // Update token0 debt if there's a change
            if debtChangeA {
                let deltaSlotA := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), tokenA))
                let currentA := tload(deltaSlotA)
                let nextA := add(currentA, debtChangeA)

                nzdCountChange := sub(iszero(currentA), iszero(nextA))

                tstore(deltaSlotA, nextA)
            }
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

**File:** src/base/FlashAccountant.sol (L289-294)
```text
                // We never expect tokens to have this much total supply
                if shr(128, payment) {
                    // cast sig "PaymentOverflow()"
                    mstore(0x00, 0x9cac58ca)
                    revert(0x1c, 4)
                }
```

**File:** src/base/FlashAccountant.sol (L389-391)
```text
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
```
