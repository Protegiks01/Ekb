# Audit Report

## Title
Permanent Token Loss Due to Transient Storage Inconsistency in TokenWrapper Transfer Functions

## Summary
The TokenWrapper contract uses transient storage for Core's balance tracking but persistent storage for user balances. Users can directly call `transfer()` or `transferFrom()` to send tokens to the Core address outside of a lock context, causing permanent and irreversible token loss when the transient `coreBalance` resets to zero at transaction end.

## Impact
**Severity**: High - Permanent loss of user funds with no recovery mechanism

Any user holding wrapped tokens can permanently lose their funds by transferring to the Core address. The tokens are irretrievably destroyed because: (1) the sender's persistent balance decreases, (2) Core's transient balance increases then resets to zero, and (3) the totalSupply (tracked in savedBalances) remains unchanged, creating an unrecoverable accounting gap where `totalSupply() > sum of all balances`.

## Finding Description

**Location:** `src/TokenWrapper.sol`, lines 96-117 in `transfer()` function and lines 127-155 in `transferFrom()` function [1](#0-0) 

**Intended Logic:** 
The design assumes transfers to Core occur exclusively within lock contexts as part of the flash accounting system. The comment on lines 97-98 states the assumption that Core transfers "will net to 0 with the Core#withdraw call," implying these should only happen during payment flows within a lock. [2](#0-1) 

**Actual Logic:**
The code does not enforce this assumption. Any user can call `wrapper.transfer(address(CORE), amount)` or `wrapper.transferFrom(from, address(CORE), amount)` directly from outside any lock context, with the following consequences:

1. Line 99: Check `msg.sender != address(CORE)` passes (user is not Core)
2. Lines 100-107: User's `_balanceOf` is decreased in **persistent storage**
3. Line 109: Check `to == address(CORE)` passes
4. Line 110: Core's `coreBalance` is increased in **transient storage**
5. Transaction completes successfully
6. Transient storage characteristic: `coreBalance` automatically resets to 0
7. Result: Tokens exist in `totalSupply()` but not in any balance [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. **Setup**: Alice wraps 100 underlying tokens through proper periphery flow, receiving 100 wrapped tokens in `_balanceOf[Alice]`. The `savedBalances` in Core is 100, matching the totalSupply.

2. **Trigger**: Alice (or any user with wrapped tokens) directly calls `wrapper.transfer(address(core), 50)`

3. **State Change**: 
   - `_balanceOf[Alice]` decreases from 100 to 50 (persistent storage, line 106)
   - `coreBalance` increases from 0 to 50 (transient storage, line 110)
   - `savedBalances` remains at 100 (no call to `updateSavedBalances`)

4. **Transaction End**: Transient storage resets: `coreBalance` → 0

5. **Result**: 
   - `totalSupply()` = 100 (reads from savedBalances)
   - `balanceOf(Alice)` = 50
   - `balanceOf(core)` = 0
   - 50 tokens permanently lost with no recovery path [5](#0-4) [6](#0-5) 

**Security Guarantee Broken:**
The fundamental ERC20 accounting invariant that `totalSupply() == sum of all balances` is violated. This breaks the "Withdrawal Availability" invariant stated in README line 202: "All positions should be able to be withdrawn at any time."

## Impact Explanation

**Affected Assets**: All wrapped tokens in circulation. Any TokenWrapper instance deployed by the TokenWrapperFactory is vulnerable.

**Damage Severity**:
- Users suffer complete and permanent loss of transferred amounts
- No recovery mechanism exists - the tokens cannot be unwrapped, transferred back, or retrieved by any means
- The accounting gap between totalSupply and actual circulating supply grows with each occurrence
- Underlying tokens remain locked in Core but are no longer claimable by anyone

**User Impact**: 
- Accidental transfers to Core address (wallet UI errors, address confusion)
- Malicious griefing attacks where users intentionally burn tokens
- Any user attempting non-standard token operations without understanding the lock requirement

**Trigger Conditions**: Single transaction with standard ERC20 `transfer()` or `transferFrom()` call. No special permissions, state conditions, or complex setup required.

## Likelihood Explanation

**Attacker Profile**: Any user holding wrapped tokens. No special privileges, permissions, or positions required. Can also occur through accidental user error.

**Preconditions**:
1. User must have wrapped tokens in their balance (achieved through normal wrap operations)
2. No other preconditions required

**Execution Complexity**: Trivial - single function call to public `transfer()` or `transferFrom()` with Core address as recipient

**Economic Cost**: Only standard transaction gas fees (< 0.01 ETH). No capital requirements or locked funds.

**Frequency**: Can occur unlimited times. Every user with wrapped tokens can trigger it. No rate limiting, cooldowns, or prevention mechanisms exist.

**Overall Likelihood**: HIGH - Trivially executable by any wrapped token holder at any time

## Recommendation

**Primary Fix:**
Add explicit validation in both `transfer()` and `transferFrom()` functions to prevent transfers to Core from addresses other than Core itself:

```solidity
// In src/TokenWrapper.sol, function transfer, line 109:

if (to == address(CORE)) {
    // Prevent user-initiated transfers to Core outside lock context
    // Only Core itself can transfer to Core (during withdrawal operations)
    if (msg.sender != address(CORE)) {
        revert("Cannot transfer to Core outside lock context");
    }
    coreBalance += amount;
}
```

Apply identical protection in `transferFrom()` at line 148.

**Alternative Mitigation:**
Use persistent storage for Core's balance instead of transient storage. However, this sacrifices the gas optimization benefits that transient storage provides for the flash accounting system.

**Additional Safeguards:**
Consider adding an invariant check that compares `totalSupply()` with the sum of recoverable balances in test suites to detect this condition early.

## Proof of Concept

The provided PoC has implementation issues (incorrect use of `vm.prank`), but the vulnerability logic is correct. A working PoC would:

1. Deploy TokenWrapper through TokenWrapperFactory
2. Wrap tokens properly through TokenWrapperPeriphery to establish user balance
3. Directly call `wrapper.transfer(address(core), amount)` from user address
4. Verify `totalSupply() > balanceOf(user) + balanceOf(core)`
5. Demonstrate tokens are permanently unrecoverable

## Notes

The vulnerability stems from an **unenforced assumption** rather than a missing feature. The comment on lines 97-98 clearly shows developers assumed transfers to Core would only occur within properly managed lock contexts where the transient balance nets to zero. However, this assumption is not programmatically enforced, allowing direct transfers that violate the intended design. [2](#0-1) 

The test file demonstrates proper usage through `TokenWrapperPeriphery` within lock contexts, but the base `transfer()` and `transferFrom()` functions remain publicly accessible without guards against direct Core transfers. [7](#0-6) 

This is not standard ERC20 behavior - normal ERC20 tokens maintain the invariant that totalSupply equals the sum of all balances at all times. The mixed use of persistent and transient storage creates a critical edge case that breaks this fundamental guarantee.

### Citations

**File:** src/TokenWrapper.sol (L52-52)
```text
    mapping(address account => uint256) private _balanceOf;
```

**File:** src/TokenWrapper.sol (L54-56)
```text
    /// @notice Transient balance for the Core contract
    /// @dev Core never actually holds a real balance of this token, we just use this transient balance to enable low cost payments to core
    uint256 private transient coreBalance;
```

**File:** src/TokenWrapper.sol (L60-63)
```text
    function balanceOf(address account) external view returns (uint256) {
        if (account == address(CORE)) return coreBalance;
        return _balanceOf[account];
    }
```

**File:** src/TokenWrapper.sol (L67-76)
```text
    function totalSupply() external view override returns (uint256) {
        (uint128 supply,) = CORE.savedBalances({
            owner: address(this),
            token0: address(UNDERLYING_TOKEN),
            token1: address(type(uint160).max),
            salt: bytes32(0)
        });

        return supply;
    }
```

**File:** src/TokenWrapper.sol (L96-117)
```text
    function transfer(address to, uint256 amount) external returns (bool) {
        // note we do not need to check that core balance is sufficient as the sender
        // even if the caller gets core to withdraw to itself, as part of a payment, it will net to 0 with the Core#withdraw call
        if (msg.sender != address(CORE)) {
            uint256 balance = _balanceOf[msg.sender];
            if (balance < amount) {
                revert InsufficientBalance();
            }
            // since we already checked balance >= amount
            unchecked {
                _balanceOf[msg.sender] = balance - amount;
            }
        }
        if (to == address(CORE)) {
            coreBalance += amount;
        } else if (to != address(0)) {
            // we save storage writes on burn by checking to != address(0)
            _balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
```

**File:** test/TokenWrapper.t.sol (L16-73)
```text
contract TokenWrapperPeriphery is BaseLocker {
    using FlashAccountantLib for *;

    constructor(ICore core) BaseLocker(core) {}

    function wrap(TokenWrapper wrapper, uint128 amount) external {
        lock(abi.encode(wrapper, msg.sender, msg.sender, int256(uint256(amount))));
    }

    function wrap(TokenWrapper wrapper, address recipient, uint128 amount) external {
        lock(abi.encode(wrapper, msg.sender, recipient, int256(uint256(amount))));
    }

    function unwrap(TokenWrapper wrapper, uint128 amount) external {
        lock(abi.encode(wrapper, msg.sender, msg.sender, -int256(uint256(amount))));
    }

    function unwrap(TokenWrapper wrapper, address recipient, uint128 amount) external {
        lock(abi.encode(wrapper, msg.sender, recipient, -int256(uint256(amount))));
    }

    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory) {
        (TokenWrapper wrapper, address payer, address recipient, int256 amount) =
            abi.decode(data, (TokenWrapper, address, address, int256));

        if (amount >= 0) {
            // this creates the deltas
            ACCOUNTANT.forward(address(wrapper), abi.encode(amount));
            // now withdraw to the recipient
            if (uint128(uint256(amount)) > 0) {
                ACCOUNTANT.withdraw(address(wrapper), recipient, uint128(uint256(amount)));
            }
            // and pay the wrapped token from the payer
            if (uint256(amount) != 0) {
                if (address(wrapper.UNDERLYING_TOKEN()) == NATIVE_TOKEN_ADDRESS) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                } else {
                    ACCOUNTANT.payFrom(payer, address(wrapper.UNDERLYING_TOKEN()), uint256(amount));
                }
            }
        } else {
            // this creates the deltas
            ACCOUNTANT.forward(address(wrapper), abi.encode(amount));
            // now withdraw to the recipient
            if (uint128(uint256(-amount)) > 0) {
                ACCOUNTANT.withdraw(address(wrapper.UNDERLYING_TOKEN()), recipient, uint128(uint256(-amount)));
            }
            // and pay the wrapped token from the payer
            if (uint256(-amount) != 0) {
                if (address(wrapper) == NATIVE_TOKEN_ADDRESS) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(-amount));
                } else {
                    ACCOUNTANT.payFrom(payer, address(wrapper), uint256(-amount));
                }
            }
        }
    }
}
```
