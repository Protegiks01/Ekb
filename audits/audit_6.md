# Audit Report

## Title
Permanent Token Loss Due to Transient Storage Inconsistency in TokenWrapper

## Summary
The TokenWrapper contract implements a hybrid storage model where user balances use persistent storage (`_balanceOf`) while Core's balance uses transient storage (`coreBalance`). Users can directly call `transfer()` to send tokens to the Core address outside of a lock context, causing permanent and irrecoverable loss of funds when transient storage resets to zero at transaction end. This breaks the fundamental ERC20 accounting invariant where `totalSupply != sum of all balances`.

## Impact
**Severity**: High

Permanent and complete loss of user funds with no recovery mechanism. Any user holding wrapped tokens can accidentally or intentionally destroy their tokens by transferring to the Core address. The total supply tracked in Core's persistent storage remains unchanged, but the actual circulating supply decreases, creating an unrecoverable accounting discrepancy that violates the core ERC20 invariant. This affects all TokenWrapper instances and can occur through simple user error, UI mistakes, or malicious griefing.

## Finding Description

**Location:** `src/TokenWrapper.sol`, functions `transfer()` (lines 96-117) and `transferFrom()` (lines 127-155) [1](#0-0) 

**Intended Logic:**
The contract design assumes transfers to Core occur exclusively within lock contexts as part of the flash accounting system, where the transient `coreBalance` is properly managed and balanced to zero before transaction completion. [2](#0-1)  The comment at lines 97-98 explicitly states this assumption about payment flows netting to zero.

**Actual Logic:**
The contract declares it "Implements full ERC20 functionality" [3](#0-2)  but imposes no programmatic enforcement preventing direct transfers to Core. Users store balances in persistent storage `_balanceOf` [4](#0-3) , while Core uses transient storage `coreBalance` [5](#0-4) . The `balanceOf()` view function returns `coreBalance` for the Core address. [6](#0-5) 

**Exploitation Path:**
1. **Setup**: Alice wraps 100 underlying tokens through proper `TokenWrapperPeriphery.wrap()` flow within a lock context, receiving 100 wrapped tokens in `_balanceOf[Alice]` (persistent storage).
2. **Trigger**: Alice directly calls `wrapper.transfer(address(core), 100)` outside any lock context.
3. **State Change**: 
   - Line 106: `_balanceOf[Alice]` decreases by 100 (persistent storage update)
   - Line 110: `coreBalance` increases by 100 (transient storage update)
   - Transaction completes successfully with no reverts
4. **Transaction End**: Transient storage automatically resets to zero per EIP-1153 specification.
5. **Result**: 
   - `balanceOf(alice)` returns 0
   - `balanceOf(core)` returns 0 (transient storage reset)
   - `totalSupply()` returns 100 (unchanged, reads from `Core.savedBalances`) [7](#0-6) 
   - 100 tokens permanently lost with no recovery mechanism

**Security Property Broken:**
The fundamental ERC20 accounting invariant `totalSupply() == sum of all balances` is violated. The `totalSupply()` function reads from `Core.savedBalances` which is only updated via `updateSavedBalances()` during wrap/unwrap operations within lock contexts [8](#0-7) , not during regular transfers. Direct transfers to Core permanently decrease circulating balances without updating total supply.

## Impact Explanation

**Affected Assets**: All wrapped tokens in any TokenWrapper instance. Every user holding wrapped tokens is at risk.

**Damage Severity**:
- Complete and irreversible loss of transferred token amounts
- No administrative function or recovery mechanism exists to restore lost tokens
- The accounting discrepancy is permanent: `totalSupply()` shows higher value than actual sum of recoverable balances
- Protocol-wide impact affecting all TokenWrapper instances deployed by `TokenWrapperFactory`

**User Impact**: 
- Accidental transfers to Core address (common user error with address input)
- UI/frontend bugs displaying Core address as valid transfer destination  
- Users unfamiliar with lock context requirements
- Malicious actors can intentionally burn others' tokens if they obtain allowances

**Trigger Conditions**: 
Any user with non-zero wrapped token balance can trigger with a single transaction. No special state, timing, or permissions required.

## Likelihood Explanation

**Attacker Profile**: 
- Any externally owned account (EOA) or contract holding wrapped tokens
- No special privileges, whitelisting, or setup required
- Can be unintentional (user error) or intentional (griefing/destruction)

**Preconditions**:
1. User must possess wrapped tokens (obtained through proper `wrap()` flow)
2. No other preconditions required

**Execution Complexity**: 
Single transaction calling standard ERC20 `transfer(address(core), amount)` or `transferFrom(from, address(core), amount)` function. Trivial to execute from any wallet interface.

**Economic Cost**: 
Only transaction gas fees (~30,000 gas for transfer). No capital lockup, no opportunity cost, no slippage.

**Frequency**: 
Can occur continuously, unlimited times per block, affecting any number of users simultaneously. No rate limiting, cooldown periods, or prevention mechanisms exist.

**Overall Likelihood**: 
HIGH - The combination of zero barriers to entry, trivial execution, and high probability of accidental occurrence (users transferring to wrong addresses) makes this highly likely to manifest in production.

## Recommendation

**Primary Fix:**
Add access control to prevent transfers to Core outside lock contexts:

```solidity
// In src/TokenWrapper.sol, function transfer(), lines 109-110:

// CURRENT (vulnerable):
if (to == address(CORE)) {
    coreBalance += amount;
}

// FIXED:
if (to == address(CORE)) {
    // Only Core itself can receive transfers (during flash accounting operations)
    // Direct user transfers to Core would cause permanent token loss
    if (msg.sender != address(CORE)) {
        revert("TokenWrapper: cannot transfer to Core outside lock context");
    }
    coreBalance += amount;
}
```

Apply identical fix to `transferFrom()` function at lines 148-149.

**Alternative Mitigations**:
1. Use persistent storage for Core's balance instead of transient storage (increases gas costs, defeats optimization purpose)
2. Implement a redemption mechanism allowing Core owner to return mistakenly transferred tokens (complex governance implications)
3. Override ERC20 metadata to warn users in token name/symbol (insufficient protection, doesn't prevent loss)

**Additional Considerations**:
- Add NatSpec documentation explicitly warning about this restriction
- Update frontend interfaces to validate recipient addresses before transfer
- Consider implementing a whitelist of safe transfer recipients

## Proof of Concept

```solidity
// File: test/TokenWrapperVulnerability.t.sol
// Demonstrates permanent token loss from direct transfers to Core

pragma solidity >=0.8.30;

import "forge-std/Test.sol";
import "../src/TokenWrapper.sol";
import "../src/TokenWrapperFactory.sol";
import "./TestToken.sol";
import "./FullTest.sol";

contract TokenWrapperVulnerabilityTest is FullTest {
    TokenWrapperFactory factory;
    TokenWrapperPeriphery periphery; 
    TestToken underlying;
    TokenWrapper wrapper;
    address alice = address(0x1111);
    
    function setUp() public override {
        FullTest.setUp();
        underlying = new TestToken(address(this));
        factory = new TokenWrapperFactory(core);
        periphery = new TokenWrapperPeriphery(core);
        
        // Deploy wrapper with unlock time in future
        wrapper = factory.deployWrapper(IERC20(address(underlying)), block.timestamp + 365 days);
        
        // Setup: Wrap 1000 tokens for Alice through proper flow
        underlying.transfer(alice, 1000);
        vm.startPrank(alice);
        underlying.approve(address(periphery), 1000);
        periphery.wrap(wrapper, 1000);
        vm.stopPrank();
        
        // Verify initial state
        assertEq(wrapper.balanceOf(alice), 1000, "Alice should have 1000 wrapped tokens");
        assertEq(wrapper.totalSupply(), 1000, "Total supply should be 1000");
    }
    
    function test_PermanentLossFromDirectTransferToCore() public {
        uint256 totalSupplyBefore = wrapper.totalSupply();
        
        // EXPLOIT: Alice transfers 500 tokens directly to Core (outside lock context)
        vm.prank(alice);
        wrapper.transfer(address(core), 500);
        
        // VERIFY VULNERABILITY:
        
        // 1. Alice's balance decreased (persistent storage updated)
        assertEq(wrapper.balanceOf(alice), 500, "Alice's balance decreased");
        
        // 2. Core's balance is 0 (transient storage reset after transaction)
        assertEq(wrapper.balanceOf(address(core)), 0, "Core balance is 0 - tokens disappeared");
        
        // 3. Total supply unchanged (reads from Core.savedBalances)
        assertEq(wrapper.totalSupply(), totalSupplyBefore, "Total supply unchanged");
        
        // 4. CRITICAL: Accounting invariant broken
        uint256 sumOfBalances = wrapper.balanceOf(alice) + wrapper.balanceOf(address(core));
        assertLt(sumOfBalances, wrapper.totalSupply(), "VULNERABILITY: totalSupply > sum of balances");
        
        // 5. 500 tokens permanently lost and unrecoverable
        assertEq(wrapper.totalSupply() - sumOfBalances, 500, "500 tokens permanently lost");
    }
    
    function test_MultipleLossesCompound() public {
        // Multiple users can lose tokens independently
        address bob = address(0x2222);
        underlying.transfer(bob, 500);
        
        vm.startPrank(bob);
        underlying.approve(address(periphery), 500);
        periphery.wrap(wrapper, 500);
        vm.stopPrank();
        
        assertEq(wrapper.totalSupply(), 1500, "Total supply now 1500");
        
        // Both Alice and Bob lose tokens
        vm.prank(alice);
        wrapper.transfer(address(core), 300);
        
        vm.prank(bob);
        wrapper.transfer(address(core), 200);
        
        // Total loss compounds
        uint256 totalLost = 300 + 200;
        uint256 totalRecoverable = wrapper.balanceOf(alice) + wrapper.balanceOf(bob) + wrapper.balanceOf(address(core));
        
        assertEq(wrapper.totalSupply() - totalRecoverable, totalLost, "500 tokens total permanently lost");
    }
}
```

**Expected PoC Result:**
- **If Vulnerable**: Tests pass, demonstrating tokens disappear with totalSupply > sum of balances
- **If Fixed**: Transaction reverts with "cannot transfer to Core outside lock context" error

## Notes

This vulnerability arises from an architectural mismatch between storage types (persistent vs. transient) combined with unrestricted access to standard ERC20 transfer functions. While transient storage provides critical gas optimization for flash accounting within lock contexts, extending this optimization to user-facing transfers creates an unintended burn mechanism.

The code comment at lines 97-98 acknowledges Core's special handling but assumes all Core transfers occur within payment flows that net to zero. This assumption lacks programmatic enforcement, making it an invalid security assumption. The contract's self-description as implementing "full ERC20 functionality" contradicts the implicit restriction that transfers to Core should only occur in specific contexts.

The test file demonstrates intended usage through `TokenWrapperPeriphery` within proper lock contexts [9](#0-8) , but the base `transfer()` and `transferFrom()` functions remain publicly accessible without protection against this destructive edge case.

### Citations

**File:** src/TokenWrapper.sol (L18-19)
```text
/// @dev Wrapping and unwrapping happens via Ekubo Core#forward. Implements full ERC20 functionality
contract TokenWrapper is UsesCore, IERC20, BaseForwardee {
```

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
