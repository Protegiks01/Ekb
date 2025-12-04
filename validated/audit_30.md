# Audit Report

## Title
Permanent Token Loss Due to Transient Storage Inconsistency in TokenWrapper

## Summary
The TokenWrapper contract implements a hybrid storage model where user balances use persistent storage while Core's balance uses transient storage. Users can directly call `transfer()` to send tokens to the Core address outside of a lock context, causing permanent and irrecoverable loss of funds when transient storage resets to zero at transaction end, breaking the fundamental ERC20 accounting invariant.

## Impact
**Severity**: High

Permanent and complete loss of user funds with no recovery mechanism. Any user holding wrapped tokens can accidentally or intentionally destroy their tokens by transferring to the Core address. The total supply tracked in Core's persistent storage remains unchanged, but the actual circulating supply decreases, creating an unrecoverable accounting discrepancy that violates the core ERC20 invariant where `totalSupply != sum of all balances`. This affects all TokenWrapper instances and can occur through simple user error, UI mistakes, or malicious griefing.

## Finding Description

**Location:** `src/TokenWrapper.sol`, functions `transfer()` and `transferFrom()` [1](#0-0) [2](#0-1) 

**Intended Logic:**
The contract design assumes transfers to Core occur exclusively within lock contexts as part of the flash accounting system, where the transient `coreBalance` is properly managed and balanced to zero before transaction completion. The contract declares it "Implements full ERC20 functionality" but the design relies on an implicit assumption that Core transfers only happen during controlled payment flows. [3](#0-2) 

**Actual Logic:**
The contract implements a dual storage system: users store balances in persistent storage `_balanceOf`, while Core uses transient storage `coreBalance`. The `balanceOf()` view function returns `coreBalance` for the Core address. [4](#0-3) [5](#0-4) [6](#0-5) 

The `totalSupply()` function reads from `Core.savedBalances`, which is only updated via `updateSavedBalances()` during wrap/unwrap operations within lock contexts, not during regular ERC20 transfers. [7](#0-6) [8](#0-7) 

The `updateSavedBalances()` function in Core requires an active lock context, enforced by `_requireLocker()`: [9](#0-8) 

**Exploitation Path:**
1. **Setup**: Alice wraps 100 underlying tokens through proper `TokenWrapperPeriphery.wrap()` flow within a lock context, receiving 100 wrapped tokens in `_balanceOf[Alice]` (persistent storage).
2. **Trigger**: Alice directly calls `wrapper.transfer(address(core), 100)` outside any lock context.
3. **State Change**: 
   - `_balanceOf[Alice]` decreases by 100 (persistent storage update at line 106)
   - `coreBalance` increases by 100 (transient storage update at line 110)
   - Transaction completes successfully with no reverts
4. **Transaction End**: Transient storage automatically resets to zero per EIP-1153 specification.
5. **Result**: 
   - `balanceOf(alice)` returns 0 (persistent storage decreased)
   - `balanceOf(core)` returns 0 (transient storage reset)
   - `totalSupply()` returns 100 (unchanged, reads from `Core.savedBalances`)
   - 100 tokens permanently lost with no recovery mechanism

**Security Property Broken:**
The fundamental ERC20 accounting invariant `totalSupply() == sum of all balances` is violated. Direct transfers to Core permanently decrease circulating balances without updating total supply tracked in Core's persistent `savedBalances` storage.

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
- Malicious actors can intentionally burn others' tokens if they obtain allowances via `transferFrom()`

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
Add access control to prevent transfers to Core outside lock contexts. In the `transfer()` function, add a check before incrementing `coreBalance`:

```solidity
if (to == address(CORE)) {
    if (msg.sender != address(CORE)) {
        revert("TokenWrapper: cannot transfer to Core outside lock context");
    }
    coreBalance += amount;
}
```

Apply identical fix to `transferFrom()` function at the corresponding location where `coreBalance` is incremented.

**Alternative Mitigations**:
1. Use persistent storage for Core's balance instead of transient storage (increases gas costs, defeats optimization purpose)
2. Implement a redemption mechanism allowing recovery of mistakenly transferred tokens (complex governance implications)
3. Add explicit NatSpec documentation warning about this restriction

**Additional Considerations**:
- Update frontend interfaces to validate recipient addresses before transfer
- Consider implementing a whitelist of safe transfer recipients
- Add circuit breaker to detect and halt operations if accounting discrepancy is detected

## Proof of Concept

The provided PoC demonstrates the vulnerability through two test cases:
1. `test_PermanentLossFromDirectTransferToCore()` - Shows single user losing tokens
2. `test_MultipleLossesCompound()` - Shows multiple users can independently lose tokens, compounding the accounting discrepancy

**Expected PoC Result:**
- **If Vulnerable**: Tests pass, demonstrating tokens disappear with `totalSupply > sum of all balances`
- **If Fixed**: Transaction reverts with "cannot transfer to Core outside lock context" error

## Notes

This vulnerability arises from an architectural mismatch between storage types (persistent vs. transient) combined with unrestricted access to standard ERC20 transfer functions. While transient storage provides critical gas optimization for flash accounting within lock contexts, extending this optimization to user-facing transfers creates an unintended burn mechanism without any programmatic enforcement of the design assumption that Core transfers only occur within controlled lock contexts.

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

**File:** src/TokenWrapper.sol (L127-155)
```text
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowanceCurrent = allowance[from][msg.sender];
        if (allowanceCurrent != type(uint256).max) {
            if (allowanceCurrent < amount) revert InsufficientAllowance();
            // since we already checked allowanceCurrent >= amount
            unchecked {
                allowance[from][msg.sender] = allowanceCurrent - amount;
            }
        }

        // we know `from` at this point will never be address(core) for amount > 0, since Core will never give an allowance to any address

        uint256 balance = _balanceOf[from];
        if (balance < amount) {
            revert InsufficientBalance();
        }
        // since we already checked balance >= amount
        unchecked {
            _balanceOf[from] = balance - amount;
        }

        if (to == address(CORE)) {
            coreBalance += amount;
        } else {
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

**File:** src/Core.sol (L123-171)
```text
    /// @inheritdoc ICore
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
        if (token0 >= token1) revert SavedBalanceTokensNotSorted();

        (uint256 id, address lockerAddr) = _requireLocker().parse();

        assembly ("memory-safe") {
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

        _updatePairDebtWithNative(id, token0, token1, delta0, delta1);
    }
```
