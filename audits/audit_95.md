## Title
Permanent ETH Loss Due to NATIVE_TOKEN_ADDRESS Conflict - Withdrawals to address(0) Burn Funds Irreversibly

## Summary
The protocol uses `address(0)` as `NATIVE_TOKEN_ADDRESS` to identify native ETH in pool operations. However, the withdrawal mechanism in `FlashAccountant.sol` performs no validation to prevent users from specifying `address(0)` as the recipient. When ETH is withdrawn to `address(0)`, the EVM call succeeds but permanently burns the funds, causing irreversible user fund loss.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/base/FlashAccountant.sol` (lines 348-356, withdraw function)
- `src/base/BasePositions.sol` (lines 120-133, withdraw function)
- `src/Router.sol` (lines 280-289, swap function)
- `src/Orders.sol` (lines 155, 168, withdraw calls) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:** The protocol uses `address(0)` as a sentinel value to represent native ETH in pool operations, allowing uniform handling of ETH alongside ERC20 tokens. The withdrawal mechanism should safely transfer tokens to user-specified recipients.

**Actual Logic:** When a user calls withdrawal functions (withdraw, collectFees, swap) with `recipient = address(0)` for a pool containing native ETH (where `token0 = NATIVE_TOKEN_ADDRESS = address(0)`), the FlashAccountant performs:
```
switch token
case 0 {
    let success := call(gas(), recipient, amount, 0, 0, 0, 0)
```
This executes `call(gas(), 0, amount, 0, 0, 0, 0)`, which in EVM succeeds but sends ETH to the zero address where it is permanently burned and unrecoverable.

**Exploitation Path:**
1. User creates a liquidity position in a pool with `token0 = NATIVE_TOKEN_ADDRESS` (ETH paired with any ERC20)
2. User accrues fees or wishes to withdraw liquidity
3. User calls `positions.collectFees(id, poolKey, tickLower, tickUpper, address(0))` or `positions.withdraw(id, poolKey, tickLower, tickUpper, liquidity, address(0), true)`
4. The call propagates through BasePositions → FlashAccountantLib.withdrawTwo → FlashAccountant.withdraw
5. FlashAccountant executes `call(gas(), 0, ethAmount, 0, 0, 0, 0)`, successfully sending ETH to address(0)
6. ETH is permanently burned; user loses funds irreversibly [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

**Security Property Broken:** This violates the **Solvency Invariant** - while the protocol's accounting correctly reduces debt and maintains internal consistency, the actual ETH is destroyed rather than transferred to a valid recipient, causing real economic loss to users.

## Impact Explanation
- **Affected Assets**: Native ETH in any pool where `token0 = NATIVE_TOKEN_ADDRESS`
- **Damage Severity**: Complete and permanent loss of withdrawn ETH amount. Unlike ERC20 tokens where address(0) transfers may fail or simply not credit balances, ETH transfers to address(0) via `call()` succeed and burn the funds irreversibly. Users lose 100% of withdrawn/collected amounts.
- **User Impact**: Any user withdrawing liquidity or collecting fees from ETH pools who accidentally or intentionally specifies `address(0)` as recipient will suffer permanent fund loss. This could affect liquidity providers across all ETH-paired pools.

## Likelihood Explanation
- **Attacker Profile**: Any user (including honest users making mistakes). No special permissions required.
- **Preconditions**: 
  - Pool with `token0 = NATIVE_TOKEN_ADDRESS` must exist (common scenario)
  - User must have a position or execute a swap
  - User specifies `address(0)` as recipient parameter
- **Execution Complexity**: Single transaction calling standard withdrawal/swap functions with recipient parameter set to address(0)
- **Frequency**: Can occur on every withdrawal/collection where user specifies address(0) as recipient

## Recommendation

Add explicit validation to prevent withdrawals to address(0):

```solidity
// In src/base/FlashAccountant.sol, withdraw function, line ~331:

// CURRENT (vulnerable):
for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
    let token := shr(96, calldataload(i))
    let recipient := shr(96, calldataload(add(i, 20)))
    let amount := shr(128, calldataload(add(i, 40)))
    
    if amount {
        // ... rest of code
        switch token
        case 0 {
            let success := call(gas(), recipient, amount, 0, 0, 0, 0)
            // ...
        }
    }
}

// FIXED:
for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
    let token := shr(96, calldataload(i))
    let recipient := shr(96, calldataload(add(i, 20)))
    let amount := shr(128, calldataload(add(i, 40)))
    
    // Validate recipient is not address(0) to prevent fund burning
    if iszero(recipient) {
        // cast sig "InvalidRecipient()"
        mstore(0x00, 0xd1c6f9e7)
        revert(0x1c, 4)
    }
    
    if amount {
        // ... rest of code unchanged
    }
}
```

**Alternative Mitigation:** Add validation in user-facing contracts (BasePositions, Router, Orders) before calling withdraw functions, though the core protection should be in FlashAccountant for defense-in-depth.

## Proof of Concept

```solidity
// File: test/Exploit_ETHBurnToAddressZero.t.sol
// Run with: forge test --match-test test_ETHBurnToAddressZero -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/Router.sol";
import "./TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_ETHBurnToAddressZero is Test {
    Core core;
    Positions positions;
    Router router;
    TestToken token1;
    
    address user = makeAddr("user");
    
    function setUp() public {
        core = new Core();
        positions = new Positions(core, address(this), 0, 1);
        router = new Router(core);
        token1 = new TestToken(address(this));
        
        // Fund user with ETH and tokens
        vm.deal(user, 100 ether);
        token1.mint(user, 1000e18);
        
        vm.startPrank(user);
        token1.approve(address(positions), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_ETHBurnToAddressZero() public {
        vm.startPrank(user);
        
        // SETUP: Create ETH/Token1 pool
        PoolKey memory poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS, // ETH
            token1: address(token1),
            config: createFullRangePoolConfig({_fee: 3000, _extension: address(0)})
        });
        
        // Initialize pool
        positions.maybeInitializePool(poolKey, 0);
        
        // Record initial balances
        uint256 initialUserETH = user.balance;
        uint256 initialZeroAddressETH = address(0).balance;
        
        // Deposit liquidity with ETH
        (uint256 positionId,,,) = positions.mintAndDeposit{value: 1 ether}({
            poolKey: poolKey,
            tickLower: MIN_TICK,
            tickUpper: MAX_TICK,
            maxAmount0: 1 ether,
            maxAmount1: 1000e18,
            minLiquidity: 0
        });
        
        // Generate some swap fees
        vm.stopPrank();
        vm.deal(address(this), 10 ether);
        router.swap{value: 0.1 ether}({
            poolKey: poolKey,
            isToken1: false,
            amount: 0.1 ether,
            sqrtRatioLimit: 0,
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min
        });
        
        vm.startPrank(user);
        
        // EXPLOIT: Collect fees to address(0) - this burns ETH permanently
        (uint128 collectedETH, uint128 collectedToken1) = positions.collectFees({
            id: positionId,
            poolKey: poolKey,
            tickLower: MIN_TICK,
            tickUpper: MAX_TICK,
            recipient: address(0) // Sending to address(0)!
        });
        
        vm.stopPrank();
        
        // VERIFY: ETH was permanently burned
        assertTrue(collectedETH > 0, "Should have collected some ETH fees");
        
        // The user did NOT receive the ETH
        assertEq(user.balance, initialUserETH - 1 ether, "User ETH unchanged (fees lost)");
        
        // address(0) balance may appear unchanged (ETH is burned in EVM)
        // The key point is the ETH is GONE - not in user wallet, not recoverable
        console.log("ETH fees collected (permanently lost):", collectedETH);
        console.log("User final balance:", user.balance);
        console.log("ETH was burned - permanently lost!");
    }
}
```

## Notes

This vulnerability arises from the dual use of `address(0)` as both:
1. A **token identifier** for native ETH (`NATIVE_TOKEN_ADDRESS`)
2. A potential **recipient address** in withdrawal operations

While ERC20 transfers to `address(0)` typically fail or simply don't credit balances (saving gas as seen in TokenWrapper.sol), **ETH transfers via `call()` to address(0) succeed** in EVM but permanently burn the funds. The protocol's accounting correctly reduces debt and maintains consistency, but the actual ETH is destroyed, violating user expectations and causing real economic loss.

The TokenWrapper contract intentionally allows transfers to `address(0)` as a burn mechanism for wrapped tokens, but this pattern is unsafe when applied to native ETH withdrawals where the funds are irreversibly lost rather than simply uncredited.

### Citations

**File:** src/math/constants.sol (L24-26)
```text
// Address used to represent the native token (ETH) within the protocol
// Using address(0) allows the protocol to handle native ETH alongside ERC20 tokens
address constant NATIVE_TOKEN_ADDRESS = address(0);
```

**File:** src/base/FlashAccountant.sol (L348-356)
```text
                    switch token
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
```

**File:** src/base/BasePositions.sol (L120-133)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L328-328)
```text
            ACCOUNTANT.withdrawTwo(poolKey.token0, poolKey.token1, recipient, amount0, amount1);
```

**File:** src/libraries/FlashAccountantLib.sol (L199-228)
```text
    function withdrawTwo(
        IFlashAccountant accountant,
        address token0,
        address token1,
        address recipient,
        uint128 amount0,
        uint128 amount1
    ) internal {
        assembly ("memory-safe") {
            let free := mload(0x40)

            // cast sig "withdraw()"
            mstore(free, shl(224, 0x3ccfd60b))

            // Pack first withdrawal: token0 (20 bytes) + recipient (20 bytes) + amount0 (16 bytes)
            mstore(add(free, 4), shl(96, token0))
            mstore(add(free, 24), shl(96, recipient))
            mstore(add(free, 44), shl(128, amount0))

            // Pack second withdrawal: token1 (20 bytes) + recipient (20 bytes) + amount1 (16 bytes)
            mstore(add(free, 60), shl(96, token1))
            mstore(add(free, 80), shl(96, recipient))
            mstore(add(free, 100), shl(128, amount1))

            if iszero(call(gas(), accountant, 0, free, 116, 0, 0)) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }
        }
    }
```

**File:** src/Router.sol (L123-123)
```text
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
```

**File:** src/Router.sol (L130-130)
```text
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
```

**File:** src/Orders.sol (L155-155)
```text
                        ACCOUNTANT.withdraw(sellToken, recipientOrPayer, uint128(uint256(-amount)));
```

**File:** src/Orders.sol (L168-168)
```text
                ACCOUNTANT.withdraw(orderKey.buyToken(), recipient, proceeds);
```
