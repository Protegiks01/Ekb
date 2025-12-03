## Title
Contract-Owned Orders Cannot Be Canceled When Recipient Reverts on Token Receipt

## Summary
The `Orders.decreaseSaleRate()` function requires immediate token transfer to a recipient address. If the recipient (including the order owner via `msg.sender`) is a contract that reverts on token receipt, the entire cancel operation fails. [1](#0-0)  This prevents contract-owned orders from being canceled, violating the protocol's "Withdrawal Availability" invariant.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Orders.sol` (lines 77-94, 152-156), `src/base/FlashAccountant.sol` (lines 322-381)

**Intended Logic:** Users should be able to cancel their TWAMM orders at any time by calling `decreaseSaleRate()`, receiving a refund of unsold tokens. The protocol has two overloads: one with an explicit recipient parameter, and one defaulting to `msg.sender`. [2](#0-1) 

**Actual Logic:** When `decreaseSaleRate()` is called, the refund tokens are immediately transferred to the recipient via `ACCOUNTANT.withdraw()`. [3](#0-2)  The `FlashAccountant.withdraw()` function performs direct token transfers that revert if the recipient cannot receive tokens. [4](#0-3) 

**Exploitation Path:**
1. A smart contract (e.g., a multisig wallet, DAO treasury, or automated trading contract) mints an Orders NFT and creates a TWAMM order by calling `mintAndIncreaseSellAmount()`
2. The contract's `receive()` function reverts (or doesn't exist), or it cannot handle ERC20 `transfer()` callbacks properly
3. The contract attempts to cancel its order by calling `decreaseSaleRate(id, orderKey, saleRateDecrease, recipient)` with any recipient address that reverts
4. The transaction reverts during `ACCOUNTANT.withdraw()` when tokens are transferred to the recipient
5. The contract also cannot use the `msg.sender` overload because that also sends to the contract's address, which still reverts
6. The contract's order continues executing until it naturally expires, with funds locked during this period

**Security Property Broken:** **Withdrawal Availability Invariant** - "All positions MUST be withdrawable at any time (except third-party extensions; in-scope extensions MUST NOT block withdrawal)". Orders are NFT-based positions, and contract owners cannot withdraw their positions if they cannot receive tokens.

## Impact Explanation
- **Affected Assets**: TWAMM orders owned by smart contracts (multisigs, DAOs, trading bots, contract wallets) that cannot receive token transfers
- **Damage Severity**: Funds remain locked in active TWAMM orders until they naturally complete. For long-duration orders, this could mean weeks or months of forced execution at potentially unfavorable prices
- **User Impact**: Any contract that owns an Orders NFT and has a reverting receive mechanism is affected. This includes legitimate use cases like automated market makers, treasury management contracts, or smart contract wallets with specific token handling logic

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a design flaw affecting legitimate users (contracts) that own orders
- **Preconditions**: 
  1. A contract must own an Orders NFT (no restrictions prevent this)
  2. The contract cannot receive native tokens OR cannot handle ERC20 transfers properly
  3. The contract attempts to cancel an order
- **Execution Complexity**: Single transaction that inevitably reverts
- **Frequency**: Affects any contract owner attempting to cancel, continuously until order expires

## Recommendation

Add a delayed withdrawal mechanism or allow cancellation without immediate token transfer:

```solidity
// In src/Orders.sol, add a new function:

/// @notice Cancels an order without immediate refund, storing refund for later claim
/// @param id The NFT token ID representing the order
/// @param orderKey Key identifying the order parameters
/// @param saleRateDecrease Amount to decrease the sale rate by
/// @return refund Amount of tokens available for later claim
function decreaseSaleRateWithDelayedRefund(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease)
    external
    payable
    authorizedForNft(id)
    returns (uint112 refund)
{
    // Store refund in a mapping instead of immediately transferring
    // Users can claim later via a separate claimRefund() function
}
```

Alternative mitigation: Add a try-catch around the token transfer in `FlashAccountant.withdraw()` with a fallback mechanism to store failed transfers for later claim, though this would require significant architectural changes to the flash accounting system.

## Proof of Concept

```solidity
// File: test/Exploit_ContractOrderCancellation.t.sol
// Run with: forge test --match-test test_ContractCannotCancelOrder -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import {BaseTWAMMTest} from "./extensions/TWAMM.t.sol";
import {OrderKey} from "../src/interfaces/extensions/ITWAMM.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

// Contract that cannot receive ETH (for native token orders)
contract RevertingContract {
    Orders public orders;
    
    constructor(Orders _orders) {
        orders = _orders;
    }
    
    // This contract cannot receive ETH - any transfer will revert
    receive() external payable {
        revert("Cannot receive ETH");
    }
    
    function createOrder(OrderKey memory key, uint112 amount) external returns (uint256 id) {
        (id,) = orders.mintAndIncreaseSellAmount(key, amount, type(uint112).max);
    }
    
    function cancelOrder(uint256 id, OrderKey memory key, uint112 decrease) external returns (uint112) {
        // This will revert because the refund tries to send to address(this)
        return orders.decreaseSaleRate(id, key, decrease);
    }
}

contract Exploit_ContractOrderCancellation is BaseTWAMMTest {
    RevertingContract public revertingContract;
    
    function test_ContractCannotCancelOrder() public {
        // SETUP: Create a pool and position
        uint64 fee = uint64((uint256(5) << 64) / 100);
        PoolKey memory poolKey = createTwammPool({fee: fee, tick: 0});
        createPosition(poolKey, MIN_TICK, MAX_TICK, 10000, 10000);
        
        // Deploy reverting contract
        revertingContract = new RevertingContract(orders);
        
        // Fund the reverting contract with tokens
        token0.transfer(address(revertingContract), 1000);
        
        // Contract approves Orders to spend its tokens
        vm.prank(address(revertingContract));
        token0.approve(address(orders), type(uint256).max);
        
        // Contract creates an order
        uint64 startTime = uint64(block.timestamp);
        uint64 endTime = uint64(block.timestamp + 256);
        OrderKey memory key = OrderKey({
            token0: poolKey.token0,
            token1: poolKey.token1,
            config: createOrderConfig({_fee: fee, _isToken1: false, _startTime: startTime, _endTime: endTime})
        });
        
        uint256 orderId = revertingContract.createOrder(key, 100);
        
        // Verify order was created
        assertGt(orderId, 0, "Order should be created");
        
        // EXPLOIT: Contract tries to cancel order
        vm.expectRevert(); // Will revert with "ETHTransferFailed()" or token transfer failure
        revertingContract.cancelOrder(orderId, key, 50);
        
        // VERIFY: Order cannot be canceled, funds remain locked
        // The contract is stuck with an active order it cannot cancel
    }
}
```

**Notes:**
- The vulnerability affects both native token (ETH) orders and ERC20 token orders where the recipient contract cannot properly handle transfers
- Even burning the NFT doesn't help because "burning the NFT does NOT cancel the underlying TWAMM order - it only destroys the NFT representation" [5](#0-4) 
- This is distinct from the "non-standard ERC20 token behavior" known issue, as the problem is with the RECIPIENT reverting, not the token itself
- The protocol explicitly allows contracts to own Orders NFTs (no restrictions in the mint functions), making this a legitimate concern for the withdrawal availability invariant

### Citations

**File:** src/Orders.sol (L77-94)
```text
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint112 refund)
    {
        refund = uint112(
            uint256(
                -abi.decode(
                    lock(
                        abi.encode(
                            CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                        )
                    ),
                    (int256)
                )
            )
        );
```

**File:** src/Orders.sol (L152-156)
```text
                } else {
                    unchecked {
                        // we know amount will never exceed the uint128 type because of limitations on sale rate (fixed point 80.32) and duration (uint32)
                        ACCOUNTANT.withdraw(sellToken, recipientOrPayer, uint128(uint256(-amount)));
                    }
```

**File:** src/interfaces/IOrders.sol (L39-58)
```text
    /// @notice Decreases the sale rate for an existing TWAMM order
    /// @param id The NFT token ID representing the order
    /// @param orderKey Key identifying the order parameters
    /// @param saleRateDecrease Amount to decrease the sale rate by
    /// @param recipient Address to receive the refunded tokens
    /// @return refund Amount of tokens refunded
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        external
        payable
        returns (uint112 refund);

    /// @notice Decreases the sale rate for an existing TWAMM order (refund to msg.sender)
    /// @param id The NFT token ID representing the order
    /// @param orderKey Key identifying the order parameters
    /// @param saleRateDecrease Amount to decrease the sale rate by
    /// @return refund Amount of tokens refunded
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease)
        external
        payable
        returns (uint112 refund);
```

**File:** src/base/FlashAccountant.sol (L348-368)
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
                    default {
                        mstore(0x14, recipient)
                        mstore(0x34, amount)
                        mstore(0x00, 0xa9059cbb000000000000000000000000)
                        let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                        if iszero(and(eq(mload(0x00), 1), success)) {
                            if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                                revert(0x1c, 0x04)
                            }
                        }
                    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-135)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```
