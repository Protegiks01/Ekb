## Title
Drop Owner Can Prevent Legitimate Claims by Refunding After Merkle Root Change

## Summary
The Incentives contract allows drop owners to withdraw remaining funds at any time via the `refund()` function. When a drop owner creates a new drop with an updated merkle root (effectively creating a separate drop ID), they can refund the old drop, preventing users with valid proofs for the original merkle tree from claiming their entitled tokens.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Incentives.sol` (lines 45-71 for `refund()`, lines 74-117 for `claim()`)

**Intended Logic:** The Incentives contract manages airdrops using merkle proofs. Users with valid proofs should be able to claim their allocated tokens. The drop owner can reclaim unclaimed funds, but this should not prevent legitimate users from claiming.

**Actual Logic:** The drop ID is computed as `keccak256(owner, token, root)`. [1](#0-0)  When the owner wants to "update" the merkle root (e.g., to add more recipients or fix errors), they create an entirely new drop with a new root, resulting in a different drop ID. The owner can then call `refund()` on the old drop to recover remaining funds. [2](#0-1)  This sets the funded amount equal to the claimed amount, leaving zero remaining funds. [3](#0-2) 

When users with valid proofs for the old merkle tree attempt to claim, the function verifies their proof successfully [4](#0-3)  but then reverts at the insufficient funds check. [5](#0-4) 

**Exploitation Path:**
1. Owner creates Drop A with `root1` by calling `fund(DropKey(owner, tokenX, root1), 1000e18)`
2. User Alice claims 200e18 using a valid proof for `root1` (800e18 remains)
3. Owner decides to change the merkle root (to add more users or fix an error) and creates Drop B with `root2` by calling `fund(DropKey(owner, tokenX, root2), 1000e18)`
4. Owner calls `refund(DropKey(owner, tokenX, root1))` to recover the 800e18 from Drop A
5. User Bob, who has a valid merkle proof for 300e18 in `root1`, attempts to claim but the transaction reverts with `InsufficientFunds()` even though his proof is cryptographically valid

**Security Property Broken:** Users with valid merkle proofs cannot claim their entitled tokens, resulting in direct loss of funds. This violates the fundamental expectation that valid proofs guarantee the ability to claim.

## Impact Explanation
- **Affected Assets**: All tokens in drops where the owner has refunded after some claims were made and before all entitled users claimed
- **Damage Severity**: Users with valid proofs lose 100% of their entitled tokens. In the example scenario, User Bob loses his entire 300e18 allocation
- **User Impact**: Any user who hasn't claimed yet from a drop where the owner has executed a refund. This could affect dozens or hundreds of users if the drop owner decides to create a new drop with an updated merkle root and refunds the old one

## Likelihood Explanation
- **Attacker Profile**: Drop owner (trusted role, but this creates a rugpull vector)
- **Preconditions**: 
  - A drop has been created and funded
  - Some users have claimed (but not all)
  - Owner wants to "update" the distribution for any reason (add users, fix errors, change allocations)
- **Execution Complexity**: Simple - owner calls `fund()` with new root, then `refund()` on old drop (2 transactions)
- **Frequency**: Can happen once per drop update. Given that merkle tree errors or desired distribution changes are common in airdrops, this is a realistic scenario

## Recommendation

Add a restriction to prevent refunding drops that have had any claims made. This ensures that once users start claiming, the owner commits to the full distribution:

```solidity
// In src/Incentives.sol, function refund(), after line 56:

function refund(DropKey memory key) external override returns (uint128 refundAmount) {
    if (msg.sender != key.owner) {
        revert DropOwnerOnly();
    }

    bytes32 id = key.toDropId();

    // Load drop state from storage slot: drop id
    DropState dropState;
    assembly ("memory-safe") {
        dropState := sload(id)
    }

    // NEW: Prevent refund if any claims have been made
    if (dropState.claimed() > 0) {
        revert CannotRefundAfterClaims();
    }

    refundAmount = dropState.getRemaining();
    if (refundAmount > 0) {
        // Set funded amount to claimed amount (no remaining funds)
        dropState = dropState.setFunded(dropState.claimed());

        // Store updated drop state
        assembly ("memory-safe") {
            sstore(id, dropState)
        }

        SafeTransferLib.safeTransfer(key.token, key.owner, refundAmount);
    }
    emit Refunded(key, refundAmount);
}
```

Alternative mitigation: Implement a timelock mechanism where refunds are only allowed before a certain timestamp or after all expected claims have been made.

## Proof of Concept

```solidity
// File: test/Exploit_IncentivesRefundRug.t.sol
// Run with: forge test --match-test test_refundPreventsValidClaims -vvv

pragma solidity ^0.8.31;

import {Test} from "forge-std/Test.sol";
import {Incentives} from "../src/Incentives.sol";
import {IIncentives} from "../src/interfaces/IIncentives.sol";
import {DropKey} from "../src/types/dropKey.sol";
import {ClaimKey} from "../src/types/claimKey.sol";
import {TestToken} from "./TestToken.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

contract Exploit_IncentivesRefundRug is Test {
    Incentives incentives;
    TestToken token;
    address owner;
    address alice;
    address bob;
    
    // Simple merkle tree with 2 leaves for testing
    bytes32 root1;
    bytes32 root2;
    
    function setUp() public {
        owner = address(0x1000);
        alice = address(0x2000);
        bob = address(0x3000);
        
        incentives = new Incentives();
        token = new TestToken(owner);
        
        // Create simple merkle tree for root1 with alice(200e18) and bob(300e18)
        bytes32 leafAlice = keccak256(abi.encodePacked(uint256(0), alice, uint128(200e18)));
        bytes32 leafBob = keccak256(abi.encodePacked(uint256(1), bob, uint128(300e18)));
        root1 = keccak256(abi.encodePacked(leafAlice, leafBob));
        
        // Create different root2 for "updated" distribution
        bytes32 leafAlice2 = keccak256(abi.encodePacked(uint256(0), alice, uint128(250e18)));
        bytes32 leafBob2 = keccak256(abi.encodePacked(uint256(1), bob, uint128(350e18)));
        root2 = keccak256(abi.encodePacked(leafAlice2, leafBob2));
    }
    
    function test_refundPreventsValidClaims() public {
        // SETUP: Owner creates and funds drop with root1
        vm.startPrank(owner);
        token.approve(address(incentives), type(uint256).max);
        
        DropKey memory dropA = DropKey({
            owner: owner,
            token: address(token),
            root: root1
        });
        
        incentives.fund(dropA, 1000e18);
        vm.stopPrank();
        
        // Alice claims her 200e18 successfully
        bytes32[] memory proofAlice = new bytes32[](1);
        bytes32 leafBob = keccak256(abi.encodePacked(uint256(1), bob, uint128(300e18)));
        proofAlice[0] = leafBob;
        
        ClaimKey memory claimAlice = ClaimKey({
            index: 0,
            account: alice,
            amount: 200e18
        });
        
        vm.prank(alice);
        incentives.claim(dropA, claimAlice, proofAlice);
        
        assertEq(token.balanceOf(alice), 200e18, "Alice should have claimed 200e18");
        
        // EXPLOIT: Owner decides to "update" merkle root by creating new drop
        vm.startPrank(owner);
        DropKey memory dropB = DropKey({
            owner: owner,
            token: address(token),
            root: root2
        });
        
        incentives.fund(dropB, 1000e18);
        
        // Owner refunds the old drop to recover remaining 800e18
        uint128 refunded = incentives.refund(dropA);
        assertEq(refunded, 800e18, "Owner should refund 800e18");
        vm.stopPrank();
        
        // VERIFY: Bob cannot claim even with valid proof for root1
        bytes32[] memory proofBob = new bytes32[](1);
        bytes32 leafAlice = keccak256(abi.encodePacked(uint256(0), alice, uint128(200e18)));
        proofBob[0] = leafAlice;
        
        ClaimKey memory claimBob = ClaimKey({
            index: 1,
            account: bob,
            amount: 300e18
        });
        
        // Bob's claim reverts with InsufficientFunds even though proof is valid
        vm.expectRevert(IIncentives.InsufficientFunds.selector);
        vm.prank(bob);
        incentives.claim(dropA, claimBob, proofBob);
        
        // Bob loses his 300e18 allocation permanently
        assertEq(token.balanceOf(bob), 0, "Bob received nothing despite valid proof");
    }
}
```

## Notes

While the documentation in `dropKey.sol` states "The owner can reclaim the drop token at any time" [6](#0-5) , this design creates a significant vulnerability. The ability to refund at any time, combined with the fact that changing merkle roots creates separate drops, allows owners to prevent legitimate users from claiming their entitled tokens.

This is particularly concerning because:
1. Users have no on-chain guarantee that their valid proofs will remain claimable
2. The owner might make this mistake accidentally (e.g., creating a corrected drop and refunding the old one without realizing users haven't all claimed yet)
3. There's no way for affected users to recover their tokens

The trust model states "DO NOT assume trusted roles act maliciously" but this vulnerability exists regardless of intent - an honest owner could inadvertently rug users when attempting to fix a merkle tree error or add additional recipients.

### Citations

**File:** src/types/dropKey.sol (L5-5)
```text
/// @dev The owner can reclaim the drop token at any time
```

**File:** src/types/dropKey.sol (L21-25)
```text
function toDropId(DropKey memory key) pure returns (bytes32 h) {
    assembly ("memory-safe") {
        // assumes that owner, token have no dirty upper bits
        h := keccak256(key, 96)
    }
```

**File:** src/Incentives.sol (L45-71)
```text
    function refund(DropKey memory key) external override returns (uint128 refundAmount) {
        if (msg.sender != key.owner) {
            revert DropOwnerOnly();
        }

        bytes32 id = key.toDropId();

        // Load drop state from storage slot: drop id
        DropState dropState;
        assembly ("memory-safe") {
            dropState := sload(id)
        }

        refundAmount = dropState.getRemaining();
        if (refundAmount > 0) {
            // Set funded amount to claimed amount (no remaining funds)
            dropState = dropState.setFunded(dropState.claimed());

            // Store updated drop state
            assembly ("memory-safe") {
                sstore(id, dropState)
            }

            SafeTransferLib.safeTransfer(key.token, key.owner, refundAmount);
        }
        emit Refunded(key, refundAmount);
    }
```

**File:** src/Incentives.sol (L86-88)
```text
        // Check the proof is valid
        bytes32 leaf = c.toClaimId();
        if (!MerkleProofLib.verify(proof, key.root, leaf)) revert InvalidProof();
```

**File:** src/Incentives.sol (L96-100)
```text
        // Check sufficient funds
        uint128 remaining = dropState.getRemaining();
        if (remaining < c.amount) {
            revert InsufficientFunds();
        }
```

**File:** src/types/dropState.sol (L48-54)
```text
/// @notice Gets the remaining amount (funded - claimed) from a drop state
/// @param state The drop state
/// @return remaining The remaining amount available for claims
function getRemaining(DropState state) pure returns (uint128 remaining) {
    unchecked {
        remaining = state.funded() - state.claimed();
    }
```
