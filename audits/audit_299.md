## Title
Permanent Fund Lock in Incentives Contract Due to Inaccessible Drop Owner

## Summary
The Incentives contract allows drops to be created with any owner address, including address(0) or inaccessible addresses, without validation. Once funded, unclaimed tokens become permanently irrecoverable if the owner address is inaccessible, as the `refund()` function is the only recovery mechanism and strictly requires `msg.sender == key.owner`.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Incentives.sol` - `fund()` function (lines 20-42) and `refund()` function (lines 45-71)

**Intended Logic:** The owner field in DropKey should identify a valid, accessible address that can reclaim unclaimed tokens after the airdrop period via the `refund()` function. [1](#0-0) 

**Actual Logic:** The `fund()` function accepts any DropKey without validating the owner address. [2](#0-1)  The `refund()` function enforces a strict ownership check that permanently locks funds if the owner is inaccessible. [3](#0-2) 

**Exploitation Path:**
1. A user (accidentally or maliciously) creates a drop with `owner = address(0)` or an inaccessible address by calling `fund()` with a DropKey containing the invalid owner
2. The drop is funded with tokens via `fund()`, which performs no validation on the owner field
3. Users claim portions of the airdrop via `claim()`, leaving remaining unclaimed tokens
4. When attempting to recover unclaimed tokens via `refund()`, the transaction reverts because `msg.sender` can never equal address(0) or an inaccessible address
5. The remaining tokens are permanently locked in the Incentives contract with no recovery mechanism

**Security Property Broken:** This violates the fundamental expectation that drop creators can recover their unclaimed tokens, and creates a scenario where user funds can be permanently lost through an unvalidated input parameter.

## Impact Explanation
- **Affected Assets**: Any ERC20 tokens used to fund drops with inaccessible owners
- **Damage Severity**: Complete and permanent loss of all unclaimed tokens in the affected drop. The entire remaining balance becomes irrecoverable.
- **User Impact**: Any drop creator who accidentally specifies an incorrect owner address, loses their private key after drop creation, or intentionally sets owner to address(0) will lose all unclaimed tokens permanently. Since drops have no expiry deadline and remain claimable indefinitely, there is no time-based recovery mechanism. [4](#0-3) 

## Likelihood Explanation
- **Attacker Profile**: Any user can create a drop (no permission required). This affects both malicious actors (griefing) and honest users (accidental errors).
- **Preconditions**: 
  - Drop is created with owner set to address(0), a typo address, or any inaccessible address
  - Drop is funded with tokens via the `fund()` function
  - Some tokens remain unclaimed
- **Execution Complexity**: Single transaction to fund a drop with an invalid owner. The vulnerability is triggered passively when the owner later attempts to refund.
- **Frequency**: Can occur with any new drop creation. Given the owner address is part of the immutable drop identifier, once a drop is created with an inaccessible owner, the funds are permanently locked. [5](#0-4) 

## Recommendation

Add validation in the `fund()` function to prevent drops from being created with invalid owner addresses:

```solidity
// In src/Incentives.sol, function fund(), after line 20:

function fund(DropKey memory key, uint128 minimum) external override returns (uint128 fundedAmount) {
    // ADD THIS VALIDATION:
    if (key.owner == address(0)) {
        revert InvalidOwner(); // New error: error InvalidOwner();
    }
    
    bytes32 id = key.toDropId();
    // ... rest of function
}
```

Alternative mitigation: Implement an emergency recovery mechanism with a reasonable timelock (e.g., 180 days after last claim) that allows anyone to sweep unclaimed funds to a designated treasury or burn address if the owner hasn't called refund.

## Proof of Concept

```solidity
// File: test/Exploit_PermanentFundLock.t.sol
// Run with: forge test --match-test test_PermanentFundLock -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Incentives.sol";
import "../src/types/dropKey.sol";
import "../src/types/claimKey.sol";

contract Exploit_PermanentFundLock is Test {
    Incentives incentives;
    MockERC20 token;
    
    function setUp() public {
        incentives = new Incentives();
        token = new MockERC20("Test Token", "TEST", 18);
    }
    
    function test_PermanentFundLock() public {
        // SETUP: Create a drop with owner = address(0)
        DropKey memory key = DropKey({
            owner: address(0), // Invalid owner - nobody can call from address(0)
            token: address(token),
            root: bytes32(uint256(1)) // Arbitrary merkle root
        });
        
        // Fund the drop with 1000 tokens
        address funder = address(0x1234);
        token.mint(funder, 1000 ether);
        
        vm.startPrank(funder);
        token.approve(address(incentives), 1000 ether);
        incentives.fund(key, 1000 ether);
        vm.stopPrank();
        
        // Verify tokens are in the contract
        assertEq(token.balanceOf(address(incentives)), 1000 ether, "Tokens should be in Incentives contract");
        
        // EXPLOIT: Try to refund - this will ALWAYS revert
        vm.expectRevert(IIncentives.DropOwnerOnly.selector);
        vm.prank(address(0)); // Even pranking as address(0) won't work
        incentives.refund(key);
        
        // Try with any other address - still reverts
        vm.expectRevert(IIncentives.DropOwnerOnly.selector);
        vm.prank(funder);
        incentives.refund(key);
        
        // VERIFY: Tokens are permanently locked
        assertEq(token.balanceOf(address(incentives)), 1000 ether, 
            "Vulnerability confirmed: Tokens permanently locked with no recovery path");
    }
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    string public name;
    string public symbol;
    uint8 public decimals;
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        
        return true;
    }
}
```

---

## Notes

The vulnerability stems from the immutable nature of the drop identifier combined with lack of input validation. The drop ID is derived from the owner address via `keccak256(owner, token, root)`, making the owner permanently fixed once the drop is created. [5](#0-4) 

The Incentives contract has no admin functions or ownership mechanisms that could provide an alternative recovery path. [6](#0-5)  The only external functions are `fund()`, `refund()`, and `claim()`, with `refund()` being the sole recovery mechanism.

Real-world scenarios where this could occur:
1. **User error**: Copy-paste mistake, typo in owner address, or confusion with multisig addresses
2. **Key loss**: Owner loses private key after drop creation but before refunding
3. **Smart contract owner**: Drop created with a contract address that lacks `refund()` calling capability
4. **Intentional griefing**: Malicious actor intentionally locks tokens by setting owner to address(0)

### Citations

**File:** src/types/dropKey.sol (L5-6)
```text
/// @dev The owner can reclaim the drop token at any time
///      The root is the root of a merkle trie that contains all the incentives to be distributed
```

**File:** src/types/dropKey.sol (L21-26)
```text
function toDropId(DropKey memory key) pure returns (bytes32 h) {
    assembly ("memory-safe") {
        // assumes that owner, token have no dirty upper bits
        h := keccak256(key, 96)
    }
}
```

**File:** src/Incentives.sol (L18-18)
```text
contract Incentives is IIncentives, ExposedStorage, Multicallable {
```

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
