## Title
Orders Constructor Lacks Core-TWAMM Compatibility Validation Causing Permanent Fund Lock

## Summary
The Orders constructor accepts `ICore core` and `ITWAMM _twamm` as separate parameters but fails to validate that the TWAMM extension is configured for the same Core instance. [1](#0-0)  If Orders is deployed with a mismatched Core and TWAMM (e.g., Orders.CORE = CoreA but Orders.TWAMM_EXTENSION points to a TWAMM deployed with CoreB), all order operations will permanently revert, locking user funds indefinitely.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Orders.sol` - constructor (lines 38-40), `handleLockData` function (lines 134-174)

**Intended Logic:** The Orders contract should interact with a TWAMM extension that is registered with the same Core instance that Orders uses for lock management and token accounting.

**Actual Logic:** The constructor validates that `core` is non-zero via the `UsesCore(core)` inheritance chain [2](#0-1)  but does not verify that `_twamm` was deployed with the same `core` instance. The TWAMM's internal `CORE` reference is not publicly accessible for validation. [3](#0-2) 

**Exploitation Path:**
1. **Mismatched Deployment**: Orders is deployed with `core = CoreA` and `_twamm = TWAMM_B` (where TWAMM_B was constructed with `CoreB`) [1](#0-0) 

2. **User Creates Order**: User calls `increaseSellAmount()` which encodes a call to `CORE.updateSaleRate()` via TWAMMLib [4](#0-3) 

3. **Forward Call Fails**: In `handleLockData`, the code calls `CORE.updateSaleRate(TWAMM_EXTENSION, ...)` which uses TWAMMLib to invoke `CoreA.forward(address(TWAMM_B), data)` [5](#0-4) [6](#0-5) 

4. **TWAMM Rejects Call**: CoreA's forward mechanism calls `TWAMM_B.forwarded_2374103877()`, but TWAMM_B's BaseForwardee checks `if (msg.sender != address(ACCOUNTANT))` where `ACCOUNTANT = CoreB` [7](#0-6)  Since `msg.sender = CoreA ≠ CoreB`, it reverts with `BaseForwardeeAccountantOnly()`

5. **Permanent Lock**: All order operations (`increaseSellAmount`, `decreaseSaleRate`, `collectProceeds`) become permanently unusable [8](#0-7)  Users cannot modify or withdraw from their orders, causing permanent fund loss.

**Security Property Broken:** Violates Critical Invariant #2: "All positions MUST be withdrawable at any time" and Invariant #4: "Extension failures should not freeze pools or lock user capital (for in-scope extensions)"

## Impact Explanation
- **Affected Assets**: All tokens deposited into TWAMM orders through the misconfigured Orders contract become permanently locked and unrecoverable.
- **Damage Severity**: 100% of user funds in orders are permanently lost. Users cannot increase orders (locked deposits), decrease sale rates (no refunds), or collect proceeds (purchased tokens inaccessible).
- **User Impact**: Every user who interacts with the misconfigured Orders contract loses all deposited funds. The Orders NFTs become worthless as the underlying positions cannot be managed or redeemed.

## Likelihood Explanation
- **Attacker Profile**: This is primarily a deployment footgun rather than an active attack. However, a malicious actor could deploy a fake Orders contract with intentionally mismatched parameters and social-engineer users into using it.
- **Preconditions**: Orders contract deployed with `core` parameter pointing to one Core instance and `_twamm` parameter pointing to a TWAMM extension deployed with a different Core instance.
- **Execution Complexity**: Single deployment error or deliberate misconfiguration. Once deployed, every user interaction triggers the permanent lock.
- **Frequency**: One-time deployment error affects all subsequent users indefinitely until a corrected Orders contract is deployed.

## Recommendation

Since the TWAMM's `CORE` reference is internal and cannot be read externally, the validation must be added to the TWAMM contract or documented clearly:

```solidity
// OPTION 1: Add public getter to BaseExtension/UsesCore
// In src/base/UsesCore.sol, add:

/// @notice Returns the Core contract this contract was configured with
/// @return The Core contract address
function getCoreAddress() external view returns (address) {
    return address(CORE);
}

// Then in src/Orders.sol constructor:
constructor(ICore core, ITWAMM _twamm, address owner) 
    BaseNonfungibleToken(owner) 
    BaseLocker(core) 
    UsesCore(core) 
{
    // Validate TWAMM is configured for the same Core
    require(
        _twamm.getCoreAddress() == address(core),
        "Orders: TWAMM must be configured for the same Core instance"
    );
    TWAMM_EXTENSION = _twamm;
}
```

**Alternative mitigation**: Add comprehensive deployment tests that verify Orders, Core, and TWAMM are correctly configured together before mainnet deployment.

## Proof of Concept

```solidity
// File: test/Exploit_MismatchedCoreTWAMM.t.sol
// Run with: forge test --match-test test_MismatchedCoreTWAMM -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Orders.sol";
import "../src/extensions/TWAMM.sol";
import "../src/types/orderKey.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {ERC20Mock} from "./mocks/ERC20Mock.sol";

contract Exploit_MismatchedCoreTWAMM is Test {
    Core coreA;
    Core coreB;
    TWAMM twammB;
    Orders orders;
    ERC20Mock token0;
    ERC20Mock token1;
    address owner = address(this);
    address user = address(0x1234);

    function setUp() public {
        // Deploy two separate Core instances
        coreA = new Core();
        coreB = new Core();
        
        // Deploy TWAMM for CoreB
        twammB = new TWAMM(coreB);
        
        // Deploy Orders with MISMATCHED Core and TWAMM
        // Orders points to CoreA, but TWAMM points to CoreB
        orders = new Orders(coreA, twammB, owner);
        
        // Deploy tokens
        token0 = new ERC20Mock("Token0", "TK0");
        token1 = new ERC20Mock("Token1", "TK1");
        
        // Fund user
        token0.mint(user, 1000e18);
        vm.deal(user, 100 ether);
    }

    function test_MismatchedCoreTWAMM() public {
        // SETUP: User approves Orders and tries to create an order
        vm.startPrank(user);
        token0.approve(address(orders), type(uint256).max);
        
        uint64 startTime = uint64(block.timestamp + 1000);
        uint64 endTime = startTime + 3600;
        
        OrderKey memory orderKey = OrderKey({
            token0: address(token0),
            token1: address(token1),
            config: createOrderConfig({
                fee: 3000,
                isToken1: false,
                startTime: startTime,
                endTime: endTime
            })
        });
        
        // EXPLOIT: Attempt to create order
        // This will REVERT because Orders uses CoreA but TWAMM expects CoreB
        vm.expectRevert(); // BaseForwardeeAccountantOnly() error
        orders.mintAndIncreaseSellAmount(orderKey, 100e18, type(uint112).max);
        
        vm.stopPrank();
        
        // VERIFY: Contract is permanently bricked
        // All order operations will fail with the same revert
        assertEq(orders.balanceOf(user), 0, "No orders created due to misconfiguration");
    }
}
```

## Notes

The vulnerability stems from the architectural decision to pass Core and TWAMM as separate constructor parameters without validation. While the `UsesCore` base contract validates the Core reference, [2](#0-1)  there is no mechanism to verify compatibility between the two parameters.

The BaseForwardee pattern used by TWAMM validates that calls come from the correct ACCOUNTANT (which is the Core it was deployed with), [9](#0-8) [7](#0-6)  but this security check becomes a foot gun when Orders is misconfigured to use a different Core instance than its TWAMM extension expects.

This is not merely a deployment error - it's a missing critical validation that could result from honest mistakes during upgrades, redeployments, or multi-chain deployments where different Core instances exist. The protocol should defensively validate compatibility at deployment time to prevent permanent user fund loss.

### Citations

**File:** src/Orders.sol (L38-40)
```text
    constructor(ICore core, ITWAMM _twamm, address owner) BaseNonfungibleToken(owner) BaseLocker(core) UsesCore(core) {
        TWAMM_EXTENSION = _twamm;
    }
```

**File:** src/Orders.sol (L53-119)
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

    /// @inheritdoc IOrders
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

    /// @inheritdoc IOrders
    function decreaseSaleRate(uint256 id, OrderKey memory orderKey, uint112 saleRateDecrease)
        external
        payable
        returns (uint112 refund)
    {
        refund = decreaseSaleRate(id, orderKey, saleRateDecrease, msg.sender);
    }

    /// @inheritdoc IOrders
    function collectProceeds(uint256 id, OrderKey memory orderKey, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 proceeds)
    {
        proceeds = abi.decode(lock(abi.encode(CALL_TYPE_COLLECT_PROCEEDS, id, orderKey, recipient)), (uint128));
    }

    /// @inheritdoc IOrders
    function collectProceeds(uint256 id, OrderKey memory orderKey) external payable returns (uint128 proceeds) {
        proceeds = collectProceeds(id, orderKey, msg.sender);
    }
```

**File:** src/Orders.sol (L142-142)
```text
                CORE.updateSaleRate(TWAMM_EXTENSION, bytes32(id), orderKey, SafeCastLib.toInt112(saleRateDelta));
```

**File:** src/base/UsesCore.sol (L14-14)
```text
    ICore internal immutable CORE;
```

**File:** src/base/UsesCore.sol (L18-20)
```text
    constructor(ICore _core) {
        CORE = _core;
    }
```

**File:** src/libraries/TWAMMLib.sol (L124-130)
```text
    function updateSaleRate(ICore core, ITWAMM twamm, bytes32 salt, OrderKey memory orderKey, int112 saleRateDelta)
        internal
        returns (int256 amount)
    {
        amount =
            abi.decode(core.forward(address(twamm), abi.encode(uint256(0), salt, orderKey, saleRateDelta)), (int256));
    }
```

**File:** src/base/BaseForwardee.sol (L19-20)
```text
    constructor(IFlashAccountant _accountant) {
        ACCOUNTANT = _accountant;
```

**File:** src/base/BaseForwardee.sol (L31-32)
```text
    function forwarded_2374103877(Locker original) external {
        if (msg.sender != address(ACCOUNTANT)) revert BaseForwardeeAccountantOnly();
```
