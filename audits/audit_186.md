# NoVulnerability found for this question.

## Investigation Summary

After thorough investigation of the Ekubo Protocol codebase, I found that the **premise of the security question is false**. The Core contract is NOT upgradeable and does NOT use a proxy pattern, therefore the scenario described cannot occur.

## Key Findings

### 1. Core Contract Architecture

The Core contract is deployed as an **immutable singleton** with no upgrade mechanisms: [1](#0-0) 

The contract inherits from `ICore`, `FlashAccountant`, and `ExposedStorage` with no ownership or upgrade functionality. The README explicitly confirms this architecture:

- README-sponsor.md states: "multi-chain ownerless and permissionless contract"
- No `selfdestruct`, `delegatecall`, or proxy patterns found in Core.sol

### 2. UsesCore.sol Implementation

The `UsesCore` base contract stores an immutable reference to the Core contract: [2](#0-1) 

The immutable `CORE` variable is set once in the constructor and can never be changed. The `onlyCore` modifier checks that `msg.sender` matches this immutable address.

### 3. Extension Architecture

All production extensions inherit from `BaseExtension`, which inherits from `UsesCore`: [3](#0-2) [4](#0-3) 

Each extension's constructor passes the Core instance to the base contracts, establishing a permanent, immutable reference.

### 4. Test Validation

The test suite confirms the onlyCore modifier behavior: [5](#0-4) [6](#0-5) 

The tests demonstrate that the onlyCore modifier correctly validates the caller matches the immutable CORE address.

## Conclusion

Since the Core contract is **not upgradeable** and **does not use a proxy pattern**, the immutable `CORE` address in `UsesCore.sol` **cannot become stale**. The onlyCore modifier will always function correctly for calls originating from the specific Core instance the extension was deployed with.

The only scenario where extensions might reference a different Core is if a completely new Core contract is deployed to a different address - but this would represent two independent protocol instances, not an upgrade scenario. Extensions would continue to work correctly with their designated Core instance.

**This is not a vulnerability** - it is the intended immutable architecture design of the Ekubo Protocol.

### Citations

**File:** src/Core.sol (L40-46)
```text
/// @title Ekubo Protocol Core
/// @author Moody Salem <moody@ekubo.org>
/// @notice Singleton contract holding all tokens and containing all possible operations in Ekubo Protocol
/// @dev Implements the core AMM functionality including pools, positions, swaps, and fee collection
/// @dev Note this code is under the terms of the Ekubo DAO Shared Revenue License 1.0.
/// @dev The full terms of the license can be found at the contenthash specified at ekubo-license-v1.eth.
contract Core is ICore, FlashAccountant, ExposedStorage {
```

**File:** src/base/UsesCore.sol (L9-27)
```text
abstract contract UsesCore {
    /// @notice Thrown when a function restricted to the core contract is called by another address
    error CoreOnly();

    /// @notice The core contract instance that this contract interacts with
    ICore internal immutable CORE;

    /// @notice Constructs the UsesCore contract with a core contract reference
    /// @param _core The core contract instance to use
    constructor(ICore _core) {
        CORE = _core;
    }

    /// @notice Restricts function access to only the core contract
    /// @dev Reverts with CoreOnly if called by any address other than the core contract
    modifier onlyCore() {
        if (msg.sender != address(CORE)) revert CoreOnly();
        _;
    }
```

**File:** src/extensions/MEVCapture.sol (L42-46)
```text
contract MEVCapture is IMEVCapture, BaseExtension, BaseForwardee, ExposedStorage {
    using CoreLib for *;
    using ExposedStorageLib for *;

    constructor(ICore core) BaseExtension(core) BaseForwardee(core) {}
```

**File:** src/extensions/TWAMM.sol (L60-63)
```text
contract TWAMM is ITWAMM, ExposedStorage, BaseExtension, BaseForwardee {
    using CoreLib for *;

    constructor(ICore core) BaseExtension(core) BaseForwardee(core) {}
```

**File:** test/base/UsesCore.t.sol (L31-39)
```text
    function test_protected_revertsIfNotCore(address core, address caller) public {
        vm.assume(caller != core);

        TestTarget tt = new TestTarget(ICore(payable(core)));
        vm.prank(caller);
        vm.expectRevert(UsesCore.CoreOnly.selector);
        tt.protected();
        assertEq(tt.x(), 0);
    }
```

**File:** test/base/UsesCore.t.sol (L41-47)
```text
    function test_protected_callableByCore(address core) public {
        TestTarget tt = new TestTarget(ICore(payable(core)));
        assertEq(tt.x(), 0);
        vm.prank(core);
        tt.protected();
        assertEq(tt.x(), 1);
    }
```
