# NoVulnerability found for this question.

After a comprehensive investigation of the MEVCapture extension and the forward() mechanism, I found **no exploitable vulnerability** that allows bypassing priority fee charges. Here's my analysis:

## Investigation Summary

**MEVCapture Fee Enforcement Mechanism:**
The `beforeSwap` hook enforces that all swaps must go through the `forward()` mechanism, preventing direct `Core.swap()` calls on MEVCapture pools. [1](#0-0) 

**Forward Mechanism Debt Tracking:**
When `forward()` is called, it temporarily changes the locker address but **preserves the original locker ID**, ensuring debt is tracked correctly for the original caller. [2](#0-1) 

**Fee Calculation and Charging:**
MEVCapture calculates additional fees based on tick movement (not blockchain priority fees), then properly charges them via `updateSavedBalances`, which updates the debt for the current locker ID. [3](#0-2) [4](#0-3) [5](#0-4) 

## Why No Bypass Exists

1. **Direct swap prevention**: The `beforeSwap` hook blocks all direct swaps, forcing use of `forward()`
2. **Locker ID preservation**: The same locker ID is maintained across forward calls, so all debt accumulates under the original caller
3. **Mandatory debt settlement**: All debt must be settled before the lock is released
4. **Tick-based fees**: Fees are calculated from tick movement (objective price impact), not manipulable transaction parameters

## Notes

The comment at line 41 mentions "priority fee" but the implementation uses tick movement instead. This is **not a vulnerability** - it's actually more robust because:
- Blockchain priority fees can be manipulated by submitting transactions through contracts
- Tick movement directly measures the swap's price impact on the pool
- This approach is more resistant to MEV extraction attempts

All attack vectors explored (nested forwards, multiple swaps, custom contracts, state manipulation) fail to bypass the fee mechanism.

### Citations

**File:** src/extensions/MEVCapture.sol (L83-86)
```text
    /// @notice We only allow swapping via forward to this extension
    function beforeSwap(Locker, PoolKey memory, SwapParameters) external pure override(BaseExtension, IExtension) {
        revert SwapMustHappenThroughForward();
    }
```

**File:** src/extensions/MEVCapture.sol (L211-216)
```text
            // however many tick spacings were crossed is the fee multiplier
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));

```

**File:** src/extensions/MEVCapture.sol (L254-256)
```text
            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
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

**File:** src/Core.sol (L170-171)
```text
        _updatePairDebtWithNative(id, token0, token1, delta0, delta1);
    }
```
