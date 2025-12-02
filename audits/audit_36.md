# NoVulnerability found for this question.

After thorough investigation of the MEVCaptureRouter._swap function and the complete debt accounting flow, I found no exploitable vulnerability related to the "late ETH payment" concern.

## Analysis Summary

**The questioned code path:** [1](#0-0) 

**Key findings:**

1. **Trust Model Violation**: The security question assumes a "malicious MEV_CAPTURE extension," but the protocol's trust model explicitly states that in-scope extensions (including MEVCapture) should NOT be assumed malicious, and third-party extension misbehavior is out of scope.

2. **Correct Debt Accounting**: The "late" ETH payment at line 40 is intentional and properly handled through a two-phase settlement:
   - **Phase 1**: MEVCaptureRouter sends the user's specified ETH amount after forward returns [2](#0-1) 
   
   - **Phase 2**: Router.handleLockData() sends additional ETH to cover MEV fees based on the actual balanceUpdate [3](#0-2) 

3. **Protected Against Manipulation**: 
   - Extension hooks are skipped when the locker equals the extension address, preventing recursive callbacks [4](#0-3) 
   
   - The flash accounting system tracks debt by lock ID and enforces zero-debt invariant before lock completion [5](#0-4) 

4. **MEV Fees Correctly Handled**: MEVCapture increases debt through updateSavedBalances when adding fees, and this debt is properly settled by the Router's payment logic [6](#0-5) 

**Notes:**
- The forward mechanism temporarily changes the locker address but maintains the same lock ID, ensuring debt continuity
- For multihop swaps, the protocol uses both `totalSpecified` and `totalCalculated` to properly account for MEV fees
- Any debt mismatch would cause the transaction to revert with `DebtsNotZeroed`, preventing exploitation
- The architecture correctly separates user-specified amounts from calculated amounts including fees

The late ETH transfer is a design choice to support the forward pattern and does not create a vulnerability. The debt accounting system correctly handles all scenarios.

### Citations

**File:** src/MEVCaptureRouter.sol (L35-41)
```text
            (balanceUpdate, stateAfter) = abi.decode(
                CORE.forward(MEV_CAPTURE, abi.encode(poolKey, params.withDefaultSqrtRatioLimit())),
                (PoolBalanceUpdate, PoolState)
            );
            if (value != 0) {
                SafeTransferLib.safeTransferETH(address(CORE), value);
            }
```

**File:** src/Router.sol (L134-146)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
```

**File:** src/libraries/ExtensionCallPointsLib.sol (L81-85)
```text
    function shouldCallBeforeSwap(IExtension extension, Locker locker) internal pure returns (bool yes) {
        assembly ("memory-safe") {
            yes := and(shr(158, extension), iszero(eq(shl(96, locker), shl(96, extension))))
        }
    }
```

**File:** src/base/FlashAccountant.sol (L174-181)
```text
            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }
```

**File:** src/extensions/MEVCapture.sol (L254-256)
```text
            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }
```
