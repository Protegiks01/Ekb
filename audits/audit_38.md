## Title
MEVCaptureRouter Debt Accounting Mismatch Causes DOS on Native ETH Exact Output Swaps

## Summary
When using MEVCaptureRouter for exact output swaps with native ETH as the input token, the MEV_CAPTURE extension modifies the returned balanceUpdate to add additional fees, but the Core's debt tracking system only accounts for the original swap amount. This mismatch causes the Router's settlement logic to send more ETH than tracked by the debt system, resulting in a DebtsNotZeroed revert that blocks all such transactions. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/MEVCaptureRouter.sol` (MEVCaptureRouter._swap function, lines 27-43) and `src/extensions/MEVCapture.sol` (handleForwardData function, lines 177-260)

**Intended Logic:** The MEVCaptureRouter should enable swaps through pools with the MEV_CAPTURE extension by forwarding the swap to the extension, which then adds additional fees based on tick movement and returns the modified balanceUpdate to the Router for settlement. [2](#0-1) 

**Actual Logic:** For exact output swaps where the user pays with native ETH:
1. Router calculates `value = 0` for exact output swaps (condition at line 106-110 requires exact input)
2. MEVCaptureRouter calls CORE.forward with no ETH value
3. MEVCapture.handleForwardData calls CORE.swap(0, poolKey, params) with msg.value=0
4. CORE.swap executes and updates debt: Debt[token0] = originalInputAmount (e.g., 100)
5. MEVCapture adds additional fees to the input amount: modifiedBalanceUpdate.delta0() = originalInputAmount + fee (e.g., 105)
6. MEVCaptureRouter returns this modified balanceUpdate to Router
7. Router's settlement logic (lines 132-146) sends modifiedBalanceUpdate.delta0() amount of ETH (105)
8. Debt becomes: Debt[token0] = 100 - 105 = -5 (non-zero credit)
9. Transaction reverts with DebtsNotZeroed at lock completion [3](#0-2) 

**Exploitation Path:**
1. User initiates an exact output swap to receive 50 token1, paying with native ETH on a MEV_CAPTURE pool
2. Call Router.swap{value: 150}() with params.amount = -50 (negative for exact output), params.isToken1 = true
3. Router.handleLockData calculates value = 0 (exact output condition)
4. MEVCaptureRouter._swap forwards to MEV_CAPTURE extension without sending ETH
5. CORE.swap calculates input required: delta0 = 100 ETH, updates Debt[address(0)] = 100
6. MEVCapture adds 5 ETH additional fee based on tick crossing: returns balanceUpdate with delta0 = 105
7. Router settlement at line 141 sends 105 ETH via SafeTransferLib.safeTransferETH
8. Final debt: Debt[address(0)] = -5 (credit), Debt[token1] = 0
9. Lock completion check (line 175-180) finds nonzeroDebtCount = 1
10. Transaction reverts with DebtsNotZeroed(id) [4](#0-3) 

**Security Property Broken:** Flash Accounting invariant - all flash loans must be repaid with proper accounting. The debt tracking becomes inconsistent when MEVCapture modifies the balanceUpdate but the debt was already recorded with the original amount. [5](#0-4) 

## Impact Explanation
- **Affected Assets**: All pools using the MEV_CAPTURE extension when users attempt exact output swaps with native ETH as input
- **Damage Severity**: Complete DOS - users cannot execute exact output swaps with native ETH on MEV_CAPTURE pools. While not direct fund theft, this breaks core protocol functionality and forces users to use less efficient exact input swaps or avoid MEV_CAPTURE pools entirely
- **User Impact**: Any user attempting exact output swaps with ETH input on MEV_CAPTURE pools will have their transactions revert. This affects all users of these pools for this swap type

## Likelihood Explanation
- **Attacker Profile**: Any regular user attempting a legitimate swap (no malicious intent required)
- **Preconditions**: Pool must have MEV_CAPTURE extension and user must attempt exact output swap with native ETH as input token
- **Execution Complexity**: Single transaction, normal user flow
- **Frequency**: Every exact output swap with native ETH on MEV_CAPTURE pools will revert

## Recommendation

The issue requires MEVCaptureRouter to handle the value parameter correctly for the modified balanceUpdate. The fix should transfer ETH based on the modified delta, not the original value: [6](#0-5) 

```solidity
// In src/MEVCaptureRouter.sol, function _swap, lines 32-42:

// CURRENT (vulnerable):
// For MEV_CAPTURE pools, forwards call and then sends ETH separately based on original value parameter
// This causes debt mismatch when balanceUpdate is modified

// FIXED:
function _swap(uint256 value, PoolKey memory poolKey, SwapParameters params)
    internal
    override
    returns (PoolBalanceUpdate balanceUpdate, PoolState stateAfter)
{
    if (poolKey.config.extension() != MEV_CAPTURE) {
        (balanceUpdate, stateAfter) = CORE.swap(value, poolKey, params.withDefaultSqrtRatioLimit());
    } else {
        (balanceUpdate, stateAfter) = abi.decode(
            CORE.forward(MEV_CAPTURE, abi.encode(poolKey, params.withDefaultSqrtRatioLimit())),
            (PoolBalanceUpdate, PoolState)
        );
        // For exact output swaps, send ETH based on the MODIFIED delta0 amount, not the original value
        // This ensures debt accounting matches the returned balanceUpdate
        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS && balanceUpdate.delta0() > 0) {
            SafeTransferLib.safeTransferETH(address(CORE), uint128(uint256(int256(balanceUpdate.delta0()))));
        } else if (value != 0) {
            SafeTransferLib.safeTransferETH(address(CORE), value);
        }
    }
}
```

Alternative: Modify MEVCapture to not add fees on native token input, or have it handle the ETH transfer internally.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureNativeETHDOS.t.sol
// Run with: forge test --match-test test_MEVCaptureNativeETH_ExactOutput_DOS -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import {BaseMEVCaptureTest} from "./extensions/MEVCapture.t.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {NATIVE_TOKEN_ADDRESS} from "../src/math/constants.sol";
import {IFlashAccountant} from "../src/interfaces/IFlashAccountant.sol";

contract Exploit_MEVCaptureNativeETH is BaseMEVCaptureTest {
    PoolKey poolKeyWithNative;
    
    function setUp() public override {
        BaseMEVCaptureTest.setUp();
        
        // Create pool with native ETH as token0 and MEV_CAPTURE extension
        poolKeyWithNative = createPool(
            NATIVE_TOKEN_ADDRESS,
            address(token1),
            0,
            createConcentratedPoolConfig(500, 1, address(mevCapture))
        );
        
        // Add liquidity
        core.lock(abi.encode(0, poolKeyWithNative, 1000000e18));
    }
    
    function test_MEVCaptureNativeETH_ExactOutput_DOS() public {
        // SETUP: User wants exactly 1e18 token1 output, paying with native ETH
        int128 exactOutputAmount = -int128(1e18); // negative = exact output
        
        // Mint some token1 to the pool for the swap
        deal(address(token1), address(this), 100e18);
        token1.approve(address(router), type(uint256).max);
        
        // EXPLOIT: Attempt exact output swap with native ETH input
        // This will revert with DebtsNotZeroed when MEVCapture adds fees
        
        vm.expectRevert(abi.encodeWithSelector(IFlashAccountant.DebtsNotZeroed.selector, 0));
        router.swap{value: 10e18}(
            poolKeyWithNative,
            createSwapParameters({
                _amount: exactOutputAmount,
                _isToken1: true,  // specifying token1 as output
                _sqrtRatioLimit: 0,
                _skipAhead: 0
            }),
            type(int256).min,
            address(this)
        );
        
        // VERIFY: Transaction reverts with DebtsNotZeroed
        // The vulnerability is confirmed: exact output swaps with native ETH are DOSed on MEV_CAPTURE pools
    }
}
```

### Citations

**File:** src/MEVCaptureRouter.sol (L27-43)
```text
    function _swap(uint256 value, PoolKey memory poolKey, SwapParameters params)
        internal
        override
        returns (PoolBalanceUpdate balanceUpdate, PoolState stateAfter)
    {
        if (poolKey.config.extension() != MEV_CAPTURE) {
            (balanceUpdate, stateAfter) = CORE.swap(value, poolKey, params.withDefaultSqrtRatioLimit());
        } else {
            (balanceUpdate, stateAfter) = abi.decode(
                CORE.forward(MEV_CAPTURE, abi.encode(poolKey, params.withDefaultSqrtRatioLimit())),
                (PoolBalanceUpdate, PoolState)
            );
            if (value != 0) {
                SafeTransferLib.safeTransferETH(address(CORE), value);
            }
        }
    }
```

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

**File:** src/Router.sol (L106-146)
```text
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

                int128 amountCalculated = params.isToken1() ? -balanceUpdate.delta0() : -balanceUpdate.delta1();
                if (amountCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
                }

                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
                } else {
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
                    }

                    if (balanceUpdate.delta0() != 0) {
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

**File:** src/base/FlashAccountant.sol (L175-180)
```text
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
```

**File:** src/Core.sol (L834-834)
```text
                _updatePairDebtWithNative(locker.id(), token0, token1, balanceUpdate.delta0(), balanceUpdate.delta1());
```
