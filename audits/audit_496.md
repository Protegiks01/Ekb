## Title
MEVCapture Storage Slot Mismatch Causes Permanent Loss of MEV Capture Fees

## Summary
The MEVCapture extension contains a critical storage slot calculation mismatch where saved balances are read from one slot but written to a different slot. When swaps execute via the forward path (normal user flow through MEVCaptureRouter), MEVCapture reads saved balances using its own address but writes using the router's address as the locker, causing all MEV capture fees to accumulate in an inaccessible storage slot.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/extensions/MEVCapture.sol` (functions `loadCoreState` line 163, `handleForwardData` line 255) and `src/Core.sol` (function `updateSavedBalances` line 155)

**Intended Logic:** MEVCapture should accumulate MEV fees in its saved balances slot, then periodically convert them to protocol fees via `accumulateAsFees`. The saved balances act as a buffer where MEV fees are stored before being converted to protocol fees.

**Actual Logic:** The storage slot for saved balances is calculated differently for reads vs writes:
- **Read**: MEVCapture.loadCoreState calculates the slot using `address(this)` (MEVCapture's address)
- **Write**: Core.updateSavedBalances calculates the slot using `lockerAddr` from `_requireLocker()` (the current locker's address)

When users swap through MEVCaptureRouter:
1. Router calls `Core.lock()` → locker is set to Router's address
2. Router calls `Core.forward(MEVCapture, swapData)` within the lock
3. MEVCapture.handleForwardData executes the swap
4. handleForwardData reads saved balances from slot = `keccak256(MEVCapture || token0 || token1 || poolId)` (always returns 0)
5. handleForwardData writes new MEV fees to slot = `keccak256(Router || token0 || token1 || poolId)` (different slot!) [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. Pool with MEVCapture extension is initialized
2. User swaps via MEVCaptureRouter (normal flow)
3. MEVCaptureRouter.swap() → calls internal lock → locker = MEVCaptureRouter
4. Within lock, calls `CORE.forward(MEV_CAPTURE, swapData)`
5. MEVCapture.handleForwardData executes:
   - Reads saved balances from MEVCapture's slot (gets 0, thinks no fees accumulated)
   - Charges MEV capture fee based on tick movement (e.g., 100 tokens)
   - Calls `updateSavedBalances` with positive delta to save the new fees
   - Core writes to Router's slot: `savedBalances[Router][pool] = 100`
6. Next swap repeats the same issue:
   - Reads from MEVCapture's slot (still 0)
   - Doesn't convert previous fees to protocol fees (because it thinks there are none)
   - Charges new MEV fee (e.g., 50 tokens)
   - Writes to Router's slot: `savedBalances[Router][pool] = 150`
7. MEV fees accumulate indefinitely in Router's slot but are never read or converted to protocol fees [3](#0-2) [4](#0-3) 

**Security Property Broken:** Fee Accounting invariant - "Position fee collection must be accurate and never allow double-claiming" is violated. MEV capture fees are collected from users but never properly accounted for as protocol fees, resulting in permanent loss.

## Impact Explanation
- **Affected Assets**: All MEV capture fees collected from user swaps through the forward path (normal user flow via MEVCaptureRouter)
- **Damage Severity**: 100% of MEV capture fees are permanently locked in Core contract under the router's saved balances slot. These fees can never be recovered because:
  - MEVCapture always reads from its own slot (which remains at 0)
  - The Router has no logic to withdraw or convert saved balances
  - Even calling `accumulatePoolFees` directly doesn't help because it reads from MEVCapture's slot, not Router's slot
- **User Impact**: The protocol loses all MEV capture fees, which are a core revenue source. Users pay MEV fees but the protocol cannot collect them as intended. This affects every pool with MEVCapture extension.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a bug that occurs during normal operation
- **Preconditions**: 
  - Pool with MEVCapture extension exists
  - User swaps through MEVCaptureRouter (standard user flow)
  - Tick movement occurs (which triggers MEV fees)
- **Execution Complexity**: Happens automatically on every user swap via the forward path
- **Frequency**: Occurs on every swap where tick movement causes MEV fees to be charged. Affects all pools with MEVCapture extension continuously.

## Recommendation

```solidity
// In src/extensions/MEVCapture.sol, function loadCoreState, line 163:

// CURRENT (vulnerable):
StorageSlot feesSlot = CoreStorageLayout.savedBalancesSlot(address(this), token0, token1, PoolId.unwrap(poolId));

// FIXED:
// When reading saved balances within a lock context, use the current locker address
// to match the slot that updateSavedBalances will write to
(, address lockerAddr) = CORE.getCurrentLocker().parse();
StorageSlot feesSlot = CoreStorageLayout.savedBalancesSlot(lockerAddr, token0, token1, PoolId.unwrap(poolId));
```

**Alternative approach:** Modify Core.updateSavedBalances to accept an explicit `owner` parameter instead of deriving it from the locker:

```solidity
// In src/Core.sol, function updateSavedBalances, line 124:

// CURRENT (vulnerable):
function updateSavedBalances(
    address token0,
    address token1,
    bytes32,
    int256 delta0,
    int256 delta1
)
    external
    payable
{
    if (token0 >= token1) revert SavedBalanceTokensNotSorted();
    (uint256 id, address lockerAddr) = _requireLocker().parse();
    // ... uses lockerAddr for slot calculation

// FIXED:
function updateSavedBalances(
    address token0,
    address token1,
    bytes32 salt,
    int256 delta0,
    int256 delta1
)
    external
    payable
{
    if (token0 >= token1) revert SavedBalanceTokensNotSorted();
    (uint256 id, address lockerAddr) = _requireLocker().parse();
    
    // Allow msg.sender to be either the locker (for self-owned balances)
    // or the Core contract (for extension-managed balances)
    address owner = (msg.sender == address(this)) ? lockerAddr : msg.sender;
    
    assembly ("memory-safe") {
        function addDelta(u, i) -> result {
            let sum := add(u, i)
            let sign := shr(255, i)
            if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                mstore(0x00, 0x1293d6fa)
                revert(0x1c, 0x04)
            }
            result := sum
        }

        let free := mload(0x40)
        mstore(free, owner)  // Use explicit owner instead of lockerAddr
        mstore(add(free, 0x20), token0)
        mstore(add(free, 0x40), token1)
        mstore(add(free, 0x60), salt)
        let slot := keccak256(free, 128)
        let balances := sload(slot)

        let b0 := shr(128, balances)
        let b1 := shr(128, shl(128, balances))

        let b0Next := addDelta(b0, delta0)
        let b1Next := addDelta(b1, delta1)

        sstore(slot, add(shl(128, b0Next), b1Next))
    }

    _updatePairDebtWithNative(id, token0, token1, delta0, delta1);
}
```

The first approach is simpler and requires minimal changes to MEVCapture only.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureStorageMismatch.t.sol
// Run with: forge test --match-test test_MEVCaptureStorageMismatch -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import "../src/types/poolKey.sol";
import "../src/types/poolConfig.sol";
import "../src/libraries/CoreStorageLayout.sol";

contract Exploit_MEVCaptureStorageMismatch is Test {
    Core core;
    MEVCapture mevCapture;
    MEVCaptureRouter router;
    address token0;
    address token1;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy protocol contracts
        core = new Core();
        mevCapture = new MEVCapture(core);
        router = new MEVCaptureRouter(core, address(mevCapture));
        
        // Setup tokens (mock addresses)
        token0 = address(0x1000);
        token1 = address(0x2000);
        
        // Initialize pool with MEVCapture extension
        poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: createConcentratedPoolConfig(3000, 60, address(mevCapture))
        });
        core.initializePool(poolKey, /* initial tick */ 0);
    }
    
    function test_MEVCaptureStorageMismatch() public {
        // SETUP: Execute swap via router (normal user flow)
        SwapParameters params = createSwapParameters({
            specifiedAmount: 1000,
            isExactOut: false,
            skipAhead: 0
        });
        
        // EXPLOIT: Swap causes tick movement, MEV fees are charged
        // This happens within Router's lock context
        router.swap(poolKey, params, /* minAmountOut */ 0, /* deadline */ block.timestamp);
        
        // VERIFY: MEV fees are in wrong storage slot
        PoolId poolId = poolKey.toPoolId();
        
        // Check MEVCapture's slot (where it reads from)
        StorageSlot mevCaptureSlot = CoreStorageLayout.savedBalancesSlot(
            address(mevCapture), 
            token0, 
            token1, 
            PoolId.unwrap(poolId)
        );
        bytes32 mevCaptureBalance = core.sload(mevCaptureSlot);
        
        // Check Router's slot (where it writes to)
        StorageSlot routerSlot = CoreStorageLayout.savedBalancesSlot(
            address(router),
            token0,
            token1,
            PoolId.unwrap(poolId)
        );
        bytes32 routerBalance = core.sload(routerSlot);
        
        // MEVCapture's slot should be 0 (never written to)
        assertEq(uint256(mevCaptureBalance), 0, "MEVCapture slot should be empty");
        
        // Router's slot should have the MEV fees (but they're inaccessible)
        assertTrue(uint256(routerBalance) > 0, "Router slot has trapped MEV fees");
        
        // Execute second swap - fees continue accumulating in wrong slot
        router.swap(poolKey, params, 0, block.timestamp);
        
        // Router's balance increases (fees accumulating)
        bytes32 routerBalanceAfter = core.sload(routerSlot);
        assertTrue(
            uint256(routerBalanceAfter) > uint256(routerBalance),
            "Fees keep accumulating in wrong slot"
        );
        
        // MEVCapture's slot still empty - fees are permanently lost
        assertEq(
            uint256(core.sload(mevCaptureSlot)),
            0,
            "Vulnerability confirmed: MEV fees permanently locked in router's slot"
        );
    }
}
```

**Notes**

This vulnerability demonstrates a storage architecture mismatch where MEVCapture's assumption about slot ownership conflicts with Core's locker-based slot calculation. The issue affects the core fee accounting invariant and causes permanent loss of protocol revenue (MEV capture fees). The vulnerability occurs in normal operation without requiring any malicious action - it's simply triggered by users swapping through the standard MEVCaptureRouter flow.

The root cause is that `updateSavedBalances` in Core uses the current locker's address to calculate the storage slot [5](#0-4) , while MEVCapture's `loadCoreState` always uses its own address [6](#0-5) . When MEVCapture operates within a forward context initiated by MEVCaptureRouter, the locker is the router, not MEVCapture, causing the mismatch [7](#0-6) .

### Citations

**File:** src/extensions/MEVCapture.sol (L157-175)
```text
    function loadCoreState(PoolId poolId, address token0, address token1)
        private
        view
        returns (int32 tick, uint128 fees0, uint128 fees1)
    {
        StorageSlot stateSlot = CoreStorageLayout.poolStateSlot(poolId);
        StorageSlot feesSlot = CoreStorageLayout.savedBalancesSlot(address(this), token0, token1, PoolId.unwrap(poolId));

        (bytes32 v0, bytes32 v1) = CORE.sload(stateSlot, feesSlot);
        tick = PoolState.wrap(v0).tick();

        assembly ("memory-safe") {
            fees0 := shr(128, v1)
            fees0 := sub(fees0, gt(fees0, 0))

            fees1 := shr(128, shl(128, v1))
            fees1 := sub(fees1, gt(fees1, 0))
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

**File:** src/Core.sol (L137-167)
```text
        (uint256 id, address lockerAddr) = _requireLocker().parse();

        assembly ("memory-safe") {
            function addDelta(u, i) -> result {
                // full‐width sum mod 2^256
                let sum := add(u, i)
                // 1 if i<0 else 0
                let sign := shr(255, i)
                // if sum > type(uint128).max || (i>=0 && sum<u) || (i<0 && sum>u) ⇒ 256-bit wrap or underflow
                if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                    mstore(0x00, 0x1293d6fa) // `SavedBalanceOverflow()`
                    revert(0x1c, 0x04)
                }
                result := sum
            }

            // we can cheaply calldatacopy the arguments into memory, hence no call to CoreStorageLayout#savedBalancesSlot
            let free := mload(0x40)
            mstore(free, lockerAddr)
            // copy the first 3 arguments in the same order
            calldatacopy(add(free, 0x20), 4, 96)
            let slot := keccak256(free, 128)
            let balances := sload(slot)

            let b0 := shr(128, balances)
            let b1 := shr(128, shl(128, balances))

            let b0Next := addDelta(b0, delta0)
            let b1Next := addDelta(b1, delta1)

            sstore(slot, add(shl(128, b0Next), b1Next))
```

**File:** src/base/FlashAccountant.sol (L145-186)
```text
    /// @inheritdoc IFlashAccountant
    function lock() external {
        assembly ("memory-safe") {
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))

            let free := mload(0x40)
            // Prepare call to locked_(uint256) -> selector 0
            mstore(free, 0)
            mstore(add(free, 4), id) // ID argument

            calldatacopy(add(free, 36), 4, sub(calldatasize(), 4))

            // Call the original caller with the packed data
            let success := call(gas(), caller(), 0, free, add(calldatasize(), 32), 0, 0)

            // Pass through the error on failure
            if iszero(success) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Undo the "locker" state changes
            tstore(_CURRENT_LOCKER_SLOT, current)

            // Check if something is nonzero
            let nonzeroDebtCount := tload(add(_NONZERO_DEBT_COUNT_OFFSET, id))
            if nonzeroDebtCount {
                // cast sig "DebtsNotZeroed(uint256)"
                mstore(0x00, 0x9731ba37)
                mstore(0x20, id)
                revert(0x1c, 0x24)
            }

            // Directly return whatever the subcall returned
            returndatacopy(free, 0, returndatasize())
            return(free, returndatasize())
        }
```

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
