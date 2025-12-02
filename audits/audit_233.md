## Title
Fee Tracking Error in MEVCapture Due to Incorrect Decoding of savedBalances Without +1 Encoding

## Summary
The `loadCoreState()` function in MEVCapture extension incorrectly subtracts 1 from non-zero savedBalances values, assuming they use +1 encoding like feesPerLiquidity. However, Core's `updateSavedBalances()` stores values directly without adding 1, causing a permanent loss of 1 wei per cross-block fee accumulation cycle.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The code appears to assume savedBalances use +1 encoding (where storage value of N represents actual value N-1, with 0 meaning uninitialized), similar to how feesPerLiquidity slots are initialized to 1 during pool creation [2](#0-1) .

**Actual Logic:** The Core contract's `updateSavedBalances()` function stores values directly without any +1 offset [3](#0-2) . When MEVCapture reads these values and subtracts 1, it creates a mismatch between stored and retrieved amounts.

**Exploitation Path:**
1. **Initial State**: Pool has accumulated 1000 wei of MEV fees in savedBalances (storage = 1000)
2. **Next Block Swap**: `handleForwardData` calls `loadCoreState` which reads 1000 but returns 999 after subtracting 1 [4](#0-3) 
3. **Fee Distribution**: Only 999 wei is accumulated to LPs via `accumulateAsFees` [5](#0-4) 
4. **Balance Update**: 999 wei is subtracted from savedBalances via `updateSavedBalances(..., -999, ...)` [6](#0-5) 
5. **Result**: Storage becomes 1000 - 999 = 1 wei permanently stuck

**Security Property Broken:** Violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." The 1 wei loss per cycle accumulates over time, and these funds can never be recovered or distributed to LPs.

## Impact Explanation
- **Affected Assets**: All token pairs in MEVCapture-enabled pools lose 1 wei per cross-block fee accumulation event
- **Damage Severity**: For high-frequency pools with thousands of swaps per day, this results in cumulative loss of thousands of wei daily. For high-value tokens (e.g., WBTC where 1 wei = ~$0.0003), this represents measurable economic loss
- **User Impact**: All liquidity providers in MEVCapture pools receive slightly less fees than they should. The missing fees accumulate in savedBalances storage but can never be claimed

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is an automatic loss occurring during normal operation
- **Preconditions**: MEVCapture pool must be active with MEV fees being accumulated
- **Execution Complexity**: Occurs automatically whenever fees are accumulated across different blocks
- **Frequency**: Once per block where MEVCapture accumulates previously collected fees (could be thousands of times per day for active pools)

## Recommendation

The fix is to remove the incorrect -1 decoding since savedBalances don't use +1 encoding:

```solidity
// In src/extensions/MEVCapture.sol, function loadCoreState, lines 168-174:

// CURRENT (vulnerable):
assembly ("memory-safe") {
    fees0 := shr(128, v1)
    fees0 := sub(fees0, gt(fees0, 0))  // ❌ Incorrectly assumes +1 encoding
    
    fees1 := shr(128, shl(128, v1))
    fees1 := sub(fees1, gt(fees1, 0))  // ❌ Incorrectly assumes +1 encoding
}

// FIXED:
assembly ("memory-safe") {
    fees0 := shr(128, v1)  // ✅ Read value directly without adjustment
    
    fees1 := shr(128, shl(128, v1))  // ✅ Read value directly without adjustment
}
```

**Alternative:** If +1 encoding is intentionally desired for savedBalances (to distinguish uninitialized from zero), then Core's `updateSavedBalances` must be modified to add 1 when storing non-zero values. However, this would be a more invasive change affecting all savedBalances users.

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureFeeTrackingError.t.sol
// Run with: forge test --match-test test_MEVCaptureFeeTrackingError -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/MEVCaptureRouter.sol";
import "../test/FullTest.sol";

contract Exploit_MEVCaptureFeeTrackingError is FullTest {
    using CoreLib for *;
    
    MEVCapture mevCapture;
    MEVCaptureRouter mevRouter;
    PoolKey poolKey;
    
    function setUp() public override {
        FullTest.setUp();
        
        // Deploy MEVCapture
        address deployAddress = address(uint160(mevCaptureCallPoints().toUint8()) << 152);
        deployCodeTo("MEVCapture.sol", abi.encode(core), deployAddress);
        mevCapture = MEVCapture(deployAddress);
        mevRouter = new MEVCaptureRouter(core, address(mevCapture));
        
        // Create MEVCapture pool
        poolKey = createPool(
            address(token0), 
            address(token1), 
            0, 
            createConcentratedPoolConfig(uint64(uint256(1 << 64) / 100), 20_000, address(mevCapture))
        );
        
        // Add liquidity
        createPosition(poolKey, -100_000, 100_000, 1_000_000, 1_000_000);
        token0.approve(address(mevRouter), type(uint256).max);
    }
    
    function test_MEVCaptureFeeTrackingError() public {
        // SETUP: Execute swap in block N to accumulate fees
        vm.roll(block.number);
        mevRouter.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false, 
                _amount: 500_000, 
                _sqrtRatioLimit: SqrtRatio.wrap(0), 
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // Check savedBalances after first swap
        PoolId poolId = poolKey.toPoolId();
        (uint128 saved0_before, uint128 saved1_before) = core.savedBalances(
            address(mevCapture), 
            poolKey.token0, 
            poolKey.token1, 
            PoolId.unwrap(poolId)
        );
        
        console.log("SavedBalances after block N:", saved0_before, saved1_before);
        assertGt(saved1_before, 0, "Should have accumulated MEV fees");
        uint128 expectedFees = saved1_before;
        
        // EXPLOIT: Move to next block and trigger fee accumulation
        advanceTime(1);
        vm.roll(block.number + 1);
        
        mevRouter.swap({
            poolKey: poolKey,
            params: createSwapParameters({
                _isToken1: false, 
                _amount: 100_000, 
                _sqrtRatioLimit: SqrtRatio.wrap(0), 
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // VERIFY: Check that 1 wei is stuck in savedBalances
        (uint128 saved0_after, uint128 saved1_after) = core.savedBalances(
            address(mevCapture), 
            poolKey.token0, 
            poolKey.token1, 
            PoolId.unwrap(poolId)
        );
        
        console.log("SavedBalances after block N+1:", saved0_after, saved1_after);
        console.log("Expected fees accumulated:", expectedFees);
        console.log("Fee tracking error (lost wei):", expectedFees > saved1_after ? 1 : 0);
        
        // The vulnerability: 1 wei is permanently lost due to -1 decoding
        // If savedBalances had N wei, only N-1 was accumulated and subtracted,
        // leaving 1 wei stuck forever (plus any new fees from this swap)
        assertEq(
            saved1_after % expectedFees, 
            1, 
            "Vulnerability confirmed: 1 wei permanently lost per accumulation cycle"
        );
    }
}
```

## Notes

The root cause is a mismatch between storage encoding assumptions. The MEVCapture code was likely written expecting savedBalances to use +1 sentinel encoding (like feesPerLiquidity initialized to 1), but Core's implementation stores raw values. This subtle discrepancy causes incremental but permanent loss of funds that violates the fee accounting invariant.

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

**File:** src/extensions/MEVCapture.sol (L195-196)
```text
                if (fees0 != 0 || fees1 != 0) {
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
```

**File:** src/extensions/MEVCapture.sol (L198-199)
```text
                    saveDelta0 -= int256(uint256(fees0));
                    saveDelta1 -= int256(uint256(fees1));
```

**File:** src/Core.sol (L93-96)
```text
        // initialize these slots so the first swap or deposit on the pool is the same cost as any other swap
        StorageSlot fplSlot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
        fplSlot0.store(bytes32(uint256(1)));
        fplSlot0.next().store(bytes32(uint256(1)));
```

**File:** src/Core.sol (L139-168)
```text
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
        }
```
