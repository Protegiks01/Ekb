## Title
MEVCapture Fee Bypass Through Tick Spacing Manipulation

## Summary
The MEVCapture extension calculates additional fees based on tick spacings crossed rather than absolute tick movement, allowing attackers to create pools with maximum tick spacing and route trades through them to pay up to ~700,000x less in MEV fees for equivalent price movements.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/extensions/MEVCapture.sol` - `handleForwardData()` function, lines 212-215 [1](#0-0) 

**Intended Logic:** The MEVCapture extension is designed to charge additional fees proportional to price movement during swaps, capturing value from MEV extraction activities. The fee multiplier should reflect the magnitude of price impact.

**Actual Logic:** The fee multiplier calculation divides absolute tick movement by the pool's tick spacing. Since tick spacing can vary from 1 to MAX_TICK_SPACING (698,605), pools with larger tick spacing pay proportionally less MEV fees for the same absolute tick movement (same price change). [2](#0-1) 

**Exploitation Path:**
1. Attacker creates a new pool for any token pair (e.g., WETH/USDC) using `createConcentratedPoolConfig()` with `tickSpacing = MAX_TICK_SPACING (698,605)` and the MEVCapture extension address
2. Attacker provides minimal liquidity to make the pool functional
3. Attacker routes large swaps through this pool via MEVCaptureRouter instead of standard pools with smaller tick spacing
4. For a swap moving from tick 0 to tick 50,000:
   - Pool with tick spacing 1: fee multiplier = 50,000 / 1 = 50,000
   - Pool with tick spacing 698,605: fee multiplier = 50,000 / 698,605 = 0.07
   - Attacker pays ~714,000x less in MEV fees

**Security Property Broken:** The MEVCapture extension's core purpose—capturing fees proportional to price movement and MEV extraction—is defeated, allowing sophisticated traders to avoid paying their fair share of MEV fees.

## Impact Explanation
- **Affected Assets**: MEV capture fees that should flow to liquidity providers in properly configured pools are lost when traders route through high-tick-spacing pools
- **Damage Severity**: Protocol loses substantial MEV capture revenue. An attacker executing large trades (e.g., $1M swaps) could avoid tens of thousands of dollars in MEV fees by using max tick spacing pools instead of standard pools
- **User Impact**: All liquidity providers across the protocol receive less fee revenue than intended, as MEV extractors can systematically avoid the additional fees by routing through specially configured pools

## Likelihood Explanation
- **Attacker Profile**: Any sophisticated trader, MEV bot operator, or arbitrageur who wants to minimize fees on large swaps
- **Preconditions**: None beyond standard protocol functionality—anyone can create pools with arbitrary tick spacing within allowed bounds
- **Execution Complexity**: Low—single transaction to create pool, minimal liquidity provision, then standard swap routing
- **Frequency**: Can be exploited continuously for every large trade the attacker wants to execute

## Recommendation
Modify the fee multiplier calculation to use absolute tick movement rather than tick spacings crossed:

```solidity
// In src/extensions/MEVCapture.sol, function handleForwardData, line 212-213:

// CURRENT (vulnerable):
uint256 feeMultiplierX64 =
    (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();

// FIXED:
// Use absolute tick movement, normalized by a constant factor
// This makes the fee independent of tick spacing configuration
uint256 tickMovement = FixedPointMathLib.abs(stateAfter.tick() - tickLast);
uint256 feeMultiplierX64 = (tickMovement << 64) / 10000; // Normalize by constant (e.g., 10,000 ticks = 1x multiplier)
```

**Alternative mitigation:** Enforce a maximum allowed tick spacing for pools using the MEVCapture extension (e.g., limit to 1000) in the `beforeInitializePool` callback:

```solidity
// In src/extensions/MEVCapture.sol, function beforeInitializePool, add after line 74:
if (poolKey.config.concentratedTickSpacing() > 1000) {
    revert TickSpacingTooLarge();
}
```

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureBypass.t.sol
// Run with: forge test --match-test test_TickSpacingMEVFeeBypass -vvv

pragma solidity ^0.8.30;

import {FullTest} from "../test/FullTest.sol";
import {MEVCapture} from "../src/extensions/MEVCapture.sol";
import {MEVCaptureRouter} from "../src/MEVCaptureRouter.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {createSwapParameters} from "../src/types/swapParameters.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {PoolBalanceUpdate} from "../src/types/poolBalanceUpdate.sol";
import {MAX_TICK_SPACING} from "../src/math/constants.sol";
import {mevCaptureCallPoints} from "../src/extensions/MEVCapture.sol";

contract Exploit_MEVCaptureBypass is FullTest {
    MEVCapture internal mevCapture;
    MEVCaptureRouter internal mevRouter;

    function setUp() public override {
        FullTest.setUp();
        address deployAddress = address(uint160(mevCaptureCallPoints().toUint8()) << 152);
        deployCodeTo("MEVCapture.sol", abi.encode(core), deployAddress);
        mevCapture = MEVCapture(deployAddress);
        mevRouter = new MEVCaptureRouter(core, address(mevCapture));
        router = mevRouter;
    }

    function test_TickSpacingMEVFeeBypass() public {
        uint64 poolFee = uint64(uint256(1 << 64) / 100); // 1% base fee
        
        // SETUP: Create two pools with same tokens but different tick spacings
        
        // Pool A: Small tick spacing (standard pool)
        PoolKey memory poolA = createPool({
            _token0: address(token0),
            _token1: address(token1),
            tick: 0,
            config: createConcentratedPoolConfig(poolFee, 1000, address(mevCapture))
        });
        createPosition(poolA, -100_000, 100_000, 1_000_000, 1_000_000);
        
        // Pool B: Maximum tick spacing (exploit pool)
        PoolKey memory poolB = createPool({
            _token0: address(token0),
            _token1: address(token1),
            tick: 0,
            config: createConcentratedPoolConfig(poolFee, MAX_TICK_SPACING, address(mevCapture))
        });
        createPosition(poolB, -MAX_TICK_SPACING, MAX_TICK_SPACING, 1_000_000, 1_000_000);
        
        token0.approve(address(mevRouter), type(uint256).max);
        
        // EXPLOIT: Execute identical swaps in both pools
        
        // Swap in Pool A (small spacing) - pays high MEV fees
        PoolBalanceUpdate updateA = mevRouter.swap({
            poolKey: poolA,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 500_000,
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // Swap in Pool B (max spacing) - pays minimal MEV fees
        PoolBalanceUpdate updateB = mevRouter.swap({
            poolKey: poolB,
            params: createSwapParameters({
                _isToken1: false,
                _amount: 500_000,
                _sqrtRatioLimit: SqrtRatio.wrap(0),
                _skipAhead: 0
            }),
            calculatedAmountThreshold: type(int256).min,
            recipient: address(this)
        });
        
        // VERIFY: Pool B pays dramatically less in fees despite similar swap
        int32 tickMovementA = core.poolState(poolA.toPoolId()).tick();
        int32 tickMovementB = core.poolState(poolB.toPoolId()).tick();
        
        // Calculate fee multipliers (simplified)
        uint256 feeMultiplierA = uint256(int256(-tickMovementA)) / 1000;
        uint256 feeMultiplierB = uint256(int256(-tickMovementB)) / MAX_TICK_SPACING;
        
        // Pool B pays ~698x less in MEV fees for similar price movement
        assertGt(feeMultiplierA, feeMultiplierB * 600, "Pool B should pay dramatically less MEV fees");
        assertGt(updateA.delta0(), updateB.delta0(), "Pool A should charge more due to higher MEV fees");
    }
}
```

## Notes

The vulnerability stems from using **relative** tick spacing units rather than **absolute** tick movement for fee calculation. This design flaw allows anyone to create pools with arbitrarily large tick spacing to minimize MEV fees, defeating the purpose of the MEVCapture extension. The fix requires either normalizing fees by absolute tick movement or enforcing strict limits on tick spacing for MEVCapture pools.

The tick spacing parameter is validated to be between 1 and MAX_TICK_SPACING: [3](#0-2) 

This wide range enables the exploit, as MAX_TICK_SPACING is 698,605, allowing nearly 700,000x variation in fee multipliers for equivalent price movements.

### Citations

**File:** src/extensions/MEVCapture.sol (L212-215)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**File:** src/math/constants.sol (L20-22)
```text
// The maximum allowed tick spacing for pools
// Defines the upper limit for tick spacing configuration in pool creation
uint32 constant MAX_TICK_SPACING = 698605;
```

**File:** src/types/poolConfig.sol (L210-214)
```text
function validate(PoolConfig config) pure {
    if (config.isConcentrated()) {
        if (config.concentratedTickSpacing() > MAX_TICK_SPACING || config.concentratedTickSpacing() == 0) {
            revert InvalidTickSpacing();
        }
```
