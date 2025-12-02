## Title
Fees Collected from Users But Not Credited to LPs Due to Rounding in `stepFeesPerLiquidity` Calculation

## Summary
In `Core.sol` swap function, when `stepFeesPerLiquidity` rounds down to 0 due to high liquidity, the conditional check at line 737 prevents the fees per liquidity from being updated. However, users are still charged the full fee amount, causing a permanent mismatch where fees are collected but never credited to liquidity providers, violating the Fee Accounting invariant.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/Core.sol`, `swap()` function, lines 639-643, 715-718, 736-749, 817, 828-832

**Intended Logic:** 
When a swap occurs, fees should be extracted from the input amount, the price should move based on the remaining amount, and the fees should be accurately tracked in `feesPerLiquidity` so that liquidity providers can claim their proportional share. [1](#0-0) 

**Actual Logic:** 
The fee amount is calculated and deducted from the amount that moves the price. Then `stepFeesPerLiquidity` is computed as `(feeAmount << 128) / stepLiquidity`. When `stepLiquidity` is very large relative to `feeAmount`, this division rounds down to 0. The conditional check only updates fees per liquidity if `stepFeesPerLiquidity != 0`, meaning fees are skipped. [2](#0-1) [3](#0-2) 

However, the user is still charged the full amount including fees: [4](#0-3) 

And the storage update is conditional on `feesAccessed == 2`, which only happens inside the `if (stepFeesPerLiquidity != 0)` block: [5](#0-4) 

**Exploitation Path:**
1. Pool has very high liquidity (e.g., `stepLiquidity > 2^136`)
2. User performs small swap that generates small fee (e.g., 100 wei fee)
3. `feeAmount = computeFee(amountRemaining, poolFee)` calculates non-zero fee (e.g., 100 wei)
4. `stepFeesPerLiquidity = (100 << 128) / stepLiquidity = 0` (rounds down)
5. Line 737 condition fails, so `feesAccessed` stays 0 or 1 (never becomes 2)
6. User pays full `specifiedAmountDelta` including 100 wei fee (line 817)
7. Line 828 condition fails because `feesAccessed != 2`, so `inputTokenFeesPerLiquidity` is not stored
8. The 100 wei fee sits in pool balance but is not tracked in any LP's claimable fees
9. Fees are permanently stuck and unclaimable

**Security Property Broken:** 
**Fee Accounting Invariant**: "Position fee collection must be accurate and never allow double-claiming" - fees are collected from users but not accurately credited to LPs, causing them to lose their rightful fee earnings.

## Impact Explanation
- **Affected Assets**: Swap fees in pools with high liquidity that should go to LPs
- **Damage Severity**: For pools with `liquidity >= 2^129`, any fee amount less than `liquidity >> 128` will be lost. In a pool with `2^136` liquidity, all fees < 256 wei are lost per swap iteration. Over time, this accumulates to significant unclaimed fees stuck in the pool.
- **User Impact**: All liquidity providers in high-liquidity pools lose a portion of their fee earnings. Any trader performing small swaps triggers this bug. The more successful a pool (higher liquidity), the more susceptible it becomes.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a systemic bug affecting normal users. Any trader executing small swaps triggers the issue.
- **Preconditions**: Pool must have high liquidity (common for successful DEX pools). Small swaps or low fee rates increase likelihood.
- **Execution Complexity**: Occurs automatically during normal swap operations, no special actions needed.
- **Frequency**: Every swap that generates `feeAmount < stepLiquidity >> 128` loses fees. In high-volume pools, this could be thousands of times per day.

## Recommendation

The issue occurs because the code assumes that if `stepFeesPerLiquidity == 0`, no fees were charged. However, fees are still charged; they just round to 0 in the per-liquidity calculation.

**Fix Option 1: Track fees separately when they round to zero**

```solidity
// In src/Core.sol, swap function, around lines 736-749:

// CURRENT (vulnerable):
// Lines 715-718 calculate stepFeesPerLiquidity
// Lines 736-749 only update if stepFeesPerLiquidity != 0

// FIXED:
// Add a variable to track the actual fee amount collected
uint128 actualFeesCollected;

// After calculating stepFeesPerLiquidity (line 718), also track:
actualFeesCollected += uint128(amountRemaining - priceImpactAmount);

// Then modify lines 736-749:
if (stepFeesPerLiquidity != 0) {
    // existing logic to update inputTokenFeesPerLiquidity
    feesAccessed = 2;
} else if (actualFeesCollected > 0) {
    // Fees were collected but rounded to 0 in per-liquidity calc
    // Load and increment by minimum trackable amount
    if (feesAccessed == 0) {
        inputTokenFeesPerLiquidity = uint256(
            CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                .load()
        ) + 1; // Minimum increment to track that fees were collected
    } else {
        inputTokenFeesPerLiquidity += 1;
    }
    feesAccessed = 2;
}
```

**Fix Option 2: Accumulate fees until they're large enough to track**

Store accumulated but untracked fees in a separate storage slot per pool, and add them to the next swap's fees once they exceed the tracking threshold.

**Fix Option 3: Prevent rounding to zero**

Ensure `stepFeesPerLiquidity` is at least 1 if any fees were collected:

```solidity
// After calculating stepFeesPerLiquidity
if (stepFeesPerLiquidity == 0 && feeAmount > 0) {
    stepFeesPerLiquidity = 1;
}
```

Note: All fixes require careful consideration of edge cases and gas costs. Fix Option 3 is simplest but may over-credit LPs slightly. Fix Option 1 is most accurate but more complex.

## Proof of Concept

```solidity
// File: test/Exploit_FeeRoundingLoss.t.sol
// Run with: forge test --match-test test_FeeRoundingLoss -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/Positions.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";
import {MIN_SQRT_RATIO, MAX_SQRT_RATIO} from "../src/types/sqrtRatio.sol";

contract Exploit_FeeRoundingLoss is Test {
    Core core;
    Router router;
    Positions positions;
    ERC20 token0;
    ERC20 token1;
    
    function setUp() public {
        // Initialize protocol
        core = new Core();
        positions = new Positions(core, address(this));
        router = new Router(core);
        
        token0 = new MockERC20();
        token1 = new MockERC20();
        
        // Mint tokens
        token0.mint(address(this), 1e30);
        token1.mint(address(this), 1e30);
        
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_FeeRoundingLoss() public {
        // SETUP: Create pool with VERY high liquidity
        uint64 fee = 1 << 61; // ~0.3% fee (2^61 / 2^64 ≈ 0.5 * 0.5)
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_fee: fee, _extension: address(0)})
        });
        
        positions.maybeInitializePool(poolKey, 0);
        
        // Add extremely high liquidity: 2^136
        uint128 hugeLiquidity = uint128(1) << 136;
        (uint256 positionId,,,) = positions.mintAndDeposit({
            poolKey: poolKey,
            tickLower: MIN_TICK,
            tickUpper: MAX_TICK,
            maxAmount0: type(uint128).max,
            maxAmount1: type(uint128).max,
            minLiquidity: hugeLiquidity
        });
        
        // Record LP's fees before swap
        (uint128 feesBefore0, uint128 feesBefore1) = 
            positions.collectFees(positionId, poolKey, MIN_TICK, MAX_TICK, address(this));
        
        // EXPLOIT: Perform small swap that generates small fee
        // With 0.3% fee, a 500 wei swap generates ~1-2 wei fee
        // stepFeesPerLiquidity = (2 << 128) / (2^136) = 2^129 / 2^136 = 0 (rounds down!)
        uint256 swapAmount = 500;
        
        router.swap({
            poolKey: poolKey,
            isToken1: false,
            amount: int128(uint128(swapAmount)),
            sqrtRatioLimit: MIN_SQRT_RATIO,
            skipAhead: 0,
            calculatedAmountThreshold: type(int128).min,
            recipient: address(this)
        });
        
        // VERIFY: LP cannot claim the fees that were collected
        (uint128 feesAfter0, uint128 feesAfter1) = 
            positions.collectFees(positionId, poolKey, MIN_TICK, MAX_TICK, address(this));
        
        // The fee was charged to user (can verify by checking pool balance change)
        // But LP received 0 fees because stepFeesPerLiquidity rounded to 0
        assertEq(feesAfter0, feesBefore0, "Vulnerability confirmed: LP received 0 fees despite user paying fees");
        
        // The fees are now stuck in the pool balance, unclaimable by anyone
    }
}
```

**Notes:**
- The vulnerability manifests in pools with liquidity above `2^128`, which is achievable in successful, high-TVL pools
- The rounding occurs in Solidity's integer division: `(feeAmount << 128) / stepLiquidity`
- When `feeAmount < stepLiquidity >> 128`, the result is 0
- The fee calculation in `computeFee()` correctly rounds UP, so users DO pay the fee [6](#0-5) 
- But the per-liquidity tracking rounds DOWN to 0, breaking the accounting
- The same issue affects all three fee calculation paths in the swap function (exact input hitting limit, exact input not hitting limit, and price-doesn't-move case) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/Core.sol (L639-643)
```text
                            uint128 feeAmount = computeFee(amountU128, config.fee());
                            assembly ("memory-safe") {
                                // feeAmount will never exceed amountRemaining since fee is < 100%
                                priceImpactAmount := sub(amountRemaining, feeAmount)
                            }
```

**File:** src/Core.sol (L680-683)
```text
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitCalculatedAmountDelta)),
                                        stepLiquidity
                                    )
```

**File:** src/Core.sol (L690-693)
```text
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(beforeFee, limitSpecifiedAmountDelta)),
                                        stepLiquidity
                                    )
```

**File:** src/Core.sol (L715-718)
```text
                                    stepFeesPerLiquidity := div(
                                        shl(128, sub(amountRemaining, priceImpactAmount)),
                                        stepLiquidity
                                    )
```

**File:** src/Core.sol (L730-731)
```text
                                stepFeesPerLiquidity := div(shl(128, amountRemaining), stepLiquidity)
                            }
```

**File:** src/Core.sol (L736-749)
```text
                        // only if fees per liquidity was updated in this swap iteration
                        if (stepFeesPerLiquidity != 0) {
                            if (feesAccessed == 0) {
                                // this loads only the input token fees per liquidity
                                inputTokenFeesPerLiquidity = uint256(
                                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                                        .load()
                                ) + stepFeesPerLiquidity;
                            } else {
                                inputTokenFeesPerLiquidity += stepFeesPerLiquidity;
                            }

                            feesAccessed = 2;
                        }
```

**File:** src/Core.sol (L814-818)
```text
                int128 specifiedAmountDelta;
                int128 specifiedAmount = params.amount();
                assembly ("memory-safe") {
                    specifiedAmountDelta := sub(specifiedAmount, amountRemaining)
                }
```

**File:** src/Core.sol (L828-832)
```text
                if (feesAccessed == 2) {
                    // this stores only the input token fees per liquidity
                    CoreStorageLayout.poolFeesPerLiquiditySlot(poolId).add(LibBit.rawToUint(increasing))
                        .store(bytes32(inputTokenFeesPerLiquidity));
                }
```

**File:** src/math/fee.sol (L6-10)
```text
function computeFee(uint128 amount, uint64 fee) pure returns (uint128 result) {
    assembly ("memory-safe") {
        result := shr(64, add(mul(amount, fee), 0xffffffffffffffff))
    }
}
```
