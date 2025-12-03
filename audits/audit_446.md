## Title
Integer Overflow in QuoteDataFetcher When Pool Liquidity Reaches 2^127

## Summary
In `QuoteDataFetcher.sol`, when a stableswap pool's liquidity reaches exactly 2^127, casting `uint128(liquidity)` to `int128` causes overflow. Both tick boundaries receive `liquidityDelta = -2^127` instead of the intended `+2^127` and `-2^127`, corrupting quote data used by off-chain systems and potentially causing user losses through incorrect price estimates. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/QuoteDataFetcher.sol`, function `getQuoteData()`, lines 73-74

**Intended Logic:** For stableswap pools, the function should create two TickDelta structs representing liquidity boundaries: the lower tick with positive liquidityDelta (+liquidity) and the upper tick with negative liquidityDelta (-liquidity).

**Actual Logic:** When pool liquidity equals exactly 2^127 (0x80000000000000000000000000000000):
- `int128(liquidity)` overflows to `-2^127` (the minimum int128 value)
- `-int128(liquidity)` = `-(-2^127)` which should equal `+2^127`, but this also overflows int128's positive range, wrapping back to `-2^127`
- Result: BOTH ticks incorrectly have `liquidityDelta = -2^127` [2](#0-1) 

**Exploitation Path:**
1. **Initial State:** Create a stableswap pool with minimal liquidity (e.g., 1 unit)
2. **Add Large Position:** User deposits liquidity = `type(int128).max` = 2^127-1 (within the deposit cap enforced at BasePositions.sol:89-91) [3](#0-2) 

3. **Pool Liquidity Reaches 2^127:** Total pool liquidity = 1 + (2^127-1) = 2^127
4. **Data Corruption:** Off-chain systems calling `getQuoteData()` receive corrupted tick data with both boundaries showing negative deltas

**Security Property Broken:** Data integrity for off-chain systems. While not a direct protocol invariant violation, this breaks the expected contract between the protocol and external integrators, potentially leading to user losses through incorrect routing/pricing.

## Impact Explanation
- **Affected Assets**: Users trading through aggregators/routers that rely on QuoteDataFetcher for liquidity depth information
- **Damage Severity**: Off-chain quoters would calculate completely incorrect swap amounts, potentially causing:
  - Failed transactions due to incorrect slippage parameters
  - Sub-optimal routing by aggregators
  - Sandwich attack vulnerability if users trust wrong quotes
  - Trading bots making incorrect decisions
- **User Impact**: Any user or system querying this pool's quote data would receive corrupted information. Given that 2^127 ≈ 1.7e38, this requires extraordinary capital but is theoretically achievable.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider with sufficient capital, or coordination among multiple LPs
- **Preconditions**: 
  - Stableswap pool must be initialized
  - Total pool liquidity must reach exactly 2^127 through accumulated deposits
  - External systems must be actively querying this lens contract
- **Execution Complexity**: Moderate - requires large capital (2^127 ≈ 1.7e38 units) but no complex transaction sequencing
- **Frequency**: Once per affected pool; the corruption persists as long as liquidity remains at 2^127

## Recommendation

Add bounds checking before casting to prevent overflow: [2](#0-1) 

```solidity
// In src/lens/QuoteDataFetcher.sol, function getQuoteData, lines 70-75:

// CURRENT (vulnerable):
if (liquidity > 0) {
    (int32 lower, int32 upper) = poolKeys[i].config.stableswapActiveLiquidityTickRange();
    ticks = new TickDelta[](2);
    ticks[0] = TickDelta({number: lower, liquidityDelta: int128(liquidity)});
    ticks[1] = TickDelta({number: upper, liquidityDelta: -int128(liquidity)});
}

// FIXED:
if (liquidity > 0) {
    (int32 lower, int32 upper) = poolKeys[i].config.stableswapActiveLiquidityTickRange();
    ticks = new TickDelta[](2);
    // Cap at type(int128).max to prevent overflow
    int128 liquidityDeltaSafe = liquidity > uint128(type(int128).max) 
        ? type(int128).max 
        : int128(liquidity);
    ticks[0] = TickDelta({number: lower, liquidityDelta: liquidityDeltaSafe});
    ticks[1] = TickDelta({number: upper, liquidityDelta: -liquidityDeltaSafe});
}
```

Alternative: Revert if liquidity exceeds int128 range to make the issue explicit rather than silently capping.

## Proof of Concept

```solidity
// File: test/Exploit_QuoteDataOverflow.t.sol
// Run with: forge test --match-test test_QuoteDataOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import "../src/lens/QuoteDataFetcher.sol";
import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createStableswapPoolConfig, PoolConfig} from "../src/types/poolConfig.sol";
import {QuoteData, TickDelta} from "../src/lens/QuoteDataFetcher.sol";

contract Exploit_QuoteDataOverflow is FullTest {
    QuoteDataFetcher internal qdf;
    
    function setUp() public override {
        FullTest.setUp();
        qdf = new QuoteDataFetcher(core);
    }
    
    function test_QuoteDataOverflow() public {
        // SETUP: Create stableswap pool
        PoolConfig poolConfigStable = createStableswapPoolConfig({
            _fee: 100,
            _amplification: 8,
            _centerTick: 693147,
            _extension: address(0)
        });
        
        PoolKey memory poolKeyStable = createPool({
            _token0: address(token0),
            _token1: address(token1),
            tick: 693147 * 2,
            config: poolConfigStable
        });
        
        (int32 lowerTick, int32 upperTick) = poolConfigStable.stableswapActiveLiquidityTickRange();
        
        // Add 1 unit of liquidity first
        createPosition(poolKeyStable, lowerTick, upperTick, 1, 1);
        
        // Add type(int128).max liquidity (2^127 - 1)
        // Total pool liquidity will be: 1 + (2^127 - 1) = 2^127
        uint128 maxLiquidity = uint128(type(int128).max);
        createPosition(poolKeyStable, lowerTick, upperTick, type(uint128).max, type(uint128).max);
        
        // EXPLOIT: Query quote data
        PoolKey[] memory keys = new PoolKey[](1);
        keys[0] = poolKeyStable;
        QuoteData[] memory qd = qdf.getQuoteData(keys, 1);
        
        // VERIFY: Confirm both ticks have the same NEGATIVE liquidityDelta
        // This is the bug - they should have opposite signs
        int128 lowerDelta = qd[0].ticks[0].liquidityDelta;
        int128 upperDelta = qd[0].ticks[1].liquidityDelta;
        
        console.log("Lower tick liquidityDelta:", lowerDelta);
        console.log("Upper tick liquidityDelta:", upperDelta);
        
        // Both should be -2^127 (minimum int128 value) due to overflow
        int128 minInt128 = type(int128).min;
        assertEq(lowerDelta, minInt128, "Lower tick should overflow to -2^127");
        assertEq(upperDelta, minInt128, "Upper tick should ALSO overflow to -2^127");
        
        // This is wrong - they should have opposite signs!
        assertEq(lowerDelta, upperDelta, "Vulnerability confirmed: both ticks have same negative value");
    }
}
```

## Notes

This vulnerability demonstrates a subtle integer overflow edge case in Solidity 0.8.x. While the protocol correctly caps individual deposits at `type(int128).max` in BasePositions.sol, the cumulative pool liquidity can exceed this through multiple deposits. The lens contract then unsafely casts this accumulated liquidity without bounds checking. [4](#0-3) 

The impact is limited to off-chain data consumers rather than direct fund loss, but represents a real threat to protocol integrators and could lead to user losses through incorrect trading decisions. The issue is particularly concerning because:

1. It affects a critical data source (QuoteDataFetcher) used by aggregators and routers
2. The corruption is silent - no revert occurs, just wrong data
3. Off-chain systems may not anticipate this edge case in their error handling

The fix is straightforward: add bounds checking or use SafeCast before the conversion to int128.

### Citations

**File:** src/lens/QuoteDataFetcher.sol (L70-75)
```text
                        if (liquidity > 0) {
                            (int32 lower, int32 upper) = poolKeys[i].config.stableswapActiveLiquidityTickRange();
                            ticks = new TickDelta[](2);
                            ticks[0] = TickDelta({number: lower, liquidityDelta: int128(liquidity)});
                            ticks[1] = TickDelta({number: upper, liquidityDelta: -int128(liquidity)});
                        }
```

**File:** src/base/BasePositions.sol (L79-91)
```text
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }

        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }
```
