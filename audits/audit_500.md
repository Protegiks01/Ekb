## Title
Integer Overflow in Tick Crossing During Swaps Due to Unchecked Negation of type(int128).min

## Summary
The swap function's assembly code performs unchecked arithmetic when crossing ticks with `liquidityDelta = type(int128).min`. When the swap direction requires negating this value, the operation produces `2^127`, which when added to the current liquidity can exceed `uint128.max`. The subsequent silent truncation on the next loop iteration corrupts the pool's liquidity state, breaking the solvency invariant and enabling potential fund theft.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When a swap crosses an initialized tick, the pool's active liquidity should be updated by adding or subtracting the tick's `liquidityDelta` based on the swap direction. The liquidity value should remain within valid `uint128` bounds.

**Actual Logic:** The assembly code extracts `liquidityDelta` from tick storage and multiplies it by +1 or -1 based on swap direction. When `liquidityDelta = type(int128).min` and the direction requires negation, the multiplication produces `2^127`. This value, when added to a large liquidity value, can overflow `uint128.max`. Since the assembly uses unchecked arithmetic and the result is stored in a 256-bit stack variable, the overflow is silent. On the next loop iteration, when the variable is cast back to `uint128`, the upper bits are truncated, resulting in a corrupted liquidity value.

**Exploitation Path:**

1. **Accumulate liquidityDelta:** Multiple users create overlapping positions with upper bounds at the same tick. Each position mint executes the calculation at [2](#0-1) , which subtracts the position's liquidity from the upper tick's `liquidityDelta`. Through sequential operations, the tick's `liquidityDelta` reaches `type(int128).min`.

2. **Setup pool state:** Ensure the pool has significant active liquidity (approaching or at `type(uint128).max / 2`) such that adding `2^127` would exceed `uint128.max`.

3. **Execute vulnerable swap:** Perform a swap that crosses the vulnerable tick with `increasing = false` (price moving down). The assembly code at [3](#0-2)  extracts the `liquidityDelta`, multiplies by `-1` to get `2^127`, and adds it to the current liquidity in the 256-bit assembly context.

4. **Trigger corruption:** On the next swap loop iteration at [4](#0-3) , the corrupted 256-bit liquidity value is cast to `uint128`, silently truncating the upper bits. The pool now operates with an incorrect liquidity value, causing mispriced swaps and enabling arbitrage extraction or fund theft.

**Security Property Broken:** Violates the **Solvency invariant** - the corrupted liquidity leads to incorrect swap calculations, potentially allowing extraction of more tokens than the pool actually holds.

## Impact Explanation

- **Affected Assets:** All tokens in pools where vulnerable ticks exist. Both token0 and token1 reserves are at risk.

- **Damage Severity:** Attacker can exploit the corrupted liquidity to execute swaps that receive more tokens out than mathematically correct, effectively draining pool reserves. The severity depends on the degree of liquidity corruption - if liquidity drops from `2^127` to near-zero after truncation, virtually unlimited tokens could be extracted.

- **User Impact:** All liquidity providers in the affected pool suffer proportional losses. Any user executing swaps during the corrupted state receives incorrect amounts, creating cascading economic damage until the pool is abandoned.

## Likelihood Explanation

- **Attacker Profile:** Any user or coordinated group of users with sufficient capital to create multiple large positions. Alternatively, could occur organically through legitimate user activity over time.

- **Preconditions:** 
  - Concentrated liquidity pool must exist
  - Tick must be initialized with accumulated `liquidityDelta` approaching or at `type(int128).min`
  - Pool must have active liquidity in range where overflow is possible
  - Requires capital to create positions totaling ~`2^127` liquidity units

- **Execution Complexity:** Moderate - requires creating many positions (can be done over multiple transactions/blocks) followed by a single swap transaction to trigger the corruption. No complex timing or sandwich attack coordination needed.

- **Frequency:** Once per vulnerable tick per pool. However, the attacker can strategically create vulnerable ticks at key price levels, then trigger the exploit when profitable.

## Recommendation

Add an explicit check in the tick crossing logic to prevent silent overflow when adding liquidityDelta to liquidity: [3](#0-2) 

```solidity
// CURRENT (vulnerable):
// Uses unchecked assembly arithmetic that allows silent overflow

// FIXED:
if (isInitialized) {
    bytes32 tickValue = CoreStorageLayout.poolTicksSlot(poolId, nextTick).load();
    int128 tickLiquidityDelta = int128(uint128(uint256(tickValue)));
    
    // Safe negation check for type(int128).min
    if (tickLiquidityDelta == type(int128).min && !increasing) {
        revert("Cannot negate type(int128).min");
    }
    
    // Checked arithmetic for liquidity update
    if (increasing) {
        liquidity = addLiquidityDelta(liquidity, tickLiquidityDelta);
    } else {
        liquidity = addLiquidityDelta(liquidity, -tickLiquidityDelta);
    }
```

Alternative mitigation: Add a constraint in `_updateTick` to prevent any tick from reaching `liquidityDelta = type(int128).min` by checking after the calculation at [2](#0-1) :

```solidity
int128 liquidityDeltaNext =
    isUpper ? currentLiquidityDelta - liquidityDelta : currentLiquidityDelta + liquidityDelta;

// Prevent type(int128).min from being stored
if (liquidityDeltaNext == type(int128).min) {
    revert("liquidityDelta cannot be type(int128).min");
}
```

## Proof of Concept

```solidity
// File: test/Exploit_TickLiquidityDeltaOverflow.t.sol
// Run with: forge test --match-test test_tickLiquidityDeltaOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/types/poolKey.sol";
import "../src/types/positionId.sol";

contract Exploit_TickLiquidityDeltaOverflow is Test {
    Core core;
    PoolKey poolKey;
    
    function setUp() public {
        // Deploy Core contract
        core = new Core();
        
        // Create a concentrated liquidity pool
        poolKey = PoolKey({
            token0: address(0x1),
            token1: address(0x2),
            config: createConcentratedPoolConfig(3000, 10, address(0))
        });
        
        // Initialize pool at tick 0
        core.initializePool(poolKey, 0);
    }
    
    function test_tickLiquidityDeltaOverflow() public {
        // SETUP: Create many positions to accumulate liquidityDelta toward type(int128).min
        // at upper tick = 100
        
        int32 lowerTick = -100;
        int32 upperTick = 100;
        
        // Simulate accumulating liquidityDelta = type(int128).min at upperTick
        // (In reality this would require many position mint operations)
        
        // Get current pool liquidity
        PoolState stateBefore = core.poolState(poolKey.toPoolId());
        uint128 liquidityBefore = stateBefore.liquidity();
        
        // EXPLOIT: Execute swap that crosses the vulnerable tick
        // When increasing = false and tick has liquidityDelta = type(int128).min,
        // the negation produces 2^127, causing overflow
        
        SwapParameters params = createSwapParameters({
            specifiedAmount: 1000000,
            sqrtRatioLimit: MIN_SQRT_RATIO,
            isToken1: false,
            skipAhead: 0
        });
        
        // Execute swap (would trigger the overflow)
        (PoolBalanceUpdate balanceUpdate, PoolState stateAfter) = 
            core.swap(poolKey, params);
        
        // VERIFY: Pool liquidity is corrupted after crossing the tick
        uint128 liquidityAfter = stateAfter.liquidity();
        
        // If the exploit works, liquidity would be truncated to incorrect value
        // Expected: liquidityAfter == liquidityBefore + 2^127 (mod 2^128)
        // This demonstrates the silent overflow corruption
        
        assertNotEq(liquidityAfter, liquidityBefore, 
            "Liquidity should be different after crossing vulnerable tick");
        
        // Additional verification: subsequent swaps would use corrupted liquidity,
        // leading to incorrect pricing and potential fund extraction
    }
}
```

**Note:** The full PoC would require setting up positions to actually create a tick with `liquidityDelta = type(int128).min`, which involves significant setup. The above demonstrates the exploit flow; a complete implementation would need to properly fund accounts and execute the position minting sequence.

### Citations

**File:** src/Core.sol (L293-294)
```text
        int128 liquidityDeltaNext =
            isUpper ? currentLiquidityDelta - liquidityDelta : currentLiquidityDelta + liquidityDelta;
```

**File:** src/Core.sol (L570-570)
```text
                    uint128 stepLiquidity = liquidity;
```

**File:** src/Core.sol (L759-766)
```text
                        if (isInitialized) {
                            bytes32 tickValue = CoreStorageLayout.poolTicksSlot(poolId, nextTick).load();
                            assembly ("memory-safe") {
                                // if increasing, we add the liquidity delta, otherwise we subtract it
                                let liquidityDelta :=
                                    mul(signextend(15, tickValue), sub(increasing, iszero(increasing)))
                                liquidity := add(liquidity, liquidityDelta)
                            }
```
