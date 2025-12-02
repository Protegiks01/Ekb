## Title
Fee Burning Vulnerability in `accumulateAsFees` When Pool Liquidity is Zero

## Summary
The `accumulateAsFees` function in Core.sol does not check if pool liquidity is non-zero before accumulating fees, as explicitly noted in the comment at lines 241-242. This allows extensions (MEVCapture and TWAMM) to inadvertently burn fees when calling `accumulateAsFees` on pools with zero liquidity, causing permanent loss of fees that should be distributed to liquidity providers.

## Impact
**Severity**: Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `accumulateAsFees` function should distribute accumulated fees proportionally to all liquidity providers based on their liquidity positions, crediting the fees to their positions via the fee-per-liquidity tracking mechanism.

**Actual Logic:** When liquidity is zero, the function skips updating fee-per-liquidity trackers (lines 254-268) but still debits the extension's saved balances. The fees are permanently lost as they cannot be claimed by any position.

**Exploitation Path:**

1. **Pool operates normally:** A pool with MEVCapture extension has active liquidity, users perform swaps, and MEVCapture accumulates extra fees in its saved balances at: [2](#0-1) 

2. **Liquidity drains to zero:** All LPs withdraw their liquidity positions (via `updatePosition` with negative `liquidityDelta`), causing the pool's active liquidity to become 0. This is tracked at: [3](#0-2) 

3. **Fee accumulation triggered:** A user calls `collectFees` or `updatePosition` on this pool, which triggers the extension's before-hook at: [4](#0-3) 

4. **Fees burned:** The MEVCapture extension calls `accumulatePoolFees`, which invokes `accumulateAsFees` at: [5](#0-4) 

   Since `liquidity == 0`, the fee-per-liquidity updates are skipped at: [6](#0-5) 

   However, the extension still pays the debt at: [7](#0-6) 

   The extension's saved balances are decremented to settle this debt, but no LP positions receive fee credits. The fees are permanently lost.

**Security Property Broken:** This violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." While it doesn't allow double-claiming, it causes fees to be completely lost rather than accurately distributed to the LPs who provided liquidity when those fees were earned.

## Impact Explanation

- **Affected Assets:** MEV capture fees (in MEVCapture pools) and withdrawal fees (in TWAMM pools) that are held in extension saved balances awaiting distribution to LPs.

- **Damage Severity:** All accumulated fees for a pool are permanently lost when they're accumulated while liquidity is zero. For active pools, this could be substantial. LPs who provided liquidity during the fee-earning period receive nothing, while the tokens remain locked in the Core contract but unallocated.

- **User Impact:** All liquidity providers who were active in the pool during the period when fees were accumulated are affected. This can happen naturally (all LPs exit due to market conditions) or maliciously (large LP intentionally drains pool to zero to grief smaller LPs' pending fees).

## Likelihood Explanation

- **Attacker Profile:** Any user can trigger this vulnerability. A sophisticated attacker with sufficient capital could intentionally cause it; alternatively, it can occur naturally through normal market dynamics.

- **Preconditions:** 
  1. Pool must be initialized with MEVCapture or TWAMM extension
  2. Extension must have accumulated fees in saved balances (requires prior swap/order activity)
  3. Pool liquidity must reach zero (all LPs withdraw)
  4. Someone must trigger fee accumulation (via swap attempt, `updatePosition`, or `collectFees`)

- **Execution Complexity:** Low - can happen through normal protocol operations. No special permissions or timing required beyond market conditions that lead to zero liquidity.

- **Frequency:** Can occur once per pool per zero-liquidity period. Given the concentrated liquidity model, pools can frequently have periods of zero active liquidity, especially for less popular trading pairs or during market volatility.

## Recommendation

Add a liquidity check in `accumulateAsFees` to prevent fee burning: [8](#0-7) 

**Recommended Fix:**

```solidity
// In src/Core.sol, function accumulateAsFees, after line 239:

// Add this check before processing fees:
uint256 liquidity;
{
    uint128 _liquidity = readPoolState(poolId).liquidity();
    assembly ("memory-safe") {
        liquidity := _liquidity
    }
}

// Revert if attempting to accumulate fees when no liquidity exists
if ((amount0 != 0 || amount1 != 0) && liquidity == 0) {
    revert CannotAccumulateFeesWithZeroLiquidity();
}

// Continue with existing logic...
```

Alternative mitigation: Extensions could implement their own checks before calling `accumulateAsFees`, but this is error-prone. The Core contract should enforce this invariant to protect all extensions.

## Proof of Concept

```solidity
// File: test/Exploit_FeeBurning.t.sol
// Run with: forge test --match-test test_FeeBurningWhenLiquidityZero -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/extensions/MEVCapture.sol";
import "../src/Router.sol";

contract Exploit_FeeBurning is Test {
    Core core;
    MEVCapture mevCapture;
    Router router;
    
    address token0;
    address token1;
    address lp1;
    address lp2;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        mevCapture = new MEVCapture(core);
        router = new Router(core);
        
        // Setup tokens and users
        token0 = address(new MockERC20("Token0", "TK0"));
        token1 = address(new MockERC20("Token1", "TK1"));
        lp1 = address(0x1);
        lp2 = address(0x2);
    }
    
    function test_FeeBurningWhenLiquidityZero() public {
        // SETUP: Initialize pool with MEVCapture extension
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: PoolConfig.wrap(/* MEVCapture extension + fees */)
        });
        
        core.initializePool(poolKey, 0);
        
        // LP1 provides liquidity
        vm.startPrank(lp1);
        core.lock(abi.encode(
            "addLiquidity",
            poolKey,
            1000e18 // liquidity amount
        ));
        vm.stopPrank();
        
        // User performs swap, generating MEV fees stored in extension
        vm.startPrank(address(0x3));
        mevCapture.forward(abi.encode(
            poolKey,
            SwapParameters.wrap(/* swap params */)
        ));
        vm.stopPrank();
        
        // Record extension's saved balance before
        uint256 feesBefore = getExtensionSavedBalance(address(mevCapture), poolKey);
        assertGt(feesBefore, 0, "Should have accumulated fees");
        
        // EXPLOIT: LP1 withdraws all liquidity (liquidity becomes 0)
        vm.startPrank(lp1);
        core.lock(abi.encode(
            "removeLiquidity",
            poolKey,
            -1000e18 // withdraw all
        ));
        vm.stopPrank();
        
        // Verify pool liquidity is now 0
        PoolState state = core.poolState(poolKey.toPoolId());
        assertEq(state.liquidity(), 0, "Pool liquidity should be 0");
        
        // TRIGGER: Any user calls updatePosition, triggering fee accumulation
        vm.startPrank(lp2);
        core.lock(abi.encode(
            "updatePosition",
            poolKey,
            positionId,
            0 // no liquidity change
        ));
        vm.stopPrank();
        
        // VERIFY: Fees were burned (removed from extension but not credited to any LP)
        uint256 feesAfter = getExtensionSavedBalance(address(mevCapture), poolKey);
        assertEq(feesAfter, 1, "Fees should be cleared from extension"); // 1 due to offset
        
        // LP1's position has no additional fees despite being active when fees were earned
        uint256 lp1Fees = getPositionFees(lp1, poolKey, positionId);
        assertEq(lp1Fees, 0, "LP1 received no fees - they were burned");
    }
}
```

## Notes

The vulnerability affects both MEVCapture and TWAMM extensions as they both call `accumulateAsFees` without checking pool liquidity:
- MEVCapture: [9](#0-8) 
- MEVCapture (in swap flow): [10](#0-9) 
- TWAMM: [11](#0-10) 

The comment at line 241-242 acknowledges this behavior but describes it as "fees are simply burned" rather than treating it as a security concern. However, this represents a loss of user funds (LP fees) and violates the fee accounting invariant.

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

**File:** src/Core.sol (L367-368)
```text
        IExtension(poolKey.config.extension())
            .maybeCallBeforeUpdatePosition(locker, poolKey, positionId, liquidityDelta);
```

**File:** src/Core.sol (L409-416)
```text
                if (state.tick() >= positionId.tickLower() && state.tick() < positionId.tickUpper()) {
                    state = createPoolState({
                        _sqrtRatio: state.sqrtRatio(),
                        _tick: state.tick(),
                        _liquidity: addLiquidityDelta(state.liquidity(), liquidityDelta)
                    });
                    writePoolState(poolId, state);
                }
```

**File:** src/extensions/MEVCapture.sol (L136-149)
```text
        (int32 tick, uint128 fees0, uint128 fees1) = loadCoreState(poolId, poolKey.token0, poolKey.token1);

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
```

**File:** src/extensions/MEVCapture.sol (L196-196)
```text
                    CORE.accumulateAsFees(poolKey, fees0, fees1);
```

**File:** src/extensions/MEVCapture.sol (L254-256)
```text
            if (saveDelta0 != 0 || saveDelta1 != 0) {
                CORE.updateSavedBalances(poolKey.token0, poolKey.token1, PoolId.unwrap(poolId), saveDelta0, saveDelta1);
            }
```

**File:** src/extensions/TWAMM.sol (L323-323)
```text
                        CORE.accumulateAsFees(poolKey, 0, fee);
```
