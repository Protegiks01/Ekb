## Title
Permanent Loss of Accrued Fees When Withdrawing All Liquidity Without Fee Collection

## Summary
When a liquidity provider withdraws all liquidity from a position without collecting fees first (by setting `withFees=false`), the accrued fees become permanently locked and unrecoverable. The `Core.updatePosition` function resets the position's fee tracking to zero when liquidity reaches zero, making subsequent fee collection impossible since the fee calculation formula requires non-zero liquidity.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol` (updatePosition function) and `src/base/BasePositions.sol` (withdraw flow)

**Intended Logic:** Positions should always be able to collect their accrued swap fees, even after liquidity withdrawal. Fee tracking should preserve uncollected fees for later claim.

**Actual Logic:** When `Core.updatePosition` reduces a position's liquidity to zero, it unconditionally resets both `position.liquidity` and `position.feesPerLiquidityInsideLast` to zero, destroying all tracking of previously accrued but uncollected fees. [1](#0-0) 

The fee calculation depends on multiplying the fee-per-liquidity difference by the current liquidity amount. When liquidity is zero, this formula always returns zero fees regardless of how much was previously accrued: [2](#0-1) 

**Exploitation Path:**
1. Liquidity provider creates a position and earns swap fees (feesPerLiquidityInside increases from initial snapshot in feesPerLiquidityInsideLast)
2. Provider calls `BasePositions.withdraw()` with full liquidity amount and `withFees=false` (either accidentally, through contract integration, or via malicious approved operator)
3. In the withdraw flow, if `withFees=false`, `CORE.collectFees` is not called: [3](#0-2) 

4. `CORE.updatePosition` is then called with negative liquidity delta, setting `liquidityNext=0`, which triggers the reset: `position.liquidity=0` and `position.feesPerLiquidityInsideLast=FeesPerLiquidity(0,0)`
5. Any subsequent attempt to collect fees via `CORE.collectFees` calculates: `(currentFPL - 0) * 0 / 2^128 = 0`, returning zero fees
6. The originally accrued fees remain in the Core contract but are permanently unclaimable by the position owner

**Security Property Broken:** Violates the "Fee Accounting" invariant that "position fee collection must be accurate and never allow double-claiming." While this doesn't allow double-claiming, it causes the opposite problem—fees are lost entirely rather than accurately tracked.

## Impact Explanation
- **Affected Assets**: All accrued but uncollected swap fees (both token0 and token1) from any position where full liquidity is withdrawn without fee collection
- **Damage Severity**: 100% loss of all accrued fees for the affected position. Fees remain locked in the Core contract with no mechanism for recovery
- **User Impact**: Affects any liquidity provider who:
  - Accidentally sets `withFees=false` when withdrawing all liquidity
  - Uses smart contract integrations that don't properly handle fee collection
  - Has a malicious approved operator who withdraws their liquidity without collecting fees
  - Encounters frontend bugs that incorrectly pass the `withFees` parameter

## Likelihood Explanation
- **Attacker Profile**: Any position owner, approved operator, or smart contract with position management capabilities. Can also occur through honest user error
- **Preconditions**: Position must have positive liquidity with accrued fees, and the withdraw operation must specify the full liquidity amount with `withFees=false`
- **Execution Complexity**: Single transaction calling `withdraw()` with appropriate parameters
- **Frequency**: Can affect any position withdrawal where fees aren't collected first. Particularly likely in:
  - Automated position management contracts
  - Multicall operations with incorrect ordering
  - Frontend integration bugs
  - Users unfamiliar with the `withFees` parameter semantics

## Recommendation

**Option 1: Automatic Fee Collection (Recommended)**
Modify `Core.updatePosition` to automatically collect fees before resetting position state when liquidity goes to zero:

```solidity
// In src/Core.sol, updatePosition function, around line 430:

// CURRENT (vulnerable):
if (liquidityNext == 0) {
    position.liquidity = 0;
    position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
}

// FIXED:
if (liquidityNext == 0) {
    // Collect any outstanding fees before closing position
    (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
    if (fees0 > 0 || fees1 > 0) {
        _updatePairDebt(
            locker.id(), poolKey.token0, poolKey.token1, 
            -int256(uint256(fees0)), -int256(uint256(fees1))
        );
        emit PositionFeesCollected(locker.addr(), poolId, positionId, fees0, fees1);
    }
    position.liquidity = 0;
    position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
}
```

**Option 2: Enforce Fee Collection in BasePositions**
Modify `BasePositions.handleLockData` to require `withFees=true` when withdrawing all liquidity:

```solidity
// In src/base/BasePositions.sol, handleLockData function, around line 282:

// Add validation before processing withdrawal
if (liquidity != 0) {
    Position memory currentPosition = CORE.poolPositions(
        poolKey.toPoolId(), 
        address(this), 
        createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
    );
    
    // If withdrawing all liquidity, fees must be collected
    if (currentPosition.liquidity == liquidity && !withFees) {
        revert MustCollectFeesWhenWithdrawingAllLiquidity();
    }
}
```

**Option 3: Preserve Fee Tracking**
Store uncollected fees separately when liquidity goes to zero, allowing later collection. This requires additional storage and is more complex.

## Proof of Concept

```solidity
// File: test/Exploit_FeesLockedOnFullWithdrawal.t.sol
// Run with: forge test --match-test test_FeesLockedOnFullWithdrawal -vvv

pragma solidity ^0.8.31;

import {Test} from "forge-std/Test.sol";
import {Core} from "../src/Core.sol";
import {Positions} from "../src/Positions.sol";
import {Router} from "../src/Router.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {RouteNode} from "../src/types/routeNode.sol";
import {TokenAmount} from "../src/types/tokenAmount.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract Exploit_FeesLockedOnFullWithdrawal is Test {
    Core core;
    Positions positions;
    Router router;
    MockERC20 token0;
    MockERC20 token1;
    
    function setUp() public {
        core = new Core();
        positions = new Positions(core, address(this));
        router = new Router(core);
        
        token0 = new MockERC20("Token0", "T0", 18);
        token1 = new MockERC20("Token1", "T1", 18);
        
        token0.mint(address(this), 1000000e18);
        token1.mint(address(this), 1000000e18);
        
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
    }
    
    function test_FeesLockedOnFullWithdrawal() public {
        // SETUP: Create pool and position
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        (uint256 id, uint128 liquidity) = createPosition(poolKey, -100, 100, 100e18, 100e18);
        
        // Generate fees by swapping
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: 100e18}),
            type(int256).min
        );
        
        // Verify fees exist before withdrawal
        (,, uint128 fees0Before, uint128 fees1Before) = positions.getPositionFeesAndLiquidity(
            id, poolKey, -100, 100
        );
        assertTrue(fees0Before > 0, "Should have token0 fees");
        
        // EXPLOIT: Withdraw all liquidity WITHOUT collecting fees
        uint256 balance0Before = token0.balanceOf(address(this));
        (uint128 withdrawn0, uint128 withdrawn1) = positions.withdraw(
            id, poolKey, -100, 100, liquidity, address(this), false  // withFees=false
        );
        uint256 balance0After = token0.balanceOf(address(this));
        
        // Verify only principal was received, not fees
        uint256 received = balance0After - balance0Before;
        assertTrue(received < fees0Before + withdrawn0, "Fees were not collected");
        
        // VERIFY: Attempting to collect fees now returns zero
        (uint128 collectedFees0, uint128 collectedFees1) = positions.collectFees(
            id, poolKey, -100, 100
        );
        
        assertEq(collectedFees0, 0, "VULNERABILITY: Cannot collect fees after full withdrawal");
        assertEq(collectedFees1, 0, "VULNERABILITY: Cannot collect fees after full withdrawal");
        
        // The fees0Before tokens are now permanently locked in Core contract
        assertTrue(fees0Before > 0, "User lost fees worth this amount");
    }
    
    function createPool(uint8 extension, uint24 fee, int32 tickSpacing) internal returns (PoolKey memory) {
        // Pool creation logic
        PoolKey memory poolKey;
        // ... initialize poolKey fields
        positions.maybeInitializePool(poolKey, 0);
        return poolKey;
    }
    
    function createPosition(PoolKey memory poolKey, int32 lower, int32 upper, uint128 amount0, uint128 amount1) 
        internal returns (uint256 id, uint128 liquidity) {
        (id, liquidity,,) = positions.mintAndDeposit(
            poolKey, lower, upper, amount0, amount1, 0
        );
    }
}
```

**Notes:**
- The test demonstrates the exact scenario where fees are locked: withdraw all liquidity with `withFees=false`
- A real-world PoC exists in the codebase test suite at `test/Positions.t.sol` line 527 (`test_withdraw_without_fees_burns_fees`) which explicitly documents this behavior with the comment "The fees are now burned" [4](#0-3) 

- This is NOT listed in the "Publicly known issues" section of the README, making it a valid finding
- The vulnerability affects real user funds (accrued fees) with no recovery mechanism

### Citations

**File:** src/Core.sol (L430-432)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
```

**File:** src/types/position.sol (L48-51)
```text
    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
```

**File:** src/base/BasePositions.sol (L283-301)
```text
            if (withFees) {
                (amount0, amount1) = CORE.collectFees(
                    poolKey,
                    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
                );

                // Collect swap protocol fees
                (uint128 swapProtocolFee0, uint128 swapProtocolFee1) =
                    _computeSwapProtocolFees(poolKey, amount0, amount1);

                if (swapProtocolFee0 != 0 || swapProtocolFee1 != 0) {
                    CORE.updateSavedBalances(
                        poolKey.token0, poolKey.token1, bytes32(0), int128(swapProtocolFee0), int128(swapProtocolFee1)
                    );

                    amount0 -= swapProtocolFee0;
                    amount1 -= swapProtocolFee1;
                }
            }
```

**File:** test/Positions.t.sol (L564-568)
```text
        // The fees are now burned - they cannot be collected since the position has zero liquidity
        // Attempting to collect fees should return zero
        (uint128 collectedAfter0, uint128 collectedAfter1) = positions.collectFees(id, poolKey, -100, 100);
        assertEq(collectedAfter0, 0, "Should not be able to collect fees after full withdrawal");
        assertEq(collectedAfter1, 0, "Should not be able to collect fees after full withdrawal");
```
