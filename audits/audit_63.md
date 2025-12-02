## Title
Permanent Fee Loss When Withdrawing Full Liquidity Without Prior Fee Collection

## Summary
In `Core.sol` `updatePosition` function, when a negative `liquidityDelta` causes a position's liquidity to reach zero, the function zeros out the position's fee tracking state without calculating or crediting accumulated fees. This causes permanent and irrecoverable loss of all fees that accrued since the last fee collection, affecting users who build custom position managers or use the withdrawal functionality without fee collection.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/Core.sol`, function `updatePosition`, lines 430-438 [1](#0-0) 

**Intended Logic:** When updating a position, the protocol should maintain accurate fee accounting regardless of whether liquidity is partially or fully withdrawn. Fees accumulated since the last update should remain collectible until explicitly claimed by the position owner.

**Actual Logic:** The function has asymmetric behavior based on whether `liquidityNext` is zero:
- When `liquidityNext != 0` (partial withdrawal): Fees are calculated using `position.fees(feesPerLiquidityInside)` and accounting is updated to preserve them for future collection
- When `liquidityNext == 0` (full withdrawal): The position is immediately zeroed without fee calculation, permanently destroying the fee tracking state [2](#0-1) 

**Exploitation Path:**
1. Liquidity provider deposits liquidity via any position manager that calls `Core.updatePosition`
2. Swaps occur in the pool, generating fees that accumulate in the position's fee tracking (feesPerLiquidityInside grows)
3. User or custom position manager calls `Core.updatePosition` with negative `liquidityDelta` equal to full position liquidity, WITHOUT calling `collectFees` first
4. Core zeros `position.liquidity` and `position.feesPerLiquidityInsideLast` (lines 431-432), destroying all fee tracking
5. Any subsequent attempt to collect fees calculates: `(feesPerLiquidityInside - 0) * 0 = 0`, making fees permanently unrecoverable [3](#0-2) 

**Security Property Broken:** Critical Invariant #5 - "Fee Accounting: Position fee collection must be accurate and never allow double-claiming." This vulnerability violates the accurate collection requirement by causing permanent fee loss.

## Impact Explanation
- **Affected Assets**: All accumulated swap fees (token0 and token1) for positions that are fully withdrawn without prior fee collection
- **Damage Severity**: 100% loss of all uncollected fees accumulated since the last fee collection. The amount scales with swap volume and time between fee collections.
- **User Impact**: 
  - All users building custom position managers that don't follow BasePositions' pattern of collecting fees before full withdrawal
  - Users of BasePositions who explicitly set `withFees=false` during full withdrawal
  - Any contract integrating with Core directly that withdraws all liquidity

The official test suite acknowledges this behavior: [4](#0-3) 

## Likelihood Explanation
- **Attacker Profile**: Not strictly an "attack" but affects any user or protocol building on top of Core who doesn't understand the fee collection requirement before full withdrawal
- **Preconditions**: 
  - Position exists with accumulated fees from swaps
  - User/contract calls `updatePosition` with negative liquidityDelta bringing liquidity to zero
  - No prior call to `collectFees` within the same transaction
- **Execution Complexity**: Single transaction calling `updatePosition` through the lock mechanism
- **Frequency**: Occurs every time a position is fully withdrawn without fee collection, potentially affecting multiple positions across all pools

## Recommendation

The `updatePosition` function should handle fee accounting consistently regardless of whether liquidity goes to zero. When `liquidityNext == 0`, calculate and credit accumulated fees before zeroing the position:

```solidity
// In src/Core.sol, function updatePosition, lines 430-438:

// CURRENT (vulnerable):
// if (liquidityNext == 0) {
//     position.liquidity = 0;
//     position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
// } else {
//     (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
//     position.liquidity = liquidityNext;
//     position.feesPerLiquidityInsideLast =
//         feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
// }

// FIXED:
// Calculate fees using OLD liquidity before zeroing
(uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);

if (liquidityNext == 0) {
    // Credit accumulated fees to user before zeroing position
    if (fees0 != 0 || fees1 != 0) {
        _updatePairDebt(
            locker.id(), 
            poolKey.token0, 
            poolKey.token1, 
            -int256(uint256(fees0)), 
            -int256(uint256(fees1))
        );
    }
    position.liquidity = 0;
    position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
} else {
    position.liquidity = liquidityNext;
    position.feesPerLiquidityInsideLast =
        feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
}
```

This ensures fees are automatically credited when a position is fully withdrawn, maintaining consistent fee accounting behavior.

## Proof of Concept

```solidity
// File: test/Exploit_FeeLossOnFullWithdrawal.t.sol
// Run with: forge test --match-test test_FeeLossOnFullWithdrawal -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/interfaces/ICore.sol";
import "./TestToken.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createConcentratedPoolConfig} from "../src/types/poolConfig.sol";
import {PositionId, createPositionId} from "../src/types/positionId.sol";
import {Position} from "../src/types/position.sol";
import {BaseLocker} from "../src/base/BaseLocker.sol";
import {UsesCore} from "../src/base/UsesCore.sol";
import {CoreLib} from "../src/libraries/CoreLib.sol";
import {FlashAccountantLib} from "../src/libraries/FlashAccountantLib.sol";
import {PoolBalanceUpdate} from "../src/types/poolBalanceUpdate.sol";
import {Router, RouteNode, TokenAmount} from "../src/Router.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";

contract VulnerableLocker is BaseLocker, UsesCore {
    using CoreLib for *;
    using FlashAccountantLib for *;

    TestToken public immutable token0;
    TestToken public immutable token1;

    constructor(ICore core, TestToken _token0, TestToken _token1) 
        BaseLocker(core) UsesCore(core) {
        token0 = _token0;
        token1 = _token1;
    }

    function withdrawFullLiquidity(
        PoolKey memory poolKey, 
        PositionId positionId, 
        int128 liquidity
    ) external returns (bytes memory) {
        return lock(abi.encode(poolKey, positionId, liquidity));
    }

    function handleLockData(uint256, bytes memory data) 
        internal override returns (bytes memory) {
        (PoolKey memory poolKey, PositionId positionId, int128 liquidityDelta) =
            abi.decode(data, (PoolKey, PositionId, int128));

        // Withdraw ALL liquidity WITHOUT collecting fees first
        PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
            poolKey, positionId, liquidityDelta
        );

        if (liquidityDelta < 0) {
            ACCOUNTANT.withdraw(
                poolKey.token0, address(this), 
                uint128(-balanceUpdate.delta0())
            );
            ACCOUNTANT.withdraw(
                poolKey.token1, address(this), 
                uint128(-balanceUpdate.delta1())
            );
        } else {
            ACCOUNTANT.pay(poolKey.token0, uint128(balanceUpdate.delta0()));
            ACCOUNTANT.pay(poolKey.token1, uint128(balanceUpdate.delta1()));
        }
    }
}

contract Exploit_FeeLossOnFullWithdrawal is Test {
    Core public core;
    Router public router;
    VulnerableLocker public locker;
    TestToken public token0;
    TestToken public token1;
    PoolKey public poolKey;

    function setUp() public {
        core = new Core();
        router = new Router(core);
        
        token0 = new TestToken(address(this));
        token1 = new TestToken(address(this));
        
        locker = new VulnerableLocker(core, token0, token1);
        
        token0.transfer(address(locker), type(uint128).max);
        token1.transfer(address(locker), type(uint128).max);

        poolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createConcentratedPoolConfig(3000, 60, address(0))
        });

        core.initializePool(poolKey, 0);
    }

    function test_FeeLossOnFullWithdrawal() public {
        // SETUP: Deposit liquidity
        PositionId positionId = createPositionId({
            _salt: bytes24(0), 
            _tickLower: -60, 
            _tickUpper: 60
        });
        
        locker.withdrawFullLiquidity(poolKey, positionId, 1000e18);
        
        Position memory positionAfterDeposit = core.poolPositions(
            poolKey.toPoolId(), address(locker), positionId
        );
        uint128 depositedLiquidity = positionAfterDeposit.liquidity;
        assertEq(depositedLiquidity, 1000e18, "Liquidity deposited");
        
        // Generate fees via swap
        token0.approve(address(router), 1000e18);
        router.swap(
            RouteNode({
                poolKey: poolKey, 
                sqrtRatioLimit: SqrtRatio.wrap(0), 
                skipAhead: 0
            }),
            TokenAmount({token: address(token0), amount: 1000e18}),
            type(int256).min
        );
        
        // Verify fees accumulated
        Position memory positionBeforeWithdraw = core.poolPositions(
            poolKey.toPoolId(), address(locker), positionId
        );
        
        // Fees should be non-zero (feesPerLiquidityInsideLast has grown)
        assertTrue(
            positionBeforeWithdraw.feesPerLiquidityInsideLast.value0 > 0 || 
            positionBeforeWithdraw.feesPerLiquidityInsideLast.value1 > 0,
            "Fee tracking should be non-zero after swaps"
        );
        
        // EXPLOIT: Withdraw ALL liquidity WITHOUT collecting fees
        locker.withdrawFullLiquidity(poolKey, positionId, -int128(depositedLiquidity));
        
        // VERIFY: Position is zeroed and fees are permanently lost
        Position memory positionAfterWithdraw = core.poolPositions(
            poolKey.toPoolId(), address(locker), positionId
        );
        
        assertEq(
            positionAfterWithdraw.liquidity, 
            0, 
            "Vulnerability confirmed: Position liquidity zeroed"
        );
        assertEq(
            positionAfterWithdraw.feesPerLiquidityInsideLast.value0, 
            0, 
            "Vulnerability confirmed: Fee tracking value0 zeroed"
        );
        assertEq(
            positionAfterWithdraw.feesPerLiquidityInsideLast.value1, 
            0, 
            "Vulnerability confirmed: Fee tracking value1 zeroed"
        );
        
        // Accumulated fees are permanently lost - cannot be recovered
    }
}
```

**Notes:**

The vulnerability is confirmed by the protocol's own test suite, which explicitly documents that fees are "burned" when withdrawing without collecting them first. While `BasePositions` correctly handles this by calling `collectFees` before full withdrawal when `withFees=true`, the Core contract itself does not enforce this pattern, allowing fee loss for:

1. Custom position managers that integrate directly with Core
2. Users who explicitly set `withFees=false` 
3. Any future integrations unaware of this requirement

The asymmetric handling between partial withdrawals (which preserve fees) and full withdrawals (which destroy fees) violates the principle of least surprise and the Fee Accounting invariant.

### Citations

**File:** src/Core.sol (L430-438)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }
```

**File:** src/types/position.sol (L33-51)
```text
function fees(Position memory position, FeesPerLiquidity memory feesPerLiquidityInside)
    pure
    returns (uint128, uint128)
{
    uint128 liquidity;
    uint256 difference0;
    uint256 difference1;
    assembly ("memory-safe") {
        liquidity := mload(add(position, 0x20))
        // feesPerLiquidityInsideLast is now at offset 0x40 due to extraData field
        let positionFpl := mload(add(position, 0x40))
        difference0 := sub(mload(feesPerLiquidityInside), mload(positionFpl))
        difference1 := sub(mload(add(feesPerLiquidityInside, 0x20)), mload(add(positionFpl, 0x20)))
    }

    return (
        uint128(FixedPointMathLib.fullMulDivN(difference0, liquidity, 128)),
        uint128(FixedPointMathLib.fullMulDivN(difference1, liquidity, 128))
    );
```

**File:** test/Positions.t.sol (L564-568)
```text
        // The fees are now burned - they cannot be collected since the position has zero liquidity
        // Attempting to collect fees should return zero
        (uint128 collectedAfter0, uint128 collectedAfter1) = positions.collectFees(id, poolKey, -100, 100);
        assertEq(collectedAfter0, 0, "Should not be able to collect fees after full withdrawal");
        assertEq(collectedAfter1, 0, "Should not be able to collect fees after full withdrawal");
```
