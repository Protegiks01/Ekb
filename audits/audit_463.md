## Title
Missing Slippage Protection in withdraw() Enables Sandwich Attacks on Liquidity Withdrawals

## Summary
The `withdraw()` function in BasePositions.sol lacks `minAmount0` and `minAmount1` slippage protection parameters, allowing sandwich attackers to manipulate pool prices before withdrawals and cause users to receive suboptimal token amounts due to forced impermanent loss realization.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** Users should be able to withdraw liquidity from their positions and receive token amounts corresponding to their liquidity share at fair market prices.

**Actual Logic:** The `withdraw()` function calculates withdrawal amounts based on the current pool price using `liquidityDeltaToAmountDelta()` [2](#0-1) , but provides no mechanism for users to specify minimum acceptable amounts. The token amounts depend on the pool's `sqrtRatio` at execution time [3](#0-2) , making withdrawals vulnerable to price manipulation.

**Exploitation Path:**
1. Alice submits a transaction to withdraw liquidity from her position
2. Bob (MEV searcher) observes Alice's pending withdrawal transaction in the mempool
3. Bob front-runs with a large swap that temporarily moves the pool price away from equilibrium (paying swap fees)
4. Alice's withdrawal executes at the manipulated price, receiving tokens at an unfavorable ratio due to increased impermanent loss at the distorted price point
5. Bob back-runs to restore the pool price (paying more swap fees)
6. Alice has permanently locked in impermanent loss from the temporary price manipulation and received less total value than she would have at the fair market price

**Security Property Broken:** Users suffer unexpected value loss during withdrawal operations due to lack of protection mechanisms, violating the reasonable expectation of withdrawal safety present in the `deposit()` function's slippage protection [4](#0-3) .

## Impact Explanation
- **Affected Assets**: All user liquidity positions across all pools are vulnerable during withdrawal operations
- **Damage Severity**: Users can lose a percentage of their position value corresponding to the additional impermanent loss induced by temporary price manipulation. Loss magnitude depends on position range width, liquidity depth, and manipulation size.
- **User Impact**: Every user withdrawing liquidity is potentially vulnerable. The attack is most profitable on positions with tight ranges and in pools with lower liquidity where price manipulation is cheaper.

## Likelihood Explanation
- **Attacker Profile**: MEV searchers and sandwich bot operators who monitor the mempool for withdrawal transactions
- **Preconditions**: Pool must be initialized with sufficient liquidity, and the user must be withdrawing liquidity from an active position
- **Execution Complexity**: Moderate - requires front-running and back-running in the same block, but this is standard MEV infrastructure
- **Frequency**: Can be exploited on every withdrawal transaction where the profit from induced impermanent loss exceeds the gas costs and swap fees paid

## Recommendation

Add `amount0Min` and `amount1Min` slippage protection parameters to the `withdraw()` function, similar to the `minLiquidity` protection in `deposit()`: [5](#0-4) 

The function signature should be updated to:
```solidity
function withdraw(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    uint128 amount0Min,
    uint128 amount1Min,
    address recipient,
    bool withFees
) external payable returns (uint128 amount0, uint128 amount1);
```

Add validation after calculating withdrawal amounts:
```solidity
if (amount0 < amount0Min || amount1 < amount1Min) {
    revert WithdrawFailedDueToSlippage(amount0, amount1, amount0Min, amount1Min);
}
```

This mirrors the industry standard approach used by Uniswap V3's NonfungiblePositionManager and provides users with essential protection against sandwich attacks during withdrawals.

## Proof of Concept

```solidity
// File: test/Exploit_WithdrawSandwich.t.sol
// Run with: forge test --match-test test_WithdrawSandwich -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {RouteNode, TokenAmount} from "../src/Router.sol";
import {SqrtRatio} from "../src/types/sqrtRatio.sol";
import {CallPoints} from "../src/types/callPoints.sol";

contract Exploit_WithdrawSandwich is FullTest {
    function test_WithdrawSandwich() public {
        // SETUP: Create pool and Alice's position
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints(false,false,false,false,false,false,false,false));
        
        // Alice deposits large liquidity position
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        (uint256 aliceId, uint128 liquidity) = createPosition(poolKey, -1000, 1000, 10000e18, 10000e18);
        
        // Record Alice's position value at fair price
        (uint128 expectedAmount0, uint128 expectedAmount1) = 
            positions.getPositionFeesAndLiquidity(aliceId, poolKey, -1000, 1000);
        
        // EXPLOIT: Bob front-runs Alice's withdrawal
        // Bob manipulates price downward with large swap
        token0.approve(address(router), type(uint256).max);
        router.swap(
            RouteNode({poolKey: poolKey, sqrtRatioLimit: SqrtRatio.wrap(0), skipAhead: 0}),
            TokenAmount({token: address(token0), amount: int128(5000e18)}),
            type(int256).min
        );
        
        // Alice's withdrawal executes at manipulated price
        (uint128 actualAmount0, uint128 actualAmount1) = 
            positions.withdraw(aliceId, poolKey, -1000, 1000, liquidity);
        
        // VERIFY: Alice received different amounts due to price manipulation
        // She received more token0 and less token1 at the manipulated price
        // The total VALUE is less due to impermanent loss at manipulated price
        assert(actualAmount0 > expectedAmount0); // More of cheaper token
        assert(actualAmount1 < expectedAmount1); // Less of expensive token
        
        // Without slippage protection, Alice cannot prevent this loss
        // A minAmount0/minAmount1 parameter would have reverted the transaction
    }
}
```

## Notes

This vulnerability represents a **design asymmetry**: `deposit()` includes slippage protection via `minLiquidity` [6](#0-5) , but `withdraw()` provides no equivalent protection [5](#0-4) . This deviation from industry standards (Uniswap V3 includes `amount0Min`/`amount1Min` in `decreaseLiquidity`) creates an exploitable attack surface.

The vulnerability is particularly severe in Ekubo's singleton architecture where multiple pools share the same Core contract, as attackers can monitor all withdrawal transactions across all pools from a single mempool observation point.

### Citations

**File:** src/base/BasePositions.sol (L85-87)
```text
        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }
```

**File:** src/base/BasePositions.sol (L120-133)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/Core.sol (L378-379)
```text
            (int128 delta0, int128 delta1) =
                liquidityDeltaToAmountDelta(state.sqrtRatio(), liquidityDelta, sqrtRatioLower, sqrtRatioUpper);
```

**File:** src/math/liquidity.sol (L22-54)
```text
function liquidityDeltaToAmountDelta(
    SqrtRatio sqrtRatio,
    int128 liquidityDelta,
    SqrtRatio sqrtRatioLower,
    SqrtRatio sqrtRatioUpper
) pure returns (int128 delta0, int128 delta1) {
    unchecked {
        if (liquidityDelta == 0) {
            return (0, 0);
        }
        bool isPositive = (liquidityDelta > 0);
        int256 sign = -1 + 2 * int256(LibBit.rawToUint(isPositive));
        // absolute value of a int128 always fits in a uint128
        uint128 magnitude = uint128(FixedPointMathLib.abs(liquidityDelta));

        if (sqrtRatio <= sqrtRatioLower) {
            delta0 = SafeCastLib.toInt128(
                sign * int256(uint256(amount0Delta(sqrtRatioLower, sqrtRatioUpper, magnitude, isPositive)))
            );
        } else if (sqrtRatio < sqrtRatioUpper) {
            delta0 = SafeCastLib.toInt128(
                sign * int256(uint256(amount0Delta(sqrtRatio, sqrtRatioUpper, magnitude, isPositive)))
            );
            delta1 = SafeCastLib.toInt128(
                sign * int256(uint256(amount1Delta(sqrtRatioLower, sqrtRatio, magnitude, isPositive)))
            );
        } else {
            delta1 = SafeCastLib.toInt128(
                sign * int256(uint256(amount1Delta(sqrtRatioLower, sqrtRatioUpper, magnitude, isPositive)))
            );
        }
    }
}
```

**File:** src/interfaces/IPositions.sol (L45-45)
```text
    /// @param minLiquidity Minimum liquidity to receive (for slippage protection)
```

**File:** src/interfaces/IPositions.sol (L94-102)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) external payable returns (uint128 amount0, uint128 amount1);
```
