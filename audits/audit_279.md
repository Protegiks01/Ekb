## Title
Position Liquidity Accumulation Beyond int128 Breaks View Functions and Complicates Withdrawals

## Summary
`BasePositions.deposit` validates that each individual deposit doesn't exceed `type(int128).max`, but multiple deposits can accumulate position liquidity beyond this limit. This causes `getPositionFeesAndLiquidity` to revert when attempting to cast the accumulated liquidity, creating a denial-of-service condition for position queries and complicating withdrawals.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/base/BasePositions.sol`
- Lines 89-91 (deposit validation)
- Line 59 (getPositionFeesAndLiquidity unsafe cast)
- Line 277 (withdraw validation) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** The deposit function validates that liquidity doesn't exceed `type(int128).max` to ensure safe casting when calling `Core.updatePosition`. The validation is intended to prevent overflow when the liquidity is cast to `int128`. [4](#0-3) 

**Actual Logic:** While each individual deposit is validated, the validation doesn't consider the cumulative position liquidity stored in `Core`. The `addLiquidityDelta` function in Core allows position liquidity to grow beyond `type(int128).max` as long as each delta is valid. [5](#0-4) [6](#0-5) [7](#0-6) 

**Exploitation Path:**

1. User deposits liquidity = `type(int128).max` (170141183460469231731687303715884105727) to a position. This passes validation and succeeds.

2. User deposits again with liquidity = `type(int128).max` to the same position. This passes validation again.

3. The position now has total liquidity = 2 × `type(int128).max` = 340282366920938463463374607431768211454, which is less than `type(uint128).max` but greater than `type(int128).max`.

4. When anyone calls `getPositionFeesAndLiquidity` for this position, it attempts `SafeCastLib.toInt128(position.liquidity)`, which reverts with `SafeCastLib.Overflow` because the value exceeds `type(int128).max`.

5. When attempting to withdraw the entire position, the user must call `withdraw` with liquidity > `type(int128).max`, which reverts at the overflow check, forcing multiple partial withdrawals.

**Security Property Broken:** 
- **Withdrawal Availability**: Positions cannot be fully withdrawn in a single transaction when liquidity exceeds `type(int128).max`, violating the principle that "All positions MUST be withdrawable at any time."
- **View Function Reliability**: Critical view functions become unusable, breaking integrations and user interfaces that depend on position queries.

## Impact Explanation

- **Affected Assets**: Any position with accumulated liquidity exceeding `type(int128).max` (achievable through 2+ deposits)
- **Damage Severity**: 
  - View function `getPositionFeesAndLiquidity` becomes permanently unusable for affected positions
  - Users cannot withdraw their entire position in a single transaction
  - Front-ends, analytics tools, and smart contract integrations relying on position queries will fail
  - Users incur additional gas costs for multiple withdrawal transactions
- **User Impact**: Any user who makes multiple large deposits to the same position. This is a natural behavior for liquidity providers who want to increase their position over time.

## Likelihood Explanation

- **Attacker Profile**: Any liquidity provider, no special privileges required
- **Preconditions**: 
  - Position must be initialized
  - User needs sufficient tokens to make deposits totaling more than `type(int128).max` liquidity
  - This is achievable in 2+ deposits
- **Execution Complexity**: Very simple - just call `deposit` multiple times with large liquidity amounts
- **Frequency**: Can affect any position at any time, and once triggered, the position permanently has this limitation until liquidity is reduced below `type(int128).max`

## Recommendation

Add validation to check if the accumulated position liquidity would exceed `type(int128).max` after the deposit:

```solidity
// In src/base/BasePositions.sol, function deposit, after line 91:

if (liquidity > uint128(type(int128).max)) {
    revert DepositOverflow();
}

// ADD THIS CHECK:
// Fetch current position liquidity from Core
Position memory currentPosition = CORE.poolPositions(
    poolKey.toPoolId(), 
    address(this), 
    createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper})
);

// Check if accumulated liquidity would overflow int128
uint256 totalLiquidity = uint256(currentPosition.liquidity) + uint256(liquidity);
if (totalLiquidity > uint256(uint128(type(int128).max))) {
    revert DepositOverflow();
}
```

Alternative mitigation: Modify `getPositionFeesAndLiquidity` to handle large liquidity values gracefully:

```solidity
// In src/base/BasePositions.sol, function getPositionFeesAndLiquidity, line 58-60:

// CURRENT (vulnerable):
(int128 delta0, int128 delta1) = liquidityDeltaToAmountDelta(
    sqrtRatio, -SafeCastLib.toInt128(position.liquidity), tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper)
);

// FIXED:
// Handle positions with liquidity exceeding int128.max by capping the calculation
uint128 liquidityForCalc = position.liquidity > uint128(type(int128).max) 
    ? uint128(type(int128).max) 
    : position.liquidity;
(int128 delta0, int128 delta1) = liquidityDeltaToAmountDelta(
    sqrtRatio, -SafeCastLib.toInt128(liquidityForCalc), tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper)
);
// Note: This returns approximate values for very large positions
```

## Proof of Concept

```solidity
// File: test/Exploit_LiquidityAccumulationOverflow.t.sol
// Run with: forge test --match-test test_LiquidityAccumulationOverflow -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/Positions.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {PoolConfig} from "../src/types/poolConfig.sol";

contract Exploit_LiquidityAccumulationOverflow is Test {
    Core core;
    Positions positions;
    address token0;
    address token1;
    
    function setUp() public {
        // Deploy core contracts
        core = new Core();
        positions = new Positions(core, address(this));
        
        // Setup tokens and pool
        token0 = address(new MockERC20("Token0", "TK0"));
        token1 = address(new MockERC20("Token1", "TK1"));
        
        // Mint tokens to user
        MockERC20(token0).mint(address(this), type(uint128).max);
        MockERC20(token1).mint(address(this), type(uint128).max);
        
        // Approve positions contract
        MockERC20(token0).approve(address(positions), type(uint256).max);
        MockERC20(token1).approve(address(positions), type(uint256).max);
    }
    
    function test_LiquidityAccumulationOverflow() public {
        // SETUP: Create pool and mint position NFT
        PoolKey memory poolKey = PoolKey({
            token0: token0,
            token1: token1,
            config: PoolConfig.wrap(0) // Default config
        });
        
        positions.maybeInitializePool(poolKey, 0);
        uint256 positionId = positions.mint();
        
        // EXPLOIT: Deposit type(int128).max liquidity twice
        uint128 maxDeposit = uint128(type(int128).max);
        
        // First deposit - succeeds
        positions.deposit(
            positionId,
            poolKey,
            -100, // tickLower
            100,  // tickUpper
            maxDeposit,
            maxDeposit,
            0 // minLiquidity
        );
        
        // Second deposit - succeeds (validation only checks individual deposit)
        positions.deposit(
            positionId,
            poolKey,
            -100,
            100,
            maxDeposit,
            maxDeposit,
            0
        );
        
        // VERIFY: Position now has liquidity > type(int128).max
        // Attempting to call getPositionFeesAndLiquidity will revert with SafeCastLib.Overflow
        vm.expectRevert(SafeCastLib.Overflow.selector);
        positions.getPositionFeesAndLiquidity(positionId, poolKey, -100, 100);
        
        // VERIFY: Cannot withdraw entire position in one transaction
        // The total liquidity is approximately 2 * type(int128).max
        uint128 totalLiquidity = uint128(type(int128).max) * 2;
        vm.expectRevert(IPositions.WithdrawOverflow.selector);
        positions.withdraw(positionId, poolKey, -100, 100, totalLiquidity);
        
        // User must withdraw in multiple transactions
        positions.withdraw(positionId, poolKey, -100, 100, uint128(type(int128).max));
        positions.withdraw(positionId, poolKey, -100, 100, uint128(type(int128).max));
    }
}
```

## Notes

- The vulnerability stems from the mismatch between per-deposit validation (`type(int128).max`) and the cumulative position storage (`uint128`).
- While position liquidity is stored as `uint128` in the Core contract, all operations that consume this value expect it to fit within `int128` range.
- The `addLiquidityDelta` function correctly handles the arithmetic but doesn't enforce the `int128` limit on the final accumulated value.
- This issue affects both the deposit and withdrawal flows, creating friction for users with large positions.
- The recommended fix prevents positions from growing beyond `type(int128).max`, maintaining consistency across all operations.

### Citations

**File:** src/base/BasePositions.sol (L58-60)
```text
        (int128 delta0, int128 delta1) = liquidityDeltaToAmountDelta(
            sqrtRatio, -SafeCastLib.toInt128(position.liquidity), tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper)
        );
```

**File:** src/base/BasePositions.sol (L89-91)
```text
        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }
```

**File:** src/base/BasePositions.sol (L243-247)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** src/base/BasePositions.sol (L277-277)
```text
            if (liquidity > uint128(type(int128).max)) revert WithdrawOverflow();
```

**File:** src/Core.sol (L387-387)
```text
            uint128 liquidityNext = addLiquidityDelta(position.liquidity, liquidityDelta);
```

**File:** src/Core.sol (L435-435)
```text
                position.liquidity = liquidityNext;
```

**File:** src/math/liquidity.sol (L129-136)
```text
function addLiquidityDelta(uint128 liquidity, int128 liquidityDelta) pure returns (uint128 result) {
    assembly ("memory-safe") {
        result := add(liquidity, liquidityDelta)
        if and(result, shl(128, 0xffffffffffffffffffffffffffffffff)) {
            mstore(0, shl(224, 0x6d862c50))
            revert(0, 4)
        }
    }
```
