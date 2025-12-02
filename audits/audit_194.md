# NoVulnerability found for this question.

After thorough investigation of the security question regarding the liquidity check in `BasePositions.sol` withdraw function at line 277, I found that **the check cannot be bypassed** to withdraw excessive liquidity.

## Investigation Summary

The check at line 277 [1](#0-0)  prevents withdrawing more than `type(int128).max` (2^127 - 1) liquidity in a single transaction. This check is **essential and correctly implemented** for the following reason:

At line 307 [2](#0-1) , the liquidity is cast to `int128` and negated before being passed to `Core.updatePosition`. Without the check, if liquidity exceeded `type(int128).max`, the cast would cause two's complement overflow, resulting in incorrect negative values.

## Bypass Attempts Analyzed

1. **Direct Core.updatePosition calls**: Positions are isolated by locker address [3](#0-2) . Direct calls create separate positions not associated with BasePositions NFTs.

2. **Multiple deposits accumulation**: Each deposit is similarly limited by the same check [4](#0-3) . The maximum achievable position liquidity through deposits is `2 * type(int128).max - 2`, which can be withdrawn in exactly 2 transactions.

3. **Position liquidity validation**: The `addLiquidityDelta` function [5](#0-4)  ensures position liquidity never exceeds `type(uint128).max` and prevents underflow on withdrawals.

4. **Alternative withdrawal paths**: All withdrawal functions (including `collectFees` [6](#0-5) ) route through the same lock callback that performs the check.

## Conclusion

The check is **functioning as intended** and successfully enforces the invariant that all positions remain withdrawable. No exploitable vulnerability exists that would allow bypassing this protection to withdraw excessive liquidity.

### Citations

**File:** src/base/BasePositions.sol (L89-91)
```text
        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }
```

**File:** src/base/BasePositions.sol (L116-116)
```text
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
```

**File:** src/base/BasePositions.sol (L277-277)
```text
            if (liquidity > uint128(type(int128).max)) revert WithdrawOverflow();
```

**File:** src/base/BasePositions.sol (L307-307)
```text
                    -int128(liquidity)
```

**File:** src/Core.sol (L381-385)
```text
            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
            Position storage position;
            assembly ("memory-safe") {
                position.slot := positionSlot
            }
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
