# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the `updatePosition` function and the consecutive `_updateTick` calls at lines 400-401, I can confirm that **the two calls maintain perfect consistency** and a revert in the second call **cannot** leave the first tick in an inconsistent state.

## Key Findings

### The Two Consecutive Calls [1](#0-0) 

These calls execute sequentially without any external calls or complex operations between them.

### Potential Revert Conditions in `_updateTick`

The function has three potential revert conditions:

1. **Overflow in `addLiquidityDelta`** (line 291): [2](#0-1) 

2. **Checked arithmetic overflow/underflow** (lines 293-294): [3](#0-2) 

3. **Max liquidity per tick exceeded** (lines 298-300): [4](#0-3) 

### Asymmetry Between Calls

The two ticks have **different states** and the `isUpper` parameter causes **different arithmetic operations**:
- tickLower (isUpper=false): performs addition
- tickUpper (isUpper=true): performs subtraction

This means one call can succeed while the other fails under specific conditions (e.g., different `currentLiquidityNet` values, different overflow behavior).

### Why Consistency is Maintained

**Solidity's atomic transaction model** ensures that if the second `_updateTick` call reverts for any reason, ALL state changes from the first call are automatically rolled back:

1. **Standard storage operations**: All storage writes use `StorageSlot.store()` which uses standard SSTORE: [5](#0-4) 

2. **No external calls between operations**: Lines 400-401 are consecutive private function calls
3. **No bypass mechanisms**: No selfdestruct, delegatecall, or other operations that could corrupt state
4. **EVM revert behavior**: The EVM REVERT opcode rolls back all state changes within the transaction

## Conclusion

This is a well-designed implementation that leverages Solidity's fundamental transaction atomicity guarantees. Even though the two ticks can have different revert behaviors due to their independent state and different arithmetic operations, the EVM ensures that partial updates cannot occur. If either `_updateTick` call reverts, the entire transaction reverts, maintaining complete consistency.

**No vulnerability exists in this design.**

### Citations

**File:** src/Core.sol (L291-291)
```text
        uint128 liquidityNetNext = addLiquidityDelta(currentLiquidityNet, liquidityDelta);
```

**File:** src/Core.sol (L293-294)
```text
        int128 liquidityDeltaNext =
            isUpper ? currentLiquidityDelta - liquidityDelta : currentLiquidityDelta + liquidityDelta;
```

**File:** src/Core.sol (L298-300)
```text
        if (liquidityNetNext > maxLiquidity) {
            revert MaxLiquidityPerTickExceeded(tick, liquidityNetNext, maxLiquidity);
        }
```

**File:** src/Core.sol (L400-401)
```text
                _updateTick(poolId, positionId.tickLower(), poolKey.config, liquidityDelta, false);
                _updateTick(poolId, positionId.tickUpper(), poolKey.config, liquidityDelta, true);
```

**File:** src/types/storageSlot.sol (L19-23)
```text
function store(StorageSlot slot, bytes32 value) {
    assembly ("memory-safe") {
        sstore(slot, value)
    }
}
```
