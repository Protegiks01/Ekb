# NoVulnerability found for this question.

After a thorough investigation of the `_emitVirtualOrdersExecuted()` function and all related code paths, I found that the assumption stated in the comment is always satisfied by the code's invariants.

## Analysis Summary

The `_emitVirtualOrdersExecuted()` function assumes `saleRateToken0` and `saleRateToken1` are <= type(uint112).max for correct memory packing in the log emission. [1](#0-0) 

However, this assumption is guaranteed to hold because:

1. **Type-safe extraction**: The `saleRateToken0()` and `saleRateToken1()` functions extract exactly 112 bits from packed storage and return uint112 values. [2](#0-1) 

2. **Overflow protection**: The `addSaleRateDelta()` function enforces that results must be <= uint112.max by checking if any bits beyond position 112 are set, reverting with `SaleRateDeltaOverflow` if so. [3](#0-2) 

3. **Controlled state writes**: All TwammPoolState updates go through `createTwammPoolState()` which accepts uint112 parameters and properly packs them into 112-bit fields. [4](#0-3) 

4. **No bypass mechanisms**: The contract only exposes read-only storage functions, preventing direct state manipulation. [5](#0-4) 

5. **Validated call sites**: Both invocations of `_emitVirtualOrdersExecuted()` pass values that are guaranteed to be <= uint112.max - either from the validated state accessors or literal zeros. [6](#0-5) 

The memory layout in the assembly log emission (poolId at bytes 0-31, saleRateToken0 at bytes 32-45, saleRateToken1 at bytes 46-59) will always contain correct data because the type system and validation logic ensure the invariant is maintained throughout all execution paths.

**Notes**: While the function signature accepts uint256 parameters, all actual call sites provide uint112-bounded values. The assembly memory operations assume this constraint for correct packing, and the codebase rigorously enforces it at every state transition point.

### Citations

**File:** src/extensions/TWAMM.sol (L66-81)
```text
    /// @dev Emits an event for the virtual order execution. Assumes that saleRateToken0 and saleRateToken1 are <= type(uint112).max
    /// @param poolId The unique identifier for the pool
    /// @param saleRateToken0 The sale rate for token0 orders
    /// @param saleRateToken1 The sale rate for token1 orders
    function _emitVirtualOrdersExecuted(PoolId poolId, uint256 saleRateToken0, uint256 saleRateToken1) internal {
        assembly ("memory-safe") {
            // by writing it backwards, we overwrite only the empty bits with each subsequent write
            // 28-60, only 46-60 can be non-zero
            mstore(28, saleRateToken1)
            // 14-46, only 32-46 can be non-zero
            mstore(14, saleRateToken0)
            mstore(0, poolId)

            log0(0, 60)
        }
    }
```

**File:** src/extensions/TWAMM.sol (L589-589)
```text
                _emitVirtualOrdersExecuted(poolId, state.saleRateToken0(), state.saleRateToken1());
```

**File:** src/types/twammPoolState.sol (L26-36)
```text
function saleRateToken0(TwammPoolState state) pure returns (uint112 rate) {
    assembly ("memory-safe") {
        rate := shr(144, shl(112, state))
    }
}

function saleRateToken1(TwammPoolState state) pure returns (uint112 rate) {
    assembly ("memory-safe") {
        rate := shr(144, state)
    }
}
```

**File:** src/types/twammPoolState.sol (L46-56)
```text
function createTwammPoolState(uint32 _lastVirtualOrderExecutionTime, uint112 _saleRateToken0, uint112 _saleRateToken1)
    pure
    returns (TwammPoolState s)
{
    assembly ("memory-safe") {
        // s = (lastVirtualOrderExecutionTime) | (saleRateToken0 << 32) | (saleRateToken1 << 144)
        s := or(
            or(and(_lastVirtualOrderExecutionTime, 0xffffffff), shr(112, shl(144, _saleRateToken0))),
            shl(144, _saleRateToken1)
        )
    }
```

**File:** src/math/twamm.sol (L26-38)
```text
/// @dev Adds the sale rate delta to the saleRate and reverts if the result is greater than type(uint112).max
/// @dev Assumes saleRate <= type(uint112).max and saleRateDelta <= type(int112).max and saleRateDelta >= type(int112).min
function addSaleRateDelta(uint256 saleRate, int256 saleRateDelta) pure returns (uint256 result) {
    assembly ("memory-safe") {
        result := add(saleRate, saleRateDelta)
        // if any of the upper bits are non-zero, revert
        if shr(112, result) {
            // cast sig "SaleRateDeltaOverflow()"
            mstore(0, shl(224, 0xc902643d))
            revert(0, 4)
        }
    }
}
```

**File:** src/base/ExposedStorage.sol (L15-20)
```text
    function sload() external view {
        assembly ("memory-safe") {
            for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } { mstore(sub(i, 4), sload(calldataload(i))) }
            return(0, sub(calldatasize(), 4))
        }
    }
```
