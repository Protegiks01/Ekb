# NoVulnerability found for this question.

After conducting a thorough investigation of the poolPositions() assembly block and tracing all related code paths, I found no exploitable vulnerability related to dirty bits in the unpacking operations.

## Analysis Summary

**Storage Format** (confirmed): [1](#0-0) 

The Position struct is packed in storage as:
- Upper 128 bits: `liquidity` (uint128)
- Lower 128 bits: `extraData` (bytes16)

**Unpacking Operations** (the questioned code): [2](#0-1) 

The assembly performs:
- `shl(128, v0)`: Shifts lower 128 bits (extraData) to upper 128 bits, zeros in lower → correct for bytes16 memory layout (left-aligned)
- `shr(128, v0)`: Shifts upper 128 bits (liquidity) to lower 128 bits, zeros in upper → correct for uint128 memory layout (right-aligned)

**Why Dirty Bits Cannot Exist:**

1. **EVM Guarantees**: The SHL and SHR opcodes always fill with zeros by EVM specification. This is not implementation-dependent but a fundamental guarantee of the instruction set.

2. **Storage Write Protection**: Position storage is only written through two controlled paths:
   - [3](#0-2) 
   - [1](#0-0) 

   Both properly maintain field boundaries using Solidity's struct packing or careful bit manipulation.

3. **Fee Calculation Safety**: [4](#0-3) 

   The fees() function loads liquidity from position+0x20, which contains the result of `shr(128, v0)`. Since SHR guarantees zeros in upper 128 bits, the multiplication in fullMulDivN receives a clean uint256 value.

4. **Test Validation**: [5](#0-4) 

   Tests verify that extraData and liquidity are correctly set and retrieved across all scenarios, including before/after position creation.

The premise "if v0 contains dirty bits outside the expected fields" is impossible because v0 is exactly 256 bits containing two 128-bit fields with no bits "outside" these fields, and the shift operations mathematically guarantee clean results.

**Notes:**
- The unpacking is mathematically correct and verified by extensive tests
- Storage layout is consistent between writes (setExtraData, updatePosition) and reads (poolPositions)
- No attack vector exists to inject dirty bits into the storage or memory representation

### Citations

**File:** src/Core.sol (L430-435)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
```

**File:** src/Core.sol (L451-460)
```text
    function setExtraData(PoolId poolId, PositionId positionId, bytes16 _extraData) external {
        StorageSlot firstSlot = CoreStorageLayout.poolPositionsSlot(poolId, msg.sender, positionId);

        bytes32 extraData;
        assembly ("memory-safe") {
            extraData := _extraData
        }

        firstSlot.store(((firstSlot.load() >> 128) << 128) | (extraData >> 128));
    }
```

**File:** src/libraries/CoreLib.sol (L69-72)
```text
        assembly ("memory-safe") {
            mstore(position, shl(128, v0))
            mstore(add(position, 0x20), shr(128, v0))
        }
```

**File:** src/types/position.sol (L40-50)
```text
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
```

**File:** test/PositionExtraData.t.sol (L82-103)
```text
    function test_setExtraData_position_does_not_exist(PoolId poolId, PositionId positionId, bytes16 extraData) public {
        locker.setExtraData(poolId, positionId, extraData);
        Position memory position = core.poolPositions(poolId, address(locker), positionId);
        assertEq(position.liquidity, 0);
        assertEq(position.extraData, extraData);
        assertEq(position.feesPerLiquidityInsideLast.value0, 0);
        assertEq(position.feesPerLiquidityInsideLast.value1, 0);
    }

    function test_setExtraData_before_position_created(uint128 liquidity, bytes16 extraData) public {
        liquidity = uint128(bound(liquidity, 1, type(uint64).max));
        PositionId positionId = createPositionId({_salt: bytes24(0), _tickLower: -60, _tickUpper: 60});

        locker.setExtraData(poolKey.toPoolId(), positionId, extraData);

        locker.doLock(abi.encode(poolKey, positionId, int128(liquidity)));

        Position memory position = core.poolPositions(poolKey.toPoolId(), address(locker), positionId);

        assertEq(position.extraData, extraData, "extraData should be zero at create");
        assertEq(position.liquidity, liquidity, "liquidity should equal what we set");
    }
```
