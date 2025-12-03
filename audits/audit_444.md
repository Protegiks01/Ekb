# Analysis Result

After thorough investigation of the `getPoolState()` function in TWAMMDataFetcher.sol, I have identified a legitimate implementation inconsistency in the timestamp calculation logic.

## Title
Integer Overflow in Unchecked `lastTimeReal` Calculation When uint32 Timestamp Wraps Around

## Summary
The `getPoolState()` function at line 70 performs a timestamp reconstruction calculation inside an unchecked block that differs from the correct implementation used elsewhere in the protocol. [1](#0-0) 

When `block.timestamp` crosses the uint32 boundary (February 2106), the missing bit-masking causes integer underflow that produces an incorrect `lastTimeReal` value, leading to wrong time slot queries and incorrect pool state data.

## Impact
**Severity**: Low/QA

## Finding Description

**Location:** `src/lens/TWAMMDataFetcher.sol`, function `getPoolState()`, line 70

**Intended Logic:** The code should reconstruct the full 64-bit timestamp from the 32-bit `lastVirtualOrderExecutionTime` by computing the time delta and subtracting it from the current timestamp, correctly handling uint32 wraparound scenarios.

**Actual Logic:** The calculation at line 70 uses: [1](#0-0) 

This differs from the correct implementation in the protocol: [2](#0-1) 

The critical difference is that the correct assembly implementation includes `and(..., 0xffffffff)` to mask the result to 32 bits AFTER the subtraction, which properly handles underflow when the uint32 timestamp wraps around. The buggy version lacks this masking.

**Exploitation Path:**
1. Wait until `block.timestamp` crosses the uint32 boundary (~February 2106)
2. A pool has `lastVirtualOrderExecutionTime` set to a value before the boundary (e.g., `0xFFFFFFF0`)
3. Call `getPoolState()` on the TWAMMDataFetcher contract
4. The calculation `uint32(block.timestamp) - lastVirtualOrderExecutionTime` underflows in unchecked mode to a huge uint256 value
5. Then `block.timestamp - (huge_value)` underflows again, producing an incorrect `lastTimeReal`
6. `getAllValidFutureTimes(lastTimeReal)` computes wrong time slots to query [3](#0-2) 

7. Wrong `TimeInfo` storage slots are queried, returning incorrect `saleRateDeltas` data [4](#0-3) 

**Security Property Broken:** Data integrity - the lens contract returns incorrect pool state information that could mislead off-chain systems, UIs, or aggregators relying on this data.

## Impact Explanation

- **Affected Assets**: No direct assets at risk. This affects off-chain data consumers (UIs, aggregators, bots) that query TWAMM pool state via this lens contract.
- **Damage Severity**: Off-chain systems receive incorrect `saleRateDeltas` information, potentially leading to wrong pricing decisions or UI displays. However, no on-chain funds are directly at risk since this is a view-only lens contract.
- **User Impact**: Users of frontends or tools that call this data fetcher would see incorrect information about future TWAMM order executions.

## Likelihood Explanation

- **Attacker Profile**: Not directly exploitable by an attacker. The issue manifests naturally when timestamps exceed uint32 range.
- **Preconditions**: 
  - Current timestamp must exceed `type(uint32).max` (~February 2106)
  - Pool must have been initialized with orders placed before the uint32 boundary
- **Execution Complexity**: Automatic - the bug triggers on any call to `getPoolState()` after February 2106
- **Frequency**: Would affect all calls to the function after the timestamp boundary is crossed

## Recommendation

Apply the same bit-masking pattern used in the correct implementation: [1](#0-0) 

**Fix:**
```solidity
// Change line 70 from:
uint64 lastTimeReal = uint64(block.timestamp - (uint32(block.timestamp) - lastVirtualOrderExecutionTime));

// To match the correct implementation pattern:
uint64 lastTimeReal = uint64(block.timestamp - ((uint32(block.timestamp) - lastVirtualOrderExecutionTime) & 0xffffffff));
```

This ensures the time delta is properly masked to 32 bits after the subtraction, correctly handling wraparound scenarios.

## Notes

**Severity Justification**: While this is a real implementation bug with a concrete manifestation scenario, the severity is assessed as Low/QA because:

1. **No Direct Fund Loss**: TWAMMDataFetcher is a lens contract (view functions only) with no state-changing capabilities or fund custody [5](#0-4) 

2. **Distant Timeframe**: The issue only manifests after February 2106 when Unix timestamps exceed uint32.max (4,294,967,295 seconds)

3. **Correct Implementation Exists**: The actual TWAMM extension uses the correct timestamp calculation [2](#0-1) , so on-chain protocol operations are unaffected

4. **Limited Scope**: Only affects off-chain data consumers, not protocol invariants or fund security

5. **In-Scope but Low Impact**: While TWAMMDataFetcher is listed in scope [6](#0-5) , the Code4rena severity framework classifies this as Low/QA since it doesn't involve theft, fund lock, or direct user harm.

The finding is valid and should be corrected for code consistency and future-proofing, but does not meet the threshold for High or Medium severity in the HM pool per the contest rules.

### Citations

**File:** src/lens/TWAMMDataFetcher.sol (L54-116)
```text
contract TWAMMDataFetcher is UsesCore {
    using CoreLib for *;
    using TWAMMLib for *;

    TWAMM public immutable TWAMM_EXTENSION;

    constructor(ICore core, TWAMM _twamm) UsesCore(core) {
        TWAMM_EXTENSION = _twamm;
    }

    function getPoolState(PoolKey memory poolKey) public view returns (PoolState memory state) {
        unchecked {
            (SqrtRatio sqrtRatio, int32 tick, uint128 liquidity) = CORE.poolState(poolKey.toPoolId()).parse();
            (uint32 lastVirtualOrderExecutionTime, uint112 saleRateToken0, uint112 saleRateToken1) =
                TWAMM_EXTENSION.poolState(poolKey.toPoolId()).parse();

            uint64 lastTimeReal = uint64(block.timestamp - (uint32(block.timestamp) - lastVirtualOrderExecutionTime));

            uint64[] memory allValidTimes = getAllValidFutureTimes(lastTimeReal);

            PoolId poolId = poolKey.toPoolId();
            StorageSlot[] memory timeInfoSlots = new StorageSlot[](allValidTimes.length);

            for (uint256 i = 0; i < timeInfoSlots.length; i++) {
                timeInfoSlots[i] = TWAMMStorageLayout.poolTimeInfosSlot(poolId, allValidTimes[i]);
            }

            (bool success, bytes memory result) =
                address(TWAMM_EXTENSION).staticcall(abi.encodePacked(IExposedStorage.sload.selector, timeInfoSlots));
            assert(success);

            uint256 countNonZero = 0;
            TimeSaleRateInfo[] memory saleRateDeltas = new TimeSaleRateInfo[](timeInfoSlots.length);

            for (uint256 i = 0; i < allValidTimes.length; i++) {
                TimeInfo timeInfo;
                assembly ("memory-safe") {
                    timeInfo := mload(add(result, mul(add(i, 1), 32)))
                }

                (uint32 numOrders, int112 saleRateDeltaToken0, int112 saleRateDeltaToken1) = timeInfo.parse();

                if (numOrders != 0) {
                    saleRateDeltas[countNonZero++] =
                        TimeSaleRateInfo(allValidTimes[i], saleRateDeltaToken0, saleRateDeltaToken1);
                }
            }

            assembly ("memory-safe") {
                mstore(saleRateDeltas, countNonZero)
            }

            state = PoolState({
                sqrtRatio: sqrtRatio,
                tick: tick,
                liquidity: liquidity,
                lastVirtualOrderExecutionTime: lastTimeReal,
                saleRateToken0: saleRateToken0,
                saleRateToken1: saleRateToken1,
                saleRateDeltas: saleRateDeltas
            });
        }
    }
```

**File:** src/types/twammPoolState.sol (L20-24)
```text
function realLastVirtualOrderExecutionTime(TwammPoolState state) view returns (uint256 time) {
    assembly ("memory-safe") {
        time := sub(timestamp(), and(sub(and(timestamp(), 0xffffffff), and(state, 0xffffffff)), 0xffffffff))
    }
}
```

**File:** scope.txt (L39-39)
```text
./src/lens/TWAMMDataFetcher.sol
```
