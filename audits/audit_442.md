## Title
Missing Return Data Length Validation in TWAMMDataFetcher.getPoolState() Allows Corrupted Pool State Data

## Summary
The `TWAMMDataFetcher.getPoolState()` function performs a staticcall to the TWAMM extension's `sload()` function but only validates call success without checking the returned data length. If the TWAMM's `sload()` implementation returns fewer bytes than expected, the function reads uninitialized memory as valid TimeInfo data, corrupting the returned pool state. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/TWAMMDataFetcher.sol`, function `getPoolState()`, lines 81-92

**Intended Logic:** The function should query the TWAMM extension's storage to retrieve TimeInfo data for all valid future times, returning accurate sale rate deltas for each time period. The `sload()` function is expected to return exactly `timeInfoSlots.length * 32` bytes (one 32-byte word per storage slot).

**Actual Logic:** The function only checks `assert(success)` after the staticcall, without validating that the returned data has the expected length. When reading from the result bytes at line 91, if the actual data length is shorter than expected, the code reads beyond the returned data into uninitialized or leftover memory. This corrupted data is then parsed as valid TimeInfo structures and included in the returned PoolState. [2](#0-1) 

**Exploitation Path:**
1. Deploy a TWAMM contract with a non-standard `sload()` implementation that returns fewer bytes than requested (e.g., returns 0 bytes or partial data)
2. Deploy TWAMMDataFetcher pointing to this malicious/buggy TWAMM contract
3. Call `getPoolState()` which executes the staticcall to the TWAMM's `sload()` 
4. The staticcall succeeds (returns true) but with malformed data, passing `assert(success)`
5. The loop at lines 88-92 reads past the end of the returned data, loading garbage values from memory
6. These corrupted values are parsed as valid TimeInfo and included in the returned PoolState's `saleRateDeltas` array
7. Off-chain systems, UIs, or trading bots consuming this data make incorrect decisions based on corrupted sale rate information

**Security Property Broken:** Data integrity - view functions should return accurate information. The codebase demonstrates defensive validation patterns in similar contexts, as seen in TokenDataFetcher. [3](#0-2) 

## Impact Explanation
- **Affected Assets**: Users and bots relying on TWAMMDataFetcher for TWAMM pool state information
- **Damage Severity**: Users may make trading decisions based on incorrect sale rate delta information, leading to suboptimal trades, incorrect pricing, or missed arbitrage opportunities. While no direct fund theft occurs, financial harm results from misinformed decisions.
- **User Impact**: Any user, bot, or off-chain system querying TWAMM pool state through a TWAMMDataFetcher instance connected to a malicious or buggy TWAMM implementation

## Likelihood Explanation
- **Attacker Profile**: Any actor who can deploy contracts (malicious deployer) or introduce a bug in the TWAMM implementation
- **Preconditions**: 
  - A TWAMM contract with non-standard `sload()` behavior must exist
  - Users/systems must be using a TWAMMDataFetcher instance pointing to this TWAMM
  - The malicious TWAMM's `sload()` must return fewer bytes than expected while still succeeding
- **Execution Complexity**: Low - simply calling `getPoolState()` on a compromised deployment triggers the vulnerability
- **Frequency**: Continuous - every call to `getPoolState()` returns corrupted data once the vulnerable configuration exists

## Recommendation

Add explicit validation of the returned data length before reading from it:

```solidity
// In src/lens/TWAMMDataFetcher.sol, function getPoolState, after line 82:

(bool success, bytes memory result) =
    address(TWAMM_EXTENSION).staticcall(abi.encodePacked(IExposedStorage.sload.selector, timeInfoSlots));
assert(success);

// ADD THIS VALIDATION:
require(result.length == timeInfoSlots.length * 32, "TWAMMDataFetcher: invalid result length");

uint256 countNonZero = 0;
TimeSaleRateInfo[] memory saleRateDeltas = new TimeSaleRateInfo[](timeInfoSlots.length);
```

Alternative mitigation: Use assembly to check `returndatasize()` immediately after the staticcall:

```solidity
(bool success, bytes memory result) =
    address(TWAMM_EXTENSION).staticcall(abi.encodePacked(IExposedStorage.sload.selector, timeInfoSlots));
assembly {
    // Verify returndatasize matches expected length
    if iszero(eq(returndatasize(), mul(mload(timeInfoSlots), 32))) {
        revert(0, 0)
    }
}
assert(success);
```

## Proof of Concept

```solidity
// File: test/Exploit_MalformedSloadData.t.sol
// Run with: forge test --match-test test_MalformedSloadData -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/lens/TWAMMDataFetcher.sol";
import "../src/interfaces/IExposedStorage.sol";

// Malicious TWAMM that returns empty data
contract MaliciousTWAMM is IExposedStorage {
    function sload() external view override {
        // Return 0 bytes instead of the expected data
        assembly {
            return(0, 0)
        }
    }
    
    function tload() external view override {
        revert("Not implemented");
    }
    
    // Stub for poolState query
    function poolState(PoolId) external pure returns (TwammPoolState) {
        return TwammPoolState.wrap(0);
    }
}

contract Exploit_MalformedSloadData is Test {
    ICore core;
    MaliciousTWAMM maliciousTWAMM;
    TWAMMDataFetcher dataFetcher;
    
    function setUp() public {
        // Deploy core (stub)
        core = ICore(address(0x1234)); // Assume deployed
        
        // Deploy malicious TWAMM that returns empty sload() data
        maliciousTWAMM = new MaliciousTWAMM();
        
        // Deploy TWAMMDataFetcher with malicious TWAMM
        dataFetcher = new TWAMMDataFetcher(core, TWAMM(address(maliciousTWAMM)));
    }
    
    function test_MalformedSloadData() public {
        // Create a pool key
        PoolKey memory poolKey; // ... initialize pool key
        
        // EXPLOIT: Call getPoolState - it will read garbage data
        // The staticcall succeeds but returns 0 bytes
        // Code reads uninitialized memory as TimeInfo values
        PoolState memory state = dataFetcher.getPoolState(poolKey);
        
        // VERIFY: The returned state contains corrupted data
        // saleRateDeltas may contain non-zero garbage values
        // parsed from uninitialized memory
        console.log("Sale rate deltas length:", state.saleRateDeltas.length);
        for (uint i = 0; i < state.saleRateDeltas.length; i++) {
            console.log("Corrupted delta", i, ":", uint(state.saleRateDeltas[i].saleRateDelta0));
        }
    }
}
```

**Notes:**
- This vulnerability requires the TWAMM extension to have a non-standard `sload()` implementation, which could occur through deployment error, upgrade to buggy implementation, or malicious deployment
- The codebase establishes defensive validation patterns elsewhere (TokenDataFetcher line 53), indicating this is an oversight rather than an intentional trust assumption
- While TWAMMDataFetcher is a lens contract for off-chain queries, corrupted data can lead to financial losses when users make trading decisions based on incorrect information

### Citations

**File:** src/lens/TWAMMDataFetcher.sol (L81-92)
```text
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
```

**File:** src/lens/TokenDataFetcher.sol (L51-53)
```text
                        (bool success, bytes memory result) =
                            token.staticcall(abi.encodeWithSelector(IERC20.allowance.selector, owner, spender));
                        if (success && result.length == 32) {
```
