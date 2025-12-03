## Title
ERC7726 Oracle Dependency Creates Single Point of Failure for Dependent Protocols Without Error Handling

## Summary
The `ERC7726.getQuote()` function has a hard dependency on the Oracle extension with zero error handling around `extrapolateSnapshot()` calls. When Oracle pools are uninitialized, have insufficient history, or encounter bugs, all price queries revert, creating a cascading failure for dependent protocols that lack fallback oracles.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/ERC7726.sol` - functions `getQuote()` (line 138-154) and `getAverageTick()` (line 91-112)

**Intended Logic:** The ERC7726 contract should provide manipulation-resistant price quotes using time-weighted average prices from the Oracle extension. External protocols integrate with `getQuote()` to obtain reliable price data for their operations (liquidations, position management, swaps).

**Actual Logic:** The contract unconditionally calls `ORACLE.extrapolateSnapshot()` without any error handling mechanism. When the Oracle extension cannot provide data, the entire transaction reverts, blocking all dependent protocols that don't implement their own fallback oracles. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. A DeFi protocol integrates ERC7726 for price feeds without implementing a fallback oracle
2. The protocol queries a cross-pair price (e.g., USDC/DAI) via `getQuote()`
3. `getAverageTick()` performs cross-pair calculation requiring both USDC/ETH and DAI/ETH Oracle pools
4. One intermediate Oracle pool (e.g., DAI/ETH) was never initialized or has insufficient history
5. `extrapolateSnapshot()` calls `searchRangeForPrevious()` which reverts with `NoPreviousSnapshotExists` when count == 0 [3](#0-2) 

6. The entire `getQuote()` transaction reverts, blocking all operations in the dependent protocol that rely on this price feed

**Security Property Broken:** Extension Isolation - While the README states "extension failures should not freeze pools or lock user capital," the Oracle extension failure effectively freezes all price-dependent operations in external protocols that integrate with ERC7726, creating a broader system-wide DOS vulnerability.

## Impact Explanation
- **Affected Assets**: Any external protocol integrating ERC7726 for price feeds without implementing fallback oracles experiences complete DOS of price query functionality
- **Damage Severity**: While no direct fund theft occurs, critical operations like liquidations, position management, or automated market making can be blocked. In cross-pair scenarios where even one of two required Oracle pools is missing, the entire price query fails.
- **User Impact**: All users of dependent protocols that rely on ERC7726 price feeds are affected whenever querying tokens without initialized Oracle pools or during the TWAP_DURATION window after pool creation

## Likelihood Explanation
- **Attacker Profile**: Not an active attack - this is a design flaw that manifests whenever normal users query prices for tokens without Oracle pools
- **Preconditions**: 
  - A token doesn't have an Oracle pool initialized (requires native token pairing, zero fees, full-range configuration per Oracle requirements) [4](#0-3) 
  
  - Cross-pair calculations require BOTH intermediate pools to exist
  - Insufficient history (less than TWAP_DURATION) after pool initialization [5](#0-4) 

- **Execution Complexity**: Single call to `getQuote()` - no complex setup required
- **Frequency**: Occurs on every query attempt until Oracle pools are properly initialized with sufficient history

## Recommendation

Implement graceful error handling with availability checks before querying the Oracle:

```solidity
// In src/lens/ERC7726.sol, function getAverageTick, add pre-checks:

function getAverageTick(address baseToken, address quoteToken) private view returns (int32 tick) {
    unchecked {
        bool baseIsOracleToken = baseToken == NATIVE_TOKEN_ADDRESS;
        if (baseIsOracleToken || quoteToken == NATIVE_TOKEN_ADDRESS) {
            (int32 tickSign, address otherToken) =
                baseIsOracleToken ? (int32(1), quoteToken) : (int32(-1), baseToken);

            // NEW: Check if Oracle has sufficient data before querying
            uint32 maxPeriod = OracleLib.getMaximumObservationPeriod(ORACLE, otherToken);
            if (maxPeriod < TWAP_DURATION) {
                revert InsufficientOracleHistory(otherToken, maxPeriod, TWAP_DURATION);
            }

            (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
            (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

            return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
        } else {
            // NEW: For cross-pair, check BOTH intermediate pools first
            uint32 basePeriod = OracleLib.getMaximumObservationPeriod(ORACLE, baseToken);
            uint32 quotePeriod = OracleLib.getMaximumObservationPeriod(ORACLE, quoteToken);
            
            if (basePeriod < TWAP_DURATION) {
                revert InsufficientOracleHistory(baseToken, basePeriod, TWAP_DURATION);
            }
            if (quotePeriod < TWAP_DURATION) {
                revert InsufficientOracleHistory(quoteToken, quotePeriod, TWAP_DURATION);
            }

            int32 baseTick = getAverageTick(NATIVE_TOKEN_ADDRESS, baseToken);
            int32 quoteTick = getAverageTick(NATIVE_TOKEN_ADDRESS, quoteToken);

            return int32(
                FixedPointMathLib.min(MAX_TICK, FixedPointMathLib.max(MIN_TICK, int256(quoteTick - baseTick)))
            );
        }
    }
}

// Add custom error for better UX:
error InsufficientOracleHistory(address token, uint32 availablePeriod, uint32 requiredPeriod);
```

Alternative mitigation: Implement a view function for dependent protocols to check data availability before calling `getQuote()`:

```solidity
/// @notice Check if sufficient Oracle data exists for a token pair
/// @param baseToken The base token address
/// @param quoteToken The quote token address
/// @return isAvailable True if getQuote() will succeed
function isQuoteAvailable(address baseToken, address quoteToken) external view returns (bool isAvailable) {
    address normalizedBase = normalizeAddress(baseToken);
    address normalizedQuote = normalizeAddress(quoteToken);
    
    if (normalizedBase == normalizedQuote) return true;
    
    if (normalizedBase == NATIVE_TOKEN_ADDRESS || normalizedQuote == NATIVE_TOKEN_ADDRESS) {
        address otherToken = normalizedBase == NATIVE_TOKEN_ADDRESS ? normalizedQuote : normalizedBase;
        return OracleLib.getMaximumObservationPeriod(ORACLE, otherToken) >= TWAP_DURATION;
    } else {
        return OracleLib.getMaximumObservationPeriod(ORACLE, normalizedBase) >= TWAP_DURATION
            && OracleLib.getMaximumObservationPeriod(ORACLE, normalizedQuote) >= TWAP_DURATION;
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_OracleDependencyFailure.t.sol
// Run with: forge test --match-test test_OracleDependencyFailure -vvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "../extensions/Oracle.t.sol";
import {ERC7726, IERC7726_ETH_ADDRESS} from "../../src/lens/ERC7726.sol";
import {TestToken} from "../TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../../src/math/constants.sol";
import {IOracle} from "../../src/interfaces/extensions/IOracle.sol";

contract Exploit_OracleDependencyFailure is BaseOracleTest {
    ERC7726 internal erc;
    TestToken internal usdc;
    TestToken internal dai;

    function setUp() public override {
        BaseOracleTest.setUp();
        usdc = new TestToken(address(this));
        dai = new TestToken(address(this));
        erc = new ERC7726(oracle, address(usdc), address(0), NATIVE_TOKEN_ADDRESS, 60);
    }

    function test_OracleDependencyFailure() public {
        // SETUP: Initialize USDC Oracle pool with sufficient history
        oracle.expandCapacity(address(usdc), 10);
        createOraclePool(address(usdc), 0);
        advanceTime(60);

        // Verify USDC/ETH quote works
        uint256 usdcToEth = erc.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        assertGt(usdcToEth, 0, "USDC/ETH quote should work");

        // EXPLOIT: Query cross-pair USDC/DAI without DAI Oracle pool
        // This represents a dependent protocol trying to get a price feed
        // but DAI's Oracle pool was never initialized
        
        vm.expectRevert(); // Will revert with NoPreviousSnapshotExists
        erc.getQuote(1e18, address(usdc), address(dai));

        // VERIFY: The revert proves that dependent protocols without fallback
        // oracles will experience complete DOS when Oracle data is unavailable
        // This is especially problematic for cross-pair calculations where
        // BOTH intermediate pools (USDC/ETH and DAI/ETH) must exist
    }

    function test_CrossPairFailureWithOnePool() public {
        // SETUP: Initialize only USDC Oracle pool
        oracle.expandCapacity(address(usdc), 10);
        createOraclePool(address(usdc), 0);
        advanceTime(60);

        // DAI Oracle pool is NOT initialized (count = 0)

        // EXPLOIT: Attempt cross-pair calculation
        // getAverageTick will try to calculate:
        // 1. getAverageTick(ETH, USDC) - succeeds
        // 2. getAverageTick(ETH, DAI) - fails because no Oracle pool exists
        
        vm.expectRevert(
            abi.encodeWithSelector(
                IOracle.NoPreviousSnapshotExists.selector,
                address(dai),
                block.timestamp - 60
            )
        );
        erc.getQuote(1e18, address(usdc), address(dai));

        // VERIFY: This demonstrates the cascading failure:
        // - Dependent protocol queries USDC/DAI price
        // - ERC7726 tries cross-pair calculation via ETH
        // - One intermediate pool (DAI/ETH) doesn't exist
        // - Entire transaction reverts, blocking protocol operations
    }

    function test_InsufficientHistoryFailure() public {
        // SETUP: Create Oracle pool but don't advance time
        oracle.expandCapacity(address(usdc), 10);
        createOraclePool(address(usdc), 0);
        
        // NO time advancement - history < TWAP_DURATION (60 seconds)

        // EXPLOIT: Query immediately after pool creation
        vm.expectRevert(); // Will revert due to insufficient history
        erc.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);

        // VERIFY: Dependent protocols cannot get prices during the TWAP_DURATION
        // window after Oracle pool initialization, causing temporary DOS
    }
}
```

## Notes

This vulnerability represents a **design limitation** rather than a traditional exploit, but it has **significant real-world impact** for protocol integrations:

1. **Cross-Pair Amplification**: The issue is particularly severe for cross-pair calculations (tokens not paired with native token) because it requires TWO Oracle pools to exist. If either intermediate pool is missing, the entire query fails. [6](#0-5) 

2. **Oracle Pool Requirements**: The Oracle extension enforces strict requirements (native token pairing, zero fees, full-range), making it non-trivial to initialize pools for all tokens. [4](#0-3) 

3. **Helper Methods Exist But Unused**: The codebase provides `OracleLib.getMaximumObservationPeriod()` and `OracleLib.getEarliestSnapshotTimestamp()` for checking data availability, but ERC7726 doesn't utilize them. [7](#0-6) 

4. **Integration Burden**: The burden of implementing fallback oracles falls entirely on dependent protocols. Without clear documentation or helper methods, integrators may not realize their systems are vulnerable to Oracle unavailability until production deployment.

5. **Not a Known Issue**: While the test suite demonstrates that reverts occur with insufficient history, the README does not list this as a known limitation or warn integrators about the lack of fallback mechanisms in ERC7726.

### Citations

**File:** src/lens/ERC7726.sol (L98-99)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);
```

**File:** src/lens/ERC7726.sol (L102-109)
```text
            } else {
                int32 baseTick = getAverageTick(NATIVE_TOKEN_ADDRESS, baseToken);
                int32 quoteTick = getAverageTick(NATIVE_TOKEN_ADDRESS, quoteToken);

                return
                    int32(
                        FixedPointMathLib.min(MAX_TICK, FixedPointMathLib.max(MIN_TICK, int256(quoteTick - baseTick)))
                    );
```

**File:** src/lens/ERC7726.sol (L147-147)
```text
        int32 tick = getAverageTick({baseToken: normalizedBase, quoteToken: normalizedQuote});
```

**File:** src/extensions/Oracle.sol (L155-157)
```text
        if (key.token0 != NATIVE_TOKEN_ADDRESS) revert PairsWithNativeTokenOnly();
        if (key.config.fee() != 0) revert FeeMustBeZero();
        if (!key.config.isFullRange()) revert FullRangePoolOnly();
```

**File:** src/extensions/Oracle.sol (L256-257)
```text
            if (logicalMin >= logicalMaxExclusive) {
                revert NoPreviousSnapshotExists(token, time);
```

**File:** test/lens/ERC7726.t.sol (L39-49)
```text
    function test_getQuote_insufficient_history(uint32 time) public {
        time = uint32(bound(time, 0, type(uint32).max - 1));
        ERC7726 longTwapOracle =
            new ERC7726(oracle, address(usdc), address(wbtc), NATIVE_TOKEN_ADDRESS, uint32(time + 1));

        oracle.expandCapacity(address(usdc), 10);
        createOraclePool(address(usdc), 0);

        vm.expectRevert();
        longTwapOracle.getQuote(1e18, address(usdc), address(0)); // ETH quote requires oracle call
    }
```

**File:** src/libraries/OracleLib.sol (L48-54)
```text
    function getMaximumObservationPeriod(IOracle oracle, address token) internal view returns (uint32) {
        unchecked {
            uint256 earliest = getEarliestSnapshotTimestamp(oracle, token);
            if (earliest > block.timestamp) return 0;
            return uint32(block.timestamp - earliest);
        }
    }
```
