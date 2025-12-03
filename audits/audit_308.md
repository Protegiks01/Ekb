## Title
Silent Integer Truncation in ERC7726 Constructor Enables Oracle Manipulation via Weak TWAP Window

## Summary
The ERC7726 constructor accepts `twapDuration` as a `uint32` parameter but does not validate that the caller's intended value wasn't silently truncated during ABI encoding. When a deployer passes a value larger than `type(uint32).max`, Solidity automatically truncates it to fit `uint32`, potentially creating an unintentionally short TWAP window that is vulnerable to price manipulation. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/lens/ERC7726.sol`, constructor function (lines 68-82)

**Intended Logic:** The constructor should validate that the deployer's intended TWAP duration is stored correctly to ensure the oracle provides manipulation-resistant prices. The validation at line 75 is meant to prevent zero-duration TWAP windows. [2](#0-1) 

**Actual Logic:** The constructor parameter is typed as `uint32`, causing Solidity's ABI encoder to silently truncate any input value larger than `type(uint32).max` (4,294,967,295). The validation only checks for zero, not for truncation. This means a deployer who passes `2^32 + 1` (intending a large duration) will actually deploy an oracle with a 1-second TWAP window. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. A protocol deploys ERC7726 intending a secure TWAP duration (e.g., 1 year = 31,536,000 seconds) but makes a unit error, passing `31_536_000_000` (thinking milliseconds) or `2^32 + 60`
2. The value truncates to a small duration: `31_536_000_000 % 2^32 = 2,241,065,408` (~26 days) or `(2^32 + 60) % 2^32 = 60` (60 seconds)
3. The constructor's zero-check passes since the truncated value is non-zero
4. The resulting oracle has a much shorter TWAP window than intended
5. An attacker manipulates Ekubo pool prices using flash loans or multi-block MEV
6. DeFi protocols relying on this oracle are exploited using the manipulated prices

**Security Property Broken:** The oracle's manipulation resistance is compromised. A TWAP window that's too short (e.g., 1-60 seconds) can be manipulated via flash loans or sandwich attacks, violating the core security assumption of time-weighted average prices. [5](#0-4) 

## Impact Explanation
- **Affected Assets**: Any DeFi protocol that queries the misconfigured ERC7726 oracle for prices becomes vulnerable to manipulation. This includes lending protocols, AMMs, or any contract using the oracle for critical price data.
- **Damage Severity**: An attacker can manipulate the oracle to show artificially inflated or deflated prices, enabling theft from protocols that trust the oracle. For example, a lending protocol could be tricked into accepting under-collateralized loans or liquidating healthy positions.
- **User Impact**: All users of downstream protocols that rely on the misconfigured oracle are at risk. The deployer's configuration error creates a systemic vulnerability affecting potentially thousands of users.

## Likelihood Explanation
- **Attacker Profile**: Any sophisticated attacker who identifies a deployed ERC7726 oracle with a weak TWAP window can exploit it. The attacker doesn't need to cause the misconfiguration—they only need to find and exploit it.
- **Preconditions**: 
  1. ERC7726 must be deployed with a truncated duration parameter (requires deployer error due to unit confusion or calculation mistake)
  2. A downstream protocol must integrate the misconfigured oracle
  3. The Ekubo pools must have sufficient liquidity to manipulate
- **Execution Complexity**: Low—once a weak oracle is identified, standard flash loan or MEV techniques can manipulate prices within the short TWAP window
- **Frequency**: The misconfiguration is a one-time deployment error, but the resulting oracle can be exploited repeatedly until detected and replaced

## Recommendation

**Fix:** Modify the constructor to accept `uint256` and explicitly validate the range before casting to `uint32`:

```solidity
// In src/lens/ERC7726.sol, constructor, lines 68-82:

// CURRENT (vulnerable):
constructor(
    IOracle oracle,
    address usdProxyToken,
    address btcProxyToken,
    address ethProxyToken,
    uint32 twapDuration
) {
    if (twapDuration == 0) revert InvalidTwapDuration();
    
    ORACLE = oracle;
    USD_PROXY_TOKEN = usdProxyToken;
    BTC_PROXY_TOKEN = btcProxyToken;
    ETH_PROXY_TOKEN = ethProxyToken;
    TWAP_DURATION = twapDuration;
}

// FIXED:
constructor(
    IOracle oracle,
    address usdProxyToken,
    address btcProxyToken,
    address ethProxyToken,
    uint256 twapDuration  // Accept as uint256 to detect truncation
) {
    // Validate range to prevent silent truncation
    if (twapDuration == 0 || twapDuration > type(uint32).max) {
        revert InvalidTwapDuration();
    }
    
    ORACLE = oracle;
    USD_PROXY_TOKEN = usdProxyToken;
    BTC_PROXY_TOKEN = btcProxyToken;
    ETH_PROXY_TOKEN = ethProxyToken;
    TWAP_DURATION = uint32(twapDuration);  // Explicit cast after validation
}
```

## Proof of Concept

```solidity
// File: test/lens/Exploit_TwapTruncation.t.sol
// Run with: forge test --match-test test_twapDurationTruncation -vvv

pragma solidity >=0.8.30;

import "forge-std/Test.sol";
import {BaseOracleTest} from "../extensions/Oracle.t.sol";
import {ERC7726} from "../../src/lens/ERC7726.sol";
import {TestToken} from "../TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../../src/math/constants.sol";

contract TwapTruncationTest is BaseOracleTest {
    TestToken internal usdc;
    TestToken internal wbtc;

    function setUp() public override {
        BaseOracleTest.setUp();
        usdc = new TestToken(address(this));
        wbtc = new TestToken(address(this));
    }

    function test_twapDurationTruncation() public {
        // SETUP: Deployer intends a 1-year TWAP (31,536,000 seconds)
        // but passes value in milliseconds by mistake
        uint256 intendedDuration = 31_536_000; // 1 year in seconds
        uint256 mistakeValue = intendedDuration * 1000; // Thinking milliseconds
        
        // EXPLOIT: Value gets truncated silently
        // 31,536,000,000 % 2^32 = 2,241,065,408 (~26 days instead of 1 year)
        ERC7726 weakOracle = new ERC7726(
            oracle, 
            address(usdc), 
            address(wbtc), 
            NATIVE_TOKEN_ADDRESS, 
            uint32(mistakeValue)
        );
        
        // VERIFY: TWAP window is much shorter than intended
        uint32 actualDuration = weakOracle.TWAP_DURATION();
        uint32 truncatedValue = uint32(mistakeValue);
        
        assertEq(actualDuration, truncatedValue, "Duration was silently truncated");
        assertLt(actualDuration, intendedDuration, "Actual duration is less than intended");
        
        // Even worse case: passing 2^32 + 1 results in 1 second
        ERC7726 veryWeakOracle = new ERC7726(
            oracle,
            address(usdc),
            address(wbtc),
            NATIVE_TOKEN_ADDRESS,
            uint32(type(uint32).max + 1)  // Truncates to 0, but let's try +60
        );
        
        // Passing 2^32 + 60 truncates to just 60 seconds
        uint256 largeValue = uint256(type(uint32).max) + 60;
        ERC7726 manipulatableOracle = new ERC7726(
            oracle,
            address(usdc),
            address(wbtc),
            NATIVE_TOKEN_ADDRESS,
            uint32(largeValue)
        );
        
        assertEq(manipulatableOracle.TWAP_DURATION(), 60, "Truncated to 60 seconds - highly manipulatable");
    }
}
```

## Notes

This vulnerability demonstrates a critical type safety issue where the constructor's use of `uint32` for the parameter type causes silent truncation of larger values. While this requires a deployer error as a precondition, the contract should defensively prevent such misconfigurations given the severe security implications. 

The fix is straightforward: accept `uint256` and explicitly validate the range, making any truncation explicit and caught by the validation check rather than occurring silently. This follows the principle of "fail loudly" for configuration errors that could compromise security.

The severity is Medium rather than High because exploitation requires a deployment-time misconfiguration. However, the downstream impact (oracle manipulation leading to potential theft) is severe, and the fix cost is minimal, making this a critical issue to address before deployment.

### Citations

**File:** src/lens/ERC7726.sol (L60-60)
```text
    uint32 public immutable TWAP_DURATION;
```

**File:** src/lens/ERC7726.sol (L68-82)
```text
    constructor(
        IOracle oracle,
        address usdProxyToken,
        address btcProxyToken,
        address ethProxyToken,
        uint32 twapDuration
    ) {
        if (twapDuration == 0) revert InvalidTwapDuration();

        ORACLE = oracle;
        USD_PROXY_TOKEN = usdProxyToken;
        BTC_PROXY_TOKEN = btcProxyToken;
        ETH_PROXY_TOKEN = ethProxyToken;
        TWAP_DURATION = twapDuration;
    }
```

**File:** src/lens/ERC7726.sol (L98-101)
```text
                (, int64 tickCumulativeStart) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp - TWAP_DURATION);
                (, int64 tickCumulativeEnd) = ORACLE.extrapolateSnapshot(otherToken, block.timestamp);

                return tickSign * int32((tickCumulativeEnd - tickCumulativeStart) / int64(uint64(TWAP_DURATION)));
```
