## Title
Ambiguous Year Representation in TokenWrapper Symbols Enables Deceptive Token Creation

## Summary
The `toQuarter()` function in `TimeDescriptor.sol` uses a 2-digit year format (`year % 100`) to generate token symbols, causing years that are 100 years apart to display identically. This allows malicious actors to deploy TokenWrapper contracts with unlock times centuries in the future (e.g., year 2125) that display symbols indistinguishable from near-term unlocks (e.g., year 2025), deceiving users into acquiring essentially worthless time-locked tokens.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- `src/TokenWrapper.sol` (function `symbol()`, line 87) [1](#0-0) 

- `src/libraries/TimeDescriptor.sol` (function `toQuarter()`, lines 26-34) [2](#0-1) 

**Intended Logic:** The symbol should provide a human-readable identifier indicating when the wrapped tokens unlock, helping users quickly assess the token's liquidity timeline.

**Actual Logic:** The `toQuarter()` function applies modulo 100 to the year (`year = year % 100`), creating a 2-digit year representation that wraps every century. This causes:
- Year 2025 → symbol "gTOKEN-25Q1"
- Year 2125 → symbol "gTOKEN-25Q1" (identical)
- Year 2100 → symbol "gTOKEN-00Q1" (appears like year 2000)
- Year 2200 → symbol "gTOKEN-00Q1" (identical to 2100)

**Exploitation Path:**
1. Attacker deploys TokenWrapper via TokenWrapperFactory with `unlockTime` set to January 2125 (timestamp: 4891449600) [3](#0-2) 

2. The deployed TokenWrapper displays symbol "gTOKEN-25Q1", identical to a token unlocking in 2025

3. Attacker lists these tokens on DEXes or offers them in trades, where users primarily see the symbol

4. Victims see "gTOKEN-25Q1" and assume tokens unlock in 2025 (near-term liquidity), purchasing or accepting them at inappropriate prices

5. Upon attempting to unwrap, victims discover tokens are locked for 100+ years, rendering them effectively worthless [4](#0-3) 

**Security Property Broken:** While not violating a core protocol invariant, this enables **user deception leading to financial loss** through ambiguous display of critical token parameters.

## Impact Explanation

- **Affected Assets**: Any ERC20 token wrapped with far-future unlock times deployed via TokenWrapperFactory

- **Damage Severity**: Users purchasing these tokens expect near-term liquidity but receive tokens locked for 100+ years. The tokens become practically worthless as the unlock time exceeds any reasonable investment horizon. In secondary markets where symbols are the primary identifier (DEX interfaces, wallets, aggregators), users have no indication of the true unlock century.

- **User Impact**: Any user trading wrapped tokens based on symbol alone. This includes:
  - DEX traders viewing token lists
  - Wallet users seeing balances by symbol
  - Aggregators and price feeds displaying symbols
  - OTC traders negotiating by ticker

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user can exploit this by calling `TokenWrapperFactory.deployWrapper()` with an arbitrary `unlockTime` parameter. No special permissions required. [5](#0-4) 

- **Preconditions**: None. The TokenWrapperFactory has no validation on `unlockTime` values.

- **Execution Complexity**: Single transaction to deploy, followed by normal token distribution/trading activities.

- **Frequency**: Can be exploited unlimited times, creating multiple deceptive wrappers for different tokens.

## Recommendation

Add a 4-digit year format or include century information in the symbol to eliminate ambiguity:

```solidity
// In src/libraries/TimeDescriptor.sol, function toQuarter, lines 26-34:

// CURRENT (vulnerable):
function toQuarter(uint256 unlockTime) pure returns (string memory quarterLabel) {
    (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(unlockTime);
    year = year % 100;  // Creates ambiguity
    string memory shortenedYearStr = LibString.toString(year);
    unchecked {
        quarterLabel = string.concat(year < 10 ? "0" : "", shortenedYearStr, "Q", LibString.toString(1 + (month - 1) / 3));
    }
}

// FIXED (Option 1 - Full 4-digit year):
function toQuarter(uint256 unlockTime) pure returns (string memory quarterLabel) {
    (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(unlockTime);
    string memory yearStr = LibString.toString(year); // Use full year
    unchecked {
        quarterLabel = string.concat(yearStr, "Q", LibString.toString(1 + (month - 1) / 3));
    }
}

// FIXED (Option 2 - Add validation in factory):
// In TokenWrapperFactory.sol, add reasonable bounds:
function deployWrapper(IERC20 underlyingToken, uint256 unlockTime) external returns (TokenWrapper tokenWrapper) {
    require(unlockTime > block.timestamp, "Unlock must be in future");
    require(unlockTime < block.timestamp + 50 years, "Unlock time too far in future"); // Prevent century ambiguity
    // ... rest of function
}
```

**Alternative mitigation**: Add clear warnings in documentation and UI integrations that symbols use 2-digit years and should not be solely relied upon for unlock time verification.

## Proof of Concept

```solidity
// File: test/Exploit_AmbiguousYearSymbol.t.sol
// Run with: forge test --match-test test_AmbiguousYearSymbol -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/TokenWrapper.sol";
import "../src/TokenWrapperFactory.sol";
import "../src/interfaces/ICore.sol";
import "./TestToken.sol";

contract Exploit_AmbiguousYearSymbol is Test {
    TokenWrapperFactory factory;
    ICore core;
    TestToken underlying;
    
    function setUp() public {
        // Deploy core and factory
        core = ICore(address(0x1)); // Mock for demonstration
        factory = new TokenWrapperFactory(core);
        underlying = new TestToken("Test Token", "TT", 18);
    }
    
    function test_AmbiguousYearSymbol() public {
        // SETUP: Deploy two TokenWrappers with unlock times 100 years apart
        
        // Wrapper 1: Unlocks January 1, 2025
        uint256 unlockTime2025 = 1735689600; // Jan 1, 2025
        TokenWrapper wrapper2025 = factory.deployWrapper(underlying, unlockTime2025);
        
        // Wrapper 2: Unlocks January 1, 2125 (100 years later)
        uint256 unlockTime2125 = 4891449600; // Jan 1, 2125
        TokenWrapper wrapper2125 = factory.deployWrapper(underlying, unlockTime2125);
        
        // EXPLOIT: Both symbols are identical despite 100-year difference
        string memory symbol2025 = wrapper2025.symbol();
        string memory symbol2125 = wrapper2125.symbol();
        
        // VERIFY: Symbols are identical, creating deception
        assertEq(
            keccak256(abi.encodePacked(symbol2025)),
            keccak256(abi.encodePacked(symbol2125)),
            "Symbols should be identical, enabling deception"
        );
        
        // Both show "gTT-25Q1" despite 100-year unlock difference
        assertEq(symbol2025, "gTT-25Q1");
        assertEq(symbol2125, "gTT-25Q1");
        
        // But actual unlock times are vastly different
        assertEq(wrapper2025.UNLOCK_TIME(), unlockTime2025);
        assertEq(wrapper2125.UNLOCK_TIME(), unlockTime2125);
        assertEq(unlockTime2125 - unlockTime2025, 100 * 365 days, "100 years apart");
        
        console.log("Symbol for 2025 unlock:", symbol2025);
        console.log("Symbol for 2125 unlock:", symbol2125);
        console.log("Deception confirmed: identical symbols for tokens 100 years apart");
    }
}
```

## Notes

Test evidence confirms this behavior is working as designed but creates exploitable ambiguity: [6](#0-5) 

The test explicitly expects year 2100 to display as "00Q1" and year 2109 as "09Q2", demonstrating the modulo operation is intentional. However, this design choice creates a security vulnerability when combined with:

1. Permissionless TokenWrapper deployment (no validation on unlock times)
2. Symbols being the primary identifier in DeFi interfaces
3. User expectation that symbols accurately represent unlock timelines

While the `name()` function does show the full date with 4-digit year, and `UNLOCK_TIME` is publicly readable, the overwhelming majority of DeFi interfaces display symbols prominently while names are truncated or require additional clicks to view. This asymmetry in information presentation creates the attack vector.

### Citations

**File:** src/TokenWrapper.sol (L86-88)
```text
    function symbol() external view returns (string memory) {
        return string.concat("g", UNDERLYING_TOKEN.symbol(), "-", toQuarter(UNLOCK_TIME));
    }
```

**File:** src/TokenWrapper.sol (L167-169)
```text
        if (amount < 0) {
            if (block.timestamp < UNLOCK_TIME) revert TooEarly();
        }
```

**File:** src/libraries/TimeDescriptor.sol (L26-34)
```text
function toQuarter(uint256 unlockTime) pure returns (string memory quarterLabel) {
    (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(unlockTime);
    year = year % 100;
    string memory shortenedYearStr = LibString.toString(year);

    unchecked {
        quarterLabel =
            string.concat(year < 10 ? "0" : "", shortenedYearStr, "Q", LibString.toString(1 + (month - 1) / 3));
    }
```

**File:** src/TokenWrapperFactory.sol (L35-40)
```text
    function deployWrapper(IERC20 underlyingToken, uint256 unlockTime) external returns (TokenWrapper tokenWrapper) {
        bytes32 salt = EfficientHashLib.hash(uint256(uint160(address(underlyingToken))), unlockTime);

        tokenWrapper = new TokenWrapper{salt: salt}(CORE, underlyingToken, unlockTime);

        emit TokenWrapperDeployed(underlyingToken, unlockTime, tokenWrapper);
```

**File:** test/libraries/TimeDescriptor.t.sol (L33-40)
```text
        quarterLabel = toQuarter(4102506000);
        assertEq(quarterLabel, "00Q1");

        quarterLabel = toQuarter(4110278400);
        assertEq(quarterLabel, "00Q2");

        quarterLabel = toQuarter(4394275200);
        assertEq(quarterLabel, "09Q2");
```
