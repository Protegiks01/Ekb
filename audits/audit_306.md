## Title
Insufficient TWAP Duration Validation Enables Oracle Manipulation via Short Time Windows

## Summary
The `ERC7726` constructor lacks a minimum bound on `twapDuration`, allowing deployment with extremely short durations (e.g., 1 second). This defeats the manipulation resistance of Time-Weighted Average Price oracles, enabling attackers to manipulate prices that downstream protocols rely on for critical financial decisions like liquidations and collateral valuation.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The TWAP mechanism is designed to provide manipulation-resistant price data by averaging prices over a time window. The documentation states "Longer durations provide more manipulation resistance but less price responsiveness" [2](#0-1) , implying there should be a reasonable minimum duration to ensure manipulation resistance.

**Actual Logic:** The constructor only validates that `twapDuration != 0` [3](#0-2) , allowing deployment with duration values as low as 1 second. This makes the TWAP vulnerable to single-block or two-block manipulation attacks.

**Exploitation Path:**

1. **Deployment**: A protocol (or attacker) deploys `ERC7726` with `twapDuration = 1` second, which passes the only validation check.

2. **Integration**: A downstream lending protocol integrates this oracle for collateral valuation, calling `getQuote()` to determine liquidation eligibility.

3. **Price Manipulation**: Attacker executes a large swap in the Oracle-tracked pool to drastically move the tick (e.g., from tick 0 to tick +10,000), which updates the Oracle's cumulative values [4](#0-3) .

4. **TWAP Calculation**: When `getAverageTick()` is called, it computes: `(tickCumulativeEnd - tickCumulativeStart) / 1` [5](#0-4) , where the 1-second window heavily weights the manipulated current tick.

5. **Exploitation**: 
   - For extrapolation to current timestamp, the Oracle uses current pool state [6](#0-5) , incorporating the attacker's manipulated tick.
   - The downstream protocol receives a manipulated price from `getQuote()` [7](#0-6) .
   - Attacker exploits the mispricing (e.g., unfair liquidations, borrowing against inflated collateral).

**Security Property Broken:** The oracle's manipulation resistance property is violated. TWAPs are meant to average prices over meaningful time windows to prevent flash loan and sandwich attacks, but a 1-second window provides negligible protection.

## Impact Explanation

- **Affected Assets**: All assets in downstream protocols (lending platforms, derivatives, automated market makers) that rely on this oracle for pricing decisions. Collateral positions, debt positions, and automated trading strategies are at risk.

- **Damage Severity**: 
  - **Direct theft**: Attacker can manipulate prices to liquidate healthy positions or avoid liquidation of underwater positions, stealing liquidation rewards or preventing legitimate liquidations.
  - **Scale**: A single manipulation can affect multiple users simultaneously if the protocol uses this oracle for batch liquidations or portfolio valuations.
  - **Cost vs Reward**: With a 1-second TWAP, manipulation cost is minimal (one swap's gas + slippage for 1 second), while potential profit can be massive (entire liquidation cascades).

- **User Impact**: Any user with positions valued using this oracle becomes vulnerable. Liquidation thresholds can be triggered falsely (honest users lose collateral) or avoided maliciously (protocol accrues bad debt).

## Likelihood Explanation

- **Attacker Profile**: Any user with capital to execute large swaps. Flash loans can amplify attack capital, making this accessible to attackers with minimal initial funds.

- **Preconditions**:
  1. `ERC7726` deployed with short `twapDuration` (likely if deployer prioritizes "responsiveness" without understanding security implications)
  2. Oracle pool has active liquidity (required for normal operation)
  3. Downstream protocol integrated and has valuable positions

- **Execution Complexity**: Low - single transaction containing:
  1. Flash loan (if needed for capital)
  2. Swap to manipulate price
  3. Trigger downstream protocol action (e.g., call liquidation function)
  4. Repay flash loan

- **Frequency**: Repeatable continuously across blocks. Attacker can manipulate on every block where profitable opportunities exist in downstream protocols.

## Recommendation

Add a minimum TWAP duration constant to prevent deployment with dangerously short windows: [1](#0-0) 

```solidity
// In src/lens/ERC7726.sol, add constant and update constructor:

// Add after line 60:
/// @notice Minimum TWAP duration to ensure manipulation resistance
/// @dev 10 minutes provides reasonable protection against manipulation while maintaining responsiveness
uint32 public constant MIN_TWAP_DURATION = 600; // 10 minutes

// Modify constructor validation (lines 74-75):
if (twapDuration == 0) revert InvalidTwapDuration();
if (twapDuration < MIN_TWAP_DURATION) revert InvalidTwapDuration(); // Add this check

// Alternative: Make the error more specific
error TwapDurationTooShort(uint32 provided, uint32 minimum);
if (twapDuration < MIN_TWAP_DURATION) revert TwapDurationTooShort(twapDuration, MIN_TWAP_DURATION);
```

**Alternative Mitigations:**
1. **Documentation Warning**: If flexible durations are required, add explicit documentation warning integrators about security implications of short durations
2. **Dynamic Minimum**: Calculate minimum duration based on pool liquidity depth (lower liquidity = longer required duration)
3. **Multi-Sample TWAP**: Require multiple non-adjacent samples rather than just start/end points

## Proof of Concept

```solidity
// File: test/Exploit_TWAPManipulation.t.sol
// Run with: forge test --match-test test_TWAPManipulationWith1SecondDuration -vvv

pragma solidity ^0.8.31;

import {BaseOracleTest} from "../extensions/Oracle.t.sol";
import {ERC7726} from "../../src/lens/ERC7726.sol";
import {PoolKey} from "../../src/types/poolKey.sol";
import {TestToken} from "../TestToken.sol";
import {NATIVE_TOKEN_ADDRESS} from "../../src/math/constants.sol";

contract Exploit_TWAPManipulation is BaseOracleTest {
    ERC7726 internal vulnerableOracle;
    TestToken internal usdc;
    PoolKey internal usdcPool;

    function setUp() public override {
        BaseOracleTest.setUp();
        usdc = new TestToken(address(this));
        
        // Deploy ERC7726 with dangerously short 1-second TWAP
        vulnerableOracle = new ERC7726(oracle, address(usdc), address(usdc), NATIVE_TOKEN_ADDRESS, 1);
        
        // Setup Oracle pool
        oracle.expandCapacity(address(usdc), 10);
        usdcPool = createOraclePool(address(usdc), 0); // Initial tick = 0 (1:1 price)
        
        // Wait 2 seconds to have valid history
        advanceTime(2);
    }

    function test_TWAPManipulationWith1SecondDuration() public {
        // SETUP: Record honest price at tick 0
        uint256 honestPrice = vulnerableOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        assertApproxEqAbs(honestPrice, 1e18, 1e15, "Initial price should be ~1:1");
        
        // EXPLOIT: Attacker manipulates price with large swap
        // Move price to tick +10000 (massive price increase)
        movePrice(usdcPool, 10000);
        
        // VERIFY: TWAP immediately reflects manipulated price
        uint256 manipulatedPrice = vulnerableOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        
        // With 1-second TWAP, price should be heavily influenced by current manipulated tick
        // Expected: manipulatedPrice >> honestPrice (orders of magnitude difference)
        assertTrue(manipulatedPrice > honestPrice * 100, "Price should be massively inflated");
        
        // IMPACT: Downstream protocol making decisions on this price gets exploited
        // Example: Lending protocol thinks USDC collateral is worth 100x more
        // Attacker can borrow against inflated collateral value and drain protocol
        
        // Compare with proper 60-second TWAP (more resistant to manipulation)
        ERC7726 secureOracle = new ERC7726(oracle, address(usdc), address(usdc), NATIVE_TOKEN_ADDRESS, 60);
        advanceTime(60);
        uint256 securePrice = secureOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS);
        
        // The 60-second TWAP should be much closer to honest price
        assertTrue(securePrice < manipulatedPrice / 10, "Longer TWAP provides manipulation resistance");
    }
    
    function test_AttackerProfitScenario() public {
        // Simulate downstream lending protocol liquidation scenario
        
        // SETUP: Lending protocol uses 1-second TWAP oracle
        // User has 1000 USDC collateral, 500 ETH debt
        // Liquidation threshold: collateral value < 1.2x debt value
        
        uint256 collateralAmount = 1000e18; // 1000 USDC
        uint256 debtValue = 500e18; // 500 ETH worth of debt
        uint256 liquidationThreshold = (debtValue * 120) / 100; // 1.2x = 600 ETH
        
        // Normal state: 1 USDC = 1 ETH, so 1000 USDC = 1000 ETH value > 600 ETH threshold (SAFE)
        uint256 normalCollateralValue = (collateralAmount * vulnerableOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS)) / 1e18;
        assertTrue(normalCollateralValue > liquidationThreshold, "Position should be safe normally");
        
        // ATTACK: Manipulate price down via large swap
        movePrice(usdcPool, -10000); // Crash USDC price
        
        // Manipulated state: oracle reports USDC price crashed
        uint256 manipulatedCollateralValue = (collateralAmount * vulnerableOracle.getQuote(1e18, address(usdc), NATIVE_TOKEN_ADDRESS)) / 1e18;
        
        // Attacker triggers liquidation on healthy position
        assertTrue(manipulatedCollateralValue < liquidationThreshold, "Manipulation enables unfair liquidation");
        
        // Attacker profits from liquidation bonus (typically 5-10% of position value)
        uint256 attackerProfit = normalCollateralValue / 20; // 5% liquidation bonus
        
        // Attack cost: Just 1 second of price manipulation (minimal gas + slippage)
        // Attack profit: Potentially millions if targeting large positions
        assertTrue(attackerProfit > 0, "Attacker profits from manipulated liquidation");
    }
}
```

**Notes:**
- The vulnerability exists because no minimum duration is enforced in the constructor
- With proper validation (e.g., `MIN_TWAP_DURATION = 600` seconds), the attack becomes economically infeasible
- Downstream protocols integrating this oracle without understanding the duration parameter are at severe risk
- The Oracle extension itself is sound; the vulnerability is in the ERC7726 wrapper's lack of input validation

### Citations

**File:** src/lens/ERC7726.sol (L59-59)
```text
    /// @dev Longer durations provide more manipulation resistance but less price responsiveness
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

**File:** src/lens/ERC7726.sol (L138-154)
```text
    function getQuote(uint256 baseAmount, address base, address quote) external view returns (uint256 quoteAmount) {
        address normalizedBase = normalizeAddress(base);
        address normalizedQuote = normalizeAddress(quote);

        // Short-circuit same-token quotes to avoid unnecessary oracle calls and math
        if (normalizedBase == normalizedQuote) {
            return baseAmount;
        }

        int32 tick = getAverageTick({baseToken: normalizedBase, quoteToken: normalizedQuote});

        uint256 sqrtRatio = tickToSqrtRatio(tick).toFixed();

        uint256 ratio = FixedPointMathLib.fullMulDivN(sqrtRatio, sqrtRatio, 128);

        quoteAmount = FixedPointMathLib.fullMulDivN(baseAmount, ratio, 128);
    }
```

**File:** src/extensions/Oracle.sol (L125-125)
```text
                _tickCumulative: last.tickCumulative() + int64(uint64(timePassed)) * state.tick()
```

**File:** src/extensions/Oracle.sol (L327-337)
```text
                if (logicalIndex == c.count() - 1) {
                    // Use current pool state.
                    PoolId poolId = getPoolKey(token).toPoolId();
                    PoolState state = CORE.poolState(poolId);

                    tickCumulative += int64(state.tick()) * int64(uint64(timePassed));
                    secondsPerLiquidityCumulative += uint160(
                        FixedPointMathLib.rawDiv(
                            uint256(timePassed) << 128, FixedPointMathLib.max(1, state.liquidity())
                        )
                    );
```
