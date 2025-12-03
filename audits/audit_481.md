## Title
Order Fragmentation Across Multiple Fee Tiers Enables MEV Extraction and Execution Slippage

## Summary
When the RevenueBuybacks owner changes the fee configuration via `configure()` and `roll()` is subsequently called, a new TWAMM order is created in a different pool (different fee tier) while previous orders continue executing in their original pools. This causes liquidity fragmentation across multiple pools, worse execution prices, and increased MEV opportunities as attackers can sandwich smaller fragmented orders independently.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/RevenueBuybacks.sol`, function `roll()` (lines 90-139), specifically the fee change detection at line 110 and order creation logic at lines 115-136. [1](#0-0) 

**Intended Logic:** According to the interface documentation, the `roll()` function should "either extend the current order (if conditions are met) or create a new order" - implying a single active order at any given time. [2](#0-1) 

**Actual Logic:** When the fee changes (`state.fee() != state.lastFee()`), the code creates a new order with a new `endTime` and updates `lastFee` to match the current fee. However, it does NOT cancel or decrease the sale rate of the previous order. The old order continues executing in its original pool (defined by the old fee tier), while the new order executes in a different pool (defined by the new fee tier).

The critical issue is that there is NO call to `decreaseSaleRate` anywhere in `RevenueBuybacks.sol` to cancel old orders when creating new ones: [3](#0-2) 

**Why Different Fees Mean Different Pools:**

The fee from the OrderConfig determines which pool the order executes in. When an OrderKey is converted to a PoolKey, the fee becomes part of the pool's identity: [4](#0-3) 

Different PoolKeys with different fees result in different PoolIds (via keccak256 hash): [5](#0-4) 

**Exploitation Path:**

1. **Initial Configuration**: Owner calls `configure(token, 30 days, 10 days, 3000)` to set up buybacks with 0.3% fee tier
2. **First Order Creation**: Someone calls `roll(token)` with 1000 tokens available, creating Order A selling 1000 tokens over 30 days in Pool(token, buyToken, fee=3000)
3. **Fee Reconfiguration**: On day 5, owner calls `configure(token, 30 days, 10 days, 500)` to change to 0.05% fee tier for better execution
4. **Fragmentation Trigger**: MEV bot (or any user, since `roll()` is public) immediately calls `roll(token)` when new revenue arrives (e.g., 500 tokens) [6](#0-5) 

5. **Parallel Execution**: The condition at line 110 fails (`state.fee() != state.lastFee()`), creating Order B in Pool(token, buyToken, fee=500) while Order A continues in Pool(token, buyToken, fee=3000)
6. **MEV Extraction**: Attacker sandwiches the smaller Order B independently, profiting from reduced liquidity in the 0.05% pool

**Security Property Broken:** The protocol suffers economic loss due to suboptimal execution. The buyback mechanism is designed to accumulate the best price for the protocol's token, but order fragmentation across pools with different liquidity depths results in worse overall execution than a single consolidated order.

## Impact Explanation

- **Affected Assets**: Protocol revenue tokens being sold through the buyback mechanism, and the buyback token being purchased
- **Damage Severity**: The protocol receives less buyback token than optimal due to:
  1. **Liquidity Fragmentation**: Each order has access to only the liquidity in its specific fee tier pool, rather than consolidated liquidity
  2. **Increased Slippage**: Smaller orders in pools with less liquidity experience worse price impact
  3. **MEV Losses**: Each fragmented order can be sandwiched independently, with MEV bots extracting value that should have gone to the protocol
  4. **Cascading Effect**: Each fee change compounds the problem, potentially creating 3, 4, or more simultaneous orders across different pools

- **User Impact**: While the protocol itself suffers the direct loss, this reduces the effectiveness of revenue buybacks, which ultimately affects token holders who rely on buyback support for token value. The impact scales with:
  - Frequency of fee reconfigurations
  - Amount of revenue being processed
  - Liquidity distribution across different fee tiers

## Likelihood Explanation

- **Attacker Profile**: 
  - MEV bots can monitor for `configure()` transactions and immediately call `roll()` to force fragmentation
  - Any unprivileged user can call `roll()` since it's a public function
  - Sophisticated attackers can profit by sandwiching the resulting smaller orders

- **Preconditions**:
  - Owner must call `configure()` to change fee (happens during normal operations as market conditions change)
  - New revenue must arrive for `roll()` to create a new order (happens regularly for active protocols)
  - Previous order must still be active (likely, given typical 30-day order durations)
  - Different fee tiers must have different liquidity profiles (common in DEXs)

- **Execution Complexity**: 
  - Single transaction by any user to call `roll()`
  - Can be automated by bots monitoring `configure()` events
  - No special privileges required

- **Frequency**: 
  - Can occur every time the owner reconfigures fees while orders are active
  - In active protocols, this could happen weekly or monthly as market conditions evolve
  - MEV bots can exploit each fragmentation event for profit

## Recommendation

**Primary Fix**: Automatically cancel previous orders when fee changes require creating a new order:

In `src/RevenueBuybacks.sol`, modify the `roll()` function to decrease the sale rate of the previous order before creating a new one when the fee changes. Add this logic after line 130:

```solidity
// After updating state with new fee (line 130), check if we need to cancel the old order
if (state.lastEndTime() > block.timestamp && state.lastFee() != state.fee()) {
    // Cancel the old order by collecting any proceeds and decreasing its sale rate
    // This requires tracking the previous order's parameters
    try ORDERS.decreaseSaleRate(
        NFT_ID,
        _createOrderKey(token, state.lastFee(), 0, state.lastEndTime()),
        type(uint112).max // Decrease by max to cancel completely
    ) {} catch {
        // If cancellation fails (order already completed), continue
    }
}
```

**Alternative Mitigation 1**: Add a configuration parameter that prevents fee changes while orders are active:

```solidity
function configure(...) external onlyOwner {
    BuybacksState state = ...;
    if (state.lastEndTime() > block.timestamp && state.fee() != fee) {
        revert CannotChangeFeeWhileOrderActive();
    }
    // ... rest of configure logic
}
```

**Alternative Mitigation 2**: Document the behavior clearly and provide a dedicated function for owners to manually consolidate orders:

```solidity
function consolidateOrders(address token) external onlyOwner {
    // Cancel all active orders and create a new consolidated order
    // This gives the owner explicit control over when consolidation happens
}
```

## Proof of Concept

```solidity
// File: test/Exploit_OrderFragmentation.t.sol
// Run with: forge test --match-test test_OrderFragmentationAcrossFees -vvv

pragma solidity ^0.8.31;

import "./RevenueBuybacks.t.sol";

contract Exploit_OrderFragmentation is RevenueBuybacksTest {
    
    function test_OrderFragmentationAcrossFees() public {
        // SETUP: Create initial order with 1% fee
        uint64 initialFee = uint64((uint256(1) << 64) / 100); // 1%
        rb.configure({
            token: address(token0),
            targetOrderDuration: 3600,
            minOrderDuration: 1800,
            fee: initialFee
        });
        
        // Create pool for initial fee tier
        PoolKey memory pool1 = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: initialFee})
        });
        positions.maybeInitializePool(pool1, 0);
        token0.approve(address(positions), 10e18);
        buybacksToken.approve(address(positions), 10e18);
        positions.mintAndDeposit(pool1, MIN_TICK, MAX_TICK, 10e18, 10e18, 0);
        
        rb.approveMax(address(token0));
        donate(address(token0), 1e18);
        
        // Create first order with 1% fee
        (uint64 endTime1, uint112 saleRate1) = rb.roll(address(token0));
        assertGt(saleRate1, 0, "First order should have sale rate");
        
        // EXPLOIT: Owner changes fee to 0.5%
        uint64 newFee = uint64((uint256(5) << 64) / 1000); // 0.5%
        rb.configure({
            token: address(token0),
            targetOrderDuration: 3600,
            minOrderDuration: 1800,
            fee: newFee
        });
        
        // Create pool for new fee tier
        PoolKey memory pool2 = PoolKey({
            token0: address(token0),
            token1: address(buybacksToken),
            config: createFullRangePoolConfig({_extension: address(twamm), _fee: newFee})
        });
        positions.maybeInitializePool(pool2, 0);
        positions.mintAndDeposit(pool2, MIN_TICK, MAX_TICK, 5e18, 5e18, 0);
        
        // MEV bot (or anyone) immediately calls roll() with new revenue
        donate(address(token0), 5e17); // 0.5 tokens
        (uint64 endTime2, uint112 saleRate2) = rb.roll(address(token0));
        
        // VERIFY: Fragmentation occurred
        assertGt(saleRate2, 0, "Second order should have sale rate");
        assertGt(endTime2, block.timestamp, "Second order should be active");
        
        // Both orders are active simultaneously in different pools
        assertTrue(endTime1 > block.timestamp, "First order still active");
        assertTrue(endTime2 > block.timestamp, "Second order also active");
        assertNotEq(endTime1, endTime2, "Orders have different end times");
        
        // Orders are in different pools (different fees)
        assertNotEq(initialFee, newFee, "Fee tiers are different");
        
        // This proves order fragmentation across multiple fee tier pools
        // The protocol now has 1.5 tokens selling across TWO different pools
        // instead of a single consolidated order in one pool
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Public Function Exposure**: The `roll()` function is public and can be called by anyone, giving attackers control over the timing of order creation even though only the owner can change fees.

2. **No Automated Cleanup**: The protocol provides no mechanism to automatically consolidate or cancel old orders when configurations change. The owner must manually track and cancel orders using `decreaseSaleRate`, which requires knowing all active order parameters.

3. **Cross-Pool Fragmentation**: Unlike simple order splitting within a single pool, this fragments orders across entirely different pools with independent liquidity, amplifying the negative impact on execution quality.

4. **MEV Amplification**: Smaller orders in less liquid pools are significantly more vulnerable to sandwich attacks. MEV bots can monitor `configure()` calls and immediately trigger `roll()` to create exploitable fragmentation.

5. **Cumulative Effect**: If the owner changes fees multiple times (e.g., adjusting for market conditions), the protocol could end up with numerous small orders spread across 3, 4, or more different fee tier pools, each suffering from reduced liquidity access.

The intended behavior per the documentation is that `roll()` should "either extend the current order OR create a new order" - suggesting mutual exclusivity. However, the implementation allows both old and new orders to coexist when fee changes occur, violating this design intention.

### Citations

**File:** src/RevenueBuybacks.sol (L1-188)
```text
// SPDX-License-Identifier: ekubo-license-v1.eth
pragma solidity >=0.8.30;

import {Ownable} from "solady/auth/Ownable.sol";
import {Multicallable} from "solady/utils/Multicallable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {nextValidTime} from "./math/time.sol";
import {IOrders} from "./interfaces/IOrders.sol";
import {IRevenueBuybacks} from "./interfaces/IRevenueBuybacks.sol";
import {BuybacksState, createBuybacksState} from "./types/buybacksState.sol";
import {OrderKey} from "./types/orderKey.sol";
import {createOrderConfig} from "./types/orderConfig.sol";
import {ExposedStorage} from "./base/ExposedStorage.sol";
import {NATIVE_TOKEN_ADDRESS} from "./math/constants.sol";

/// @title Revenue Buybacks
/// @author Moody Salem <moody@ekubo.org>
/// @notice Creates automated revenue buyback orders using TWAMM (Time-Weighted Average Market Maker)
/// @dev Final contract that manages the creation and execution of buyback orders for protocol revenue
/// This contract automatically creates TWAMM orders to buy back a specified token using collected revenue
contract RevenueBuybacks is IRevenueBuybacks, ExposedStorage, Ownable, Multicallable {
    /// @notice The Orders contract used to create and manage TWAMM orders
    /// @dev All buyback orders are created through this contract
    IOrders public immutable ORDERS;

    /// @notice The NFT token ID that represents all buyback orders created by this contract
    /// @dev A single NFT is minted and reused for all buyback orders to simplify management
    uint256 public immutable NFT_ID;

    /// @notice The token that is purchased with collected revenue
    /// @dev This is typically the protocol's governance or utility token
    address public immutable BUY_TOKEN;

    /// @notice Constructs the RevenueBuybacks contract
    /// @param owner The address that will own this contract and have administrative privileges
    /// @param _orders The Orders contract instance for creating TWAMM orders
    /// @param _buyToken The token that will be purchased with collected revenue
    constructor(address owner, IOrders _orders, address _buyToken) {
        _initializeOwner(owner);
        ORDERS = _orders;
        BUY_TOKEN = _buyToken;
        NFT_ID = ORDERS.mint();
    }

    /// @notice Approves the Orders contract to spend unlimited amounts of a token
    /// @dev Must be called at least once for each revenue token before creating buyback orders
    /// @param token The token to approve for spending by the Orders contract
    function approveMax(address token) external {
        SafeTransferLib.safeApproveWithRetry(token, address(ORDERS), type(uint256).max);
    }

    /// @notice Withdraws leftover tokens from the contract (only callable by owner)
    /// @dev Used to recover tokens that may be stuck in the contract
    /// @param token The address of the token to withdraw
    /// @param amount The amount of tokens to withdraw
    function take(address token, uint256 amount) external onlyOwner {
        // Transfer to msg.sender since only the owner can call this function
        SafeTransferLib.safeTransfer(token, msg.sender, amount);
    }

    /// @notice Withdraws native tokens held by this contract
    /// @dev Used to recover native tokens that may be stuck in the contract
    /// @param amount The amount of native tokens to withdraw
    function takeNative(uint256 amount) external onlyOwner {
        // Transfer to msg.sender since only the owner can call this function
        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    /// @notice Collects the proceeds from a completed buyback order
    /// @dev Can be called by anyone at any time to collect proceeds from orders that have finished
    /// @param token The revenue token that was sold in the order
    /// @param fee The fee tier of the pool where the order was executed
    /// @param endTime The end time of the order to collect proceeds from
    /// @return proceeds The amount of buyToken received from the completed order
    function collect(address token, uint64 fee, uint64 endTime) external returns (uint128 proceeds) {
        proceeds = ORDERS.collectProceeds(NFT_ID, _createOrderKey(token, fee, 0, endTime), owner());
    }

    /// @notice Allows the contract to receive ETH revenue
    /// @dev Required to accept ETH payments when ETH is used as a revenue token
    receive() external payable {}

    /// @notice Creates a new buyback order or extends an existing one with available revenue
    /// @dev Can be called by anyone to trigger the creation of buyback orders using collected revenue
    /// This function will either extend the current order (if conditions are met) or create a new order
    /// @param token The revenue token to use for creating the buyback order, or NATIVE_TOKEN_ADDRESS
    /// @return endTime The end time of the order that was created or extended
    /// @return saleRate The sale rate of the order (amount of token sold per second)
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

    /// @notice Configures buyback parameters for a revenue token (only callable by owner)
    /// @dev Sets the timing and fee parameters for automated buyback order creation
    /// @param token The revenue token to configure
    /// @param targetOrderDuration The target duration for new orders (in seconds)
    /// @param minOrderDuration The minimum duration threshold for creating new orders (in seconds)
    /// @param fee The fee tier for the buyback pool
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

    function _createOrderKey(address token, uint64 fee, uint64 startTime, uint64 endTime)
        internal
        view
        returns (OrderKey memory key)
    {
        bool isToken1 = token > BUY_TOKEN;
        address buyToken = BUY_TOKEN;
        assembly ("memory-safe") {
            mstore(add(key, mul(isToken1, 32)), token)
            mstore(add(key, mul(iszero(isToken1), 32)), buyToken)
        }

        key.config = createOrderConfig({_fee: fee, _isToken1: isToken1, _startTime: startTime, _endTime: endTime});
    }
```

**File:** src/interfaces/IRevenueBuybacks.sol (L59-62)
```text
    /// @notice Creates a new buyback order or extends an existing one with available revenue
    /// @dev Can be called by anyone to trigger the creation of buyback orders using collected revenue
    /// This function will either extend the current order (if conditions are met) or create a new order
    /// @param token The revenue token to use for creating the buyback order
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

**File:** src/types/poolKey.sol (L34-38)
```text
function toPoolId(PoolKey memory key) pure returns (PoolId result) {
    assembly ("memory-safe") {
        // it's already copied into memory
        result := keccak256(key, 96)
    }
```
