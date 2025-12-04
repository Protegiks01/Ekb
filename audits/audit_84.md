# Audit Report

## Title
Excess Native Token Theft via Unprotected refundNativeToken() in Orders and BasePositions

## Summary
The `refundNativeToken()` function inherited by `Orders` and `BasePositions` contracts lacks access control, allowing any attacker to steal accumulated excess ETH that users send when the required payment amount is less than `msg.value`. Unlike `Router` which implements automatic refunds, `Orders` and `BasePositions` leave excess ETH vulnerable to theft.

## Impact
**Severity**: High

Any user who sends excess ETH to `Orders` or `BasePositions` contracts loses 100% of the surplus to the first attacker who calls the public `refundNativeToken()` function. This represents direct theft of user funds through an unprotected function that sends the entire contract balance to `msg.sender`, regardless of who originally deposited the ETH. The vulnerability affects all users who cannot predict exact payment amounts due to calculation complexity, rounding, or who use direct function calls instead of multicall batches. [1](#0-0) 

## Finding Description

**Location:** `src/base/PayableMulticallable.sol:25-29`, inherited by `src/Orders.sol:24` and `src/base/BasePositions.sol:29`

**Intended Logic:** 
The `refundNativeToken()` function is designed to allow users to recover excess ETH sent for "transient payments" in multicall batches. [2](#0-1)  The comments indicate users should call this within the same transaction to reclaim unused ETH.

**Actual Logic:**
The function is `external payable` with no access control and sends ALL contract balance to `msg.sender`, regardless of who originally sent the ETH. [1](#0-0) 

When users call `Orders.increaseSellAmount{value: X}()` or `BasePositions.deposit{value: Y}()`, the functions are `payable` but do not validate that `msg.value` matches the required amount. [3](#0-2) [4](#0-3) 

In `Orders.handleLockData()`, when native token is the sell token, the code transfers only the calculated `amount` to ACCOUNTANT, leaving any excess in the contract. [5](#0-4) 

Similarly, `BasePositions.handleLockData()` transfers only the required `amount0` to ACCOUNTANT for native token deposits. [6](#0-5) 

**Exploitation Path:**
1. **Alice** calls `Orders.increaseSellAmount{value: 10 ETH}()` to create a TWAMM order
2. `Core.updateSaleRate()` determines only 9.5 ETH is needed based on calculated sale rate
3. Orders transfers 9.5 ETH to ACCOUNTANT [7](#0-6) 
4. 0.5 ETH remains in Orders contract balance
5. **Bob** (attacker) observes the contract balance and calls `Orders.refundNativeToken()`
6. Bob receives the entire 0.5 ETH that belonged to Alice

**Security Property Broken:**
Direct theft of user funds. The fundamental security expectation that user assets remain under their control unless explicitly transferred is violated.

**Code Evidence - Design Inconsistency:**
Router correctly implements automatic refund logic by calculating excess and immediately refunding to the swapper: [8](#0-7) 

Orders and BasePositions do not implement this protective pattern, creating an exploitable security gap.

## Impact Explanation

**Affected Assets**: Native ETH sent to `Orders` and `BasePositions` contracts

**Damage Severity**:
- 100% loss of excess ETH for affected users
- Attacker gains accumulated excess from multiple users since `refundNativeToken()` sends entire contract balance
- No recovery mechanism for stolen funds

**User Impact**: Any user who:
- Sends excess ETH due to uncertainty about exact amount needed (sale rate calculations, liquidity rounding)
- Uses direct function calls instead of multicall
- Doesn't call `refundNativeToken()` within the same transaction
- Gets front-run when attempting to recover their excess

**Affected Patterns**:
1. TWAMM order creation with native token as sell token [9](#0-8) 
2. Liquidity deposits with native token as token0 [10](#0-9) 

## Likelihood Explanation

**Attacker Profile**: Any external actor who can monitor contract balances and submit transactions

**Preconditions**:
1. Users send excess ETH to Orders or BasePositions (highly likely due to calculation complexity for sale rates, liquidity amounts, and rounding)
2. Users don't call `refundNativeToken()` in the same transaction (likely since no documentation enforces multicall usage)

**Execution Complexity**: Trivial - single function call `refundNativeToken()` with no parameters and no cost beyond gas

**Frequency**: Continuously exploitable. Attacker can:
- Monitor mempool for transactions sending ETH to these contracts
- Front-run legitimate refund attempts
- Extract accumulated balance whenever `contract.balance > 0`

**Overall Likelihood**: HIGH - The vulnerability is trivially exploitable with realistic preconditions

## Recommendation

**Primary Fix - Add Access Control:**
```solidity
// Track msg.value before lock() and refund automatically in handleLockData

// In Orders.sol:
mapping(uint256 => uint256) private _lockIdToMsgValue;

function increaseSellAmount(...) public payable authorizedForNft(id) returns (uint112 saleRate) {
    uint256 lockId = _getNextLockId();
    _lockIdToMsgValue[lockId] = msg.value;
    
    // ... existing code ...
    
    lock(abi.encode(CALL_TYPE_CHANGE_SALE_RATE, msg.sender, id, orderKey, saleRate));
}

function handleLockData(uint256 id, bytes memory data) internal override returns (bytes memory result) {
    // ... existing code for determining amount ...
    
    if (sellToken == NATIVE_TOKEN_ADDRESS && _lockIdToMsgValue[id] > 0) {
        uint256 provided = _lockIdToMsgValue[id];
        uint256 required = uint256(amount);
        
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), required);
        
        // Refund excess immediately
        if (provided > required) {
            unchecked {
                SafeTransferLib.safeTransferETH(recipientOrPayer, provided - required);
            }
        }
        
        delete _lockIdToMsgValue[id];
    }
}
```

**Alternative Fix:**
Remove `refundNativeToken()` entirely from `PayableMulticallable` or make it access-controlled to only the original sender (requires tracking depositors).

**Additional Mitigation:**
Add validation to revert on excess payments:
```solidity
if (msg.value > requiredAmount) revert ExcessPayment();
```

## Notes

**Root Cause**: `Orders` and `BasePositions` inherit `PayableMulticallable` but don't implement automatic refund logic like `Router`, creating an inconsistent security model.

**Design vs Implementation**: While `PayableMulticallable` comments suggest "transient payments" for multicall usage [2](#0-1) , there is no enforcement mechanism requiring multicall, making direct calls with excess ETH a realistic user error that becomes an exploitable vulnerability.

**Architectural Issue**: By the time `handleLockData()` callback executes, the original `msg.value` context is lost (callback comes from ACCOUNTANT with `msg.value = 0`), making it architecturally difficult to implement automatic refunds without tracking the original payment amount.

### Citations

**File:** src/base/PayableMulticallable.sol (L21-24)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
    ///      Only refunds if there is a non-zero balance to avoid unnecessary gas costs
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/Orders.sol (L43-50)
```text
    function mintAndIncreaseSellAmount(OrderKey memory orderKey, uint112 amount, uint112 maxSaleRate)
        public
        payable
        returns (uint256 id, uint112 saleRate)
    {
        id = mint();
        saleRate = increaseSellAmount(id, orderKey, amount, maxSaleRate);
    }
```

**File:** src/Orders.sol (L53-57)
```text
    function increaseSellAmount(uint256 id, OrderKey memory orderKey, uint128 amount, uint112 maxSaleRate)
        public
        payable
        authorizedForNft(id)
        returns (uint112 saleRate)
```

**File:** src/Orders.sol (L146-151)
```text
                if (saleRateDelta > 0) {
                    if (sellToken == NATIVE_TOKEN_ADDRESS) {
                        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint256(amount));
                    } else {
                        ACCOUNTANT.payFrom(recipientOrPayer, sellToken, uint256(amount));
                    }
```

**File:** src/base/BasePositions.sol (L71-97)
```text
    function deposit(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) public payable authorizedForNft(id) returns (uint128 liquidity, uint128 amount0, uint128 amount1) {
        SqrtRatio sqrtRatio = CORE.poolState(poolKey.toPoolId()).sqrtRatio();

        liquidity =
            maxLiquidity(sqrtRatio, tickToSqrtRatio(tickLower), tickToSqrtRatio(tickUpper), maxAmount0, maxAmount1);

        if (liquidity < minLiquidity) {
            revert DepositFailedDueToSlippage(liquidity, minLiquidity);
        }

        if (liquidity > uint128(type(int128).max)) {
            revert DepositOverflow();
        }

        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_DEPOSIT, msg.sender, id, poolKey, tickLower, tickUpper, liquidity)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L253-262)
```text
            if (poolKey.token0 != NATIVE_TOKEN_ADDRESS) {
                ACCOUNTANT.payTwoFrom(caller, poolKey.token0, poolKey.token1, amount0, amount1);
            } else {
                if (amount0 != 0) {
                    SafeTransferLib.safeTransferETH(address(ACCOUNTANT), amount0);
                }
                if (amount1 != 0) {
                    ACCOUNTANT.payFrom(caller, poolKey.token1, amount1);
                }
            }
```

**File:** src/Router.sol (L134-142)
```text
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
```
