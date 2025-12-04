# Audit Report

## Title
Excess Native Token Theft via Unprotected refundNativeToken() in Orders and BasePositions

## Summary
The `refundNativeToken()` function lacks access control, allowing any external actor to steal accumulated excess ETH from `Orders` and `BasePositions` contracts. When users send native tokens exceeding the calculated required amount, the surplus remains vulnerable to theft. This represents an inconsistent security model compared to `Router`, which implements automatic refunds.

## Impact
**Severity**: High

Direct theft of user funds with 100% loss of excess ETH. Any user sending `msg.value` greater than the protocol-calculated required amount loses the surplus to the first attacker calling the unprotected `refundNativeToken()` function. The vulnerability enables trivial exploitation requiring only a single external call with no special permissions or setup. [1](#0-0) 

## Finding Description

**Location:** `src/base/PayableMulticallable.sol:25-29`, inherited by `src/Orders.sol:24` and `src/base/BasePositions.sol:29`

**Intended Logic:** 
The `refundNativeToken()` function is documented to allow "callers to recover ETH that was sent for transient payments but not fully consumed" within multicall batches. [2](#0-1) 

**Actual Logic:**
The function is `external payable` with zero access control, transferring the entire contract balance to `msg.sender` regardless of who originally deposited the ETH. [1](#0-0) 

When users call payable functions in `Orders` [3](#0-2)  or `BasePositions` [4](#0-3) , the contracts accept any `msg.value` without validation.

During `Orders.handleLockData()`, when the sell token is native, only the Core-calculated `amount` is transferred to ACCOUNTANT, leaving excess in the contract: [5](#0-4) 

Similarly, `BasePositions.handleLockData()` transfers only the required `amount0` for native token deposits: [6](#0-5) 

**Exploitation Path:**
1. **Alice** calls `Orders.increaseSellAmount{value: 10 ETH}()` with intent to sell 10 ETH over time
2. `CORE.updateSaleRate()` calculates actual requirement as 9.9999 ETH due to rounding in `computeSaleRate` (truncating division) [7](#0-6)  and `computeAmountFromSaleRate` (round-up addition) [8](#0-7) 
3. Orders transfers only 9.9999 ETH to ACCOUNTANT
4. 0.0001 ETH (or more if user sends buffer) remains in contract
5. **Bob** (any external actor) calls `Orders.refundNativeToken()`
6. Bob receives entire accumulated balance that belonged to Alice

**Security Property Broken:**
User funds remain under user control unless explicitly authorized for transfer. This fundamental security expectation is violated when any external actor can extract another user's deposited assets.

**Code Evidence - Design Inconsistency:**
`Router` implements automatic refund logic by calculating `valueDifference` and immediately refunding excess to the swapper: [9](#0-8) 

`Orders` and `BasePositions` inherit `PayableMulticallable` without implementing this protective pattern, creating an exploitable security gap despite both contracts handling native token payments.

## Impact Explanation

**Affected Assets**: Native ETH sent to `Orders` and `BasePositions` contracts via payable functions

**Damage Severity**:
- 100% loss of excess ETH for affected users (no proportional recovery)
- Attacker gains accumulated excess from potentially multiple users since `refundNativeToken()` drains entire contract balance
- No on-chain recovery mechanism; funds are permanently lost to victim
- Scales with contract usage as balance accumulates from multiple transactions

**User Impact**: Any user who:
- Sends excess due to inability to predict exact Core-calculated amounts (sale rate rounding, liquidity calculations)
- Uses direct function calls instead of multicall batches (no documentation enforces multicall-only usage)
- Fails to call `refundNativeToken()` in same transaction (requires awareness of vulnerability)
- Gets front-run when attempting legitimate refund

**Affected Patterns**:
1. TWAMM order creation/increase with `NATIVE_TOKEN_ADDRESS` as sell token [10](#0-9) 
2. Liquidity deposits with native token as `token0` [11](#0-10) 

## Likelihood Explanation

**Attacker Profile**: Any external actor (EOA or contract) capable of submitting transactions. No special permissions, positions, or setup required.

**Preconditions**:
1. Users send `msg.value` > Core-calculated required amount (likely due to: calculation complexity preventing exact prediction, intentional buffer amounts for transaction success guarantee, rounding mismatches between user input and Core computation)
2. Users don't call `refundNativeToken()` within same transaction (probable since: functions are public and callable individually, no documentation mandates multicall usage, users may be unaware of refund requirement)

**Execution Complexity**: Trivial
- Single external call: `Orders.refundNativeToken()` or `BasePositions.refundNativeToken()`
- Zero parameters required
- No capital lockup or economic cost beyond gas (~30k gas)
- Can monitor contract balance or mempool for opportunities
- Can front-run legitimate refund attempts

**Frequency**: Continuously exploitable
- Each excess-sending transaction creates opportunity
- Contract balance persists across blocks until stolen
- Attacker can batch multiple refund calls targeting both contracts
- No cooldown or rate limiting

**Overall Likelihood**: HIGH - Trivial execution combined with realistic precondition occurrence makes exploitation highly probable.

## Recommendation

**Primary Fix - Implement Automatic Refund:**
Track `msg.value` context before `lock()` callback and automatically refund excess within `handleLockData()`, mirroring Router's protective pattern.

For Orders:
```solidity
mapping(uint256 => uint256) private _lockIdToMsgValue;

function increaseSellAmount(...) public payable authorizedForNft(id) returns (uint112 saleRate) {
    uint256 lockId = _getNextLockId();
    _lockIdToMsgValue[lockId] = msg.value;
    // ... existing code ...
}

function handleLockData(uint256 id, bytes memory data) internal override returns (bytes memory result) {
    // After determining required amount
    if (sellToken == NATIVE_TOKEN_ADDRESS && _lockIdToMsgValue[id] > 0) {
        uint256 provided = _lockIdToMsgValue[id];
        uint256 required = uint256(amount);
        SafeTransferLib.safeTransferETH(address(ACCOUNTANT), required);
        if (provided > required) {
            SafeTransferLib.safeTransferETH(recipientOrPayer, provided - required);
        }
        delete _lockIdToMsgValue[id];
    }
}
```

**Alternative Fixes:**
1. Remove `refundNativeToken()` and revert on any excess: `require(msg.value == calculatedAmount, "ExcessPayment")`
2. Make `refundNativeToken()` access-controlled (requires tracking original depositors per transaction)

**Additional Mitigation:**
Add validation rejecting transactions with excess native token to prevent user error.

## Notes

**Root Cause**: `Orders` and `BasePositions` inherit `PayableMulticallable` but fail to implement automatic refund logic present in `Router`, creating architectural inconsistency in native token handling.

**Design vs Implementation Gap**: While `PayableMulticallable` documentation suggests usage for "transient payments" in multicall contexts [2](#0-1) , no enforcement mechanism (access modifiers, documentation, or revert conditions) prevents direct payable function calls. Functions are `public` and individually callable, making excess ETH accumulation a realistic scenario that becomes an exploitable vulnerability.

**Architectural Challenge**: By callback execution time in `handleLockData()`, original `msg.value` context is unavailable (callback originates from ACCOUNTANT with `msg.value = 0`), requiring explicit state tracking to implement automatic refunds without modifying the lock callback architecture.

**Differential Analysis**: The presence of automatic refund logic in Router [9](#0-8)  demonstrates protocol awareness of this pattern and establishes it as the intended security model, making its absence in Orders/BasePositions a deviation rather than intentional design.

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

**File:** src/math/twamm.sol (L13-22)
```text
function computeSaleRate(uint256 amount, uint256 duration) pure returns (uint256 saleRate) {
    assembly ("memory-safe") {
        saleRate := div(shl(32, amount), duration)
        if shr(112, saleRate) {
            // cast sig "SaleRateOverflow()"
            mstore(0, shl(224, 0x83c87460))
            revert(0, 4)
        }
    }
}
```

**File:** src/math/twamm.sol (L42-46)
```text
function computeAmountFromSaleRate(uint256 saleRate, uint256 duration, bool roundUp) pure returns (uint256 amount) {
    assembly ("memory-safe") {
        amount := shr(32, add(mul(saleRate, duration), mul(0xffffffff, roundUp)))
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
