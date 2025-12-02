# NoVulnerability found for this question.

After conducting a comprehensive investigation of the protocol fee withdrawal mechanism and its interaction with pool accounting and flash loan operations, I found that the system is correctly implemented with proper safeguards.

## Investigation Summary

**Protocol Fee Withdrawal Flow Analysis:**

The withdrawal at line 70 in `PositionsOwner.sol` initiates a secure two-step process: [1](#0-0) 

This calls into the Positions contract's withdrawal handler: [2](#0-1) 

**Key Security Properties Verified:**

1. **Accounting Separation**: Protocol fees are stored in saved balances under `bytes32(0)` salt, completely separate from pool liquidity accounting: [3](#0-2) 

2. **Underflow Protection**: The `updateSavedBalances` function includes comprehensive underflow/overflow checks in its `addDelta` assembly function: [4](#0-3) 

3. **Debt Tracking Balance**: When protocol fees are withdrawn, `updateSavedBalances` with negative deltas DECREASES debt, while `withdrawTwo` INCREASES debt by the same amount, resulting in zero net debt change: [5](#0-4) 

4. **Pool State Independence**: Pool operations calculate deltas based on mathematical state (sqrtRatio, liquidity, fees per liquidity), not physical token balances. The swap function updates debt based on calculated deltas: [6](#0-5) 

**Why No Vulnerability Exists:**

- **No Reserve Inflation**: Pools don't maintain a "reserve" concept that could be inflated. They operate on pure mathematical state.
- **Separate Accounting Domains**: Protocol fees (saved balances) and pool liquidity (pool state) are tracked independently with no cross-contamination.
- **Flash Loan Safety**: The flash accounting system enforces debt settlement before lock completion, preventing unauthorized token extraction.
- **Physical Balance Irrelevance**: No pool operation checks the Core contract's physical token balance; all operations are delta-based with mandatory settlement.

## Notes

The protocol's singleton architecture with separated accounting layers (pool state, saved balances, flash accounting) prevents the scenario described in the security question. Protocol fee withdrawal cannot cause a pool's reserve to "appear larger" because pools don't track reserves—they track mathematical relationships between tokens that are enforced through the flash accounting debt settlement mechanism.

### Citations

**File:** src/PositionsOwner.sol (L70-70)
```text
            POSITIONS.withdrawProtocolFees(token0, token1, uint128(amount0), uint128(amount1), address(BUYBACKS));
```

**File:** src/base/BasePositions.sol (L194-197)
```text
    /// @inheritdoc IPositions
    function getProtocolFees(address token0, address token1) external view returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = CORE.savedBalances(address(this), token0, token1, bytes32(0));
    }
```

**File:** src/base/BasePositions.sol (L331-336)
```text
        } else if (callType == CALL_TYPE_WITHDRAW_PROTOCOL_FEES) {
            (, address token0, address token1, uint128 amount0, uint128 amount1, address recipient) =
                abi.decode(data, (uint256, address, address, uint128, uint128, address));

            CORE.updateSavedBalances(token0, token1, bytes32(0), -int256(uint256(amount0)), -int256(uint256(amount1)));
            ACCOUNTANT.withdrawTwo(token0, token1, recipient, amount0, amount1);
```

**File:** src/Core.sol (L140-151)
```text
            function addDelta(u, i) -> result {
                // full‐width sum mod 2^256
                let sum := add(u, i)
                // 1 if i<0 else 0
                let sign := shr(255, i)
                // if sum > type(uint128).max || (i>=0 && sum<u) || (i<0 && sum>u) ⇒ 256-bit wrap or underflow
                if or(shr(128, sum), or(and(iszero(sign), lt(sum, u)), and(sign, gt(sum, u)))) {
                    mstore(0x00, 0x1293d6fa) // `SavedBalanceOverflow()`
                    revert(0x1c, 0x04)
                }
                result := sum
            }
```

**File:** src/Core.sol (L170-170)
```text
        _updatePairDebtWithNative(id, token0, token1, delta0, delta1);
```

**File:** src/Core.sol (L834-834)
```text
                _updatePairDebtWithNative(locker.id(), token0, token1, balanceUpdate.delta0(), balanceUpdate.delta1());
```
