# NoVulnerability found for this question.

After thorough investigation of the MEVCapture extension's fee accumulation mechanism, I conclude that the unchecked addition in `saveDelta0`/`saveDelta1` **cannot** overflow `type(int256).max` silently.

## Analysis Summary

**Mathematical Bounds:**

The `saveDelta0` and `saveDelta1` variables are local variables that reset to zero at the start of each `handleForwardData` call. [1](#0-0) 

Within a single execution, these variables are modified at most twice:

1. **First modification (lines 198-199):** Subtracts accumulated fees from storage
   - `fees0` and `fees1` are `uint128` values (maximum: 2^128-1)
   - After subtraction: `saveDelta0 ∈ [-(2^128-1), 0]` [2](#0-1) 

2. **Second modification (lines 226, 234, 242, 248):** Adds additional MEV capture fees
   - `fee` is `int128` (maximum: 2^127-1), enforced by `SafeCastLib.toInt128`
   - Only ONE of these lines executes per swap (either token0 OR token1) [3](#0-2) 

**Maximum Possible Values:**
- Worst-case negative: `-(2^128-1) + (2^127-1) = -2^127` (approximately -1.7 × 10^38)
- Worst-case positive: `2^127-1` (approximately 1.7 × 10^38)
- `int256` range: `-2^255` to `2^255-1` (approximately ±5.8 × 10^76)

The maximum achievable values represent only **0.0000000000000000000000000000000000000029%** of the `int256` range. Mathematical overflow of `int256.max` is **impossible** with these constraints.

**Additional Protection Layer:**

Even if overflow were somehow possible, the `updateSavedBalances` function in Core.sol contains explicit overflow checks via the internal `addDelta` assembly function that reverts with `SavedBalanceOverflow()` if the resulting saved balance exceeds `uint128.max`. [4](#0-3)  This means any overflow would **NOT be silent**—it would revert the transaction.

**Test Coverage:**

The existing test suite confirms this protection works correctly, with tests specifically covering overflow scenarios that demonstrate the revert behavior. [5](#0-4) 

The comment on line 197 stating "never overflows int256 container" is mathematically accurate. [6](#0-5) 

## Notes

The unchecked block is safe here because:
1. Type constraints ensure values cannot approach `int256` boundaries
2. Local variable scope prevents cross-transaction accumulation  
3. A secondary safeguard exists at the `updateSavedBalances` level that would catch any theoretical overflow (though unreachable with current constraints)

### Citations

**File:** src/extensions/MEVCapture.sol (L188-189)
```text
            int256 saveDelta0;
            int256 saveDelta1;
```

**File:** src/extensions/MEVCapture.sol (L197-197)
```text
                    // never overflows int256 container
```

**File:** src/extensions/MEVCapture.sol (L198-199)
```text
                    saveDelta0 -= int256(uint256(fees0));
                    saveDelta1 -= int256(uint256(fees1));
```

**File:** src/extensions/MEVCapture.sol (L224-226)
```text
                        int128 fee = SafeCastLib.toInt128(amountBeforeFee(inputAmount, additionalFee) - inputAmount);

                        saveDelta0 += fee;
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

**File:** test/Core.t.sol (L239-260)
```text
    function test_overflow_always_fails(bytes32 salt, int128 delta0, int128 delta1) public {
        delta0 = int128(bound(delta0, 1, type(int128).max));
        delta1 = int128(bound(delta0, 1, type(int128).max));

        // first get it to max
        updateSavedBalances(address(token0), address(token1), salt, type(int128).max, type(int128).max);
        updateSavedBalances(address(token0), address(token1), salt, type(int128).max, type(int128).max);
        updateSavedBalances(address(token0), address(token1), salt, 1, 1);

        (uint128 s0, uint128 s1) = core.savedBalances(address(this), address(token0), address(token1), salt);
        assertEq(s0, type(uint128).max);
        assertEq(s1, type(uint128).max);

        vm.expectRevert(ICore.SavedBalanceOverflow.selector);
        updateSavedBalances(address(token0), address(token1), salt, delta0, delta1);

        vm.expectRevert(ICore.SavedBalanceOverflow.selector);
        updateSavedBalances(address(token0), address(token1), salt, delta0, 0);

        vm.expectRevert(ICore.SavedBalanceOverflow.selector);
        updateSavedBalances(address(token0), address(token1), salt, 0, 1);

```
