# NoVulnerability found for this question.

After deep investigation of the `Core.accumulateAsFees` function and its assembly block at lines 236-239, I must report my findings:

## Analysis Summary

The security question asks whether the assembly could "truncate high bits, allowing an attacker to accumulate less fees than they owe." My investigation reveals:

**The assembly does NOT truncate high bits** - it preserves them via direct assignment (`amount0 := _amount0`). [1](#0-0) 

While this represents a deviation from the defensive masking pattern used elsewhere in the codebase (e.g., `swapParameters.sol` applies explicit masking: `and(_amount, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)`), [2](#0-1)  and the README explicitly warns about dirty bits, [3](#0-2)  this specific issue falls outside the audit's valid scope for the following reasons:

## Why This Is Out of Scope

1. **Trusted Extension Assumption**: The function enforces `require(lockerAddr == poolKey.config.extension())` [4](#0-3) , meaning only the pool's designated extension can call it. While an attacker could deploy a malicious extension to their own pool, this attack vector requires the extension itself to be malicious.

2. **Third-Party Extension Risk Acknowledgment**: The README states "Third-party extensions, however, can freeze a pool and lock deposited user capital. This is considered an acceptable risk." [5](#0-4)  This indicates the protocol accepts risks from malicious custom extensions.

3. **Standard Solidity ABI Protection**: When called normally through Solidity's external function interface, the ABI decoder ensures uint128 parameters are properly bounded. The vulnerability would only manifest if an extension uses raw assembly to craft malicious calldata - which represents malicious extension behavior, not a Core contract vulnerability per se.

4. **Scope Boundary**: The trust model states "DO NOT assume trusted roles act maliciously. Focus on unprivileged attackers." [3](#0-2)  Extensions have privileged access to their pools by design.

## Notes

While the missing bit masking represents a **code quality issue** and defensive programming best practice would dictate adding `and(_amount0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)` masks in the assembly block, the actual exploitability requires a malicious extension - which crosses into third-party extension misbehavior territory that is explicitly acknowledged as out-of-scope.

The in-scope extensions (TWAMM, MEVCapture, Oracle) all call `accumulateAsFees` using normal Solidity syntax with properly-typed uint128 values, [6](#0-5) [7](#0-6)  which provides ABI-level protection against dirty bits.

### Citations

**File:** src/Core.sol (L230-230)
```text
        require(lockerAddr == poolKey.config.extension());
```

**File:** src/Core.sol (L236-239)
```text
        assembly ("memory-safe") {
            amount0 := _amount0
            amount1 := _amount1
        }
```

**File:** src/types/swapParameters.sol (L53-53)
```text
                shl(32, and(_amount, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)),
```

**File:** README.md (L50-50)
```markdown
Third-party extensions, however, can freeze a pool and lock deposited user capital. This is considered an acceptable risk.
```

**File:** README.md (L196-196)
```markdown
We use a custom storage layout and also regularly use stack values without cleaning bits and make extensive use of assembly for optimization. All assembly blocks should be treated as suspect and inputs to functions that are used in assembly should be checked that they are always cleaned beforehand if not cleaned in the function. The ABDK audit points out many cases where we assume the unused bits in narrow types (e.g. the most significant 160 bits in a uint96) are cleaned.
```

**File:** src/extensions/MEVCapture.sol (L139-139)
```text
            CORE.accumulateAsFees(poolKey, fees0, fees1);
```

**File:** src/extensions/TWAMM.sol (L323-326)
```text
                        CORE.accumulateAsFees(poolKey, 0, fee);
                        CORE.updateSavedBalances(poolKey.token0, poolKey.token1, bytes32(0), 0, amountDelta);
                    } else {
                        CORE.accumulateAsFees(poolKey, fee, 0);
```
