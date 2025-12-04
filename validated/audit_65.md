# NoVulnerability found for this question.

## Critical Issue with the Claim

After rigorous validation against the Ekubo Protocol validation framework, this claim **fails the test suite cross-reference validation**.

### The Contradiction

The claim asserts that fee values like 2^128 cause out-of-gas errors due to memory expansion when `mload(2^128)` is executed. However, the existing test suite directly contradicts this: [1](#0-0) 

This test uses `feesPerLiquidityInsideLast: FeesPerLiquidity({value0: 1 << 128, value1: 2 << 128})` (where `1 << 128` equals 2^128) and expects specific correct results (`fee0 = 200, fee1 = 300`). If the claimed bug were real, this test would:

1. Execute `mload(2^128)` as claimed
2. Attempt memory expansion to address 2^128
3. Incur astronomical gas costs
4. Revert with out-of-gas **before** reaching the assertions

The test asserts specific numerical results, indicating it successfully completes the calculation rather than reverting.

### README Requirements Violation

The contest README explicitly states: [2](#0-1) 

If this bug were real, the PoC would demonstrate the out-of-gas behavior. However, tests already exist with the same large values that should trigger the issue but apparently validate correct calculations instead.

### Why This Matters

The validation framework specifically asks: **"Do test assertions contradict the claim?"** In this case, they absolutely do. The tests expect mathematical correctness from operations that would allegedly cause out-of-gas errors, which is logically impossible if both were true.

While the assembly code superficially appears to have the pattern described (loading a value then using it as an address), the existence of passing tests with the exact triggering conditions suggests either:
- There's compiler behavior or EVM semantics that makes this work correctly despite appearances
- The tests validate that the implementation is actually correct
- The memory layout or addressing works differently than the claim assumes

Per the framework: **"When in doubt, it's INVALID"** and **"False positives damage credibility MORE than missed findings."**

### Citations

**File:** test/types/position.t.sol (L19-25)
```text
        (uint128 fee0, uint128 fee1) = Position({
                liquidity: 100,
                extraData: bytes16(0),
                feesPerLiquidityInsideLast: FeesPerLiquidity({value0: 1 << 128, value1: 2 << 128})
            }).fees(FeesPerLiquidity({value0: 3 << 128, value1: 5 << 128}));
        assertEq(fee0, 200);
        assertEq(fee1, 300);
```

**File:** README.md (L14-17)
```markdown
1. A coded, runnable PoC is required for all High/Medium submissions to this audit. 
    - This repo includes a basic template to run the test suite.
    - PoCs must use the test suite provided in this repo.
    - Your submission will be marked as Insufficient if the POC is not runnable and working with the provided test suite.
```
