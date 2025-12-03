# NoVulnerability found for this question.

After extensive investigation of the Ekubo Protocol codebase, I found **no exploitable vulnerability** related to the security question about `mcopy` reading from incorrect memory locations in CoreLib.swap.

## Investigation Summary

I conducted a comprehensive analysis of:

**1. CoreLib.swap Memory Operations** [1](#0-0) 

The function uses `mcopy(add(free, 4), poolKey, 96)` at line 134 to copy the PoolKey struct. The theoretical concern was that if `poolKey` pointed to memory at or near the `free` pointer location, the prior `mstore(free, 0)` at line 131 could corrupt the poolKey data before copying.

**2. Solidity Memory Allocation Guarantees**

In Solidity's memory model, when a function receives a `PoolKey memory poolKey` parameter, the compiler:
- Allocates memory for the parameter at the current free pointer location
- Updates the free pointer to point past the allocated memory
- The parameter variable contains the pointer to the allocated memory

Therefore, `poolKey` will **always** point to memory allocated BEFORE the current free pointer value. For `poolKey` to equal `free` would require impossible memory state.

**3. Free Pointer Manipulation Analysis** [2](#0-1) 

I discovered that FlashAccountantLib temporarily writes token addresses to memory location 0x40 (the free pointer location) as a gas optimization. However, this pattern:
- Always saves and restores the free pointer value
- Only affects the calling contract's memory context
- External calls during reentrancy receive fresh memory contexts
- Does not provide a realistic attack path to corrupt poolKey allocation

**4. Memory Safety Protections** [3](#0-2) 

The codebase explicitly handles memory safety concerns, as evidenced by comments about preventing Solidity from accessing corrupted free memory pointers.

**5. Function Access Control** [4](#0-3) 

CoreLib.swap is marked `internal`, preventing external attackers from calling it with manually crafted memory pointers.

## Notes

While the question raises a valid theoretical concern about memory safety in assembly operations, the Ekubo Protocol's implementation follows proper Solidity memory conventions. The use of `("memory-safe")` annotations throughout assembly blocks and careful memory management prevents the scenario where `mcopy` would read from incorrect memory locations. The temporary free pointer corruption in FlashAccountantLib is a known optimization pattern that doesn't create exploitable vulnerabilities due to memory context isolation between external calls.

### Citations

**File:** src/libraries/CoreLib.sol (L123-148)
```text
    function swap(ICore core, uint256 value, PoolKey memory poolKey, SwapParameters params)
        internal
        returns (PoolBalanceUpdate balanceUpdate, PoolState stateAfter)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)

            // the function selector of swap is 0
            mstore(free, 0)

            // Copy PoolKey
            mcopy(add(free, 4), poolKey, 96)

            // Add SwapParameters
            mstore(add(free, 100), params)

            if iszero(call(gas(), core, value, free, 132, free, 64)) {
                returndatacopy(free, 0, returndatasize())
                revert(free, returndatasize())
            }

            // Extract return values - balanceUpdate is packed (delta1 << 128 | delta0)
            balanceUpdate := mload(free)
            stateAfter := mload(add(free, 32))
        }
    }
```

**File:** src/libraries/FlashAccountantLib.sol (L126-189)
```text
        assembly ("memory-safe") {
            // Save free memory pointer before using 0x40
            let free := mload(0x40)

            // accountant.startPayments() with both tokens
            mstore(0x00, 0xf9b6a796) // startPayments selector
            mstore(0x20, token0) // first token
            mstore(0x40, token1) // second token

            // Call startPayments with both tokens (4 + 32 + 32 = 68 bytes)
            pop(call(gas(), accountant, 0, 0x1c, 68, 0x00, 0x00))

            // Restore free memory pointer
            mstore(0x40, free)

            // Transfer token0 from caller to accountant
            if amount0 {
                let m := mload(0x40)
                mstore(0x60, amount0)
                mstore(0x40, accountant)
                mstore(0x2c, shl(96, from))
                mstore(0x0c, 0x23b872dd000000000000000000000000) // transferFrom selector
                let success := call(gas(), token0, 0, 0x1c, 0x64, 0x00, 0x20)
                if iszero(and(eq(mload(0x00), 1), success)) {
                    if iszero(lt(or(iszero(extcodesize(token0)), returndatasize()), success)) {
                        mstore(0x00, 0x7939f424) // TransferFromFailed()
                        revert(0x1c, 0x04)
                    }
                }
                mstore(0x60, 0)
                mstore(0x40, m)
            }

            // Transfer token1 from caller to accountant
            if amount1 {
                let m := mload(0x40)
                mstore(0x60, amount1)
                mstore(0x40, accountant)
                mstore(0x2c, shl(96, from))
                mstore(0x0c, 0x23b872dd000000000000000000000000) // transferFrom selector
                let success := call(gas(), token1, 0, 0x1c, 0x64, 0x00, 0x20)
                if iszero(and(eq(mload(0x00), 1), success)) {
                    if iszero(lt(or(iszero(extcodesize(token1)), returndatasize()), success)) {
                        mstore(0x00, 0x7939f424) // TransferFromFailed()
                        revert(0x1c, 0x04)
                    }
                }
                mstore(0x60, 0)
                mstore(0x40, m)
            }

            // accountant.completePayments() with both tokens
            let free2 := mload(0x40)
            mstore(0x00, 0x12e103f1) // completePayments selector
            mstore(0x20, token0) // first token
            mstore(0x40, token1) // second token

            // Call completePayments with both tokens (4 + 32 + 32 = 68 bytes)
            pop(call(gas(), accountant, 0, 0x1c, 68, 0x00, 0x00))

            // Restore free memory pointer
            mstore(0x40, free2)
        }
    }
```

**File:** src/base/FlashAccountant.sol (L378-380)
```text
            // we return from assembly so as to prevent solidity from accessing the free memory pointer after we have written into it
            return(0, 0)
        }
```
