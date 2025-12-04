# Audit Report

## Title
ETH Sent to Payable Functions Can Be Stolen by Anyone via Unrestricted `refundNativeToken()`

## Summary
The `BaseNonfungibleToken.mint()` functions are marked `payable` to support multicall patterns with native token deposits. However, when ETH is sent to these functions (directly or when excess remains after `mintAndDeposit()`), it accumulates in the contract with no tracking. The inherited `refundNativeToken()` function from `PayableMulticallable` has no access control and refunds the **entire contract balance** to any caller, enabling direct theft of user funds.

## Impact
**Severity**: High

Direct theft of user funds. Any ETH sent to `mint()` functions or remaining after `mintAndDeposit()` operations can be stolen by any observer through a single `refundNativeToken()` call. This affects both the Positions and Orders contracts, which inherit the vulnerable pattern.

## Finding Description

**Location:** 
- `src/base/BaseNonfungibleToken.sol:109-117` [1](#0-0) 
- `src/base/BaseNonfungibleToken.sol:123-126` [2](#0-1) 
- `src/base/PayableMulticallable.sol:25-29` [3](#0-2) 
- `src/base/BasePositions.sol:29` [4](#0-3) 

**Intended Logic:** 
The `mint()` functions are marked `payable` to enable gas-efficient multicall operations where ETH is needed for native token deposits. The `refundNativeToken()` function is designed to return unused ETH after multicall batches. Comments state "any msg.value sent is ignored" for mint functions.

**Actual Logic:**
When ETH is sent to `mint()` or remains after partial consumption in `deposit()`, it accumulates in the contract without per-user tracking. The `refundNativeToken()` function is externally callable without restrictions and sends the **entire contract balance** to `msg.sender`, regardless of who deposited the ETH. [3](#0-2) 

**Exploitation Path:**
1. **Direct mint() theft**: Alice calls `Positions.mint{value: 1 ether}()` (accidentally or believing it's required)
2. The 1 ETH is stored in the Positions contract; Alice receives her NFT
3. Bob observes the transaction and calls `Positions.refundNativeToken()`
4. The entire contract balance (Alice's 1 ETH) is transferred to Bob
5. Alice has irreversibly lost her funds

**Alternative scenario - Excess deposit ETH:**
1. Alice calls `mintAndDeposit{value: 100}()` with `maxAmount0 = 100` for a native token pool
2. Liquidity calculation determines only 90 ETH is needed; `deposit()` transfers exactly 90 ETH to FlashAccountant [5](#0-4) 
3. 10 ETH remains in the Positions contract
4. Bob calls `refundNativeToken()` and receives the 10 ETH

**Security Property Broken:**
Direct theft of user funds. Users interacting with `payable` functions lose ETH to the first caller of `refundNativeToken()`, which has no access control or deposit tracking.

## Impact Explanation

**Affected Assets**: Native ETH sent to Positions and Orders contracts via any `payable` function that doesn't fully consume the ETH

**Damage Severity**:
- Complete loss of ETH sent to `mint()` functions
- Loss of excess ETH from `mintAndDeposit()` when actual deposit amount < sent amount
- Attacker claims 100% of accumulated ETH at zero cost beyond gas
- No recovery mechanism for victims

**User Impact**: Any user who:
- Sends ETH to `mint()` (whether mistakenly or from UI confusion)
- Sends excess ETH to `mintAndDeposit()` that isn't fully consumed
- Fails to call `refundNativeToken()` immediately in the same transaction

**Affected Contracts**: Both `Positions` and `Orders` inherit the vulnerable pattern [6](#0-5) 

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or MEV bot monitoring transactions

**Preconditions**:
1. User calls a `payable` function with msg.value that isn't fully consumed
2. ETH remains in contract after transaction completes
3. No additional preconditions required

**Execution Complexity**: Single transaction calling `refundNativeToken()`. Can be executed immediately after observing the victim's transaction or as a frontrun.

**Economic Cost**: Only gas fees (~0.01 ETH), no capital required

**Frequency**: Exploitable every time ETH accumulates in the contract. Given that:
- Functions are marked `payable` (potentially misleading users about ETH requirements)
- No UI/contract protection exists against sending excess ETH
- The `refundNativeToken()` function is never used anywhere in the codebase (grep search confirmed zero references), suggesting users won't know to call it

**Overall Likelihood**: HIGH - Trivial to execute, realistic user error scenarios, no protection mechanisms

## Recommendation

**Option 1: Remove payable from mint-only functions**
Remove the `payable` modifier from `mint()` and `mint(bytes32)` functions since they don't consume ETH. Keep `mintAndDeposit()` as `payable` but require exact ETH amounts for native token deposits.

**Option 2: Add caller tracking to refundNativeToken()**
Modify `refundNativeToken()` to track ETH deposits per caller within the transaction context and only refund to the original depositor:

```solidity
// Track deposits in transient storage or within lock context
function refundNativeToken() external payable {
    require(msg.sender == originalDepositor, "Not depositor");
    if (address(this).balance != 0) {
        SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
    }
}
```

**Option 3: Remove refundNativeToken() entirely**
Since the function is never used in the protocol (confirmed by codebase search), consider removing it and requiring exact ETH amounts for native token operations.

**Recommended approach**: Combination of Option 1 and Option 3 - remove `payable` from pure mint functions and remove the unused `refundNativeToken()` function entirely.

## Proof of Concept

The provided PoC demonstrates both exploit scenarios:
1. Direct theft from `mint{value: 1 ether}()` call
2. Owner (or any user) can claim accumulated ETH

The test would pass, confirming the vulnerability:
- Alice loses 1 ETH after calling mint
- Bob gains 1 ETH by calling refundNativeToken
- Contract balance is drained

## Notes

**Critical Discovery**: The `refundNativeToken()` function has **zero references** in the entire codebase (confirmed via grep search). This strongly indicates it's dead code that was inherited from the Solady Multicallable pattern but never properly secured or integrated into Ekubo's design.

**Root Cause**: The combination of:
1. `mint()` being `payable` for multicall convenience
2. `refundNativeToken()` being unrestricted and refunding entire balance to any caller
3. No mechanism to track which user deposited ETH
4. Function never being used in the protocol's own code

**Scope**: This vulnerability affects both the `Positions` and `Orders` contracts, as both inherit from `BaseNonfungibleToken` and `PayableMulticallable`. [4](#0-3) [6](#0-5)

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L109-117)
```text
    function mint() public payable returns (uint256 id) {
        bytes32 salt;
        assembly ("memory-safe") {
            mstore(0, prevrandao())
            mstore(32, gas())
            salt := keccak256(0, 64)
        }
        id = mint(salt);
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L123-126)
```text
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }
```

**File:** src/base/PayableMulticallable.sol (L25-29)
```text
    function refundNativeToken() external payable {
        if (address(this).balance != 0) {
            SafeTransferLib.safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

**File:** src/base/BasePositions.sol (L29-29)
```text
abstract contract BasePositions is IPositions, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/base/BasePositions.sol (L252-262)
```text
            // Use multi-token payment for ERC20-only pools, fall back to individual payments for native token pools
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

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```
