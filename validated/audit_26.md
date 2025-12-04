# Audit Report

## Title
Unrestricted `refundNativeToken()` Enables Direct Theft of ETH Sent to Payable NFT Functions

## Summary
The `BaseNonfungibleToken.mint()` functions are marked `payable` to support multicall patterns, but any ETH sent to these functions (or excess ETH from `mintAndDeposit()` operations) accumulates in the contract with no tracking. The inherited `refundNativeToken()` function has no access control and refunds the **entire contract balance** to any caller, enabling direct theft of user funds.

## Impact
**Severity**: High

Direct theft of user funds. Any ETH sent to `mint()` functions or remaining after `mintAndDeposit()` operations can be stolen by any observer through a single `refundNativeToken()` call. This affects both the Positions and Orders contracts. [1](#0-0) [2](#0-1) 

## Finding Description

**Location:** 
- `src/base/BaseNonfungibleToken.sol` - `mint()` functions (lines 109-117, 123-126)
- `src/base/PayableMulticallable.sol` - `refundNativeToken()` function (lines 25-29)
- Inherited by: `src/base/BasePositions.sol` (line 29), `src/Orders.sol` (line 24)

**Intended Logic:** 
The `mint()` functions are marked `payable` to enable multicall operations where ETH may be needed for native token deposits. The `refundNativeToken()` function is designed to return unused ETH after multicall batches. Function comments state "any msg.value sent is ignored" for mint functions. [3](#0-2) 

**Actual Logic:**
When ETH is sent to `mint()` or remains after partial consumption in native token deposits, it accumulates in the contract without per-user tracking. The `refundNativeToken()` function is externally callable without restrictions and sends the **entire contract balance** to `msg.sender`, regardless of who deposited the ETH. [4](#0-3) 

**Exploitation Paths:**

1. **Direct mint() theft**: 
   - Alice calls `Positions.mint{value: 1 ether}()` (accidentally or believing ETH is required)
   - The 1 ETH is stored in the Positions contract; Alice receives her NFT
   - Bob observes the transaction and calls `Positions.refundNativeToken()`
   - The entire contract balance (Alice's 1 ETH) is transferred to Bob

2. **Excess deposit ETH**:
   - Alice calls `mintAndDeposit{value: 100}()` for a native token pool
   - The `maxLiquidity()` calculation determines actual liquidity
   - Only the exact amount needed (e.g., 90 ETH) is transferred to FlashAccountant
   - 10 ETH remains in the Positions contract
   - Bob calls `refundNativeToken()` and receives the 10 ETH [5](#0-4) [6](#0-5) 

**Security Property Broken:**
Users interacting with `payable` functions lose ETH to the first caller of `refundNativeToken()`, which has no access control or deposit tracking.

## Impact Explanation

**Affected Assets**: Native ETH sent to Positions and Orders contracts via any `payable` function that doesn't fully consume the ETH

**Damage Severity**:
- Complete loss of ETH sent to `mint()` functions
- Loss of excess ETH from `mintAndDeposit()` when actual deposit amount < sent amount  
- Attacker claims 100% of accumulated ETH at zero cost beyond gas
- No recovery mechanism for victims

**User Impact**: Any user who:
- Sends ETH to `mint()` (whether mistakenly or from UI confusion about payable functions)
- Sends excess ETH to `mintAndDeposit()` that isn't fully consumed by liquidity calculations
- Fails to call `refundNativeToken()` immediately in the same transaction

**Affected Contracts**: Both `Positions` and `Orders` inherit the vulnerable pattern through `BaseNonfungibleToken` and `PayableMulticallable`. [7](#0-6) [8](#0-7) 

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user or MEV bot monitoring mempool transactions

**Preconditions**:
1. User calls a `payable` function with msg.value that isn't fully consumed
2. ETH remains in contract after transaction completes
3. No additional preconditions required

**Execution Complexity**: Single transaction calling `refundNativeToken()`. Can be executed immediately after observing the victim's transaction or bundled as a backrun.

**Economic Cost**: Only gas fees (~$0.01-0.10 depending on network), no capital lockup required

**Frequency**: Exploitable every time ETH accumulates. Risk factors:
- Functions marked `payable` may mislead users about ETH requirements
- No UI/contract protection against sending excess ETH
- The `refundNativeToken()` function is **never used anywhere in the codebase** (grep search confirmed zero internal references), suggesting even protocol developers don't use it

**Overall Likelihood**: HIGH - Trivial to execute, realistic user error scenarios, no protection mechanisms

## Recommendation

**Option 1: Remove payable from mint-only functions** (Recommended)
Remove the `payable` modifier from `mint()` and `mint(bytes32)` functions since they don't consume ETH. This prevents users from accidentally sending ETH that can be stolen.

**Option 2: Add access control to refundNativeToken()**
Track ETH deposits per caller and only allow refunds to the original depositor. However, this is complex given the multicall pattern and may require transient storage.

**Option 3: Remove refundNativeToken() entirely** (Recommended)
Since the function is never used in the protocol (confirmed by codebase search showing zero references), remove it entirely and require exact ETH amounts for native token operations.

**Recommended approach**: Combination of Option 1 and Option 3:
1. Remove `payable` modifier from pure `mint()` functions that don't consume ETH
2. Remove the unused and dangerous `refundNativeToken()` function entirely
3. For `mintAndDeposit()` and similar functions, add clear documentation that users must calculate exact ETH amounts needed

## Proof of Concept

Expected behavior in Foundry test:

**Setup**: Deploy Positions contract, fund Alice and Bob with ETH

**Exploit Scenario 1**:
- Before: Alice has 10 ETH, Positions contract has 0 ETH, Bob has 1 ETH
- Alice calls `Positions.mint{value: 1 ether}()`
- After mint: Alice has 9 ETH, Positions has 1 ETH, Bob has 1 ETH  
- Bob calls `Positions.refundNativeToken()`
- Final: Alice has 9 ETH (lost 1 ETH), Positions has 0 ETH, Bob has 2 ETH (gained 1 ETH)

**Exploit Scenario 2**:
- Alice calls `Positions.mintAndDeposit{value: 100 wei}()` for native token pool
- Liquidity calculation requires only 90 wei
- Positions contract has 10 wei remaining
- Bob calls `refundNativeToken()` and receives 10 wei

Both scenarios demonstrate direct theft with no authorization checks.

## Notes

**Critical Discovery**: The `refundNativeToken()` function has **zero references** in the entire codebase. This strongly indicates it's inherited from the Solady Multicallable pattern but never properly integrated or secured for Ekubo's design. [9](#0-8) 

**Root Cause**: The combination of:
1. `mint()` being `payable` for multicall convenience
2. `refundNativeToken()` being unrestricted and refunding entire balance to any caller  
3. No mechanism to track which user deposited ETH
4. Function never being used in the protocol's own code

**Design Intent vs Implementation**: The comment suggests the function is for "transient payments" within a multicall, but there's no enforcement that it's called in the same transaction, and there's no tracking of who sent the ETH.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L104-108)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Generates a salt using prevrandao() and gas() for pseudorandomness.
    ///      Note: This can encounter conflicts if a sender sends two identical transactions
    ///      in the same block that consume exactly the same amount of gas.
    ///      No fees are collected; any msg.value sent is ignored.
```

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

**File:** src/base/PayableMulticallable.sol (L21-23)
```text
    /// @notice Refunds any remaining native token balance to the caller
    /// @dev Allows callers to recover ETH that was sent for transient payments but not fully consumed
    ///      This is useful when exact payment amounts are difficult to calculate in advance
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

**File:** src/math/liquidity.sol (L90-96)
```text
function maxLiquidity(
    SqrtRatio _sqrtRatio,
    SqrtRatio sqrtRatioA,
    SqrtRatio sqrtRatioB,
    uint128 amount0,
    uint128 amount1
) pure returns (uint128) {
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```
