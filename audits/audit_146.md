## Title
Position NFTs Can Be Burned With Active Liquidity, Permanently Locking Funds and Violating Withdrawal Invariant

## Summary
The `burn()` function in `BaseNonfungibleToken.sol` allows burning position NFTs without verifying that associated liquidity has been withdrawn. [1](#0-0)  This violates the critical protocol invariant that "All positions MUST be withdrawable at any time," as burning the NFT makes withdrawal impossible without complex reminting procedures that may not always be feasible.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BaseNonfungibleToken.sol` (line 133-135), inherited by `src/Positions.sol` and used in `src/base/BasePositions.sol`

**Intended Logic:** The `burn()` function should allow users to burn NFTs to reclaim gas, with the comment stating it "Can be used to refund some gas after the NFT is no longer needed." [2](#0-1)  The implication is that positions should be fully withdrawn before burning.

**Actual Logic:** The function only checks authorization via the `authorizedForNft(id)` modifier [1](#0-0)  but performs no validation that the position has zero liquidity. Position data is stored in Core contract indexed by `(poolId, address(positions), positionId)` [3](#0-2)  where `positionId` is derived from the NFT ID. [4](#0-3)  Burning the NFT destroys the authorization token but leaves the position data intact in Core.

**Exploitation Path:**
1. User mints position NFT (id=X) and deposits liquidity using `deposit()` or `mintAndDeposit()` [5](#0-4) 
2. Without withdrawing liquidity, user (or approved address) calls `burn(X)` [1](#0-0) 
3. NFT is destroyed via Solady's `_burn(id)`, but position data with active liquidity remains in Core
4. All withdrawal functions require `authorizedForNft(id)` modifier [6](#0-5)  which checks `_isApprovedOrOwner(msg.sender, id)` [7](#0-6) 
5. Since NFT is burned, `ownerOf(id)` reverts, making `_isApprovedOrOwner()` fail for all callers
6. Funds become locked. While reminting with the same salt may theoretically allow recovery, this requires: (a) the original minter to remint, (b) knowledge of the original salt used, which is impossible if `mint()` without salt was used (uses `prevrandao()` and `gas()`) [8](#0-7) , and (c) NFT must not have been transferred to another user

**Security Property Broken:** Violates the critical invariant: "All positions MUST be withdrawable at any time" - positions with burned NFTs cannot be withdrawn without complex reminting procedures that may be impossible in many scenarios.

## Impact Explanation
- **Affected Assets**: All tokens (token0, token1) deposited as liquidity in any position, plus accumulated fees
- **Damage Severity**: Permanent loss of all liquidity and fees in affected positions. For positions minted via `mint()` without salt or transferred NFTs, recovery is impossible. Even when recoverable via reminting, it requires the original minter's action and violates the "at any time" withdrawal guarantee
- **User Impact**: Any user who burns a position NFT (accidentally or intentionally) with active liquidity loses access to those funds. Approved operators could maliciously burn NFTs they're approved for, locking the owner's funds

## Likelihood Explanation
- **Attacker Profile**: Any NFT owner or approved address can trigger this. Malicious approved operators can weaponize this to lock victims' funds
- **Preconditions**: Position must have active liquidity (deposited but not fully withdrawn)
- **Execution Complexity**: Single `burn(id)` transaction - extremely simple
- **Frequency**: Can be exploited on every position NFT with active liquidity. Accidental triggering is also likely given no warnings or checks

## Recommendation
Add liquidity validation before allowing burns:

```solidity
// In src/base/BaseNonfungibleToken.sol, function burn, line 133:

// CURRENT (vulnerable):
function burn(uint256 id) external payable authorizedForNft(id) {
    _burn(id);
}

// FIXED:
function burn(uint256 id) external payable authorizedForNft(id) {
    // Ensure derived contracts can override this with liquidity checks
    _beforeBurn(id);
    _burn(id);
}

// Add virtual hook that BasePositions can override
function _beforeBurn(uint256 id) internal virtual {}
```

Then in `BasePositions.sol`, override to add validation:

```solidity
// Add to BasePositions.sol:

function _beforeBurn(uint256 id) internal override {
    // Note: This doesn't prevent burning entirely, but requires explicit
    // full withdrawal first. For comprehensive protection, would need to
    // track all (poolKey, tickLower, tickUpper) combinations per NFT,
    // which is gas-intensive. Consider documenting that users must
    // withdraw all positions before burning, or implement a registry.
    
    // Minimal check: Revert with helpful message
    revert("Must withdraw all liquidity before burning. Use withdraw() functions first.");
}
```

Alternative: Implement a position registry mapping NFT ID to its active pool/tick combinations, checking all are withdrawn before allowing burn. This requires additional storage but provides complete protection.

## Proof of Concept

```solidity
// File: test/Exploit_BurnWithLiquidity.t.sol
// Run with: forge test --match-test test_burnWithLiquidityLocksF unds -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Positions.sol";
import "../src/Core.sol";
import "./FullTest.sol";

contract Exploit_BurnWithLiquidity is FullTest {
    
    function test_burnWithLiquidityLocksFunds() public {
        // SETUP: Create a pool and mint a position with liquidity
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Mint position and deposit liquidity
        (uint256 id, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, 
            -100, 
            100, 
            1e18, 
            1e18, 
            0
        );
        
        // Verify liquidity exists
        (uint128 currentLiquidity,,,uint128 fees0, uint128 fees1) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertGt(currentLiquidity, 0, "Position should have liquidity");
        
        uint256 balanceBefore0 = token0.balanceOf(address(this));
        uint256 balanceBefore1 = token1.balanceOf(address(this));
        
        // EXPLOIT: Burn the NFT while liquidity is still active
        positions.burn(id);
        
        // VERIFY: Funds are now locked - cannot withdraw
        vm.expectRevert(); // Will revert because NFT doesn't exist
        positions.withdraw(id, poolKey, -100, 100, liquidity);
        
        // Verify funds are still in the protocol (not returned to user)
        uint256 balanceAfter0 = token0.balanceOf(address(this));
        uint256 balanceAfter1 = token1.balanceOf(address(this));
        
        assertEq(balanceBefore0, balanceAfter0, "No token0 returned after burn");
        assertEq(balanceBefore1, balanceAfter1, "No token1 returned after burn");
        
        // Verify position data still exists in Core (liquidity not removed)
        (uint128 lockedLiquidity,,,uint128 lockedFees0, uint128 lockedFees1) = 
            positions.getPositionFeesAndLiquidity(id, poolKey, -100, 100);
        assertEq(lockedLiquidity, currentLiquidity, "Liquidity remains locked in Core");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- NFT burned successfully");
        console.log("- Liquidity still locked:", lockedLiquidity);
        console.log("- Withdrawal impossible - invariant violated");
    }
}
```

## Notes

The security question asked about Solady's `_burn()` making external calls that could revert. My investigation confirmed that Solady's ERC721 implementation does **not** make external calls during burn operations - it only updates internal state. Therefore, the specific concerns about contract owner fallback logic reverting and missing notifications are **not vulnerabilities** in the traditional sense.

However, this investigation uncovered a more severe vulnerability: the lack of liquidity validation before burning creates a direct path to permanent fund loss and violates the critical "Withdrawal Availability" invariant. The `burn()` function's authorization check is insufficient - it verifies *who* can burn but not *when* burning is safe.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L81-86)
```text
    modifier authorizedForNft(uint256 id) {
        if (!_isApprovedOrOwner(msg.sender, id)) {
            revert NotUnauthorizedForToken(msg.sender, id);
        }
        _;
    }
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

**File:** src/base/BaseNonfungibleToken.sol (L129-132)
```text
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
```

**File:** src/base/BaseNonfungibleToken.sol (L133-135)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```

**File:** src/Core.sol (L381-385)
```text
            StorageSlot positionSlot = CoreStorageLayout.poolPositionsSlot(poolId, locker.addr(), positionId);
            Position storage position;
            assembly ("memory-safe") {
                position.slot := positionSlot
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

**File:** src/base/BasePositions.sol (L120-133)
```text
    function withdraw(
        uint256 id,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 liquidity,
        address recipient,
        bool withFees
    ) public payable authorizedForNft(id) returns (uint128 amount0, uint128 amount1) {
        (amount0, amount1) = abi.decode(
            lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
            (uint128, uint128)
        );
    }
```

**File:** src/base/BasePositions.sol (L243-246)
```text
            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
```
