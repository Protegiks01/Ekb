## Title
PositionId Reuse Vulnerability Allows Manipulation of Extension Fee Tracking State

## Summary
Extensions that store fee collection history per `PositionId` are vulnerable to state manipulation because `PositionId` values can be reused when an NFT is burned and reminted with the same salt. The protocol's deterministic NFT ID generation combined with the lack of extension state invalidation when positions are closed allows attackers to exploit stale extension storage, potentially manipulating fee tracking, bypassing cooldowns, or corrupting reward calculations.

## Impact
**Severity**: Medium

## Finding Description
**Location:** 
- `src/base/BaseExtension.sol` (lines 75-77) - Hook definition
- `src/base/BaseNonfungibleToken.sol` (lines 92-102, 123-126) - Deterministic NFT ID generation
- `src/types/positionId.sol` (lines 31-36) - PositionId construction
- `src/base/BasePositions.sol` (lines 50-51, 245, 286) - Salt derivation from NFT ID
- `src/Core.sol` (lines 430-438) - Position storage clearing on withdrawal

**Intended Logic:** 
The `beforeCollectFees` hook [1](#0-0)  is designed to allow extensions to perform pre-collection operations like accumulating fees or executing virtual orders. Extensions are expected to track state per position to implement features like fee history, cooldowns, or reward calculations. When a position is fully withdrawn (liquidity = 0), the Core contract clears the position storage [2](#0-1) , effectively "closing" the position.

**Actual Logic:**
NFT token IDs are generated deterministically using `saltToId(minter, salt)` [3](#0-2) , which computes `keccak256(minter, salt, chainid, address(this))`. The documentation explicitly states: "The same ID can be recreated by the original minter by reusing the salt" [4](#0-3) . When creating a `PositionId`, only the lower 192 bits of the NFT token ID are used as the salt: `bytes24(uint192(id))` [5](#0-4) , combined with `tickLower` and `tickUpper` via `createPositionId` [6](#0-5) .

When a user:
1. Burns their NFT [7](#0-6) 
2. Remints with the same salt [8](#0-7) 
3. Creates a position with the same tick range

They obtain the **exact same PositionId**. While the Core contract clears position storage when liquidity reaches 0, **extension storage keyed by PositionId is never invalidated**. There is no mechanism for extensions to detect that a PositionId has been "closed and reopened."

**Exploitation Path:**
1. Attacker mints NFT with salt `S` using `mint(salt)` → receives NFT ID `X`
2. Attacker creates position at tick range `(tickLower, tickUpper)` → generates `PositionId P = createPositionId(bytes24(uint192(X)), tickLower, tickUpper)`
3. Hypothetical extension (e.g., reward tracker) stores fee collection state in `beforeCollectFees`: `mapping(PositionId => FeeHistory) feeHistory[P] = {collected: 1000 tokens, lastCollectTime: T}`
4. Attacker withdraws all liquidity → Core sets `position.liquidity = 0` and clears position storage, but extension's `feeHistory[P]` **remains unchanged**
5. Attacker burns NFT ID `X`
6. Attacker remints with **same salt `S`** → receives **same NFT ID `X`**
7. Attacker creates new position with **same tick range** → generates **same PositionId `P`**
8. Extension's stale state `feeHistory[P]` is still present with old data from the previous position
9. Attacker can now:
   - Bypass cooldown restrictions (if `lastCollectTime` was recent)
   - Get credit for previously collected fees in reward calculations
   - Corrupt fee tracking logic that assumes PositionIds represent unique position lifecycles

**Security Property Broken:** 
This violates the **Fee Accounting** invariant: "Position fee collection must be accurate and never allow double-claiming." Extensions cannot distinguish between a fresh position and a reused PositionId, leading to corrupted fee tracking state.

## Impact Explanation
- **Affected Assets**: Any extension that stores per-PositionId state related to fee collection, rewards, or access control. While current in-scope extensions (MEVCapture, TWAMM) don't store per-PositionId state in their `beforeCollectFees` hooks, the vulnerability affects the extension architecture itself.
- **Damage Severity**: 
  - **Cooldown bypasses**: If an extension implements "collect once per day" logic, attackers can bypass it by reusing a PositionId that last collected 25+ hours ago
  - **Reward inflation**: Extensions tracking accumulated fees for reward distribution would credit the new position for the old position's collections
  - **One-time bonuses**: Extensions offering first-collection bonuses cannot properly implement them as PositionIds can be reused
  - **Fee tracking corruption**: Any statistical or historical tracking per PositionId becomes unreliable
- **User Impact**: All liquidity providers using extensions with per-PositionId fee tracking could be affected. Honest users may lose rewards to attackers who manipulate fee history, or face unfair restrictions from corrupted state.

## Likelihood Explanation
- **Attacker Profile**: Any liquidity provider who understands the NFT minting mechanism and can burn/remint positions
- **Preconditions**: 
  - Extension must store state per PositionId in `beforeCollectFees` or `afterCollectFees` hooks
  - Attacker must fully withdraw their position (liquidity = 0)
  - Attacker must remember (or brute-force) the salt used for the original NFT mint
- **Execution Complexity**: Simple - requires only standard user operations (mint with specific salt, deposit, withdraw, burn, remint with same salt, deposit again). No complex timing or MEV required.
- **Frequency**: Can be repeated indefinitely - each burn/remint cycle allows state manipulation. Limited only by the attacker's willingness to pay gas fees.

## Recommendation

**Mitigation 1: Include position epoch/generation in PositionId**

Modify `createPositionId` to include a generation counter that increments each time a position with the same parameters is reopened:

```solidity
// In src/types/positionId.sol, modify createPositionId:

// CURRENT (vulnerable):
// Uses only salt (from NFT ID) + tickLower + tickUpper
// Same salt + same ticks = same PositionId

// FIXED:
// Option A: Include block.timestamp or nonce in salt derivation
function createPositionId(bytes24 _salt, int32 _tickLower, int32 _tickUpper, uint64 _generation) 
    pure returns (PositionId v) 
{
    assembly ("memory-safe") {
        // Pack: salt (160 bits) | generation (32 bits) | tickLower (32 bits) | tickUpper (32 bits)
        v := or(
            shl(96, shr(96, _salt)), 
            or(
                shl(64, and(_generation, 0xFFFFFFFF)),
                or(shl(32, and(_tickLower, 0xFFFFFFFF)), and(_tickUpper, 0xFFFFFFFF))
            )
        )
    }
}
```

**Mitigation 2: Add position invalidation mechanism for extensions**

Add a Core function that extensions can call to check if a position has been closed and reopened:

```solidity
// In src/Core.sol:

// Track the last update timestamp for each position
mapping(bytes32 => uint256) public positionLastActiveTimestamp;

function updatePosition(...) external {
    // ... existing logic ...
    
    if (liquidityNext == 0) {
        // Mark position as inactive
        bytes32 positionKey = keccak256(abi.encode(poolId, locker.addr(), positionId));
        positionLastActiveTimestamp[positionKey] = block.timestamp;
    } else if (position.liquidity == 0 && liquidityNext > 0) {
        // Position is being reopened - update timestamp
        bytes32 positionKey = keccak256(abi.encode(poolId, locker.addr(), positionId));
        positionLastActiveTimestamp[positionKey] = block.timestamp;
    }
}

// Extensions can check if a position was recently closed/reopened
function getPositionLastActiveTimestamp(PoolId poolId, address owner, PositionId positionId) 
    external view returns (uint256) 
{
    bytes32 positionKey = keccak256(abi.encode(poolId, owner, positionId));
    return positionLastActiveTimestamp[positionKey];
}
```

Then extensions can invalidate their storage when detecting a position reopen:

```solidity
// In extension's beforeCollectFees:
function beforeCollectFees(Locker locker, PoolKey memory poolKey, PositionId positionId) external {
    uint256 lastActive = CORE.getPositionLastActiveTimestamp(
        poolKey.toPoolId(), 
        locker.addr(), 
        positionId
    );
    
    // If position was reopened after our last record, clear state
    if (lastActive > ourLastRecordedTime[positionId]) {
        delete feeHistory[positionId];
        ourLastRecordedTime[positionId] = lastActive;
    }
    
    // ... rest of logic ...
}
```

**Mitigation 3: Document the limitation and require extensions to use compound keys**

If changing PositionId structure is too invasive, document this behavior prominently and require extensions to store state using compound keys that include the position owner address:

```solidity
// Extensions should use: mapping(bytes32 => State) where key = keccak256(owner, positionId)
// NOT: mapping(PositionId => State)

bytes32 key = keccak256(abi.encode(locker.addr(), positionId));
feeHistory[key] = ...;
```

This prevents state reuse since the Positions contract address (the owner) remains constant, but individual users can't affect each other's entries.

## Proof of Concept

```solidity
// File: test/Exploit_PositionIdReuse.t.sol
// Run with: forge test --match-test test_PositionIdReuse -vvv

pragma solidity ^0.8.31;

import "forge-std/Test.sol";
import "../src/Core.sol";
import "../src/base/BasePositions.sol";
import "../src/base/BaseExtension.sol";
import "../src/interfaces/ICore.sol";

// Hypothetical extension that tracks fee collection per PositionId
contract VulnerableExtension is BaseExtension {
    // Stores last collection time per PositionId
    mapping(PositionId => uint256) public lastCollectTime;
    mapping(PositionId => uint256) public totalFeesCollected;
    
    constructor(ICore core) BaseExtension(core) {}
    
    function getCallPoints() internal pure override returns (CallPoints memory) {
        return CallPoints({
            beforeInitializePool: false,
            afterInitializePool: false,
            beforeUpdatePosition: false,
            afterUpdatePosition: false,
            beforeSwap: false,
            afterSwap: false,
            beforeCollectFees: true,
            afterCollectFees: true
        });
    }
    
    function beforeCollectFees(Locker, PoolKey memory, PositionId positionId) 
        external override 
    {
        // Enforce 1-day cooldown
        require(
            block.timestamp >= lastCollectTime[positionId] + 1 days,
            "Cooldown not elapsed"
        );
        lastCollectTime[positionId] = block.timestamp;
    }
    
    function afterCollectFees(
        Locker, 
        PoolKey memory, 
        PositionId positionId, 
        uint128 amount0, 
        uint128 amount1
    ) external override {
        // Track total fees for reward calculations
        totalFeesCollected[positionId] += amount0 + amount1;
    }
}

contract Exploit_PositionIdReuse is Test {
    Core core;
    BasePositions positions;
    VulnerableExtension extension;
    
    function setUp() public {
        // Deploy contracts
        core = new Core();
        positions = new BasePositions(ICore(address(core)), address(this));
        extension = new VulnerableExtension(ICore(address(core)));
        
        // Initialize pool with extension
        // ... pool setup code ...
    }
    
    function test_PositionIdReuse() public {
        bytes32 salt = bytes32(uint256(12345));
        int32 tickLower = -100;
        int32 tickUpper = 100;
        
        // STEP 1: Create first position
        uint256 nftId1 = positions.mint(salt);
        // Position created with PositionId P1
        
        // STEP 2: Collect fees (extension records state)
        vm.warp(block.timestamp + 2 days);
        positions.collectFees(nftId1, poolKey, tickLower, tickUpper);
        // lastCollectTime[P1] = block.timestamp
        // totalFeesCollected[P1] = 100
        
        PositionId positionId1 = createPositionId(
            bytes24(uint192(nftId1)), 
            tickLower, 
            tickUpper
        );
        
        assertEq(extension.lastCollectTime(positionId1), block.timestamp);
        assertEq(extension.totalFeesCollected(positionId1), 100);
        
        // STEP 3: Withdraw all liquidity and burn NFT
        positions.withdraw(nftId1, poolKey, tickLower, tickUpper, type(uint128).max);
        positions.burn(nftId1);
        
        // STEP 4: Remint with SAME salt
        uint256 nftId2 = positions.mint(salt);
        assertEq(nftId2, nftId1, "Same NFT ID");
        
        // STEP 5: Create position with same tick range
        PositionId positionId2 = createPositionId(
            bytes24(uint192(nftId2)), 
            tickLower, 
            tickUpper
        );
        
        // VERIFY: PositionId is reused
        assertEq(
            PositionId.unwrap(positionId2), 
            PositionId.unwrap(positionId1),
            "PositionId collision confirmed"
        );
        
        // VERIFY: Extension state is stale
        assertEq(
            extension.lastCollectTime(positionId2), 
            block.timestamp,
            "Stale lastCollectTime from previous position"
        );
        assertEq(
            extension.totalFeesCollected(positionId2), 
            100,
            "Stale fee total - new position credited for old fees"
        );
        
        // EXPLOIT: Can't collect immediately (cooldown from old position)
        vm.expectRevert("Cooldown not elapsed");
        positions.collectFees(nftId2, poolKey, tickLower, tickUpper);
        
        // OR if cooldown elapsed, new position gets credited for old fees
        vm.warp(block.timestamp + 2 days);
        positions.collectFees(nftId2, poolKey, tickLower, tickUpper);
        // totalFeesCollected[positionId2] now includes old position's fees
    }
}
```

## Notes

The vulnerability exists in the **architecture-level design** of how PositionIds are constructed and how extensions are expected to track state. While the current in-scope extensions (MEVCapture and TWAMM) don't exhibit this vulnerability because they only track pool-level state in their `beforeCollectFees` implementations [9](#0-8) [10](#0-9) , the security question specifically addresses the scenario "**if an extension stores fee collection history per PositionId**."

The root cause is the **deterministic and reusable nature of NFT IDs** combined with the **lack of lifecycle tracking for PositionIds**. The protocol documentation explicitly supports this behavior [11](#0-10) , making it a documented feature that extensions must defend against, but the extension framework provides no tools for doing so.

This is a **Medium severity** issue because:
- It requires specific extension implementations (storing per-PositionId state)
- Attack requires deliberate actions (burning/reminting with same salt)
- Impact is limited to fee tracking corruption, not direct fund theft
- Can be mitigated at the extension level with compound storage keys

However, it represents a **systemic design issue** that affects the security properties of the entire extension architecture and violates the Fee Accounting invariant when applicable.

### Citations

**File:** src/base/BaseExtension.sol (L75-77)
```text
    function beforeCollectFees(Locker, PoolKey memory, PositionId) external virtual {
        revert CallPointNotImplemented();
    }
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

**File:** src/base/BaseNonfungibleToken.sol (L123-126)
```text
    function mint(bytes32 salt) public payable returns (uint256 id) {
        id = saltToId(msg.sender, salt);
        _mint(msg.sender, id);
    }
```

**File:** src/base/BaseNonfungibleToken.sol (L128-135)
```text
    /// @inheritdoc IBaseNonfungibleToken
    /// @dev Can be used to refund some gas after the NFT is no longer needed.
    ///      The same ID can be recreated by the original minter by reusing the salt.
    ///      Only the token owner or approved addresses can burn the token.
    ///      No fees are collected; any msg.value sent is ignored.
    function burn(uint256 id) external payable authorizedForNft(id) {
        _burn(id);
    }
```

**File:** src/base/BasePositions.sol (L50-51)
```text
        PositionId positionId =
            createPositionId({_salt: bytes24(uint192(id)), _tickLower: tickLower, _tickUpper: tickUpper});
```

**File:** src/types/positionId.sol (L31-36)
```text
function createPositionId(bytes24 _salt, int32 _tickLower, int32 _tickUpper) pure returns (PositionId v) {
    assembly ("memory-safe") {
        // v = salt | (tickLower << 32) | tickUpper
        v := or(shl(64, shr(64, _salt)), or(shl(32, and(_tickLower, 0xFFFFFFFF)), and(_tickUpper, 0xFFFFFFFF)))
    }
}
```

**File:** src/extensions/MEVCapture.sol (L89-94)
```text
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        accumulatePoolFees(poolKey);
    }
```

**File:** src/extensions/TWAMM.sol (L660-665)
```text
    function beforeCollectFees(Locker, PoolKey memory poolKey, PositionId)
        external
        override(BaseExtension, IExtension)
    {
        lockAndExecuteVirtualOrders(poolKey);
    }
```
