# NoVulnerability found for this question.

## Analysis

After rigorous validation against the Ekubo security framework, this claim is **INVALID** due to explicitly documented, intentional design behavior.

### Critical Findings:

**1. Explicit Documentation**

The interface explicitly documents this behavior: [1](#0-0) 

The NatSpec clearly states: **"Collects accumulated fees from a position to msg.sender"**. The function does exactly what it documents - this is not a bug, it's the specified behavior.

**2. Alternative Safe Method Exists**

The contract provides TWO overloads:
- Convenience overload (no recipient): [2](#0-1) 
- Explicit recipient overload: [3](#0-2) 

The position owner can ALWAYS use the explicit recipient overload to collect fees to themselves, even when an operator is approved. The owner maintains full control.

**3. Consistent Design Pattern**

This pattern is consistent across ALL authorized operations:
- `deposit()` takes tokens FROM msg.sender [4](#0-3) 
- `withdraw()` sends tokens TO msg.sender [5](#0-4) 
- `collectFees()` sends tokens TO msg.sender

The design philosophy is: **authorization allows position management using the caller's address as source/destination**. This is intentional and coherent.

**4. Authorization is Explicit**

The authorization modifier correctly uses standard ERC721 semantics: [6](#0-5) 

Granting ERC721 approval is a powerful action that requires explicit user action (`approve()` or `setApprovalForAll()`). Users are responsible for understanding what they authorize.

**5. Not a Known Issue**

The behavior is not mentioned in the README's "Publicly known issues" section, which would list it if it were an unintended design flaw or accepted risk.

### Why This is NOT a Vulnerability:

1. **Documented Behavior**: The interface explicitly states fees go "to msg.sender"
2. **User Has Control**: Owner can use explicit recipient overload to maintain control
3. **Consistent Design**: Pattern matches across all authorized operations
4. **Explicit Authorization Required**: User must explicitly grant approval
5. **No Invariant Violation**: Pool solvency and withdrawal availability are maintained

### Distinction from Vulnerability:

- **Vulnerability**: Code behaves contrary to its documentation or reasonable expectations
- **This Case**: Code behaves exactly as documented; users must understand approval implications

This is a **user education issue**, not a **code security issue**. While the behavior may be counter-intuitive to users expecting "act on behalf of" semantics, it is explicitly documented and intentionally designed.

**Conclusion**: The claim fails the validation framework requirement that "State change is UNAUTHORIZED" - the behavior is explicitly authorized, documented, and intentional.

### Citations

**File:** src/interfaces/IPositions.sol (L59-69)
```text
    /// @notice Collects accumulated fees from a position to msg.sender
    /// @param id The NFT token ID representing the position
    /// @param poolKey Pool key identifying the pool
    /// @param tickLower Lower tick of the price range of the position
    /// @param tickUpper Upper tick of the price range of the position
    /// @return amount0 Amount of token0 fees collected
    /// @return amount1 Amount of token1 fees collected
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        external
        payable
        returns (uint128 amount0, uint128 amount1);
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

**File:** src/base/BasePositions.sol (L100-107)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = collectFees(id, poolKey, tickLower, tickUpper, msg.sender);
    }
```

**File:** src/base/BasePositions.sol (L110-117)
```text
    function collectFees(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, address recipient)
        public
        payable
        authorizedForNft(id)
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, 0, recipient, true);
    }
```

**File:** src/base/BasePositions.sol (L136-142)
```text
    function withdraw(uint256 id, PoolKey memory poolKey, int32 tickLower, int32 tickUpper, uint128 liquidity)
        public
        payable
        returns (uint128 amount0, uint128 amount1)
    {
        (amount0, amount1) = withdraw(id, poolKey, tickLower, tickUpper, liquidity, address(msg.sender), true);
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
