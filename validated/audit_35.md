# Audit Report

## Title
Storage Collision in Incentives Bitmap Calculation Enables Cross-Drop State Corruption and Fund Theft

## Summary
The Incentives contract's bitmap storage slot calculation uses unchecked arithmetic with unbounded user-controlled index values, allowing attackers to craft malicious indices that cause storage collisions between different drops. This enables corruption of victim drops' accounting state (funded/claimed amounts), breaking the solvency invariant and allowing unauthorized fund extraction.

## Impact
**Severity**: High

An attacker can corrupt any drop's state and extract the full token balance deposited in victim drops. The attack violates the fundamental solvency invariant that `funded >= claimed` for all drops, enabling theft of user funds through accounting manipulation.

## Finding Description

**Location:** `src/Incentives.sol` lines 74-117 (function `claim`), `src/libraries/IncentivesLib.sol` lines 41-53 (function `getClaimedBitmap`)

**Intended Logic:** 
The Incentives contract stores each drop's state at `dropId = keccak256(owner, token, root)` and stores claim bitmaps at sequential storage slots `dropId + 1 + word` where `word = index >> 8`. The design assumes these storage locations remain isolated - each drop's bitmaps should only occupy slots starting from its own `dropId + 1` offset, never colliding with other drops' state slots.

**Actual Logic:**
The `ClaimKey.index` field is an unbounded `uint256` with no validation. [1](#0-0)  The storage slot calculation uses unchecked arithmetic that allows uint256 wraparound. [2](#0-1) [3](#0-2) 

An attacker can craft an index value such that their drop's bitmap slot calculation overflows and collides with another drop's state slot.

**Exploitation Path:**
1. **Setup**: Victim creates and funds a drop with parameters (victim_owner, victim_token, victim_root) → produces `victim_dropId` from keccak256. Attacker creates their own drop with parameters they control → produces `attacker_dropId` from keccak256.

2. **Collision Calculation**: Attacker calculates `collision_word = (victim_dropId - attacker_dropId - 1) mod 2^256`, then creates malicious `index = collision_word << 8 + target_bit` (e.g., bit 127 to corrupt the MSB of the claimed field).

3. **Merkle Tree Construction**: Attacker builds a merkle tree for their drop containing a claim with the malicious index value. Since they control their drop's root, they can include any index they choose.

4. **State Corruption**: Attacker calls `claim()` with their drop key and malicious claim. The bitmap slot calculation evaluates to: `attacker_dropId + 1 + collision_word = attacker_dropId + 1 + (victim_dropId - attacker_dropId - 1) ≡ victim_dropId (mod 2^256)` due to unchecked wraparound.

5. **Invariant Broken**: The bitmap toggle operation writes to the victim's `DropState` slot instead of a bitmap slot. [4](#0-3)  Targeting bit 127 flips the MSB of the packed `claimed` field, making it jump by 2^127 and exceed `funded`.

6. **Underflow Exploitation**: The `getRemaining()` function performs unchecked subtraction `funded - claimed`, causing underflow when `claimed > funded`. [5](#0-4)  This returns a massive value, making the drop appear to have virtually unlimited funds available.

7. **Fund Extraction**: With the corrupted state, the attacker (or any user) can claim amounts far exceeding what was actually deposited, draining the contract's token balance.

**Security Guarantee Broken:**
Violates the implicit solvency invariant that `funded >= claimed` for all drops. The protocol's accounting becomes corrupted, allowing extraction of more tokens than were deposited.

**Code Evidence:**
Unlike the Core and TWAMM contracts which use large keccak-derived namespace offsets [6](#0-5)  to prevent collisions, Incentives uses simple sequential offsets that are vulnerable to wraparound attacks with unbounded user input.

## Impact Explanation

**Affected Assets**: All ERC20 tokens deposited in the Incentives contract across all drops.

**Damage Severity**:
- Attacker can corrupt any victim drop's state with a single malicious claim transaction
- For a victim drop funded with 10,000 USDC, flipping bit 127 of the claimed field makes `claimed ≈ 2^127`, causing `getRemaining()` to underflow and return `~2^127`
- Attacker can subsequently claim the entire contract balance, not just the victim drop's balance
- All users with unclaimed tokens in the victim drop lose access to their funds
- Drop owner cannot refund corrupted drops (refund logic relies on the same corrupted state)
- Multiple drops can be targeted simultaneously

**User Impact**: All legitimate users with unclaimed tokens in any drop become unable to claim their allocated funds once the drop's state is corrupted.

## Likelihood Explanation

**Attacker Profile**: Any unprivileged user with ability to deploy contracts and create drops (requires minimal gas + 1 wei of any token).

**Preconditions**:
1. Victim drop must exist and be funded (always true for any active drop)
2. Attacker must be able to create their own drop with controlled parameters (owner, token, root) - trivially achievable, no special permissions required
3. Attacker must construct a merkle tree including the malicious index - fully under attacker's control since they control their drop's root

**Execution Complexity**: Single transaction calling `claim()` with a valid merkle proof for the crafted malicious index. No special timing windows, no race conditions, no external dependencies.

**Economic Cost**: Only gas fees (typically <$10), no capital lockup required.

**Frequency**: Attack can be executed repeatedly against multiple victim drops. Each execution corrupts one drop's state, and funds can be drained immediately after corruption.

**Overall Likelihood**: HIGH - Trivial to execute with no barriers to entry, affects all drops in the protocol.

## Recommendation

**Primary Fix:**
Add bounds checking for the `index` parameter to prevent storage collisions. In `src/Incentives.sol`, function `claim`, add validation after computing the word index to ensure it cannot cause wraparound collisions. A safe upper bound like `type(uint240).max` would prevent any possibility of wraparound while still allowing extremely large merkle trees.

**Alternative Mitigation:**
Replace arithmetic-based storage slot calculation with a mapping-based approach that eliminates unchecked arithmetic entirely, preventing collision attacks at the architectural level.

**Additional Hardening:**
Add invariant checks in `claim()` to verify `state.claimed() <= state.funded()` after updating claimed amount, reverting if the invariant is violated.

## Notes

This vulnerability is particularly severe because:

1. **Architectural Inconsistency**: The Core and TWAMM contracts use sophisticated collision prevention with large keccak-derived offsets, but Incentives uses a simpler pattern without proper bounds checking.

2. **Cross-Drop Corruption**: Unlike typical vulnerabilities that affect isolated state, this allows an attacker to corrupt OTHER users' drops while operating on their own drop, violating the isolation assumption.

3. **State Persistence**: The corruption is permanent - once a drop's state is corrupted, it cannot be recovered without direct storage manipulation (which is not possible in normal contract operation).

4. **Off-Chain Impact**: Off-chain indexers and view functions reading the corrupted state will return incorrect results, potentially causing downstream systems to make incorrect decisions about claim availability.

The root cause is the combination of: (1) unbounded user-controlled input (`ClaimKey.index`), (2) unchecked arithmetic in storage slot calculation, and (3) lack of collision prevention mechanisms used elsewhere in the codebase.

### Citations

**File:** src/types/claimKey.sol (L7-7)
```text
    uint256 index;
```

**File:** src/Incentives.sol (L78-84)
```text
        (uint256 word, uint8 bit) = IncentivesLib.claimIndexToStorageIndex(c.index);
        StorageSlot bitmapSlot;
        unchecked {
            bitmapSlot = StorageSlot.wrap(bytes32(uint256(id) + 1 + word));
        }
        Bitmap bitmap = Bitmap.wrap(uint256(bitmapSlot.load()));
        if (bitmap.isSet(bit)) revert AlreadyClaimed();
```

**File:** src/Incentives.sol (L111-114)
```text
        bitmap = bitmap.toggle(bit);
        assembly ("memory-safe") {
            sstore(bitmapSlot, bitmap)
        }
```

**File:** src/libraries/IncentivesLib.sol (L49-51)
```text
        unchecked {
            slot = bytes32(uint256(dropId) + 1 + word);
        }
```

**File:** src/types/dropState.sol (L51-54)
```text
function getRemaining(DropState state) pure returns (uint128 remaining) {
    unchecked {
        remaining = state.funded() - state.claimed();
    }
```

**File:** src/libraries/CoreStorageLayout.sol (L20-31)
```text
    /// @dev Generated using: cast keccak "CoreStorageLayout#FPL_OFFSET"
    uint256 internal constant FPL_OFFSET = 0xb09b03866d96933565a9435bfb511c8ac5b2be454285ca331201452704799f72;
    /// @dev Generated using: cast keccak "CoreStorageLayout#TICKS_OFFSET"
    uint256 internal constant TICKS_OFFSET = 0x435a5eb89a296820174331cf5a3902d9fca683928d56726d8e7acd6efb28c568;
    /// @dev Generated using: cast keccak "CoreStorageLayout#FPL_OUTSIDE_OFFSET_VALUE0"
    uint256 internal constant FPL_OUTSIDE_OFFSET_VALUE0 =
        0x5695060fdb9cfea656f872ae4887221aff7dbfefc45eaf753e4e70cdfb5cd19c;
    /// @dev Generated using: cast keccak "CoreStorageLayout#FPL_OUTSIDE_OFFSET_VALUE1"
    uint256 internal constant FPL_OUTSIDE_OFFSET_VALUE1 =
        0x7a2a03fc08af3dae7869678617dc8abe8f15a3b719b37ba108dba879571f8b02;
    /// @dev Generated using: cast keccak "CoreStorageLayout#BITMAPS_OFFSET"
    uint256 internal constant BITMAPS_OFFSET = 0x3def450d0010a2fef515ce5eba4b363b5a0f42fdd4c53e1c737975db05a2e3a5;
```
