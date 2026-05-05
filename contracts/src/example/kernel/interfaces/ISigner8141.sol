// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IModule8141} from "./IModule8141.sol";

/// @title ISigner8141
/// @notice Signer interface for Kernel8141 permission system.
/// @dev Signers handle cryptographic signature verification within the permission system.
///      A permission = ISigner + IPolicy[] + PassFlag.
///      EIP-8141 native: checkFrameTxSignature receives sigHash directly (no PackedUserOperation).
interface ISigner8141 is IModule8141 {
    /// @notice Verify a frame transaction signature for a permission.
    /// @dev Called after all policies pass during permission-based validation.
    /// @param id The permission identifier (bytes32 for storage key derivation)
    /// @param account The smart account address being validated
    /// @param sigHash The canonical signature hash from TXPARAM(0x08)
    /// @param signature The raw signature bytes
    /// @return result 0 for success, 1 for failure
    function checkFrameTxSignature(bytes32 id, address account, bytes32 sigHash, bytes calldata signature)
        external
        payable
        returns (uint256 result);

    /// @notice Verify an ERC-1271 signature for a permission.
    /// @dev Called during permission-based ERC-1271 signature validation.
    /// @param id The permission identifier
    /// @param sender The address requesting the signature check
    /// @param hash The hash of the data that is signed
    /// @param sig The signature data
    /// @return magicValue ERC-1271 magic value (0x1626ba7e) or 0xffffffff
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4 magicValue);
}
