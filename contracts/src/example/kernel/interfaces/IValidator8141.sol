// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IModule8141} from "./IModule8141.sol";

/// @title IValidator8141
/// @notice Validator interface for EIP-8141 frame transactions.
/// @dev Validators are separate contracts called via CALL/STATICCALL (not delegatecall).
///      They maintain their own storage, keyed by account address.
///      Extends IModule8141 for ERC-7579 aligned lifecycle (onInstall/onUninstall with data).
interface IValidator8141 is IModule8141 {
    error InvalidTargetAddress(address target);

    /// @notice Validate a frame transaction signature.
    /// @dev Called by the Kernel during a VERIFY frame.
    ///      The validator should recover the signer and check authorization.
    ///      The Kernel handles APPROVE — the validator only answers "is this valid?"
    ///      Note: Validators may modify their own storage (including transient storage)
    ///      to pass context to hooks, unlike ERC-4337's pure validation phase.
    /// @param account The account address being validated (tx.sender)
    /// @param sigHash The canonical signature hash from TXPARAM(0x08)
    /// @param signature The raw signature bytes (format depends on validator)
    /// @return valid True if the signature is valid for this account
    function validateSignature(address account, bytes32 sigHash, bytes calldata signature)
        external
        returns (bool valid);

    /// @notice ERC-1271 off-chain signature validation (Kernel v3 compatible).
    /// @dev Called by the Kernel for ERC-1271 isValidSignature forwarding.
    ///      The validator returns ERC-1271 magic value or invalid bytes4.
    /// @param sender The address requesting the signature check (msg.sender to the Kernel)
    /// @param hash The hash of the data that is signed
    /// @param sig The signature data
    /// @return magicValue ERC-1271 magic value (0x1626ba7e) or 0xffffffff
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4 magicValue);
}
