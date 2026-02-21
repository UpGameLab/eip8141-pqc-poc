// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IValidator8141
/// @notice Validator interface for EIP-8141 frame transactions.
/// @dev Validators are separate contracts called via CALL/STATICCALL (not delegatecall).
///      They maintain their own storage, keyed by account address.
interface IValidator8141 {
    /// @notice Validate a frame transaction signature.
    /// @dev Called by the Kernel during a VERIFY frame.
    ///      The validator should recover the signer and check authorization.
    ///      The Kernel handles APPROVE — the validator only answers "is this valid?"
    ///      Note: Validators may modify their own storage (including transient storage)
    ///      to pass context to hooks, unlike ERC-4337's pure validation phase.
    /// @param account The account address being validated (tx.sender)
    /// @param sigHash The canonical signature hash from TXPARAMLOAD(0x08)
    /// @param signature The raw signature bytes (format depends on validator)
    /// @return valid True if the signature is valid for this account
    function validateSignature(
        address account,
        bytes32 sigHash,
        bytes calldata signature
    ) external returns (bool valid);

    /// @notice Install this validator for the calling account.
    /// @dev Called by the Kernel in a SENDER frame. msg.sender is the Kernel.
    /// @param data Initialization data (e.g., abi.encode(ownerAddress) for ECDSA)
    function onInstall(bytes calldata data) external;

    /// @notice Uninstall this validator for the calling account.
    /// @dev Called by the Kernel in a SENDER frame. Should clean up storage.
    function onUninstall() external;

    /// @notice Check if this validator is initialized for a given account.
    /// @param account The account address to check
    /// @return True if the validator has been installed for this account
    function isInitialized(address account) external view returns (bool);
}
