// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IModule8141} from "./IModule8141.sol";

/// @title IPolicy8141
/// @notice Policy interface for Kernel8141 permission system.
/// @dev Two-phase policy model for EIP-8141:
///      - VERIFY phase: checkFrameTxPolicy (view) — read-only validation in STATICCALL context
///      - SENDER phase: consumeFrameTxPolicy — stateful consumption (e.g. gas budget decrement)
///
///      Read-only policies (e.g. SelectorPolicy) implement consumeFrameTxPolicy as no-op.
///      Stateful policies (e.g. GasPolicy) perform state writes in consumeFrameTxPolicy.
interface IPolicy8141 is IModule8141 {
    /// @notice Validate a frame transaction against this policy (VERIFY phase).
    /// @dev Called during permission-based VERIFY frame validation (STATICCALL context).
    ///      The policy can use FrameTxLib.frameDataLoad(senderFrameIndex, offset)
    ///      to read SENDER frame's target, value, and calldata.
    /// @param id The permission identifier (bytes32 for storage key derivation)
    /// @param account The smart account address being validated
    /// @param sigHash The canonical signature hash from TXPARAM(0x08)
    /// @param senderFrameIndex The index of the SENDER frame for cross-frame reading
    /// @return result 0 for success, 1 for failure (matches ERC-4337 convention)
    function checkFrameTxPolicy(bytes32 id, address account, bytes32 sigHash, uint256 senderFrameIndex)
        external
        view
        returns (uint256 result);

    /// @notice Consume policy state for a frame transaction (SENDER phase).
    /// @dev Called from executeHooked() in SENDER frame context where state writes are allowed.
    ///      Read-only policies should implement this as a no-op.
    ///      Stateful policies (e.g. GasPolicy) perform state writes here (e.g. budget decrement).
    /// @param id The permission identifier
    /// @param account The smart account address
    function consumeFrameTxPolicy(bytes32 id, address account) external;

    /// @notice Validate an ERC-1271 signature against this policy.
    /// @dev Called during permission-based ERC-1271 signature validation.
    /// @param id The permission identifier
    /// @param sender The address requesting the signature check
    /// @param hash The hash of the data that is signed
    /// @param sig The signature data
    /// @return result 0 for success, 1 for failure
    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (uint256 result);
}
