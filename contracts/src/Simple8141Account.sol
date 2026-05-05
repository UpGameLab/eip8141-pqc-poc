// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "./FrameTxLib.sol";

/// @title Simple8141Account
/// @notice Minimal EIP-8141 smart account with single-owner ECDSA validation.
///
/// @dev Supports two frame transaction patterns:
///
///   Example 1 — Simple Transaction:
///     Frame 0: VERIFY(sender, flags=3) → validate(v, r, s) → APPROVE(both)
///     Frame 1: SENDER(target)  → execute(target, value, data)
///
///   Example 2 — Sponsored Transaction:
///     Frame 0: VERIFY(sender, flags=2) → validate(v, r, s) → APPROVE(execution)
///     Frame 1: VERIFY(sponsor) → sponsor.validate()          → APPROVE(payment)
///     Frame 2: SENDER(erc20)   → token.transfer(sponsor, fee)
///     Frame 3: SENDER(target)  → execute(target, value, data)
contract Simple8141Account {
    address public owner;

    /// @dev EIP-8141 ENTRY_POINT address — the caller in VERIFY/DEFAULT frames.
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    error InvalidCaller();
    error InvalidSignature();
    error ExecutionFailed();

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Validation entry point, called in a VERIFY frame.
    /// @param v ECDSA recovery id
    /// @param r ECDSA signature r
    /// @param s ECDSA signature s
    /// @dev Calldata layout: abi.encodeWithSelector(this.validate.selector, v, r, s, scope)
    ///      The scope argument is deprecated; approval scope is read from the current VERIFY frame flags.
    ///      The function reads the canonical sig hash via TXPARAM(0x08),
    ///      recovers the signer, checks signer==owner, and calls APPROVE.
    ///      This function does NOT return — APPROVE terminates execution like RETURN.
    function validate(uint8 v, bytes32 r, bytes32 s, uint8) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();

        bytes32 hash = FrameTxLib.sigHash();
        address signer = ecrecover(hash, v, r, s);
        if (signer != owner || signer == address(0)) revert InvalidSignature();

        FrameTxLib.approveEmpty(FrameTxLib.currentFrameAllowedScope());
    }

    /// @notice Execution entry point, called in a SENDER frame.
    /// @param target Address to call
    /// @param value ETH value to send
    /// @param data Calldata for the target call
    /// @dev In a SENDER frame, msg.sender == tx.sender == address(this).
    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();

        (bool success,) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();
    }

    receive() external payable {}
}
