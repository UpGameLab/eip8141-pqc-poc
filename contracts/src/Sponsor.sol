// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "./FrameTxLib.sol";

/// @title IERC20
/// @notice Minimal ERC-20 interface for balance checks.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// @title Sponsor
/// @notice Minimal gas sponsor for EIP-8141 sponsored transactions.
///
/// @dev Called in a VERIFY frame (Example 2, Frame 1) to approve gas payment
///      on behalf of a transaction sender. The sponsor validates that:
///      1. The tx sender is in the approved set
///      2. The tx sender has sufficient ERC-20 balance to compensate
///      Then calls APPROVE(0x1) to approve payment only.
///
///      The sponsor must hold enough ETH to cover the gas cost.
///      After execution, the sender pays the sponsor in ERC-20 tokens
///      (handled by a subsequent SENDER frame).
contract Sponsor {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    IERC20 public immutable token;
    uint256 public immutable minBalance;

    mapping(address => bool) public approvedSenders;

    error InvalidCaller();
    error SenderNotApproved();
    error InsufficientTokenBalance();

    constructor(IERC20 _token, uint256 _minBalance) {
        token = _token;
        minBalance = _minBalance;
    }

    /// @notice Register an address as an approved sender.
    function addApprovedSender(address sender) external {
        approvedSenders[sender] = true;
    }

    /// @notice Remove an address from approved senders.
    function removeApprovedSender(address sender) external {
        approvedSenders[sender] = false;
    }

    /// @notice Validation entry point, called in a VERIFY frame.
    /// @dev Reads tx.sender via TXPARAMLOAD (since msg.sender is ENTRY_POINT
    ///      in VERIFY frames). Checks the sender is approved and has enough
    ///      ERC-20 tokens, then calls APPROVE with SCOPE_PAYMENT.
    function validate() external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();

        address sender = FrameTxLib.txSender();

        if (!approvedSenders[sender]) revert SenderNotApproved();

        uint256 balance = token.balanceOf(sender);
        if (balance < minBalance) revert InsufficientTokenBalance();

        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_PAYMENT);
    }

    receive() external payable {}
}
