// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../FrameTxLib.sol";

/// @title InnerApproveAccount
/// @notice Smart account that validates signatures correctly but delegates APPROVE
///         to an external relay contract via an inner call. This should be rejected
///         because the relay's ADDRESS != frame.target (the account).
contract InnerApproveAccount {
    address public owner;
    address public relay;

    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    constructor(address _owner, address _relay) {
        owner = _owner;
        relay = _relay;
    }

    /// @notice Validates signature, then delegates APPROVE to the relay via STATICCALL.
    ///         The relay call will fail because ADDRESS (relay) != frame.target (this).
    function validate(uint8 v, bytes32 r, bytes32 s, uint8) external view {
        if (msg.sender != ENTRY_POINT) revert("not entry point");

        bytes32 hash = FrameTxLib.sigHash();
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner && signer != address(0), "bad sig");

        // Delegate APPROVE to relay via STATICCALL.
        // This must fail: relay's ADDRESS != frame.target (this account).
        (bool ok,) = relay.staticcall(abi.encodeWithSignature("relay(uint8)", FrameTxLib.currentFrameAllowedScope()));
        require(ok, "relay approve failed");
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == address(this), "not self");
        (bool ok,) = target.call{value: value}(data);
        require(ok, "exec failed");
    }

    receive() external payable {}
}
