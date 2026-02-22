// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../FrameTxLib.sol";

/// @title NoApproveValidator
/// @notice Validates the signature correctly but returns normally without calling APPROVE.
///         The mempool should reject this because VERIFY frames must exit via APPROVE.
contract NoApproveValidator {
    address public owner;

    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    error InvalidCaller();
    error InvalidSignature();

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Validates signature but does NOT call APPROVE — just returns.
    ///         The framepool rejects this: "did not APPROVE".
    function validate(uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        bytes32 hash = FrameTxLib.sigHash();
        address signer = ecrecover(hash, v, r, s);
        if (signer != owner || signer == address(0)) revert InvalidSignature();
        return true;
    }

    receive() external payable {}
}
