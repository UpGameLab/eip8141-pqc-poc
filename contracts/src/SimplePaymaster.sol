// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "./FrameTxLib.sol";

/// @title SimplePaymaster
/// @notice Signer-verified gas sponsor for EIP-8141 sponsored transactions.
///
/// @dev Called in a VERIFY frame to approve gas payment on behalf of a
///      transaction sender. The paymaster validates that a trusted off-chain
///      signer has approved the frame transaction by checking an ECDSA
///      signature over the canonical sigHash.
///
///      The sponsor must hold enough ETH to cover the gas cost.
contract SimplePaymaster {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    /// @notice The trusted signer who authorizes sponsored transactions.
    address public immutable signer;

    error InvalidCaller();
    error InvalidSignatureLength();
    error InvalidSigner();

    constructor(address _signer) {
        signer = _signer;
    }

    /// @notice Validation entry point, called in a VERIFY frame.
    /// @dev Verifies that the paymaster signer has signed the frame transaction's
    ///      sigHash, then calls APPROVE with SCOPE_PAYMENT.
    /// @param signature 65-byte ECDSA signature (r ++ s ++ v) from the paymaster signer.
    function validate(bytes calldata signature) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        if (signature.length != 65) revert InvalidSignatureLength();

        bytes32 hash = FrameTxLib.sigHash();

        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 27) v += 27;

        address recovered = ecrecover(hash, v, r, s);
        if (recovered == address(0) || recovered != signer) revert InvalidSigner();

        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_PAYMENT);
    }

    receive() external payable {}
}
