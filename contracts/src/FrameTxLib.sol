// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title FrameTxLib
/// @notice Library wrapping EIP-8141 opcodes for use in smart accounts.
/// @dev These opcodes are only functional during frame transaction execution
///      on an EVM that supports EIP-8141 (osaka+). Outside a frame tx context,
///      they will cause an exceptional halt.
library FrameTxLib {
    // ─── APPROVE scope constants ────────────────────────────────────────
    uint8 internal constant SCOPE_EXECUTION = 0; // approve execution only
    uint8 internal constant SCOPE_PAYMENT   = 1; // approve payment only
    uint8 internal constant SCOPE_BOTH      = 2; // approve both

    // ─── TXPARAM selectors (in1 values) ─────────────────────────────────
    uint8 internal constant PARAM_TX_TYPE       = 0x00;
    uint8 internal constant PARAM_NONCE         = 0x01;
    uint8 internal constant PARAM_SENDER        = 0x02;
    uint8 internal constant PARAM_GAS_TIP_CAP   = 0x03;
    uint8 internal constant PARAM_GAS_FEE_CAP   = 0x04;
    uint8 internal constant PARAM_BLOB_FEE_CAP  = 0x05;
    uint8 internal constant PARAM_MAX_COST      = 0x06;
    uint8 internal constant PARAM_BLOB_HASH_LEN = 0x07;
    uint8 internal constant PARAM_SIG_HASH      = 0x08;
    uint8 internal constant PARAM_FRAME_COUNT   = 0x09;
    uint8 internal constant PARAM_FRAME_IDX     = 0x10;
    uint8 internal constant PARAM_FRAME_TARGET  = 0x11;
    uint8 internal constant PARAM_FRAME_DATA    = 0x12;
    uint8 internal constant PARAM_FRAME_GAS     = 0x13;
    uint8 internal constant PARAM_FRAME_MODE    = 0x14;
    uint8 internal constant PARAM_FRAME_STATUS  = 0x15;

    // ─── APPROVE ────────────────────────────────────────────────────────

    /// @notice APPROVE with return data from memory.
    /// @dev Terminates execution (like RETURN) and signals approval.
    function approveWithData(bytes memory data, uint8 scope) internal pure {
        assembly {
            approve(add(data, 0x20), mload(data), scope)
        }
    }

    /// @notice APPROVE with empty return data.
    function approveEmpty(uint8 scope) internal pure {
        assembly {
            approve(0, 0, scope)
        }
    }

    // ─── TXPARAMLOAD ────────────────────────────────────────────────────

    /// @notice Load a 32-byte tx parameter word.
    /// @param in1 Parameter selector (0x00-0x15).
    /// @param in2 Frame index for frame-indexed params (0x11-0x15), 0 otherwise.
    /// @param offset Byte offset within the parameter data.
    function txParamLoad(uint8 in1, uint256 in2, uint256 offset)
        internal pure returns (bytes32 result)
    {
        assembly {
            result := txparamload(in1, in2, offset)
        }
    }

    // ─── TXPARAMSIZE ────────────────────────────────────────────────────

    /// @notice Get the byte size of a tx parameter.
    function txParamSize(uint8 in1, uint256 in2)
        internal pure returns (uint256 size)
    {
        assembly {
            size := txparamsize(in1, in2)
        }
    }

    // ─── TXPARAMCOPY ────────────────────────────────────────────────────

    /// @notice Copy tx parameter data into memory.
    function txParamCopy(
        uint8 in1,
        uint256 in2,
        uint256 destOffset,
        uint256 offset,
        uint256 size
    ) internal pure {
        assembly {
            txparamcopy(in1, in2, destOffset, offset, size)
        }
    }

    // ─── Convenience helpers ────────────────────────────────────────────

    /// @notice Get the canonical signature hash of the frame transaction.
    function sigHash() internal pure returns (bytes32) {
        return txParamLoad(PARAM_SIG_HASH, 0, 0);
    }

    /// @notice Get the frame transaction sender address.
    function txSender() internal pure returns (address) {
        return address(uint160(uint256(txParamLoad(PARAM_SENDER, 0, 0))));
    }

    /// @notice Get the nonce of the frame transaction.
    function nonce() internal pure returns (uint256) {
        return uint256(txParamLoad(PARAM_NONCE, 0, 0));
    }

    /// @notice Get the number of frames in the transaction.
    function frameCount() internal pure returns (uint256) {
        return uint256(txParamLoad(PARAM_FRAME_COUNT, 0, 0));
    }

    /// @notice Get the currently executing frame index.
    function currentFrameIndex() internal pure returns (uint256) {
        return uint256(txParamLoad(PARAM_FRAME_IDX, 0, 0));
    }

    /// @notice Get the max cost of the frame transaction.
    function maxCost() internal pure returns (uint256) {
        return uint256(txParamLoad(PARAM_MAX_COST, 0, 0));
    }

    /// @notice Get the result status of a previously executed frame.
    /// @dev Reverts if frameIndex >= current frame index.
    function frameStatus(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(txParamLoad(PARAM_FRAME_STATUS, frameIndex, 0)));
    }

    /// @notice Get the target address of a frame.
    function frameTarget(uint256 frameIndex) internal pure returns (address) {
        return address(uint160(uint256(txParamLoad(PARAM_FRAME_TARGET, frameIndex, 0))));
    }

    /// @notice Get the gas limit of a frame.
    function frameGas(uint256 frameIndex) internal pure returns (uint256) {
        return uint256(txParamLoad(PARAM_FRAME_GAS, frameIndex, 0));
    }

    /// @notice Get the mode of a frame.
    function frameMode(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(txParamLoad(PARAM_FRAME_MODE, frameIndex, 0)));
    }
}
