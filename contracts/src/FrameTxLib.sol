// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title FrameTxLib
/// @notice Library wrapping the current EIP-8141 opcodes for smart accounts.
/// @dev These opcodes are only functional during frame transaction execution
///      on an EVM and Solidity compiler that support EIP-8141. Outside a frame
///      transaction context, they may cause an exceptional halt.
library FrameTxLib {
    // ─── Frame modes ────────────────────────────────────────────────────
    uint8 internal constant FRAME_MODE_DEFAULT = 0;
    uint8 internal constant FRAME_MODE_VERIFY = 1;
    uint8 internal constant FRAME_MODE_SENDER = 2;

    // ─── APPROVE scope constants ────────────────────────────────────────
    uint8 internal constant SCOPE_NONE = 0x00;
    uint8 internal constant SCOPE_PAYMENT = 0x01;
    uint8 internal constant SCOPE_EXECUTION = 0x02;
    uint8 internal constant SCOPE_BOTH = SCOPE_PAYMENT | SCOPE_EXECUTION;
    uint8 internal constant SCOPE_MASK = SCOPE_BOTH;

    // ─── Frame flags ────────────────────────────────────────────────────
    uint8 internal constant FLAG_ATOMIC_BATCH = 0x04;

    // ─── TXPARAM selectors ──────────────────────────────────────────────
    uint8 internal constant PARAM_TX_TYPE = 0x00;
    uint8 internal constant PARAM_NONCE = 0x01;
    uint8 internal constant PARAM_SENDER = 0x02;
    uint8 internal constant PARAM_GAS_TIP_CAP = 0x03;
    uint8 internal constant PARAM_GAS_FEE_CAP = 0x04;
    uint8 internal constant PARAM_BLOB_FEE_CAP = 0x05;
    uint8 internal constant PARAM_MAX_COST = 0x06;
    uint8 internal constant PARAM_BLOB_HASH_LEN = 0x07;
    uint8 internal constant PARAM_SIG_HASH = 0x08;
    uint8 internal constant PARAM_FRAME_COUNT = 0x09;
    uint8 internal constant PARAM_FRAME_IDX = 0x0A;

    // ─── FRAMEPARAM selectors ───────────────────────────────────────────
    uint8 internal constant FRAME_PARAM_TARGET = 0x00;
    uint8 internal constant FRAME_PARAM_GAS = 0x01;
    uint8 internal constant FRAME_PARAM_MODE = 0x02;
    uint8 internal constant FRAME_PARAM_FLAGS = 0x03;
    uint8 internal constant FRAME_PARAM_DATA_LEN = 0x04;
    uint8 internal constant FRAME_PARAM_STATUS = 0x05;
    uint8 internal constant FRAME_PARAM_ALLOWED_SCOPE = 0x06;
    uint8 internal constant FRAME_PARAM_ATOMIC_BATCH = 0x07;
    uint8 internal constant FRAME_PARAM_VALUE = 0x08;

    // ─── APPROVE ────────────────────────────────────────────────────────

    /// @notice APPROVE with return data from memory.
    /// @dev Terminates the current VERIFY frame like RETURN and updates the
    ///      transaction-scoped approval context using `scope`.
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

    // ─── TXPARAM / FRAMEPARAM ───────────────────────────────────────────

    /// @notice Load a 32-byte transaction parameter.
    function txParam(uint8 param) internal pure returns (bytes32 result) {
        assembly {
            result := txparam(param)
        }
    }

    /// @notice Load a 32-byte frame parameter for `frameIndex`.
    function frameParam(uint8 param, uint256 frameIndex) internal pure returns (bytes32 result) {
        assembly {
            result := frameparam(param, frameIndex)
        }
    }

    // ─── Convenience helpers ────────────────────────────────────────────

    /// @notice Get the current frame transaction type.
    function txType() internal pure returns (uint8) {
        return uint8(uint256(txParam(PARAM_TX_TYPE)));
    }

    /// @notice Get the canonical signature hash of the frame transaction.
    function sigHash() internal pure returns (bytes32) {
        return txParam(PARAM_SIG_HASH);
    }

    /// @notice Get the frame transaction sender.
    function txSender() internal pure returns (address) {
        return address(uint160(uint256(txParam(PARAM_SENDER))));
    }

    /// @notice Get the nonce of the frame transaction.
    function nonce() internal pure returns (uint256) {
        return uint256(txParam(PARAM_NONCE));
    }

    /// @notice Get the number of frames in the transaction.
    function frameCount() internal pure returns (uint256) {
        return uint256(txParam(PARAM_FRAME_COUNT));
    }

    /// @notice Get the currently executing frame index.
    function currentFrameIndex() internal pure returns (uint256) {
        return uint256(txParam(PARAM_FRAME_IDX));
    }

    /// @notice Get the max gas/blob cost of the frame transaction.
    /// @dev Does not include frame.value transfers.
    function maxCost() internal pure returns (uint256) {
        return uint256(txParam(PARAM_MAX_COST));
    }

    /// @notice Get the result status of a previously executed frame.
    /// @dev Current EIP-8141 returns 0=failure or 1=success and reverts for
    ///      current/future frame indices.
    function frameStatus(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(frameParam(FRAME_PARAM_STATUS, frameIndex)));
    }

    /// @notice Get the raw target field of a frame.
    function frameTarget(uint256 frameIndex) internal pure returns (address) {
        return address(uint160(uint256(frameParam(FRAME_PARAM_TARGET, frameIndex))));
    }

    /// @notice Get a practical resolved target for in-contract cross-frame checks.
    /// @dev EIP-8141 resolves omitted targets to tx.sender. If the implementation
    ///      exposes omitted targets as address(0), this helper maps them to tx.sender.
    function frameResolvedTarget(uint256 frameIndex) internal pure returns (address target) {
        target = frameTarget(frameIndex);
        if (target == address(0)) target = txSender();
    }

    /// @notice Get the gas limit of a frame.
    function frameGas(uint256 frameIndex) internal pure returns (uint256) {
        return uint256(frameParam(FRAME_PARAM_GAS, frameIndex));
    }

    /// @notice Get the ETH value of a frame.
    function frameValue(uint256 frameIndex) internal pure returns (uint256) {
        return uint256(frameParam(FRAME_PARAM_VALUE, frameIndex));
    }

    /// @notice Get the mode of a frame.
    function frameMode(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(frameParam(FRAME_PARAM_MODE, frameIndex)));
    }

    /// @notice Get the flags of a frame.
    function frameFlags(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(frameParam(FRAME_PARAM_FLAGS, frameIndex)));
    }

    /// @notice Get the approval scope allowed by a VERIFY frame's flags.
    function frameAllowedScope(uint256 frameIndex) internal pure returns (uint8) {
        return uint8(uint256(frameParam(FRAME_PARAM_ALLOWED_SCOPE, frameIndex)));
    }

    /// @notice Get whether the atomic batch flag is set for a frame.
    function frameAtomicBatch(uint256 frameIndex) internal pure returns (bool) {
        return uint256(frameParam(FRAME_PARAM_ATOMIC_BATCH, frameIndex)) != 0;
    }

    /// @notice Get the mode of the currently executing frame.
    function currentFrameMode() internal pure returns (uint8) {
        return frameMode(currentFrameIndex());
    }

    /// @notice Get the current frame's raw flags.
    function currentFrameFlags() internal pure returns (uint8) {
        return frameFlags(currentFrameIndex());
    }

    /// @notice Get the current VERIFY frame's allowed approval scope.
    function currentFrameAllowedScope() internal pure returns (uint8) {
        return frameAllowedScope(currentFrameIndex());
    }

    // ─── Frame data helpers ────────────────────────────────────────────

    /// @notice Get the byte size of a frame's calldata.
    /// @dev Returns 0 for VERIFY frames.
    function frameDataSize(uint256 frameIndex) internal pure returns (uint256) {
        return uint256(frameParam(FRAME_PARAM_DATA_LEN, frameIndex));
    }

    /// @notice Load a 32-byte word from a frame's calldata.
    /// @dev Returns zero for VERIFY frames.
    function frameDataLoad(uint256 frameIndex, uint256 offset) internal pure returns (bytes32 result) {
        assembly {
            result := framedataload(offset, frameIndex)
        }
    }

    /// @notice Copy frame calldata into memory.
    /// @dev Copies nothing for VERIFY frames.
    function frameDataCopy(uint256 frameIndex, uint256 destOffset, uint256 dataOffset, uint256 size) internal pure {
        assembly {
            framedatacopy(destOffset, dataOffset, size, frameIndex)
        }
    }

    /// @notice Copy a frame's full calldata into memory.
    /// @dev Returns empty bytes for VERIFY frames.
    function frameData(uint256 frameIndex) internal pure returns (bytes memory result) {
        uint256 size = frameDataSize(frameIndex);
        result = new bytes(size);
        assembly {
            framedatacopy(add(result, 0x20), 0, size, frameIndex)
        }
    }
}
