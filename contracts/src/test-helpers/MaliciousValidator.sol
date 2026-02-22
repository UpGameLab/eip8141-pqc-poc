// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../FrameTxLib.sol";

/// @title MaliciousValidator
/// @notice Test contract that intentionally violates ERC-7562 validation rules.
///         Each validate_* function performs a valid ECDSA check then executes a
///         banned opcode before calling APPROVE. The mempool tracer should reject
///         all of these during VERIFY frame simulation.
/// @dev The via_ir optimizer may eliminate unused values, so banned opcodes
///      write their result to memory via `mstore(0x00, value)` to ensure
///      they are not optimized away.
contract MaliciousValidator {
    address public owner;

    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    error InvalidCaller();
    error InvalidSignature();
    error ExecutionFailed();

    constructor(address _owner) {
        owner = _owner;
    }

    // ─── OP-011: Banned environment opcodes ─────────────────────────────

    /// @notice Uses TIMESTAMP in VERIFY frame — banned by OP-011.
    function validate_timestamp(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, timestamp()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    /// @notice Uses COINBASE in VERIFY frame — banned by OP-011.
    function validate_coinbase(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, coinbase()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    /// @notice Uses NUMBER in VERIFY frame — banned by OP-011.
    function validate_number(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, number()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    /// @notice Uses ORIGIN in VERIFY frame — banned by OP-011.
    function validate_origin(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, origin()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    // ─── OP-080: Banned BALANCE opcodes ─────────────────────────────────

    /// @notice Uses SELFBALANCE in VERIFY frame — banned by OP-080.
    function validate_selfbalance(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, selfbalance()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    /// @notice Uses BALANCE on an address in VERIFY frame — banned by OP-080.
    function validate_balance(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, balance(0xdead)) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    // ─── OP-041: EXTCODE on codeless address ────────────────────────────

    /// @notice Uses EXTCODESIZE on address with no code — violates OP-041.
    function validate_extcode_no_code(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        // 0xdeadbeefdeadbeef has no deployed code
        assembly { mstore(0x00, extcodesize(0xdeadbeefdeadbeef)) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    // ─── OP-012: GAS not immediately before CALL ────────────────────────

    /// @notice Uses GAS opcode followed by MSTORE (not CALL) — violates OP-012.
    function validate_gas_not_call(uint8 v, bytes32 r, bytes32 s) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        assembly { mstore(0x00, gas()) }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    // ─── STO-021: Unassociated external storage ─────────────────────────

    /// @notice Reads storage from an external contract not associated with sender — violates STO-021.
    /// @param target Address of a StorageOracle contract with non-associated storage.
    function validate_external_storage(uint8 v, bytes32 r, bytes32 s, address target) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        // Read slot 0 from external contract via staticcall
        assembly {
            mstore(0x00, 0)
            let ok := staticcall(gas(), target, 0x00, 0x20, 0x00, 0x20)
            if iszero(ok) { revert(0, 0) }
        }
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    // ─── Normal validate for protocol constraint tests ──────────────────

    /// @notice Standard validate — no ERC-7562 violations. Used for protocol-level tests.
    function validate(uint8 v, bytes32 r, bytes32 s, uint8 scope) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        _verifySignature(v, r, s);
        FrameTxLib.approveEmpty(scope);
    }

    // ─── Execution ──────────────────────────────────────────────────────

    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        (bool success,) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();
    }

    receive() external payable {}

    // ─── Internal ───────────────────────────────────────────────────────

    function _verifySignature(uint8 v, bytes32 r, bytes32 s) internal view {
        bytes32 hash = FrameTxLib.sigHash();
        address signer = ecrecover(hash, v, r, s);
        if (signer != owner || signer == address(0)) revert InvalidSignature();
    }
}
