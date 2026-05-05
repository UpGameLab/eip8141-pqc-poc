// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";

/// @title MLDSA8141Account
/// @notice Post-quantum EIP-8141 smart account using ML-DSA-ETH (EIP-8051) signature verification.
///
/// @dev Uses the VERIFY_MLDSA_ETH precompile at address 0x13 (Keccak PRNG variant).
///
///   The expanded public key (20,512 bytes) is stored as bytecode in a separate data contract
///   (SSTORE2 pattern). This avoids 641 SSTOREs at deploy time and uses cheap EXTCODECOPY
///   instead of 641 SLOADs during verification.
///
///   Precompile input format (22,964 bytes):
///     msg (32 B) + signature (2,420 B) + expanded_pk (20,512 B)
///
///   Frame transaction pattern:
///     Frame 0: VERIFY(account) → validate(signature, scope) → APPROVE
///     Frame 1: SENDER(target)  → execute(target, value, data)
contract MLDSA8141Account {
    /// @dev EIP-8141 ENTRY_POINT address — the caller in VERIFY/DEFAULT frames.
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    /// @dev VERIFY_MLDSA_ETH precompile (EIP-8051, Keccak PRNG variant).
    address internal constant MLDSA_ETH = address(0x13);

    uint256 internal constant PK_SIZE = 20512;
    uint256 internal constant SIG_SIZE = 2420;
    uint256 internal constant PRECOMPILE_INPUT_SIZE = 22964; // 32 + 2420 + 20512

    /// @dev Data contract storing the expanded PK as bytecode (SSTORE2 pattern).
    ///      Runtime code layout: 0x00 (STOP) + 20,512 bytes PK data.
    address internal immutable pkContract;

    error InvalidCaller();
    error InvalidSignature();
    error InvalidPKContract();
    error ExecutionFailed();

    /// @notice Deploy with a reference to the data contract holding the expanded PK.
    /// @param _pkContract Address of the SSTORE2 data contract (runtime code = 0x00 + PK).
    constructor(address _pkContract) {
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(_pkContract)
        }
        if (codeSize != PK_SIZE + 1) revert InvalidPKContract();
        pkContract = _pkContract;
    }

    /// @notice Validation entry point, called in a VERIFY frame.
    /// @param signature ML-DSA-ETH signature (2,420 bytes: c_tilde + z + h).
    /// @dev The legacy scope argument is ignored; approval scope is read from the current VERIFY frame flags.
    function validate(bytes calldata signature, uint8) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        if (signature.length != SIG_SIZE) revert InvalidSignature();

        bytes32 sigHash = FrameTxLib.sigHash();
        address pkAddr = pkContract;

        assembly {
            // Allocate precompile input buffer (22,964 bytes)
            let ptr := mload(0x40)

            // 1. Store sigHash as message (32 bytes)
            mstore(ptr, sigHash)

            // 2. Copy signature from calldata (2,420 bytes)
            calldatacopy(add(ptr, 32), signature.offset, 2420)

            // 3. Load expanded PK from data contract (skip 1-byte STOP prefix)
            extcodecopy(pkAddr, add(ptr, 2452), 1, 20512)

            // 4. staticcall to VERIFY_MLDSA_ETH precompile (0x13)
            let ok := staticcall(gas(), 0x13, ptr, 22964, ptr, 32)

            // 5. Check call succeeded and result == 1 (valid signature)
            if iszero(ok) {
                mstore(0, 0x8baa579f) // InvalidSignature()
                revert(0x1c, 4)
            }
            if iszero(eq(mload(ptr), 1)) {
                mstore(0, 0x8baa579f) // InvalidSignature()
                revert(0x1c, 4)
            }
        }

        FrameTxLib.approveEmpty(FrameTxLib.currentFrameAllowedScope());
    }

    /// @notice Execution entry point, called in a SENDER frame.
    /// @param target Address to call.
    /// @param value ETH value to send.
    /// @param data Calldata for the target call.
    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();

        (bool success,) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();
    }

    receive() external payable {}
}
