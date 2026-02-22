// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISigner8141} from "../interfaces/ISigner8141.sol";
import {MODULE_TYPE_SIGNER, ERC1271_MAGICVALUE, ERC1271_INVALID} from "../types/Constants8141.sol";

/// @title ECDSASigner8141
/// @notice ECDSA signer for the Kernel8141 permission system.
/// @dev Each (account, permissionId) pair maps to one ECDSA signer address.
contract ECDSASigner8141 is ISigner8141 {
    /// @dev Half of secp256k1 curve order, for EIP-2 signature malleability check.
    uint256 private constant _HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // signers[account][permissionId] = signer address
    mapping(address => mapping(bytes32 => address)) public signers;

    event SignerRegistered(address indexed account, bytes32 indexed id, address signer);

    // ── ISigner8141 ─────────────────────────────────────────────────────

    /// @inheritdoc ISigner8141
    function checkFrameTxSignature(bytes32 id, address, bytes32 sigHash, bytes calldata signature)
        external
        payable
        override
        returns (uint256)
    {
        address expectedSigner = signers[msg.sender][id];
        if (expectedSigner == address(0)) return 1;

        // Use native ecrecover (solady ECDSA.recover assembly incompatible with EIP-8141 solc)
        require(signature.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if (v < 27) v += 27;
        // EIP-2: reject malleable signatures
        if (uint256(s) > _HALF_CURVE_ORDER) return 1;
        address recovered = ecrecover(sigHash, v, r, s);
        if (recovered != address(0) && recovered == expectedSigner) return 0;

        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", sigHash));
        recovered = ecrecover(ethHash, v, r, s);
        return (recovered != address(0) && recovered == expectedSigner) ? 0 : 1;
    }

    /// @inheritdoc ISigner8141
    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address expectedSigner = signers[msg.sender][id];
        if (expectedSigner == address(0)) return ERC1271_INVALID;

        // Use native ecrecover (solady ECDSA.recover assembly incompatible with EIP-8141 solc)
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        if (v < 27) v += 27;
        // EIP-2: reject malleable signatures
        if (uint256(s) > _HALF_CURVE_ORDER) return ERC1271_INVALID;
        address recovered = ecrecover(hash, v, r, s);
        if (recovered != address(0) && recovered == expectedSigner) return ERC1271_MAGICVALUE;

        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        recovered = ecrecover(ethHash, v, r, s);
        return (recovered != address(0) && recovered == expectedSigner) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    // ── IModule8141 ─────────────────────────────────────────────────────

    /// @dev initData format: abi.encodePacked(bytes32 permissionId, address signer)
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        address signer = address(bytes20(data[32:52]));
        signers[msg.sender][id] = signer;
        emit SignerRegistered(msg.sender, id, signer);
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        delete signers[msg.sender][id];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_SIGNER;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }
}
