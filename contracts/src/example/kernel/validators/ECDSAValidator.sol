// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator8141} from "../interfaces/IValidator8141.sol";
import {IHook8141} from "../interfaces/IHook8141.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants8141.sol";

/// @title ECDSAValidator
/// @notice ECDSA signature validator + hook gate for Kernel8141 (Kernel v3 compatible).
/// @dev Implements both IValidator8141 and IHook8141:
///      - As validator: validates frame tx signatures and ERC-1271 signatures.
///      - As hook (isModuleType(4)=true): allows owner direct calls when used as rootValidator.
///      Storage is keyed by account address (msg.sender during onInstall).
contract ECDSAValidator is IValidator8141, IHook8141 {
    /// @dev Half of secp256k1 curve order, for EIP-2 signature malleability check.
    uint256 private constant _HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct ECDSAValidatorStorage {
        address owner;
    }

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    error InvalidOwner();

    event OwnerRegistered(address indexed kernel, address indexed owner);

    // ── IModule8141 ─────────────────────────────────────────────────────

    function onInstall(bytes calldata data) external payable override {
        address owner = address(bytes20(data[0:20]));
        if (owner == address(0)) revert InvalidOwner();
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete ecdsaValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaValidatorStorage[smartAccount].owner != address(0);
    }

    // ── IValidator8141 ──────────────────────────────────────────────────

    /// @inheritdoc IValidator8141
    function validateSignature(address account, bytes32 sigHash, bytes calldata signature)
        external
        view
        override
        returns (bool valid)
    {
        address owner = ecdsaValidatorStorage[account].owner;
        // Use Solidity built-in ecrecover instead of solady ECDSA.recover
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
        // EIP-2: reject malleable signatures (s must be in lower half)
        if (uint256(s) > _HALF_CURVE_ORDER) return false;
        address recovered = ecrecover(sigHash, v, r, s);
        if (recovered != address(0) && recovered == owner) {
            return true;
        }
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", sigHash));
        recovered = ecrecover(ethHash, v, r, s);
        return recovered != address(0) && recovered == owner;
    }

    /// @inheritdoc IValidator8141
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
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
        if (recovered != address(0) && recovered == owner) {
            return ERC1271_MAGICVALUE;
        }
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        recovered = ecrecover(ethHash, v, r, s);
        if (recovered != address(0) && recovered == owner) {
            return ERC1271_MAGICVALUE;
        }
        return ERC1271_INVALID;
    }

    // ── IHook8141 (owner direct call gate) ──────────────────────────────

    /// @inheritdoc IHook8141
    function preCheck(address msgSender, uint256, bytes calldata)
        external
        payable
        override
        returns (bytes memory)
    {
        require(msgSender == ecdsaValidatorStorage[msg.sender].owner, "ECDSAValidator: sender is not owner");
        return hex"";
    }

    /// @inheritdoc IHook8141
    function postCheck(bytes calldata) external payable override {}

    // ── Admin ───────────────────────────────────────────────────────────

    function transferOwnership(address newOwner) external {
        if (newOwner == address(0)) revert InvalidOwner();
        ecdsaValidatorStorage[msg.sender].owner = newOwner;
        emit OwnerRegistered(msg.sender, newOwner);
    }
}
