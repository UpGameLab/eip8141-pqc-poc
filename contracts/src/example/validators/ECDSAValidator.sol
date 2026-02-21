// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator8141} from "../../interfaces/IValidator8141.sol";

/// @title ECDSAValidator
/// @notice ECDSA signature validator for Kernel8141 accounts.
/// @dev Each account has one owner stored in this contract's storage.
///      Called via CALL during validation (VERIFY frames) and install/uninstall (SENDER frames).
///      Storage is keyed by account address (msg.sender during onInstall).
contract ECDSAValidator is IValidator8141 {
    /// @dev owner[account] = ECDSA public key owner of that account
    mapping(address => address) public owners;

    error InvalidOwner();

    event OwnerRegistered(address indexed account, address indexed owner);
    event OwnerRemoved(address indexed account);

    /// @inheritdoc IValidator8141
    function validateSignature(
        address account,
        bytes32 sigHash,
        bytes calldata signature
    ) external override returns (bool valid) {
        if (signature.length != 65) return false;

        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 27) v += 27;

        address signer = ecrecover(sigHash, v, r, s);
        if (signer == address(0)) return false;

        return signer == owners[account];
    }

    /// @inheritdoc IValidator8141
    function onInstall(bytes calldata data) external override {
        address owner = abi.decode(data, (address));
        if (owner == address(0)) revert InvalidOwner();

        owners[msg.sender] = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    /// @inheritdoc IValidator8141
    function onUninstall() external override {
        delete owners[msg.sender];
        emit OwnerRemoved(msg.sender);
    }

    /// @inheritdoc IValidator8141
    function isInitialized(address account) external view override returns (bool) {
        return owners[account] != address(0);
    }

    /// @notice Transfer ownership for the calling account.
    /// @dev Must be called from the account itself (via kernel.execute).
    function transferOwnership(address newOwner) external {
        if (newOwner == address(0)) revert InvalidOwner();
        owners[msg.sender] = newOwner;
        emit OwnerRegistered(msg.sender, newOwner);
    }
}
