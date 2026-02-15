// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../FrameTxLib.sol";
import {WebAuthn} from "../lib/WebAuthn.sol";

/// @title CoinbaseSmartWallet8141
/// @notice EIP-8141 native smart wallet with multi-owner support
/// @dev Ported from Coinbase Smart Wallet (ERC-4337) to EIP-8141 frame transactions
contract CoinbaseSmartWallet8141 {
    using FrameTxLib for *;

    // ── Frame Mode Constants ──────────────────────────────────────────────
    uint8 internal constant FRAME_MODE_VERIFY = 1;
    uint8 internal constant FRAME_MODE_SENDER = 2;

    /// @notice Owner data - can be Ethereum address (32 bytes) or WebAuthn public key (64 bytes)
    struct OwnerStorage {
        uint256 nextOwnerIndex;
        uint256 removedOwnersCount;
        mapping(uint256 => bytes) ownerAtIndex;
        mapping(bytes => bool) isOwner;
    }

    /// @notice Signature wrapper for multi-owner validation
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    /// @notice Call struct for batch execution
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    OwnerStorage internal _owners;

    error Unauthorized();
    error InvalidOwner();
    error NoOwnerAtIndex(uint256 index);
    error AlreadyOwner(bytes owner);
    error LastOwner();
    error InvalidOwnerBytesLength(bytes owner);
    error InvalidEthereumAddressOwner(bytes owner);
    error InvalidFrameMode();
    error ExecutionFailed();

    event OwnerAdded(uint256 indexed index, bytes owner);
    event OwnerRemoved(uint256 indexed index, bytes owner);
    event Executed(address indexed target, uint256 value, bytes data);

    modifier onlyInSenderFrame() {
        if (FrameTxLib.currentFrameMode() != FRAME_MODE_SENDER) {
            revert InvalidFrameMode();
        }
        _;
    }

    modifier onlyOwner() {
        if (!_isOwner(msg.sender)) revert Unauthorized();
        _;
    }

    /// @notice Initialize the wallet with owners
    /// @param owners Array of owner bytes (32 bytes for address, 64 bytes for WebAuthn)
    constructor(bytes[] memory owners) {
        _initializeOwners(owners);
    }

    /// @notice Validate frame transaction signature (VERIFY frame)
    /// @param signature SignatureWrapper containing ownerIndex and signature data
    /// @param scope Validation scope (unused in this implementation)
    function validate(bytes calldata signature, uint8 scope) external {
        // Must be called in VERIFY frame
        if (FrameTxLib.currentFrameMode() != FRAME_MODE_VERIFY) {
            revert InvalidFrameMode();
        }

        // Decode signature wrapper
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));

        // Get signature hash
        bytes32 sigHash = FrameTxLib.sigHash();

        // Validate signature
        if (!_validateSignature(sigWrapper.ownerIndex, sigHash, sigWrapper.signatureData)) {
            revert Unauthorized();
        }

        // Approve both execution and payment
        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_BOTH);
    }

    /// @notice Execute a call (SENDER frame only)
    /// @param target The address to call
    /// @param value The value to send
    /// @param data The calldata
    function execute(address target, uint256 value, bytes calldata data) external payable onlyInSenderFrame {
        _call(target, value, data);
        emit Executed(target, value, data);
    }

    /// @notice Execute multiple calls (SENDER frame only)
    /// @param calls Array of Call structs
    function executeBatch(Call[] calldata calls) external payable onlyInSenderFrame {
        for (uint256 i = 0; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
            emit Executed(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Execute with graceful error handling
    /// @param target The address to call
    /// @param value The value to send
    /// @param data The calldata
    /// @return success Whether the call succeeded
    /// @return returnData The return data
    function executeTry(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyInSenderFrame
        returns (bool success, bytes memory returnData)
    {
        (success, returnData) = target.call{value: value}(data);
        emit Executed(target, value, data);
    }

    /// @notice Add a new owner
    /// @param owner Owner bytes (32 for address, 64 for WebAuthn)
    function addOwner(bytes calldata owner) external onlyInSenderFrame {
        if (_owners.isOwner[owner]) revert AlreadyOwner(owner);

        // Validate owner format
        if (owner.length == 32) {
            // Ethereum address
            if (uint256(bytes32(owner)) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(owner);
            }
        } else if (owner.length == 64) {
            // WebAuthn public key (x, y)
            // No additional validation needed
        } else {
            revert InvalidOwnerBytesLength(owner);
        }

        uint256 index = _owners.nextOwnerIndex++;
        _owners.ownerAtIndex[index] = owner;
        _owners.isOwner[owner] = true;

        emit OwnerAdded(index, owner);
    }

    /// @notice Add an Ethereum address as owner
    /// @param owner The address to add
    function addOwnerAddress(address owner) external onlyInSenderFrame {
        if (owner == address(0)) revert InvalidOwner();
        bytes memory ownerBytes = abi.encode(owner);

        if (_owners.isOwner[ownerBytes]) revert AlreadyOwner(ownerBytes);

        uint256 index = _owners.nextOwnerIndex++;
        _owners.ownerAtIndex[index] = ownerBytes;
        _owners.isOwner[ownerBytes] = true;

        emit OwnerAdded(index, ownerBytes);
    }

    /// @notice Add a WebAuthn public key as owner
    /// @param x The x coordinate
    /// @param y The y coordinate
    function addOwnerPublicKey(uint256 x, uint256 y) external onlyInSenderFrame {
        bytes memory ownerBytes = abi.encode(x, y);

        if (_owners.isOwner[ownerBytes]) revert AlreadyOwner(ownerBytes);

        uint256 index = _owners.nextOwnerIndex++;
        _owners.ownerAtIndex[index] = ownerBytes;
        _owners.isOwner[ownerBytes] = true;

        emit OwnerAdded(index, ownerBytes);
    }

    /// @notice Remove an owner at index
    /// @param index The owner index to remove
    function removeOwnerAtIndex(uint256 index) external onlyInSenderFrame {
        bytes memory owner = _owners.ownerAtIndex[index];

        if (owner.length == 0) revert NoOwnerAtIndex(index);

        // Prevent removing last owner
        if (_owners.nextOwnerIndex - _owners.removedOwnersCount == 1) {
            revert LastOwner();
        }

        delete _owners.isOwner[owner];
        delete _owners.ownerAtIndex[index];
        _owners.removedOwnersCount++;

        emit OwnerRemoved(index, owner);
    }

    /// @notice Remove the last owner
    function removeLastOwner() external onlyInSenderFrame {
        if (_owners.nextOwnerIndex == 0) revert LastOwner();

        uint256 lastIndex = _owners.nextOwnerIndex - 1;
        bytes memory owner = _owners.ownerAtIndex[lastIndex];

        if (owner.length == 0) revert NoOwnerAtIndex(lastIndex);

        // Prevent removing last owner
        if (_owners.nextOwnerIndex - _owners.removedOwnersCount == 1) {
            revert LastOwner();
        }

        delete _owners.isOwner[owner];
        delete _owners.ownerAtIndex[lastIndex];
        _owners.nextOwnerIndex--;

        emit OwnerRemoved(lastIndex, owner);
    }

    /// @notice Check if bytes is an owner
    function isOwnerBytes(bytes memory owner) external view returns (bool) {
        return _owners.isOwner[owner];
    }

    /// @notice Check if address is an owner
    function isOwnerAddress(address owner) external view returns (bool) {
        return _owners.isOwner[abi.encode(owner)];
    }

    /// @notice Check if public key is an owner
    function isOwnerPublicKey(uint256 x, uint256 y) external view returns (bool) {
        return _owners.isOwner[abi.encode(x, y)];
    }

    /// @notice Get owner at index
    function ownerAtIndex(uint256 index) external view returns (bytes memory) {
        return _owners.ownerAtIndex[index];
    }

    /// @notice Get next owner index
    function nextOwnerIndex() external view returns (uint256) {
        return _owners.nextOwnerIndex;
    }

    /// @notice Receive ETH
    receive() external payable {}

    /// @dev Initialize owners during construction
    function _initializeOwners(bytes[] memory owners) internal {
        for (uint256 i = 0; i < owners.length; i++) {
            bytes memory owner = owners[i];

            // Validate owner format
            if (owner.length == 32) {
                if (uint256(bytes32(owner)) > type(uint160).max) {
                    revert InvalidEthereumAddressOwner(owner);
                }
            } else if (owner.length != 64) {
                revert InvalidOwnerBytesLength(owner);
            }

            _owners.ownerAtIndex[i] = owner;
            _owners.isOwner[owner] = true;
            emit OwnerAdded(i, owner);
        }

        _owners.nextOwnerIndex = owners.length;
    }

    /// @dev Validate signature for an owner
    function _validateSignature(uint256 ownerIndex, bytes32 sigHash, bytes memory signatureData)
        internal
        view
        returns (bool)
    {
        bytes memory ownerBytes = _owners.ownerAtIndex[ownerIndex];

        if (ownerBytes.length == 0) return false;
        if (!_owners.isOwner[ownerBytes]) return false;

        // Ethereum address owner (32 bytes)
        if (ownerBytes.length == 32) {
            return _validateEthereumSignature(ownerBytes, sigHash, signatureData);
        }

        // WebAuthn public key owner (64 bytes)
        if (ownerBytes.length == 64) {
            return _validateWebAuthnSignature(ownerBytes, sigHash, signatureData);
        }

        return false;
    }

    /// @dev Validate ECDSA signature for Ethereum address
    function _validateEthereumSignature(bytes memory ownerBytes, bytes32 sigHash, bytes memory signatureData)
        internal
        pure
        returns (bool)
    {
        if (signatureData.length != 65) return false;

        address owner = address(uint160(uint256(bytes32(ownerBytes))));

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signatureData, 32))
            s := mload(add(signatureData, 64))
            v := byte(0, mload(add(signatureData, 96)))
        }

        if (v < 27) v += 27;

        address signer = ecrecover(sigHash, v, r, s);
        return signer == owner && signer != address(0);
    }

    /// @dev Validate WebAuthn signature using P256 verification
    function _validateWebAuthnSignature(bytes memory ownerBytes, bytes32 sigHash, bytes memory signatureData)
        internal
        view
        returns (bool)
    {
        // Extract public key coordinates from owner bytes (64 bytes = x + y)
        uint256 x;
        uint256 y;
        assembly {
            x := mload(add(ownerBytes, 32))
            y := mload(add(ownerBytes, 64))
        }

        // Decode WebAuthn authentication data from signature
        WebAuthn.WebAuthnAuth memory webAuthnAuth = abi.decode(signatureData, (WebAuthn.WebAuthnAuth));

        // Verify WebAuthn signature
        // Challenge is the sigHash (32 bytes)
        // requireUV = true for security (User Verification flag must be set)
        return WebAuthn.verify(
            abi.encodePacked(sigHash),
            true, // requireUV
            webAuthnAuth,
            x,
            y
        );
    }

    /// @dev Execute a call
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @dev Check if msg.sender is an owner
    function _isOwner(address sender) internal view returns (bool) {
        return _owners.isOwner[abi.encode(sender)];
    }
}
