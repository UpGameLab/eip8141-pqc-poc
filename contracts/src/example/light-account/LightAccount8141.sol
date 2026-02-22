// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Receiver} from "solady/accounts/Receiver.sol";

/// @title LightAccount8141
/// @notice EIP-8141 native smart wallet with a single designated owner.
/// @dev Ported from Alchemy's LightAccount (ERC-4337) to EIP-8141 frame transactions.
///      Supports EOA and contract (ERC-1271) owner signature types,
///      UUPS proxy, ERC-1271 isValidSignature with EIP-712 replay protection.
contract LightAccount8141 is UUPSUpgradeable, Receiver {
    using FrameTxLib for *;

    // ── Frame Mode Constants ──────────────────────────────────────────
    uint8 internal constant FRAME_MODE_VERIFY = 1;
    uint8 internal constant FRAME_MODE_SENDER = 2;

    /// @dev Half of secp256k1 curve order, for EIP-2 signature malleability check.
    uint256 private constant _HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // ── ERC-1271 ──────────────────────────────────────────────────────
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    bytes32 internal constant _MESSAGE_TYPEHASH = keccak256("LightAccountMessage(bytes message)");

    // ── Signature Types ───────────────────────────────────────────────
    enum SignatureType {
        EOA,
        CONTRACT
    }

    // ── ERC-7201 Namespaced Storage ───────────────────────────────────
    /// @custom:storage-location erc7201:light_account_v1.storage.8141
    struct LightAccountStorage {
        address owner;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("light_account_v1.storage.8141")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_POSITION =
        0x20952ce99cc210c0f62c282376aa84dc073f20010e91c29f2e806d2d23428e00;

    // ── Errors ────────────────────────────────────────────────────────
    error InvalidOwner(address owner);
    error InvalidInitialization();
    error InvalidSignature();
    error InvalidSignatureType();
    error InvalidFrameMode();
    error NotAuthorized(address caller);
    error ArrayLengthMismatch();
    error CreateFailed();

    // ── Events ────────────────────────────────────────────────────────
    event LightAccountInitialized(address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Modifiers ─────────────────────────────────────────────────────

    /// @notice Allows calls from SENDER frame (msg.sender == address(this)) or owner EOA.
    modifier onlySenderFrameOrOwner() {
        if (msg.sender != address(this)) {
            if (msg.sender != owner()) revert NotAuthorized(msg.sender);
        }
        _;
    }

    // ── Constructor (locks implementation) ─────────────────────────────

    constructor() {
        _getStorage().owner = address(1);
    }

    // ── Initialization ────────────────────────────────────────────────

    /// @notice Initialize the account with an owner. Can only be called once.
    /// @param owner_ The initial owner of the account.
    function initialize(address owner_) external {
        if (_getStorage().owner != address(0)) revert InvalidInitialization();
        if (owner_ == address(0)) revert InvalidOwner(address(0));
        _getStorage().owner = owner_;
        emit LightAccountInitialized(owner_);
        emit OwnershipTransferred(address(0), owner_);
    }

    // ── Validation (VERIFY Frame) ─────────────────────────────────────

    /// @notice Validate frame transaction signature (VERIFY frame).
    /// @param signature The signature with type prefix byte: 0x00=EOA, 0x01=CONTRACT.
    /// @param scope The approval scope.
    function validate(bytes calldata signature, uint8 scope) external {
        if (FrameTxLib.currentFrameMode() != FRAME_MODE_VERIFY) {
            revert InvalidFrameMode();
        }

        bytes32 sigHash = FrameTxLib.sigHash();

        if (signature.length < 1) revert InvalidSignatureType();
        uint8 signatureType = uint8(signature[0]);
        bool valid;

        if (signatureType == uint8(SignatureType.EOA)) {
            valid = _isValidEOAOwnerSignature(sigHash, signature[1:]);
        } else if (signatureType == uint8(SignatureType.CONTRACT)) {
            valid = _isValidContractOwnerSignature(sigHash, signature[1:]);
        } else {
            revert InvalidSignatureType();
        }

        if (!valid) revert InvalidSignature();
        FrameTxLib.approveEmpty(scope);
    }

    // ── Execution (SENDER Frame) ──────────────────────────────────────

    /// @notice Execute a single call.
    function execute(address dest, uint256 value, bytes calldata func)
        external
        payable
        onlySenderFrameOrOwner
    {
        _call(dest, value, func);
    }

    /// @notice Execute a batch of calls (no value).
    function executeBatch(address[] calldata dest, bytes[] calldata func)
        external
        payable
        onlySenderFrameOrOwner
    {
        if (dest.length != func.length) revert ArrayLengthMismatch();
        uint256 length = dest.length;
        for (uint256 i = 0; i < length; ++i) {
            _call(dest[i], 0, func[i]);
        }
    }

    /// @notice Execute a batch of calls (with value).
    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func)
        external
        payable
        onlySenderFrameOrOwner
    {
        if (dest.length != func.length || dest.length != value.length) {
            revert ArrayLengthMismatch();
        }
        uint256 length = dest.length;
        for (uint256 i = 0; i < length; ++i) {
            _call(dest[i], value[i], func[i]);
        }
    }

    /// @notice Deploy a contract using CREATE.
    function performCreate(uint256 value, bytes calldata initCode)
        external
        payable
        onlySenderFrameOrOwner
        returns (address createdAddr)
    {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            let len := initCode.length
            calldatacopy(fmp, initCode.offset, len)
            createdAddr := create(value, fmp, len)
            if iszero(createdAddr) {
                mstore(0x00, 0x7e16b8cd) // CreateFailed()
                revert(0x1c, 0x04)
            }
        }
    }

    /// @notice Deploy a contract using CREATE2.
    function performCreate2(uint256 value, bytes calldata initCode, bytes32 salt)
        external
        payable
        onlySenderFrameOrOwner
        returns (address createdAddr)
    {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            let len := initCode.length
            calldatacopy(fmp, initCode.offset, len)
            createdAddr := create2(value, fmp, len, salt)
            if iszero(createdAddr) {
                mstore(0x00, 0x7e16b8cd) // CreateFailed()
                revert(0x1c, 0x04)
            }
        }
    }

    // ── Owner Management ──────────────────────────────────────────────

    /// @notice Transfer ownership to a new account.
    /// @param newOwner The new owner address.
    function transferOwnership(address newOwner) external onlySenderFrameOrOwner {
        if (newOwner == address(0) || newOwner == address(this)) {
            revert InvalidOwner(newOwner);
        }
        _transferOwnership(newOwner);
    }

    /// @notice Return the current owner of this account.
    function owner() public view returns (address) {
        return _getStorage().owner;
    }

    // ── ERC-1271 ──────────────────────────────────────────────────────

    /// @notice Returns the replay-safe hash of a message that can be signed by the owner.
    /// @param message Message that should be hashed.
    /// @return The replay-safe message hash.
    function getMessageHash(bytes memory message) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(_MESSAGE_TYPEHASH, keccak256(message)));
        return _hashTypedData(structHash);
    }

    /// @notice Validates ERC-1271 signature with anti cross-account replay.
    /// @param hash Hash of the data to be signed.
    /// @param signature Signature with type prefix byte.
    /// @return Magic value 0x1626ba7e if valid, 0xffffffff otherwise.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        if (_isValidSignature(getMessageHash(abi.encode(hash)), signature)) {
            return ERC1271_MAGICVALUE;
        }
        return ERC1271_INVALID;
    }

    /// @notice Returns the EIP-712 domain separator.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("LightAccount"),
                keccak256("2"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Returns EIP-712 domain info (ERC-5267).
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0f";
        name = "LightAccount";
        version = "2";
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt;
        extensions = extensions;
    }

    // ── Proxy ─────────────────────────────────────────────────────────

    /// @notice Returns the implementation address of the ERC-1967 proxy.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    // ── Internal: Storage ─────────────────────────────────────────────

    function _getStorage() internal pure returns (LightAccountStorage storage storageStruct) {
        bytes32 position = _STORAGE_POSITION;
        assembly ("memory-safe") {
            storageStruct.slot := position
        }
    }

    // ── Internal: Owner Management ────────────────────────────────────

    function _transferOwnership(address newOwner) internal {
        LightAccountStorage storage _storage = _getStorage();
        address oldOwner = _storage.owner;
        if (newOwner == oldOwner) revert InvalidOwner(newOwner);
        _storage.owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    // ── Internal: Signature Validation ────────────────────────────────

    /// @dev Validate signature for ERC-1271 isValidSignature.
    function _isValidSignature(bytes32 replaySafeHash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length < 1) revert InvalidSignatureType();
        uint8 signatureType = uint8(signature[0]);
        if (signatureType == uint8(SignatureType.EOA)) {
            return _isValidEOAOwnerSignature(replaySafeHash, signature[1:]);
        } else if (signatureType == uint8(SignatureType.CONTRACT)) {
            return _isValidContractOwnerSignature(replaySafeHash, signature[1:]);
        }
        revert InvalidSignatureType();
    }

    /// @dev Validate EOA owner signature using native ecrecover.
    function _isValidEOAOwnerSignature(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        // EIP-2: reject malleable signatures
        if (uint256(s) > _HALF_CURVE_ORDER) return false;
        address recovered = ecrecover(digest, v, r, s);
        return recovered == owner() && recovered != address(0);
    }

    /// @dev Validate contract owner signature via ERC-1271 staticcall.
    function _isValidContractOwnerSignature(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        address ownerAddr = owner();
        if (ownerAddr.code.length == 0) return false;
        (bool success, bytes memory result) = ownerAddr.staticcall(
            abi.encodeWithSelector(ERC1271_MAGICVALUE, digest, signature)
        );
        return success && result.length >= 32
            && abi.decode(result, (bytes4)) == ERC1271_MAGICVALUE;
    }

    // ── Internal: EIP-712 ─────────────────────────────────────────────

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    // ── Internal: Execution ───────────────────────────────────────────

    function _call(address target, uint256 value, bytes calldata data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    // ── UUPS ──────────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(this) && msg.sender != owner()) {
            revert NotAuthorized(msg.sender);
        }
    }
}
