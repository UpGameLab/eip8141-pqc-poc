// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";
import {WebAuthn} from "../../lib/WebAuthn.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Receiver} from "solady/accounts/Receiver.sol";

/// @title CoinbaseSmartWallet8141
/// @notice EIP-8141 native smart wallet with multi-owner support (ECDSA + WebAuthn).
/// @dev Ported from Coinbase Smart Wallet (ERC-4337) to EIP-8141 frame transactions.
///      Feature-parity with the original: UUPS proxy, ERC-1271, cross-chain replay,
///      multi-owner management with ERC-7201 namespaced storage.
contract CoinbaseSmartWallet8141 is UUPSUpgradeable, Receiver {
    using FrameTxLib for *;

    // ── Frame Mode Constants ──────────────────────────────────────────
    uint8 internal constant FRAME_MODE_VERIFY = 1;
    uint8 internal constant FRAME_MODE_SENDER = 2;

    // ── ERC-1271 ──────────────────────────────────────────────────────
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    /// @dev Half of secp256k1 curve order, for EIP-2 signature malleability check.
    uint256 private constant _HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");

    // ── ERC-7201 Namespaced Storage ───────────────────────────────────
    /// @custom:storage-location erc7201:coinbase.storage.CoinbaseSmartWallet8141
    struct OwnerStorage {
        uint256 nextOwnerIndex;
        uint256 removedOwnersCount;
        mapping(uint256 => bytes) ownerAtIndex;
        mapping(bytes => bool) isOwner;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("coinbase.storage.CoinbaseSmartWallet8141")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _OWNER_STORAGE_SLOT =
        0xdb0a03efc38f2b109622bd0ee19bb92b9a71192dfb607cd9716afe65948e8100;

    // ── Structs ───────────────────────────────────────────────────────
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // ── Errors ────────────────────────────────────────────────────────
    error Initialized();
    error Unauthorized();
    error InvalidOwner();
    error NoOwnerAtIndex(uint256 index);
    error AlreadyOwner(bytes owner);
    error LastOwner();
    error NotLastOwner(uint256 ownersRemaining);
    error WrongOwnerAtIndex(uint256 index, bytes expectedOwner, bytes actualOwner);
    error InvalidOwnerBytesLength(bytes owner);
    error InvalidEthereumAddressOwner(bytes owner);
    error InvalidFrameMode();
    error SelectorNotAllowed(bytes4 selector);
    error InvalidImplementation(address implementation);

    // ── Events ────────────────────────────────────────────────────────
    event AddOwner(uint256 indexed index, bytes owner);
    event RemoveOwner(uint256 indexed index, bytes owner);

    // ── Modifiers ─────────────────────────────────────────────────────

    /// @notice Allows calls from SENDER frame (msg.sender == address(this)) or owner EOA.
    modifier onlySenderFrameOrOwner() {
        if (msg.sender != address(this)) {
            _checkOwner();
        }
        _;
    }

    /// @notice Allows calls from owner or self.
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    // ── Constructor (locks implementation) ─────────────────────────────

    constructor() {
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    // ── Initialization ────────────────────────────────────────────────

    /// @notice Initialize the account with owners. Can only be called once.
    function initialize(bytes[] calldata owners) external payable {
        if (_getOwnerStorage().nextOwnerIndex != 0) {
            revert Initialized();
        }
        _validateOwners(owners);
        _initializeOwners(owners);
    }

    // ── Validation (VERIFY Frame) ─────────────────────────────────────

    /// @notice Validate frame transaction signature (VERIFY frame).
    function validate(bytes calldata signature, uint8) external {
        if (FrameTxLib.currentFrameMode() != FRAME_MODE_VERIFY) {
            revert InvalidFrameMode();
        }

        (uint256 ownerIndex, bytes memory signatureData) = abi.decode(signature, (uint256, bytes));
        bytes32 sigHash = FrameTxLib.sigHash();

        if (!_validateSignature(ownerIndex, sigHash, signatureData)) {
            revert Unauthorized();
        }

        FrameTxLib.approveEmpty(FrameTxLib.currentFrameAllowedScope());
    }

    /// @notice Validate a cross-chain frame transaction (VERIFY frame).
    /// @dev Computes a chain-agnostic hash from the SENDER frame calldata.
    ///      The SENDER frame must call executeWithoutChainIdValidation().
    function validateCrossChain(bytes calldata signature, uint8) external {
        if (FrameTxLib.currentFrameMode() != FRAME_MODE_VERIFY) {
            revert InvalidFrameMode();
        }

        uint256 senderFrameIdx = _findSenderFrameIndex();

        // Verify SENDER frame calls executeWithoutChainIdValidation
        bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderFrameIdx, 0));
        if (senderSelector != this.executeWithoutChainIdValidation.selector) {
            revert SelectorNotAllowed(senderSelector);
        }

        // Compute cross-chain hash (same on all chains for the same operation)
        address sender = FrameTxLib.txSender();
        bytes memory senderCalldata = FrameTxLib.frameData(senderFrameIdx);
        bytes32 crossChainHash = keccak256(abi.encode(sender, keccak256(senderCalldata)));

        (uint256 ownerIndex, bytes memory signatureData) = abi.decode(signature, (uint256, bytes));
        if (!_validateSignature(ownerIndex, crossChainHash, signatureData)) {
            revert Unauthorized();
        }

        FrameTxLib.approveEmpty(FrameTxLib.currentFrameAllowedScope());
    }

    // ── Execution (SENDER Frame) ──────────────────────────────────────

    /// @notice Execute a single call.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlySenderFrameOrOwner
    {
        _call(target, value, data);
    }

    /// @notice Execute multiple calls.
    function executeBatch(Call[] calldata calls) external payable onlySenderFrameOrOwner {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Execute cross-chain replayable calls.
    /// @dev Only allows selectors permitted by canSkipChainIdValidation.
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable {
        if (msg.sender != address(this)) revert Unauthorized();

        for (uint256 i; i < calls.length; i++) {
            bytes calldata call_ = calls[i];
            bytes4 selector = bytes4(call_);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }

            // Validate implementation code for upgrade calls
            if (selector == UUPSUpgradeable.upgradeToAndCall.selector) {
                address newImpl;
                assembly {
                    // Skip 4 bytes selector to read first argument
                    newImpl := calldataload(add(call_.offset, 4))
                }
                if (newImpl.code.length == 0) revert InvalidImplementation(newImpl);
            }

            _call(address(this), 0, call_);
        }
    }

    /// @notice Returns whether a selector can be used with executeWithoutChainIdValidation.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == this.addOwnerAddress.selector
                || functionSelector == this.addOwnerPublicKey.selector
                || functionSelector == this.removeOwnerAtIndex.selector
                || functionSelector == this.removeLastOwner.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    // ── ERC-1271 ──────────────────────────────────────────────────────

    /// @notice Validates the signature against the given hash with anti cross-account replay.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        if (_isValidSignature(replaySafeHash(hash), signature)) {
            return ERC1271_MAGICVALUE;
        }
        return ERC1271_INVALID;
    }

    /// @notice Returns the replay-safe hash for anti cross-account replay.
    function replaySafeHash(bytes32 hash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(abi.encode(_MESSAGE_TYPEHASH, hash))
            )
        );
    }

    /// @notice Returns the EIP-712 domain separator.
    function domainSeparator() public view returns (bytes32) {
        (string memory name, string memory version) = _domainNameAndVersion();
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
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
        (name, version) = _domainNameAndVersion();
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt;
        extensions = extensions;
    }

    // ── Owner Management ──────────────────────────────────────────────

    /// @notice Add an Ethereum address as owner.
    function addOwnerAddress(address owner) external onlySenderFrameOrOwner {
        if (owner == address(0)) revert InvalidOwner();
        _addOwner(abi.encode(owner));
    }

    /// @notice Add a WebAuthn public key as owner.
    function addOwnerPublicKey(bytes32 x, bytes32 y) external onlySenderFrameOrOwner {
        _addOwner(abi.encode(x, y));
    }

    /// @notice Remove an owner at index.
    /// @param index The index of the owner to remove.
    /// @param owner The ABI encoded bytes of the owner to remove (for verification).
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external onlySenderFrameOrOwner {
        if (ownerCount() == 1) revert LastOwner();
        _removeOwnerAtIndex(index, owner);
    }

    /// @notice Remove the last owner (when only one remains).
    /// @param index The index of the owner to remove.
    /// @param owner The ABI encoded bytes of the owner to remove (for verification).
    function removeLastOwner(uint256 index, bytes calldata owner) external onlySenderFrameOrOwner {
        uint256 ownersRemaining = ownerCount();
        if (ownersRemaining > 1) revert NotLastOwner(ownersRemaining);
        _removeOwnerAtIndex(index, owner);
    }

    // ── Owner Queries ─────────────────────────────────────────────────

    /// @notice Check if address is an owner.
    function isOwnerAddress(address owner) public view returns (bool) {
        return _getOwnerStorage().isOwner[abi.encode(owner)];
    }

    /// @notice Check if public key is an owner.
    function isOwnerPublicKey(bytes32 x, bytes32 y) public view returns (bool) {
        return _getOwnerStorage().isOwner[abi.encode(x, y)];
    }

    /// @notice Check if bytes is an owner.
    function isOwnerBytes(bytes memory owner) public view returns (bool) {
        return _getOwnerStorage().isOwner[owner];
    }

    /// @notice Get owner at index.
    function ownerAtIndex(uint256 index) public view returns (bytes memory) {
        return _getOwnerStorage().ownerAtIndex[index];
    }

    /// @notice Get next owner index.
    function nextOwnerIndex() public view returns (uint256) {
        return _getOwnerStorage().nextOwnerIndex;
    }

    /// @notice Get current number of owners.
    function ownerCount() public view returns (uint256) {
        OwnerStorage storage $ = _getOwnerStorage();
        return $.nextOwnerIndex - $.removedOwnersCount;
    }

    /// @notice Get number of removed owners.
    function removedOwnersCount() public view returns (uint256) {
        return _getOwnerStorage().removedOwnersCount;
    }

    // ── Proxy ─────────────────────────────────────────────────────────

    /// @notice Returns the implementation address of the ERC-1967 proxy.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    // ── Internal: Storage ─────────────────────────────────────────────

    function _getOwnerStorage() internal pure returns (OwnerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _OWNER_STORAGE_SLOT
        }
    }

    // ── Internal: Initialization ──────────────────────────────────────

    /// @dev Validates that no owner is address(0). Called from initialize() only —
    ///      the constructor intentionally uses address(0) as a sentinel.
    function _validateOwners(bytes[] calldata owners) internal pure {
        for (uint256 i; i < owners.length; i++) {
            if (owners[i].length == 32) {
                if (uint256(bytes32(owners[i])) == 0) revert InvalidOwner();
            }
        }
    }

    function _initializeOwners(bytes[] memory owners) internal {
        OwnerStorage storage $ = _getOwnerStorage();
        for (uint256 i; i < owners.length; i++) {
            bytes memory owner = owners[i];

            if (owner.length == 32) {
                uint256 addr = uint256(bytes32(owner));
                if (addr > type(uint160).max) {
                    revert InvalidEthereumAddressOwner(owner);
                }
            } else if (owner.length == 64) {
                // WebAuthn public key
            } else {
                revert InvalidOwnerBytesLength(owner);
            }

            $.ownerAtIndex[i] = owner;
            $.isOwner[owner] = true;
            emit AddOwner(i, owner);
        }
        $.nextOwnerIndex = owners.length;
    }

    // ── Internal: Owner Management ────────────────────────────────────

    function _addOwner(bytes memory owner) internal {
        OwnerStorage storage $ = _getOwnerStorage();
        if ($.isOwner[owner]) revert AlreadyOwner(owner);

        uint256 index = $.nextOwnerIndex++;
        $.ownerAtIndex[index] = owner;
        $.isOwner[owner] = true;
        emit AddOwner(index, owner);
    }

    function _removeOwnerAtIndex(uint256 index, bytes calldata owner) internal {
        OwnerStorage storage $ = _getOwnerStorage();
        bytes memory owner_ = $.ownerAtIndex[index];
        if (owner_.length == 0) revert NoOwnerAtIndex(index);
        if (keccak256(owner_) != keccak256(owner)) {
            revert WrongOwnerAtIndex(index, owner, owner_);
        }
        delete $.isOwner[owner];
        delete $.ownerAtIndex[index];
        $.removedOwnersCount++;
        emit RemoveOwner(index, owner);
    }

    // ── Internal: Access Control ──────────────────────────────────────

    function _checkOwner() internal view {
        if (isOwnerAddress(msg.sender) || msg.sender == address(this)) {
            return;
        }
        revert Unauthorized();
    }

    // ── Internal: Signature Validation ────────────────────────────────

    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (uint256 ownerIndex, bytes memory signatureData) = abi.decode(signature, (uint256, bytes));
        return _validateSignature(ownerIndex, hash, signatureData);
    }

    function _validateSignature(uint256 ownerIndex, bytes32 hash, bytes memory signatureData)
        internal
        view
        returns (bool)
    {
        OwnerStorage storage $ = _getOwnerStorage();
        bytes memory ownerBytes = $.ownerAtIndex[ownerIndex];

        if (ownerBytes.length == 0) return false;
        if (!$.isOwner[ownerBytes]) return false;

        if (ownerBytes.length == 32) {
            return _validateEthereumSignature(ownerBytes, hash, signatureData);
        }

        if (ownerBytes.length == 64) {
            return _validateWebAuthnSignature(ownerBytes, hash, signatureData);
        }

        return false;
    }

    function _validateEthereumSignature(bytes memory ownerBytes, bytes32 hash, bytes memory signatureData)
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
        // EIP-2: reject malleable signatures
        if (uint256(s) > _HALF_CURVE_ORDER) return false;

        address signer = ecrecover(hash, v, r, s);
        return signer == owner && signer != address(0);
    }

    function _validateWebAuthnSignature(bytes memory ownerBytes, bytes32 hash, bytes memory signatureData)
        internal
        view
        returns (bool)
    {
        uint256 x;
        uint256 y;
        assembly {
            x := mload(add(ownerBytes, 32))
            y := mload(add(ownerBytes, 64))
        }

        (
            bytes memory authenticatorData,
            bytes memory clientDataJSON,
            uint256 challengeIndex,
            uint256 typeIndex,
            uint256 rVal,
            uint256 sVal
        ) = abi.decode(signatureData, (bytes, bytes, uint256, uint256, uint256, uint256));
        WebAuthn.WebAuthnAuth memory webAuthnAuth = WebAuthn.WebAuthnAuth(
            authenticatorData, clientDataJSON, challengeIndex, typeIndex, rVal, sVal
        );

        return WebAuthn.verify(abi.encodePacked(hash), true, webAuthnAuth, x, y);
    }

    // ── Internal: Execution ───────────────────────────────────────────

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    // ── Internal: Frame TX Helpers ────────────────────────────────────

    function _findSenderFrameIndex() internal view returns (uint256 idx) {
        uint256 count = FrameTxLib.frameCount();
        uint256 current = FrameTxLib.currentFrameIndex();
        for (idx = current + 1; idx < count; idx++) {
            if (
                FrameTxLib.frameMode(idx) == FRAME_MODE_SENDER
                    && FrameTxLib.frameResolvedTarget(idx) == address(this)
            ) {
                return idx;
            }
        }
        revert InvalidFrameMode();
    }

    // ── Internal: EIP-712 ─────────────────────────────────────────────

    function _domainNameAndVersion() internal pure returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }

    // ── UUPS ──────────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal view override onlyOwner {}
}
