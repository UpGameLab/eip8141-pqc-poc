// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";

/// @title Falcon8141Account
/// @notice EIP-8141 smart account PoC using the EIP-8052 Falcon-512 precompiles.
///
/// @dev EIP-8052 does not assign final precompile addresses yet, so the two
///      precompile addresses are constructor parameters. The calldata/returndata
///      layout follows EIP-8052:
///
///        hash-to-point input: 32-byte message hash || 666-byte Falcon signature
///        hash-to-point output: 896-byte packed challenge polynomial
///        core input: 666-byte signature || 896-byte public key || 896-byte challenge
///        core valid output: uint256(1) encoded in 32 bytes
///
///      Frame transaction pattern:
///        Frame 0: VERIFY(account, flags=approvalScope) -> validate(signature) -> APPROVE
///        Frame 1: SENDER(target)  -> execute(target, value, data)
contract Falcon8141Account {
    /// @dev EIP-8141 ENTRY_POINT address observed as msg.sender in VERIFY/DEFAULT frames.
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    /// @dev EIP-8141 approval scopes from the current EIP-8141 specification.
    uint8 public constant APPROVE_PAYMENT = 0x01;
    uint8 public constant APPROVE_EXECUTION = 0x02;
    uint8 public constant APPROVE_PAYMENT_AND_EXECUTION = APPROVE_PAYMENT | APPROVE_EXECUTION;
    uint8 public constant APPROVE_SCOPE_MASK = APPROVE_PAYMENT_AND_EXECUTION;

    /// @dev EIP-8052 Falcon-512 fixed sizes.
    uint256 public constant FALCON_SIGNATURE_SIZE = 666;
    uint256 public constant FALCON_PUBLIC_KEY_SIZE = 896;
    uint256 public constant FALCON_CHALLENGE_SIZE = 896;
    uint256 public constant FALCON_HASH_TO_POINT_INPUT_SIZE = 698;
    uint256 public constant FALCON_CORE_INPUT_SIZE = 2458;

    /// @dev EIP-8052/EIP-7932 Falcon algorithm type bytes.
    uint8 public constant ALG_TYPE_SHAKE256 = 0xFA;
    uint8 public constant ALG_TYPE_KECCAK_PRNG = 0xFB;

    /// @dev Domain separates signatures from raw EIP-8141 sigHash signatures.
    bytes32 public constant VALIDATION_DOMAIN = keccak256("Falcon8141Account.validation.v1");

    enum HashToPointMode {
        SHAKE256,
        KECCAK_PRNG
    }

    /// @dev Data contract storing runtime code as 0x00 || 896-byte Falcon public key.
    address public immutable publicKeyContract;

    /// @dev EIP-8052 FALCON_HASH_TO_POINT_SHAKE256 or FALCON_HASH_TO_POINT_KECCAKPRNG precompile.
    address public immutable hashToPointPrecompile;

    /// @dev EIP-8052 FALCON_CORE precompile.
    address public immutable falconCorePrecompile;

    HashToPointMode public immutable hashToPointMode;

    /// @notice keccak256(publicKey), exposed for off-chain indexing and sanity checks.
    bytes32 public immutable publicKeyHash;

    /// @notice Falcon signer address using EIP-8052's alg-type-prefixed derivation.
    address public immutable falconSigner;

    error InvalidCaller();
    error InvalidApprovalScope();
    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidPublicKeyContract();
    error InvalidPrecompileConfig();
    error ExecutionFailed();

    /// @param _publicKeyContract SSTORE2-style data contract: runtime code is 0x00 || 896-byte public key.
    /// @param _hashToPointPrecompile EIP-8052 hash-to-point precompile for the selected mode.
    /// @param _falconCorePrecompile EIP-8052 FALCON_CORE precompile.
    /// @param _hashToPointMode SHAKE256 for NIST Falcon-512, KECCAK_PRNG for the EVM-friendly variant.
    constructor(
        address _publicKeyContract,
        address _hashToPointPrecompile,
        address _falconCorePrecompile,
        HashToPointMode _hashToPointMode
    ) {
        if (_hashToPointPrecompile == address(0) || _falconCorePrecompile == address(0)) {
            revert InvalidPrecompileConfig();
        }

        uint256 codeSize;
        assembly {
            codeSize := extcodesize(_publicKeyContract)
        }
        if (codeSize != FALCON_PUBLIC_KEY_SIZE + 1) revert InvalidPublicKeyContract();

        bytes memory keyBytes = _readPublicKey(_publicKeyContract);
        uint8 algorithmType = _algType(_hashToPointMode);

        publicKeyContract = _publicKeyContract;
        hashToPointPrecompile = _hashToPointPrecompile;
        falconCorePrecompile = _falconCorePrecompile;
        hashToPointMode = _hashToPointMode;
        publicKeyHash = keccak256(keyBytes);
        falconSigner = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(algorithmType), keyBytes)))));
    }

    /// @notice Validation entry point for an EIP-8141 VERIFY frame.
    /// @param signature Falcon-512 padded compressed signature, exactly 666 bytes.
    /// @dev The legacy approvalScope argument is ignored; approval scope is read from the current VERIFY frame flags.
    ///
    /// @dev VERIFY frame calldata is elided from the canonical EIP-8141 sigHash.
    ///      To avoid unsigned scope escalation, the Falcon signature signs
    ///      validationDigest(sigHash, approvalScope), not the raw sigHash.
    function validate(bytes calldata signature, uint8 approvalScope) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        if (signature.length != FALCON_SIGNATURE_SIZE) revert InvalidSignatureLength();
        approvalScope = FrameTxLib.currentFrameAllowedScope();
        _checkApprovalScope(approvalScope);

        bytes32 digest = validationDigest(FrameTxLib.sigHash(), approvalScope);
        if (!_verifyFalcon(digest, signature)) revert InvalidSignature();

        FrameTxLib.approveEmpty(approvalScope);
    }

    /// @notice Execution entry point for an EIP-8141 SENDER frame.
    /// @dev In a SENDER frame, msg.sender is the transaction sender, i.e. this account.
    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();

        (bool success,) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();
    }

    /// @notice Digest that the Falcon key must sign for validate().
    function validationDigest(bytes32 sigHash, uint8 approvalScope) public view returns (bytes32) {
        _checkApprovalScope(approvalScope);
        return keccak256(
            abi.encode(
                VALIDATION_DOMAIN, block.chainid, address(this), _algType(hashToPointMode), sigHash, approvalScope
            )
        );
    }

    /// @notice Returns the stored 896-byte Falcon public key.
    function publicKey() external view returns (bytes memory) {
        return _readPublicKey(publicKeyContract);
    }

    /// @notice Returns the EIP-8052/EIP-7932 algorithm type byte for this account.
    function algType() external view returns (uint8) {
        return _algType(hashToPointMode);
    }

    function _verifyFalcon(bytes32 messageHash, bytes calldata signature) internal view returns (bool) {
        bytes memory publicKeyBytes = _readPublicKey(publicKeyContract);

        (bool h2pOk, bytes memory challenge) =
            hashToPointPrecompile.staticcall(abi.encodePacked(messageHash, signature));
        if (!h2pOk || challenge.length != FALCON_CHALLENGE_SIZE) return false;

        (bool coreOk, bytes memory coreResult) =
            falconCorePrecompile.staticcall(abi.encodePacked(signature, publicKeyBytes, challenge));
        if (!coreOk || coreResult.length != 32) return false;

        return abi.decode(coreResult, (uint256)) == 1;
    }

    function _readPublicKey(address dataContract) internal view returns (bytes memory publicKeyBytes) {
        publicKeyBytes = new bytes(FALCON_PUBLIC_KEY_SIZE);
        assembly {
            extcodecopy(dataContract, add(publicKeyBytes, 0x20), 1, 896)
        }
    }

    function _checkApprovalScope(uint8 approvalScope) internal pure {
        if (approvalScope == 0 || (approvalScope & ~APPROVE_SCOPE_MASK) != 0) {
            revert InvalidApprovalScope();
        }
    }

    function _algType(HashToPointMode mode) internal pure returns (uint8) {
        return mode == HashToPointMode.SHAKE256 ? ALG_TYPE_SHAKE256 : ALG_TYPE_KECCAK_PRNG;
    }

    receive() external payable {}
}
