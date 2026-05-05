// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";

/// @title EmbeddedFalcon8141Account
/// @notice EIP-8141 smart account PoC using EIP-8052 Falcon-512 precompiles.
///
/// @dev Unlike Falcon8141Account, this account stores the 896-byte Falcon public
///      key as a suffix of its own runtime code. The account must be deployed via
///      EmbeddedFalcon8141AccountFactory or equivalent initcode that returns:
///
///        type(EmbeddedFalcon8141Account).runtimeCode || publicKey
///
///      EIP-8052 does not assign final precompile addresses yet, so precompile
///      addresses are initialized after deployment. The public key itself is never
///      written to storage.
contract EmbeddedFalcon8141Account {
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
    bytes32 public constant VALIDATION_DOMAIN = keccak256("EmbeddedFalcon8141Account.validation.v1");

    enum HashToPointMode {
        SHAKE256,
        KECCAK_PRNG
    }

    bool public initialized;
    address public hashToPointPrecompile;
    address public falconCorePrecompile;
    HashToPointMode public hashToPointMode;

    error AlreadyInitialized();
    error NotInitialized();
    error InvalidCaller();
    error InvalidApprovalScope();
    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidEmbeddedPublicKey();
    error InvalidPrecompileConfig();
    error ExecutionFailed();
    error DirectDeploymentUnsupported();

    /// @dev The account runtime must be deployed with a public-key suffix. The factory
    ///      bypasses this constructor by returning `runtimeCode || publicKey` directly.
    constructor() {
        revert DirectDeploymentUnsupported();
    }

    /// @notice Initializes precompile configuration for a freshly deployed code-suffix account.
    /// @dev The factory passes expectedPublicKeyHash to prove the runtime suffix is the intended key.
    function initialize(
        address _hashToPointPrecompile,
        address _falconCorePrecompile,
        HashToPointMode _hashToPointMode,
        bytes32 expectedPublicKeyHash
    ) external {
        if (initialized) revert AlreadyInitialized();
        if (_hashToPointPrecompile == address(0) || _falconCorePrecompile == address(0)) {
            revert InvalidPrecompileConfig();
        }
        if (publicKeyHash() != expectedPublicKeyHash) revert InvalidEmbeddedPublicKey();

        initialized = true;
        hashToPointPrecompile = _hashToPointPrecompile;
        falconCorePrecompile = _falconCorePrecompile;
        hashToPointMode = _hashToPointMode;
    }

    /// @notice Validation entry point for an EIP-8141 VERIFY frame.
    /// @param signature Falcon-512 compressed signature, exactly 666 bytes.
    /// @dev The legacy approvalScope argument is ignored; approval scope is read from the current VERIFY frame flags.
    function validate(bytes calldata signature, uint8 approvalScope) external view {
        if (!initialized) revert NotInitialized();
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
        if (!initialized) revert NotInitialized();
        _checkApprovalScope(approvalScope);
        return keccak256(abi.encode(VALIDATION_DOMAIN, block.chainid, address(this), algType(), sigHash, approvalScope));
    }

    /// @notice Returns the embedded 896-byte Falcon public key.
    function publicKey() public view returns (bytes memory publicKeyBytes) {
        _requireEmbeddedPublicKey();
        publicKeyBytes = new bytes(FALCON_PUBLIC_KEY_SIZE);
        assembly {
            codecopy(add(publicKeyBytes, 0x20), sub(codesize(), 896), 896)
        }
    }

    /// @notice keccak256(publicKey), exposed for off-chain indexing and sanity checks.
    function publicKeyHash() public view returns (bytes32) {
        return keccak256(publicKey());
    }

    /// @notice Falcon signer address using EIP-8052's alg-type-prefixed derivation.
    function falconSigner() external view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(algType()), publicKey())))));
    }

    /// @notice Returns the byte offset where the embedded public key starts in runtime code.
    function publicKeyOffset() external view returns (uint256) {
        _requireEmbeddedPublicKey();
        return address(this).code.length - FALCON_PUBLIC_KEY_SIZE;
    }

    /// @notice Returns the EIP-8052/EIP-7932 algorithm type byte for this account.
    function algType() public view returns (uint8) {
        return _algType(hashToPointMode);
    }

    function _verifyFalcon(bytes32 messageHash, bytes calldata signature) internal view returns (bool) {
        bytes memory publicKeyBytes = publicKey();

        (bool h2pOk, bytes memory challenge) =
            hashToPointPrecompile.staticcall(abi.encodePacked(messageHash, signature));
        if (!h2pOk || challenge.length != FALCON_CHALLENGE_SIZE) return false;

        (bool coreOk, bytes memory coreResult) =
            falconCorePrecompile.staticcall(abi.encodePacked(signature, publicKeyBytes, challenge));
        if (!coreOk || coreResult.length != 32) return false;

        return abi.decode(coreResult, (uint256)) == 1;
    }

    function _requireEmbeddedPublicKey() internal view {
        if (address(this).code.length < FALCON_PUBLIC_KEY_SIZE) revert InvalidEmbeddedPublicKey();
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

/// @title EmbeddedFalcon8141AccountFactory
/// @notice Deploys EmbeddedFalcon8141Account with the Falcon public key appended to runtime code.
contract EmbeddedFalcon8141AccountFactory {
    uint256 internal constant FALCON_PUBLIC_KEY_SIZE = 896;
    uint256 internal constant MAX_RUNTIME_CODE_SIZE = 24_576;

    error InvalidPublicKeyLength();
    error InvalidPrecompileConfig();
    error RuntimeTooLarge();
    error CreateFailed();

    event AccountDeployed(
        address indexed account,
        bytes32 indexed publicKeyHash,
        address hashToPointPrecompile,
        address falconCorePrecompile,
        EmbeddedFalcon8141Account.HashToPointMode hashToPointMode
    );

    function deploy(
        bytes calldata publicKey,
        address hashToPointPrecompile,
        address falconCorePrecompile,
        EmbeddedFalcon8141Account.HashToPointMode hashToPointMode
    ) external returns (EmbeddedFalcon8141Account account) {
        return _deploy(publicKey, hashToPointPrecompile, falconCorePrecompile, hashToPointMode, bytes32(0), false);
    }

    function deployDeterministic(
        bytes calldata publicKey,
        address hashToPointPrecompile,
        address falconCorePrecompile,
        EmbeddedFalcon8141Account.HashToPointMode hashToPointMode,
        bytes32 salt
    ) external returns (EmbeddedFalcon8141Account account) {
        return _deploy(publicKey, hashToPointPrecompile, falconCorePrecompile, hashToPointMode, salt, true);
    }

    function initCodeHash(bytes calldata publicKey) external pure returns (bytes32) {
        return keccak256(initCode(publicKey));
    }

    function initCode(bytes calldata publicKey) public pure returns (bytes memory) {
        if (publicKey.length != FALCON_PUBLIC_KEY_SIZE) revert InvalidPublicKeyLength();

        bytes memory publicKeyBytes = publicKey;
        return _initCode(publicKeyBytes);
    }

    function _deploy(
        bytes calldata publicKey,
        address hashToPointPrecompile,
        address falconCorePrecompile,
        EmbeddedFalcon8141Account.HashToPointMode hashToPointMode,
        bytes32 salt,
        bool deterministic
    ) internal returns (EmbeddedFalcon8141Account account) {
        if (hashToPointPrecompile == address(0) || falconCorePrecompile == address(0)) {
            revert InvalidPrecompileConfig();
        }

        if (publicKey.length != FALCON_PUBLIC_KEY_SIZE) revert InvalidPublicKeyLength();

        bytes memory publicKeyBytes = publicKey;
        bytes memory accountInitCode = _initCode(publicKeyBytes);
        address deployed;
        if (deterministic) {
            assembly {
                deployed := create2(0, add(accountInitCode, 0x20), mload(accountInitCode), salt)
            }
        } else {
            assembly {
                deployed := create(0, add(accountInitCode, 0x20), mload(accountInitCode))
            }
        }
        if (deployed == address(0)) revert CreateFailed();

        account = EmbeddedFalcon8141Account(payable(deployed));
        bytes32 embeddedPublicKeyHash = keccak256(publicKeyBytes);
        account.initialize(hashToPointPrecompile, falconCorePrecompile, hashToPointMode, embeddedPublicKeyHash);

        emit AccountDeployed(
            deployed, embeddedPublicKeyHash, hashToPointPrecompile, falconCorePrecompile, hashToPointMode
        );
    }

    function _runtimeReturnInitCode(bytes memory runtime) internal pure returns (bytes memory) {
        if (runtime.length > MAX_RUNTIME_CODE_SIZE) revert RuntimeTooLarge();

        return bytes.concat(bytes1(0x61), bytes2(uint16(runtime.length)), hex"80600a3d393df3", runtime);
    }

    function _initCode(bytes memory publicKey) internal pure returns (bytes memory) {
        return _runtimeReturnInitCode(bytes.concat(type(EmbeddedFalcon8141Account).runtimeCode, publicKey));
    }
}
