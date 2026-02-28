// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator8141} from "../interfaces/IValidator8141.sol";
import {IHook8141} from "../interfaces/IHook8141.sol";
import {IPolicy8141} from "../interfaces/IPolicy8141.sol";
import {ISigner8141} from "../interfaces/ISigner8141.sol";
import {IModule8141} from "../interfaces/IModule8141.sol";
import {IERC7579Account8141} from "../interfaces/IERC7579Account8141.sol";

import {SelectorManager8141} from "./SelectorManager8141.sol";
import {HookManager8141} from "./HookManager8141.sol";
import {ExecutorManager8141} from "./ExecutorManager8141.sol";

import {EIP712} from "solady/utils/EIP712.sol";
import {ModuleLib8141} from "../utils/ModuleLib8141.sol";
import {ValidatorLib8141} from "../utils/ValidatorLib8141.sol";
import {_intersectValidationData} from "../utils/ValidationResult8141.sol";
import {FrameTxLib} from "../../../FrameTxLib.sol";

import {
    ValidationId,
    PolicyData,
    ValidationMode,
    ValidationType,
    PassFlag,
    PermissionId,
    ValidationData,
    ValidAfter,
    ValidUntil,
    CallType,
    getValidationResult,
    parseValidationData
} from "../types/Types8141.sol";

import {
    PermissionSigMemory,
    PermissionDisableDataFormat,
    PermissionEnableDataFormat,
    EnableDataFormat,
    Execution
} from "../types/Structs8141.sol";

import {
    VALIDATION_MODE_DEFAULT,
    VALIDATION_MODE_ENABLE,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    SKIP_FRAMETX,
    SKIP_SIGNATURE,
    HOOK_NOT_INSTALLED,
    HOOK_INSTALLED,
    HOOK_ONLY_ENTRYPOINT,
    VALIDATION_STORAGE_SLOT,
    MAX_NONCE_INCREMENT_SIZE,
    ENABLE_TYPE_HASH,
    KERNEL_WRAPPER_TYPE_HASH,
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MAGIC_VALUE_SIG_REPLAYABLE,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    CALLTYPE_SINGLE
} from "../types/Constants8141.sol";

/// @title ValidationManager8141
/// @notice Core validation logic for Kernel8141 — manages validators, permissions, nonces, enable mode, EIP-712, ERC-1271.
/// @dev Ported from Kernel v3 ValidationManager, adapted for EIP-8141 frame transactions.
///      Key EIP-8141 advantages:
///      - Hook resolution: SENDER frames derive hook from validator config in storage
///      - Selector ACL via frameDataLoad() cross-frame read (no executeUserOp wrapper needed)
///      - Policy data via frameDataLoad(senderFrame, offset) for rich execution context
///      - Enable data in VERIFY calldata (excluded from sigHash — cleaner separation)
///      - Nonce-based replay protection (per-validator nonce space)
abstract contract ValidationManager8141 is EIP712, SelectorManager8141, HookManager8141, ExecutorManager8141 {
    event RootValidatorUpdated(ValidationId rootValidator);
    event ValidatorInstalled(IValidator8141 validator, uint32 nonce);
    event PermissionInstalled(PermissionId permission, uint32 nonce);
    event NonceInvalidated(uint32 nonce);
    event ValidatorUninstalled(IValidator8141 validator);
    event PermissionUninstalled(PermissionId permission);
    event SelectorSet(bytes4 selector, ValidationId vId, bool allowed);

    error InvalidMode();
    error InvalidValidator();
    error InvalidSignature();
    error InvalidSelectorData();
    error EnableNotApproved();
    error PolicySignatureOrderError();
    error SignerPrefixNotPresent();
    error PolicyDataTooLarge();
    error InvalidValidationType();
    error InvalidNonce();
    error PolicyFailed(uint256 i);
    error PermissionNotAllowedForFrameTx();
    error PermissionNotAllowedForSignature();
    error PermissionDataLengthMismatch();
    error NonceInvalidationError();
    error RootValidatorCannotBeRemoved();

    // ── Storage ─────────────────────────────────────────────────────────

    struct ValidationConfig {
        uint32 nonce; // 4 bytes
        IHook8141 hook; // 20 bytes — address(1): no hook, address(0): not installed
    }

    struct PermissionConfig {
        PassFlag permissionFlag;
        ISigner8141 signer;
        PolicyData[] policyData;
    }

    struct ValidationStorage {
        ValidationId rootValidator;
        uint32 currentNonce;
        uint32 validNonceFrom;
        mapping(ValidationId => ValidationConfig) validationConfig;
        mapping(ValidationId => mapping(bytes4 => bool)) allowedSelectors;
        mapping(PermissionId => PermissionConfig) permissionConfig;
    }

    // ── View functions ──────────────────────────────────────────────────

    function rootValidator() external view returns (ValidationId) {
        return _validationStorage().rootValidator;
    }

    function currentNonce() external view returns (uint32) {
        return _validationStorage().currentNonce;
    }

    function validNonceFrom() external view returns (uint32) {
        return _validationStorage().validNonceFrom;
    }

    function isAllowedSelector(ValidationId vId, bytes4 selector) external view returns (bool) {
        return _validationStorage().allowedSelectors[vId][selector];
    }

    function validationConfig(ValidationId vId) external view returns (ValidationConfig memory) {
        return _validationStorage().validationConfig[vId];
    }

    function permissionConfig(PermissionId pId) external view returns (PermissionConfig memory) {
        return _validationStorage().permissionConfig[pId];
    }

    // ── Storage access ──────────────────────────────────────────────────

    function _validationStorage() internal pure returns (ValidationStorage storage state) {
        assembly {
            state.slot := VALIDATION_STORAGE_SLOT
        }
    }

    function _setRootValidator(ValidationId _rootValidator) internal {
        ValidationStorage storage vs = _validationStorage();
        vs.rootValidator = _rootValidator;
        emit RootValidatorUpdated(_rootValidator);
    }

    // ── Nonce management ────────────────────────────────────────────────

    function _invalidateNonce(uint32 nonce) internal {
        ValidationStorage storage state = _validationStorage();
        if (state.currentNonce + MAX_NONCE_INCREMENT_SIZE < nonce) {
            revert NonceInvalidationError();
        }
        if (nonce <= state.validNonceFrom) {
            revert InvalidNonce();
        }
        state.validNonceFrom = nonce;
        if (state.currentNonce < state.validNonceFrom) {
            state.currentNonce = state.validNonceFrom;
        }
    }

    // ── Selector ACL ────────────────────────────────────────────────────

    function _grantAccess(ValidationId vId, bytes4 selector, bool allow) internal {
        ValidationStorage storage state = _validationStorage();
        state.allowedSelectors[vId][selector] = allow;
        emit SelectorSet(selector, vId, allow);
    }

    // ── Validation install/uninstall ────────────────────────────────────

    function _installValidations(
        ValidationId[] calldata validators,
        ValidationConfig[] memory configs,
        bytes[] calldata validatorData,
        bytes[] calldata hookData
    ) internal {
        unchecked {
            for (uint256 i = 0; i < validators.length; i++) {
                _installValidation(validators[i], configs[i], validatorData[i], hookData[i]);
            }
        }
    }

    function _installValidation(
        ValidationId vId,
        ValidationConfig memory config,
        bytes calldata validatorData,
        bytes calldata hookData
    ) internal {
        ValidationStorage storage state = _validationStorage();
        if (state.validationConfig[vId].nonce == state.currentNonce) {
            unchecked {
                state.currentNonce++;
            }
        }
        if (address(config.hook) == address(0)) {
            config.hook = IHook8141(address(1));
        }
        if (state.currentNonce != config.nonce || state.validationConfig[vId].nonce >= config.nonce) {
            revert InvalidNonce();
        }
        state.validationConfig[vId] = config;
        if (config.hook != IHook8141(address(1))) {
            _installHook(config.hook, hookData);
        }
        ValidationType vType = ValidatorLib8141.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator8141 validator = ValidatorLib8141.getValidator(vId);
            validator.onInstall(validatorData);
            emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator));
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib8141.getPermissionId(vId);
            _installPermission(permission, validatorData);
        } else {
            revert InvalidValidationType();
        }
    }

    function _installPermission(PermissionId permission, bytes calldata permissionData) internal {
        ValidationStorage storage state = _validationStorage();
        PermissionEnableDataFormat calldata permissionEnableData;
        assembly {
            permissionEnableData := permissionData.offset
        }
        bytes[] calldata data = permissionEnableData.data;
        if (data.length > 254 || data.length == 0) {
            revert PolicyDataTooLarge();
        }

        // clean up existing policyData
        if (state.permissionConfig[permission].policyData.length > 0) {
            delete state.permissionConfig[permission].policyData;
        }
        unchecked {
            for (uint256 i = 0; i < data.length - 1; i++) {
                state.permissionConfig[permission].policyData.push(PolicyData.wrap(bytes22(data[i][0:22])));
                IPolicy8141(address(bytes20(data[i][2:22]))).onInstall(
                    abi.encodePacked(bytes32(PermissionId.unwrap(permission)), data[i][22:])
                );
                emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_POLICY, address(bytes20(data[i][2:22])));
            }
            // last entry is the signer
            ISigner8141 signer = ISigner8141(address(bytes20(data[data.length - 1][2:22])));
            state.permissionConfig[permission].signer = signer;
            state.permissionConfig[permission].permissionFlag =
                PassFlag.wrap(bytes2(data[data.length - 1][0:2]));
            signer.onInstall(
                abi.encodePacked(bytes32(PermissionId.unwrap(permission)), data[data.length - 1][22:])
            );
            emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_SIGNER, address(signer));
        }
    }

    function _clearValidationData(ValidationId vId) internal returns (IHook8141 hook) {
        ValidationStorage storage state = _validationStorage();
        if (vId == state.rootValidator) {
            revert RootValidatorCannotBeRemoved();
        }
        hook = state.validationConfig[vId].hook;
        state.validationConfig[vId].hook = IHook8141(address(0));
    }

    function _uninstallPermission(PermissionId pId, bytes calldata data) internal {
        PermissionDisableDataFormat calldata permissionDisableData;
        assembly {
            permissionDisableData := data.offset
        }
        PermissionConfig storage config = _validationStorage().permissionConfig[pId];
        unchecked {
            if (permissionDisableData.data.length != config.policyData.length + 1) {
                revert PermissionDataLengthMismatch();
            }
            PolicyData[] storage policyData = config.policyData;
            for (uint256 i = 0; i < policyData.length; i++) {
                (, IPolicy8141 policy) = ValidatorLib8141.decodePolicyData(policyData[i]);
                ModuleLib8141.uninstallModule(
                    address(policy),
                    abi.encodePacked(bytes32(PermissionId.unwrap(pId)), permissionDisableData.data[i])
                );
                emit IERC7579Account8141.ModuleUninstalled(MODULE_TYPE_POLICY, address(policy));
            }
            delete _validationStorage().permissionConfig[pId].policyData;
            ModuleLib8141.uninstallModule(
                address(config.signer),
                abi.encodePacked(
                    bytes32(PermissionId.unwrap(pId)),
                    permissionDisableData.data[permissionDisableData.data.length - 1]
                )
            );
            emit IERC7579Account8141.ModuleUninstalled(MODULE_TYPE_SIGNER, address(config.signer));
        }
        config.signer = ISigner8141(address(0));
        config.permissionFlag = PassFlag.wrap(bytes2(0));
    }

    // ── Frame TX Validation (EIP-8141 native) ───────────────────────────

    /// @notice Validate a frame transaction. Called during VERIFY frame.
    /// @dev EIP-8141 native: uses sigHash directly, cross-frame reading for selector ACL.
    /// @param vMode Validation mode (DEFAULT or ENABLE)
    /// @param vId The validator/permission identifier
    /// @param account The account address being validated
    /// @param sigHash The canonical signature hash from TXPARAMLOAD(0x08)
    /// @param senderFrameIndex The index of the SENDER frame for cross-frame data
    /// @param signature The raw signature bytes
    /// @return validationData Packed validation data (validAfter, validUntil, result)
    function _validateFrameTx(
        ValidationMode vMode,
        ValidationId vId,
        address account,
        bytes32 sigHash,
        uint256 senderFrameIndex,
        bytes calldata signature
    ) internal returns (ValidationData validationData) {
        ValidationStorage storage state = _validationStorage();
        bytes calldata sig = signature;

        unchecked {
            // Handle replayable signatures
            bool isReplayable;
            if (sig.length >= 32 && bytes32(sig[0:32]) == MAGIC_VALUE_SIG_REPLAYABLE) {
                sig = sig[32:];
                isReplayable = true;
                // NOTE: In EIP-8141, sigHash is protocol-provided and already binds SENDER frame.
                // Replayable mode uses chain-agnostic hashing for the enable mode digest only.
            }

            // Handle enable mode
            if (vMode == VALIDATION_MODE_ENABLE) {
                (validationData, sig) = _enableMode(vId, sig, isReplayable);
            }

            // Validate based on type
            ValidationType vType = ValidatorLib8141.getType(vId);
            if (vType == VALIDATION_TYPE_VALIDATOR) {
                IValidator8141 validator = ValidatorLib8141.getValidator(vId);
                bool valid = validator.validateSignature(account, sigHash, sig);
                if (!valid) {
                    validationData = _intersectValidationData(
                        validationData, ValidationData.wrap(1) // SIG_VALIDATION_FAILED
                    );
                }
            } else if (vType == VALIDATION_TYPE_PERMISSION) {
                validationData = _intersectValidationData(
                    validationData,
                    _validatePermissionFrameTx(vId, account, sigHash, senderFrameIndex, sig)
                );
            } else {
                revert InvalidValidationType();
            }

            // NOTE: VERIFY frames are read-only (no sstore/tstore allowed).
            // The SENDER frame derives the hook from storage directly.
        }
    }

    /// @notice Validate a permission-based frame tx signature.
    function _validatePermissionFrameTx(
        ValidationId vId,
        address account,
        bytes32 sigHash,
        uint256 senderFrameIndex,
        bytes calldata sig
    ) internal returns (ValidationData validationData) {
        ValidationStorage storage state = _validationStorage();
        PermissionId pId = ValidatorLib8141.getPermissionId(vId);
        if (
            PassFlag.unwrap(state.permissionConfig[pId].permissionFlag)
                & PassFlag.unwrap(SKIP_FRAMETX) != 0
        ) {
            revert PermissionNotAllowedForFrameTx();
        }
        (ValidationData policyCheck, ISigner8141 signer, bytes calldata signerSig) =
            _checkFrameTxPolicy(pId, account, sigHash, senderFrameIndex, sig);
        validationData = _intersectValidationData(policyCheck, ValidationData.wrap(
            signer.checkFrameTxSignature(bytes32(PermissionId.unwrap(pId)), account, sigHash, signerSig)
        ));
    }

    /// @notice Check frame tx policies for a permission.
    /// @dev EIP-8141 native: passes senderFrameIndex so policies can use frameDataLoad()
    ///      to read SENDER frame's target, value, and calldata directly.
    function _checkFrameTxPolicy(
        PermissionId pId,
        address account,
        bytes32 sigHash,
        uint256 senderFrameIndex,
        bytes calldata sig
    ) internal returns (ValidationData validationData, ISigner8141 signer, bytes calldata signerSig) {
        ValidationStorage storage state = _validationStorage();
        PolicyData[] storage policyData = state.permissionConfig[pId].policyData;
        bytes32 permId = bytes32(PermissionId.unwrap(pId));
        unchecked {
            for (uint256 i = 0; i < policyData.length; i++) {
                (sig, validationData) =
                    _checkSinglePolicy(policyData, permId, account, sigHash, senderFrameIndex, sig, i, validationData);
            }
            if (uint8(bytes1(sig[0])) != 255) {
                revert SignerPrefixNotPresent();
            }
            sig = sig[1:];
            return (validationData, state.permissionConfig[pId].signer, sig);
        }
    }

    function _checkSinglePolicy(
        PolicyData[] storage policyData,
        bytes32 permId,
        address account,
        bytes32 sigHash,
        uint256 senderFrameIndex,
        bytes calldata sig,
        uint256 i,
        ValidationData validationData
    ) internal returns (bytes calldata, ValidationData) {
        (PassFlag flag, IPolicy8141 policy) = ValidatorLib8141.decodePolicyData(policyData[i]);
        {
            uint8 idx = uint8(bytes1(sig[0]));
            if (idx == i) {
                sig = sig[9 + uint64(bytes8(sig[1:9])):];
            } else if (idx < i) {
                revert PolicySignatureOrderError();
            }
        }
        if (PassFlag.unwrap(flag) & PassFlag.unwrap(SKIP_FRAMETX) == 0) {
            ValidationData vd = ValidationData.wrap(
                policy.checkFrameTxPolicy(permId, account, sigHash, senderFrameIndex)
            );
            if (getValidationResult(vd) != address(0)) {
                revert PolicyFailed(i);
            }
            validationData = _intersectValidationData(validationData, vd);
        }
        return (sig, validationData);
    }

    // ── Stateful Policy Consumption (SENDER phase) ─────────────────────

    /// @notice Consume stateful policies in SENDER frame context.
    /// @dev Called from executeHooked() for permission-based validation.
    ///      Iterates all policies and calls consumeFrameTxPolicy() on each.
    ///      Read-only policies implement this as no-op; stateful policies
    ///      (e.g. GasPolicy) perform state writes here (e.g. budget decrement).
    function _consumeStatefulPolicies(PermissionId pId) internal {
        ValidationStorage storage state = _validationStorage();
        PolicyData[] storage policies = state.permissionConfig[pId].policyData;
        bytes32 permId = bytes32(PermissionId.unwrap(pId));
        for (uint256 i = 0; i < policies.length; i++) {
            (, IPolicy8141 policy) = ValidatorLib8141.decodePolicyData(policies[i]);
            policy.consumeFrameTxPolicy(permId, address(this));
        }
    }

    // ── Enable Mode ─────────────────────────────────────────────────────

    /// @notice Handle enable mode — install + validate in one VERIFY frame call.
    /// @dev EIP-8141 advantage: enable data is in VERIFY frame calldata, which is
    ///      excluded from sigHash computation. This means enable data doesn't pollute
    ///      the signature at all — cleaner separation than Kernel v3.
    /// @dev View-only enable mode verification. Verifies enable signature without sstore.
    ///      Used in VERIFY frame where state modification is prohibited.
    function _verifyEnableMode(ValidationId vId, bytes calldata packedData, bool isReplayable)
        internal
        view
        returns (ValidationData validationData, bytes calldata sig)
    {
        // packedData format: [20B hook address][EnableDataFormat...]
        address hook = address(bytes20(packedData[0:20]));
        EnableDataFormat calldata enableData;
        assembly {
            enableData := add(packedData.offset, 20)
        }
        (, bytes32 digest) = _enableDigest(vId, hook, enableData, isReplayable);
        validationData = _verifyEnableSig(digest, enableData.enableSig);
        return (validationData, enableData.txSig);
    }

    /// @dev Full enable mode with sstore. Called from DEFAULT frame (enableInstall).
    function _enableMode(ValidationId vId, bytes calldata packedData, bool isReplayable)
        internal
        returns (ValidationData validationData, bytes calldata sig)
    {
        // packedData format: [20B hook address][EnableDataFormat...]
        address hook = address(bytes20(packedData[0:20]));
        EnableDataFormat calldata enableData;
        assembly {
            enableData := add(packedData.offset, 20)
        }
        validationData = _enableValidationWithSig(vId, hook, enableData, isReplayable);
        return (validationData, enableData.txSig);
    }

    function _enableValidationWithSig(
        ValidationId vId,
        address hook,
        EnableDataFormat calldata enableData,
        bool isReplayable
    ) internal returns (ValidationData validationData) {
        (ValidationConfig memory config, bytes32 digest) = _enableDigest(vId, hook, enableData, isReplayable);
        validationData = _verifyEnableSig(digest, enableData.enableSig);
        _installValidation(vId, config, enableData.validatorData, enableData.hookData);
        _configureSelector(enableData.selectorData);
        _grantAccess(vId, bytes4(enableData.selectorData[0:4]), true);
    }

    function _enableDigest(
        ValidationId vId,
        address hook,
        EnableDataFormat calldata enableData,
        bool isReplayable
    ) internal view returns (ValidationConfig memory config, bytes32 digest) {
        ValidationStorage storage state = _validationStorage();
        config.hook = IHook8141(hook);
        unchecked {
            config.nonce = state.validationConfig[vId].nonce == state.currentNonce
                ? state.currentNonce + 1
                : state.currentNonce;
        }

        bytes32 structHash = keccak256(
            abi.encode(
                ENABLE_TYPE_HASH,
                ValidationId.unwrap(vId),
                config.nonce,
                config.hook,
                keccak256(enableData.validatorData),
                keccak256(enableData.hookData),
                keccak256(enableData.selectorData)
            )
        );

        digest = isReplayable ? _chainAgnosticHashTypedData(structHash) : _hashTypedData(structHash);
    }

    function _verifyEnableSig(bytes32 digest, bytes calldata enableSig)
        internal
        view
        returns (ValidationData validationData)
    {
        ValidationStorage storage state = _validationStorage();
        ValidationType vType = ValidatorLib8141.getType(state.rootValidator);
        bytes4 result;
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator8141 validator = ValidatorLib8141.getValidator(state.rootValidator);
            result = validator.isValidSignatureWithSender(address(this), digest, enableSig);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = ValidatorLib8141.getPermissionId(state.rootValidator);
            ISigner8141 signer;
            (signer, validationData, enableSig) = _checkSignaturePolicy(pId, address(this), digest, enableSig);
            result = signer.checkSignature(bytes32(PermissionId.unwrap(pId)), address(this), digest, enableSig);
        } else {
            revert InvalidValidationType();
        }
        if (result != ERC1271_MAGICVALUE) {
            revert EnableNotApproved();
        }
    }

    function _configureSelector(bytes calldata selectorData) internal {
        bytes4 selector = bytes4(selectorData[0:4]);

        if (selectorData.length >= 44) {
            // selectorData format: [4B selector][20B module][20B hook][calldata selectorInitData...][calldata hookInitData...]
            address selectorModule = address(bytes20(selectorData[4:24]));
            IHook8141 selectorHook = IHook8141(address(bytes20(selectorData[24:44])));

            // Remaining data is ABI-encoded (bytes selectorInitData, bytes hookInitData)
            // We need to pass calldata slices to _installSelector and _installHook
            // Use assembly to extract the calldata pointers
            bytes calldata selectorInitData;
            bytes calldata hookInitData;
            assembly {
                // abi.encode(bytes, bytes) layout at selectorData[44:]
                let base := add(selectorData.offset, 44)
                // first bytes offset
                let selectorInitOffset := add(base, calldataload(base))
                selectorInitData.offset := add(selectorInitOffset, 0x20)
                selectorInitData.length := calldataload(selectorInitOffset)
                // second bytes offset
                let hookInitOffset := add(base, calldataload(add(base, 0x20)))
                hookInitData.offset := add(hookInitOffset, 0x20)
                hookInitData.length := calldataload(hookInitOffset)
            }

            // If module is also an executor (isModuleType(2)), install as executor too
            if (
                selectorInitData.length > 0
                    && bytes1(selectorInitData[0]) == CallType.unwrap(CALLTYPE_SINGLE)
                    && IModule8141(selectorModule).isModuleType(MODULE_TYPE_EXECUTOR)
            ) {
                _installExecutorWithoutInit(selectorModule, selectorHook);
            }

            _installSelector(selector, selectorModule, selectorHook, selectorInitData);
            _installHook(selectorHook, hookInitData);
        } else {
            if (selectorData.length != 4) {
                revert InvalidSelectorData();
            }
        }
    }

    // ── ERC-1271 Signature Verification ─────────────────────────────────

    /// @notice Verify an off-chain signature (ERC-1271).
    /// @dev Routes to validator or permission based on signature prefix.
    function _verifySignature(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        ValidationStorage storage vs = _validationStorage();
        (ValidationId vId, bytes calldata sig) = ValidatorLib8141.decodeSignature(signature);
        if (ValidatorLib8141.getType(vId) == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }
        bool isReplayable = sig.length >= 32 && bytes32(sig[0:32]) == MAGIC_VALUE_SIG_REPLAYABLE;
        if (isReplayable) {
            sig = sig[32:];
        }
        ValidationType vType = ValidatorLib8141.getType(vId);
        ValidationConfig memory vc = vs.validationConfig[vId];
        if (address(vc.hook) == HOOK_NOT_INSTALLED) {
            revert InvalidValidator();
        }
        if (vType != VALIDATION_TYPE_ROOT && vc.nonce < vs.validNonceFrom) {
            revert InvalidNonce();
        }
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator8141 validator = ValidatorLib8141.getValidator(vId);
            return validator.isValidSignatureWithSender(msg.sender, _toWrappedHash(hash, isReplayable), sig);
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId pId = ValidatorLib8141.getPermissionId(vId);
            PassFlag permissionFlag = vs.permissionConfig[pId].permissionFlag;
            if (PassFlag.unwrap(permissionFlag) & PassFlag.unwrap(SKIP_SIGNATURE) != 0) {
                revert PermissionNotAllowedForSignature();
            }
            return _checkPermissionSignature(pId, hash, sig, isReplayable);
        } else {
            revert InvalidValidationType();
        }
    }

    function _checkPermissionSignature(
        PermissionId pId,
        bytes32 hash,
        bytes calldata sig,
        bool isReplayable
    ) internal view returns (bytes4) {
        (ISigner8141 signer, ValidationData validationData, bytes calldata validatorSig) =
            _checkSignaturePolicy(pId, msg.sender, hash, sig);
        (ValidAfter validAfter, ValidUntil validUntil,) =
            parseValidationData(ValidationData.unwrap(validationData));
        if (block.timestamp < ValidAfter.unwrap(validAfter) || block.timestamp > ValidUntil.unwrap(validUntil)) {
            return ERC1271_INVALID;
        }
        return signer.checkSignature(
            bytes32(PermissionId.unwrap(pId)), msg.sender, _toWrappedHash(hash, isReplayable), validatorSig
        );
    }

    function _checkSignaturePolicy(PermissionId pId, address caller, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (ISigner8141, ValidationData, bytes calldata)
    {
        ValidationStorage storage state = _validationStorage();
        PermissionSigMemory memory mSig;
        mSig.permission = pId;
        mSig.caller = caller;
        mSig.digest = digest;
        _checkPermissionPolicy(mSig, state, sig);
        if (uint8(bytes1(sig[0])) != 255) {
            revert SignerPrefixNotPresent();
        }
        sig = sig[1:];
        return (state.permissionConfig[mSig.permission].signer, mSig.validationData, sig);
    }

    function _checkPermissionPolicy(
        PermissionSigMemory memory mSig,
        ValidationStorage storage state,
        bytes calldata sig
    ) internal view {
        PolicyData[] storage policyData = state.permissionConfig[mSig.permission].policyData;
        unchecked {
            for (uint256 i = 0; i < policyData.length; i++) {
                (mSig.flag, mSig.policy) = ValidatorLib8141.decodePolicyData(policyData[i]);
                mSig.idx = uint8(bytes1(sig[0]));
                if (mSig.idx == i) {
                    mSig.length = uint64(bytes8(sig[1:9]));
                    mSig.permSig = sig[9:9 + mSig.length];
                    sig = sig[9 + mSig.length:];
                } else if (mSig.idx < i) {
                    revert PolicySignatureOrderError();
                } else {
                    mSig.permSig = sig[0:0];
                }

                if (PassFlag.unwrap(mSig.flag) & PassFlag.unwrap(SKIP_SIGNATURE) == 0) {
                    ValidationData vd = ValidationData.wrap(
                        mSig.policy.checkSignaturePolicy(
                            bytes32(PermissionId.unwrap(mSig.permission)), mSig.caller, mSig.digest, mSig.permSig
                        )
                    );
                    address result = getValidationResult(vd);
                    if (result != address(0)) {
                        revert PolicyFailed(i);
                    }
                    mSig.validationData = _intersectValidationData(mSig.validationData, vd);
                }
            }
        }
    }

    // ── EIP-712 helpers ─────────────────────────────────────────────────

    function _toWrappedHash(bytes32 hash, bool isReplayable) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(KERNEL_WRAPPER_TYPE_HASH, hash));
        return isReplayable ? _chainAgnosticHashTypedData(structHash) : _hashTypedData(structHash);
    }

    /// @dev Chain-agnostic domain separator (chainId = 0) for replayable signatures.
    function _buildChainAgnosticDomainSeparator() internal view returns (bytes32 separator) {
        bytes32 versionHash;
        (string memory name, string memory version) = _domainNameAndVersion();
        separator = keccak256(bytes(name));
        versionHash = keccak256(bytes(version));
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), separator) // Name hash
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), 0x00) // chainId = 0 for chain-agnostic
            mstore(add(m, 0x80), address())
            separator := keccak256(m, 0xa0)
        }
    }

    function _chainAgnosticHashTypedData(bytes32 structHash) internal view returns (bytes32 digest) {
        digest = _buildChainAgnosticDomainSeparator();
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0x1901000000000000) // "\x19\x01"
            mstore(0x1a, digest)
            mstore(0x3a, structHash)
            digest := keccak256(0x18, 0x42)
            mstore(0x3a, 0)
        }
    }

}
