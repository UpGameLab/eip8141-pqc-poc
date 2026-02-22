// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../../FrameTxLib.sol";
import {ValidationManager8141} from "./core/ValidationManager8141.sol";
import {
    ValidationId,
    ValidationMode,
    ValidationType,
    PermissionId,
    ValidationData,
    PassFlag,
    CallType,
    ExecMode,
    ExecType,
    ExecModeSelector,
    ExecModePayload
} from "./types/Types8141.sol";
import {IValidator8141} from "./interfaces/IValidator8141.sol";
import {IHook8141} from "./interfaces/IHook8141.sol";
import {IModule8141} from "./interfaces/IModule8141.sol";
import {IERC7579Account8141} from "./interfaces/IERC7579Account8141.sol";
import {ValidatorLib8141} from "./utils/ValidatorLib8141.sol";
import {ExecLib8141} from "./utils/ExecLib8141.sol";
import {ModuleLib8141} from "./utils/ModuleLib8141.sol";
import {
    InstallValidatorDataFormat,
    InstallExecutorDataFormat,
    InstallFallbackDataFormat
} from "./types/Structs8141.sol";
import {
    VALIDATION_MODE_DEFAULT,
    VALIDATION_MODE_ENABLE,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    HOOK_NOT_INSTALLED,
    HOOK_INSTALLED,
    HOOK_ONLY_ENTRYPOINT,
    ERC1967_IMPLEMENTATION_SLOT,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_STATIC,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    EXEC_MODE_DEFAULT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "./types/Constants8141.sol";

/// @title Kernel8141
/// @notice Modular EIP-8141 smart account with Kernel v3 feature parity.
/// @dev Inherits ValidationManager8141 (→ SelectorManager8141 + HookManager8141 + ExecutorManager8141).
///
///   Architecture:
///     Kernel8141
///       └── ValidationManager8141 (validator/permission/nonce/enable/EIP-712/ERC-1271)
///             ├── SelectorManager8141   (fallback selector routing)
///             ├── HookManager8141       (unified hook lifecycle)
///             └── ExecutorManager8141   (executor registry)
///
///   Frame transaction patterns:
///
///     Simple Transaction (root validator):
///       Frame 0: VERIFY(kernel)  → kernel.validate(sig, scope=2)          → APPROVE(both)
///       Frame 1: SENDER(kernel)  → kernel.execute(mode, data)
///
///     Non-Root Validator (sigHash-bound):
///       Frame 0: VERIFY(kernel)  → kernel.validateFromSenderFrame(sig, scope)
///       Frame 1: SENDER(kernel)  → kernel.validatedCall(validator, data)
///
///     Enable Mode (install + validate in one tx):
///       Frame 0: VERIFY(kernel)  → kernel.validateWithEnable(enableData, sig, scope)
///       Frame 1: SENDER(kernel)  → kernel.execute(mode, data)
///
///     Permission-Based:
///       Frame 0: VERIFY(kernel)  → kernel.validatePermission(sig, scope)
///       Frame 1: SENDER(kernel)  → kernel.execute(mode, data)
contract Kernel8141 is IERC7579Account8141, ValidationManager8141 {
    error ExecutionReverted();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();
    error InvalidModuleType();
    error InvalidCaller();
    error InvalidSelector();
    error InitConfigError(uint256 idx);
    error AlreadyInitialized();

    event Received(address sender, uint256 amount);
    event Upgraded(address indexed implementation);

    // Frame mode constants
    uint8 internal constant FRAME_MODE_DEFAULT = 0;
    uint8 internal constant FRAME_MODE_VERIFY = 1;
    uint8 internal constant FRAME_MODE_SENDER = 2;

    constructor() {
        // Sentinel: mark implementation as initialized to prevent direct use
        _validationStorage().rootValidator = ValidationId.wrap(bytes21(abi.encodePacked(hex"deadbeef")));
    }

    // ── Access control ──────────────────────────────────────────────────

    modifier onlySelfOrRoot() {
        if (msg.sender != address(this)) {
            IValidator8141 rv = ValidatorLib8141.getValidator(_validationStorage().rootValidator);
            if (rv.isModuleType(MODULE_TYPE_HOOK)) {
                bytes memory ret = IHook8141(address(rv)).preCheck(msg.sender, msg.value, msg.data);
                _;
                IHook8141(address(rv)).postCheck(ret);
            } else {
                revert InvalidCaller();
            }
        } else {
            _;
        }
    }

    // ── Initialization ──────────────────────────────────────────────────

    function initialize(
        ValidationId _rootValidator,
        IHook8141 hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes[] calldata initConfig
    ) external {
        ValidationStorage storage vs = _validationStorage();
        if (ValidationId.unwrap(vs.rootValidator) != bytes21(0)) {
            revert AlreadyInitialized();
        }
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib8141.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        ValidationConfig memory config = ValidationConfig({nonce: uint32(1), hook: hook});
        vs.currentNonce = 1;
        _installValidation(_rootValidator, config, validatorData, hookData);
        for (uint256 i = 0; i < initConfig.length; i++) {
            (bool success,) = address(this).call(initConfig[i]);
            if (!success) {
                revert InitConfigError(i);
            }
        }
    }

    function changeRootValidator(
        ValidationId _rootValidator,
        IHook8141 hook,
        bytes calldata validatorData,
        bytes calldata hookData
    ) external payable onlySelfOrRoot {
        ValidationStorage storage vs = _validationStorage();
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib8141.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        if (_validationStorage().validationConfig[_rootValidator].hook == IHook8141(HOOK_NOT_INSTALLED)) {
            ValidationConfig memory config = ValidationConfig({nonce: uint32(vs.currentNonce), hook: hook});
            _installValidation(_rootValidator, config, validatorData, hookData);
        }
    }

    function upgradeTo(address _newImplementation) external payable onlySelfOrRoot {
        assembly {
            sstore(ERC1967_IMPLEMENTATION_SLOT, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    // ── EIP-712 ─────────────────────────────────────────────────────────

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel8141";
        version = "0.1.0";
    }

    // ── VERIFY frame: Validation ────────────────────────────────────────

    /// @notice Root validator validation. Called during VERIFY frame.
    function validate(bytes calldata sig, uint8 scope) external {
        _requireVerifyFrame();
        ValidationStorage storage vs = _validationStorage();
        ValidationId vId = vs.rootValidator;
        address account = FrameTxLib.txSender();
        bytes32 sigHash = FrameTxLib.sigHash();
        uint256 senderFrameIdx = _findSenderFrameIndex();
        _validateFrameTx(VALIDATION_MODE_DEFAULT, vId, account, sigHash, senderFrameIdx, sig);
        FrameTxLib.approveEmpty(scope);
    }

    /// @notice Non-root validator validation. sigHash binds to SENDER frame calldata.
    function validateFromSenderFrame(bytes calldata sig, uint8 scope) external {
        _requireVerifyFrame();
        ValidationStorage storage vs = _validationStorage();
        address account = FrameTxLib.txSender();
        bytes32 sigHash = FrameTxLib.sigHash();
        uint256 senderFrameIdx = _findSenderFrameIndex();

        // Decode ValidationId from signature prefix
        // sig format: [1B type][20B validator addr][actual sig]
        ValidationId vId;
        bytes calldata actualSig;
        assembly {
            vId := calldataload(sig.offset)
            actualSig.offset := add(sig.offset, 21)
            actualSig.length := sub(sig.length, 21)
        }

        ValidationType vType = ValidatorLib8141.getType(vId);
        if (vType == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }

        // Check nonce validity
        ValidationConfig memory vc = vs.validationConfig[vId];
        if (address(vc.hook) == HOOK_NOT_INSTALLED && vType != VALIDATION_TYPE_ROOT) {
            revert InvalidValidator();
        }
        if (vType != VALIDATION_TYPE_ROOT && vc.nonce < vs.validNonceFrom) {
            revert InvalidNonce();
        }

        // EIP-8141 native selector ACL: read SENDER frame selector via cross-frame reading
        if (vType != VALIDATION_TYPE_ROOT) {
            bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderFrameIdx, 0));
            if (!vs.allowedSelectors[vId][senderSelector]) {
                revert InvalidSelector();
            }
        }

        _validateFrameTx(VALIDATION_MODE_DEFAULT, vId, account, sigHash, senderFrameIdx, actualSig);

        FrameTxLib.approveEmpty(scope);
    }

    /// @notice Enable mode: install a new validator and validate in one VERIFY frame.
    /// @dev EIP-8141 advantage: enable data is in VERIFY calldata, excluded from sigHash.
    ///
    /// WARNING: This function is currently non-functional under EIP-8141.
    /// The enable mode calls _installValidation(), _configureSelector(), and _grantAccess(),
    /// all of which perform `sstore` (persistent storage writes). However, this function
    /// executes inside a VERIFY frame, which is read-only (equivalent to STATICCALL).
    /// Any `sstore` or `tstore` in a VERIFY frame causes an immediate revert.
    /// To make enable mode work, the install logic would need to be moved to the
    /// SENDER frame, or performed in a separate transaction.
    function validateWithEnable(bytes calldata enableData, bytes calldata sig, uint8 scope) external {
        _requireVerifyFrame();
        address account = FrameTxLib.txSender();
        bytes32 sigHash = FrameTxLib.sigHash();
        uint256 senderFrameIdx = _findSenderFrameIndex();

        // Decode ValidationId from first 21 bytes of sig
        ValidationId vId;
        bytes calldata actualSig;
        assembly {
            vId := calldataload(sig.offset)
            actualSig.offset := add(sig.offset, 21)
            actualSig.length := sub(sig.length, 21)
        }

        // Prepend enable data to the actual signature for _enableMode processing
        // enableData is passed separately in EIP-8141 (VERIFY calldata, excluded from sigHash)
        _validateFrameTx(VALIDATION_MODE_ENABLE, vId, account, sigHash, senderFrameIdx, actualSig);

        FrameTxLib.approveEmpty(scope);
    }

    /// @notice Permission-based validation (ISigner + IPolicy[]).
    function validatePermission(bytes calldata sig, uint8 scope) external {
        _requireVerifyFrame();
        ValidationStorage storage vs = _validationStorage();
        address account = FrameTxLib.txSender();
        bytes32 sigHash = FrameTxLib.sigHash();
        uint256 senderFrameIdx = _findSenderFrameIndex();

        // Decode PermissionId from signature
        // sig format: [0x02][4B permissionId][actual sig]
        ValidationId vId;
        bytes calldata actualSig;
        assembly {
            vId := calldataload(sig.offset)
            // mask to 5 bytes (type + permissionId)
            vId := and(vId, 0xffffffffff000000000000000000000000000000000000000000000000000000)
            actualSig.offset := add(sig.offset, 5)
            actualSig.length := sub(sig.length, 5)
        }

        ValidationConfig memory vc = vs.validationConfig[vId];
        if (address(vc.hook) == HOOK_NOT_INSTALLED) {
            revert InvalidValidator();
        }
        if (vc.nonce < vs.validNonceFrom) {
            revert InvalidNonce();
        }

        // EIP-8141 native selector ACL
        bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderFrameIdx, 0));
        if (!vs.allowedSelectors[vId][senderSelector]) {
            revert InvalidSelector();
        }

        _validateFrameTx(VALIDATION_MODE_DEFAULT, vId, account, sigHash, senderFrameIdx, actualSig);

        FrameTxLib.approveEmpty(scope);
    }

    // ── SENDER frame: Execution ─────────────────────────────────────────

    /// @notice Execute a transaction. Called in SENDER frame.
    /// @dev Hook orchestration removed — hooks execute in separate DEFAULT frames.
    ///      VERIFY frame verifies hook frame presence via _verifyHookFrames().
    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable override {
        if (msg.sender != address(this)) {
            revert InvalidCaller();
        }
        ExecLib8141.execute(execMode, executionCalldata);
    }

    /// @notice Execute from an authorized executor module.
    function executeFromExecutor(ExecMode execMode, bytes calldata executionCalldata)
        external
        payable
        override
        returns (bytes[] memory returnData)
    {
        IHook8141 hook = _executorConfig(msg.sender).hook;
        if (address(hook) == HOOK_NOT_INSTALLED) {
            revert InvalidExecutor();
        }
        bytes memory context;
        bool callHook = address(hook) != HOOK_INSTALLED;
        if (callHook) {
            context = _doPreHook(hook, msg.value, msg.data);
        }
        returnData = ExecLib8141.execute(execMode, executionCalldata);
        if (callHook) {
            _doPostHook(hook, context);
        }
    }

    /// @notice Wrapper for non-root validator calls. sigHash binds this calldata.
    /// @dev Hook orchestration removed — hooks execute in separate DEFAULT frames.
    function validatedCall(IValidator8141 validator, bytes calldata data) external payable {
        if (msg.sender != address(this)) {
            revert InvalidCaller();
        }
        (bool success, bytes memory ret) = address(this).delegatecall(data);
        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    // ── ERC-1271 (native) ───────────────────────────────────────────────

    function isValidSignature(bytes32 hash, bytes calldata data)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        return _verifySignature(hash, data);
    }

    // ── Module management ───────────────────────────────────────────────

    function installModule(uint256 moduleType, address module, bytes calldata initData)
        external
        payable
        override
        onlySelfOrRoot
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationStorage storage vs = _validationStorage();
            ValidationId vId = ValidatorLib8141.validatorToIdentifier(IValidator8141(module));
            if (vs.validationConfig[vId].nonce == vs.currentNonce) {
                unchecked {
                    vs.currentNonce++;
                }
            }
            ValidationConfig memory config =
                ValidationConfig({nonce: vs.currentNonce, hook: IHook8141(address(bytes20(initData[0:20])))});
            InstallValidatorDataFormat calldata data;
            assembly {
                data := add(initData.offset, 20)
            }
            _installValidation(vId, config, data.validatorData, data.hookData);
            if (data.selectorData.length == 4) {
                _grantAccess(vId, bytes4(data.selectorData[0:4]), true);
            }
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            InstallExecutorDataFormat calldata data;
            assembly {
                data := add(initData.offset, 20)
            }
            IHook8141 hook = IHook8141(address(bytes20(initData[0:20])));
            _installExecutor(module, data.executorData, hook);
            _installHook(hook, data.hookData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            InstallFallbackDataFormat calldata data;
            assembly {
                data := add(initData.offset, 24)
            }
            _installSelector(
                bytes4(initData[0:4]), module, IHook8141(address(bytes20(initData[4:24]))), data.selectorData
            );
            _installHook(IHook8141(address(bytes20(initData[4:24]))), data.hookData);
        } else if (
            moduleType == MODULE_TYPE_HOOK || moduleType == MODULE_TYPE_POLICY || moduleType == MODULE_TYPE_SIGNER
        ) {
            // Force call onInstall for hook/policy/signer
            // These are paired with their respective validator/executor/selector/permission
            IModule8141(module).onInstall(initData);
        } else {
            revert InvalidModuleType();
        }
        emit ModuleInstalled(moduleType, module);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData)
        external
        payable
        override
        onlySelfOrRoot
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationId vId = ValidatorLib8141.validatorToIdentifier(IValidator8141(module));
            _clearValidationData(vId);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            _clearExecutorData(module);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            bytes4 selector = bytes4(deInitData[0:4]);
            (, address target) = _clearSelectorData(selector);
            if (target == address(0)) {
                return;
            }
            if (target != module) {
                revert InvalidSelector();
            }
            deInitData = deInitData[4:];
        } else if (moduleType == MODULE_TYPE_HOOK) {
            ValidationId vId = _validationStorage().rootValidator;
            if (_validationStorage().validationConfig[vId].hook == IHook8141(module)) {
                _validationStorage().validationConfig[vId].hook = IHook8141(HOOK_INSTALLED);
            }
        } else if (moduleType == MODULE_TYPE_POLICY || moduleType == MODULE_TYPE_SIGNER) {
            ValidationId rootVId = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib8141.getType(rootVId) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib8141.getPermissionId(rootVId)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
        } else {
            revert InvalidModuleType();
        }
        ModuleLib8141.uninstallModule(module, deInitData);
        emit ModuleUninstalled(moduleType, module);
    }

    function installValidations(
        ValidationId[] calldata vIds,
        ValidationConfig[] memory configs,
        bytes[] calldata validationData,
        bytes[] calldata hookData
    ) external payable onlySelfOrRoot {
        _installValidations(vIds, configs, validationData, hookData);
    }

    function uninstallValidation(ValidationId vId, bytes calldata deinitData, bytes calldata hookDeinitData)
        external
        payable
        onlySelfOrRoot
    {
        IHook8141 hook = _clearValidationData(vId);
        ValidationType vType = ValidatorLib8141.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator8141 validator = ValidatorLib8141.getValidator(vId);
            ModuleLib8141.uninstallModule(address(validator), deinitData);
            emit ModuleUninstalled(MODULE_TYPE_VALIDATOR, address(validator));
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib8141.getPermissionId(vId);
            _uninstallPermission(permission, deinitData);
        } else {
            revert InvalidValidationType();
        }
        _uninstallHook(hook, hookDeinitData);
    }

    function grantAccess(ValidationId vId, bytes4 selector, bool allow) external payable onlySelfOrRoot {
        _grantAccess(vId, selector, allow);
    }

    function invalidateNonce(uint32 nonce) external payable onlySelfOrRoot {
        _invalidateNonce(nonce);
    }

    // ── Introspection ───────────────────────────────────────────────────

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId > 0 && moduleTypeId < 7;
    }

    function isModuleInstalled(uint256 moduleType, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            return address(
                _validationStorage().validationConfig[ValidatorLib8141.validatorToIdentifier(IValidator8141(module))].hook
            ) != HOOK_NOT_INSTALLED;
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            return address(_executorConfig(module).hook) != HOOK_NOT_INSTALLED;
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            return _selectorConfig(bytes4(additionalContext[0:4])).target == module;
        } else {
            return false;
        }
    }

    function accountId() external pure override returns (string memory) {
        return "kernel8141.v0.1.0";
    }

    function supportsExecutionMode(ExecMode mode) external pure override returns (bool) {
        (CallType callType, ExecType execType, ExecModeSelector selector, ExecModePayload payload) =
            ExecLib8141.decode(mode);
        if (
            callType != CALLTYPE_BATCH && callType != CALLTYPE_SINGLE && callType != CALLTYPE_DELEGATECALL
                && callType != CALLTYPE_STATIC
        ) {
            return false;
        }
        if (
            ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_TRY)
                && ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)
        ) {
            return false;
        }
        if (ExecModeSelector.unwrap(selector) != ExecModeSelector.unwrap(EXEC_MODE_DEFAULT)) {
            return false;
        }
        if (ExecModePayload.unwrap(payload) != bytes22(0)) {
            return false;
        }
        return true;
    }

    // ── Fallback routing ────────────────────────────────────────────────

    fallback() external payable {
        SelectorConfig memory config = _selectorConfig(msg.sig);
        bool success;
        bytes memory result;
        if (address(config.hook) == HOOK_NOT_INSTALLED) {
            revert InvalidSelector();
        }
        bytes memory context;
        if (address(config.hook) == HOOK_ONLY_ENTRYPOINT) {
            // Only allow self-calls for entry-point-only selectors
            if (msg.sender != address(this)) {
                revert InvalidCaller();
            }
        } else if (address(config.hook) != HOOK_INSTALLED) {
            context = _doPreHook(config.hook, msg.value, msg.data);
        }
        if (config.callType == CALLTYPE_SINGLE) {
            (success, result) = ExecLib8141.doFallback2771Call(config.target);
        } else if (config.callType == CALLTYPE_DELEGATECALL) {
            (success, result) = ExecLib8141._executeDelegatecall(config.target, msg.data);
        } else {
            revert NotSupportedCallType();
        }
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
        if (address(config.hook) != HOOK_INSTALLED && address(config.hook) != HOOK_ONLY_ENTRYPOINT) {
            _doPostHook(config.hook, context);
        }
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    // ── Token receivers ─────────────────────────────────────────────────

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// @dev Ensure we're executing in a VERIFY frame.
    function _requireVerifyFrame() internal pure {
        require(FrameTxLib.currentFrameMode() == FRAME_MODE_VERIFY, "Not VERIFY frame");
    }

    /// @dev Find the first SENDER frame index after the current VERIFY frame.
    /// @return idx The SENDER frame index
    function _findSenderFrameIndex() internal pure returns (uint256 idx) {
        uint256 count = FrameTxLib.frameCount();
        uint256 current = FrameTxLib.currentFrameIndex();
        for (idx = current + 1; idx < count; idx++) {
            if (FrameTxLib.frameMode(idx) == FRAME_MODE_SENDER) {
                return idx;
            }
        }
        revert("No SENDER frame found");
    }
}
