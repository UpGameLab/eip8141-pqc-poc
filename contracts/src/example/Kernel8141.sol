// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "../FrameTxLib.sol";
import {IValidator8141} from "../interfaces/IValidator8141.sol";
import {IExecutor} from "../interfaces/IExecutor.sol";
import {IPreExecutionHook, IPostExecutionHook} from "../interfaces/IHook.sol";
import {IFallbackHandler} from "../interfaces/IFallbackHandler.sol";

/// @title Kernel8141
/// @notice Modular EIP-8141 smart account inspired by ZeroDev Kernel v3.
///
/// @dev Frame transaction patterns:
///
///   Simple Transaction:
///     Frame 0: VERIFY(kernel)  → kernel.validate(sig, scope=2)          → APPROVE(both)
///     Frame 1: SENDER(kernel)  → kernel.execute(target, value, data)
///
///   Sponsored Transaction:
///     Frame 0: VERIFY(kernel)  → kernel.validate(sig, scope=0)          → APPROVE(exec)
///     Frame 1: VERIFY(sponsor) → sponsor.validate()                     → APPROVE(pay)
///     Frame 2: SENDER(kernel)  → kernel.execute(erc20, 0, transfer...)
///     Frame 3: SENDER(kernel)  → kernel.execute(target, value, data)
///
///   Non-Root Validator (sigHash-bound):
///     Frame 0: VERIFY(kernel)  → kernel.validateFromSenderFrame(sig, scope)
///     Frame 1: SENDER(kernel)  → kernel.validatedCall(validator, execute.encode(...))
contract Kernel8141 {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    // Frame modes
    uint8 internal constant FRAME_MODE_DEFAULT = 0;
    uint8 internal constant FRAME_MODE_VERIFY  = 1;
    uint8 internal constant FRAME_MODE_SENDER  = 2;

    // ── Core State ────────────────────────────────────────────────────────
    IValidator8141 public rootValidator;
    mapping(IValidator8141 => bool) public isValidatorInstalled;
    bool public initialized;

    // ── Per-Selector Execution Config (Kernel v3 pattern) ────────────────
    struct ExecutionConfig {
        uint48 validAfter;
        uint48 validUntil;
        IExecutor executor;
        uint8 allowedFrameModes;  // VERIFY(1) | SENDER(2) | BOTH(3)
    }
    mapping(bytes4 => ExecutionConfig) public executionConfig;

    // ── Per-Selector Hooks ────────────────────────────────────────────────
    mapping(bytes4 => IPreExecutionHook[]) internal _preHooks;
    mapping(bytes4 => IPostExecutionHook[]) internal _postHooks;

    // ── Hook Selector Tracking (bidirectional) ────────────────────────────
    mapping(address => bytes4[]) internal _preHookSelectors;
    mapping(address => bytes4[]) internal _postHookSelectors;

    // ── Executor Selector Tracking (bidirectional) ────────────────────────
    mapping(address => bytes4[]) internal _executorSelectors;

    // ── Fallback Handler Registry ─────────────────────────────────────────
    mapping(bytes4 => address) internal _fallbackHandlers;
    mapping(address => bytes4[]) internal _handlerSelectors;

    // ── Module Lists (for introspection) ──────────────────────────────────
    mapping(ModuleType => address[]) internal _modulesByType;
    mapping(address => uint256) internal _moduleIndex;  // index + 1 (0 = not present)

    // ── Module Registry ───────────────────────────────────────────────────
    enum ModuleType { VALIDATOR, EXECUTOR, PRE_HOOK, POST_HOOK, FALLBACK_HANDLER }
    mapping(address => ModuleType) public moduleTypes;
    mapping(address => bool) public isModuleInstalled;

    error NotInitialized();
    error AlreadyInitialized();
    error InvalidCaller();
    error InvalidSignature();
    error ExecutionFailed();
    error ValidatorNotInstalled();
    error ValidatorAlreadyInstalled();
    error CannotRemoveRootValidator();
    error BatchLengthMismatch();
    error ModuleAlreadyInstalled();
    error ModuleNotInstalled();
    error InvalidFrameMode();
    error TimeRestriction();
    error NoHandlerForSelector(bytes4 selector);
    error HandlerAlreadyRegistered(bytes4 selector);
    error DelegatecallNotConfigured();
    error StorageCorruption(string reason);
    error NoValidatedCallFrame();

    event Initialized(IValidator8141 rootValidator);
    event ValidatorInstalled(IValidator8141 validator);
    event ValidatorUninstalled(IValidator8141 validator);
    event RootValidatorChanged(IValidator8141 oldValidator, IValidator8141 newValidator);
    event ModuleInstalled(ModuleType moduleType, address module);
    event ModuleUninstalled(ModuleType moduleType, address module);

    // ── Initialization ────────────────────────────────────────────────

    constructor(IValidator8141 _rootValidator, bytes memory _validatorData) {
        initialized = true;
        rootValidator = _rootValidator;
        isValidatorInstalled[_rootValidator] = true;
        _rootValidator.onInstall(_validatorData);
        emit Initialized(_rootValidator);
    }

    /// @notice Initialize the account (for factory/proxy deployments).
    function initialize(IValidator8141 _rootValidator, bytes calldata _validatorData) external {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
        rootValidator = _rootValidator;
        isValidatorInstalled[_rootValidator] = true;
        _rootValidator.onInstall(_validatorData);
        emit Initialized(_rootValidator);
    }

    // ── Validation (VERIFY frame) ─────────────────────────────────────

    /// @notice Validate using the root validator. Called in a VERIFY frame.
    /// @param signature Raw signature bytes (format depends on validator)
    /// @param scope Approval scope: 0=execution, 1=payment, 2=both
    function validate(bytes calldata signature, uint8 scope) external {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        if (!initialized) revert NotInitialized();

        bytes32 sigHash = FrameTxLib.sigHash();
        address account = FrameTxLib.txSender();

        bool valid = rootValidator.validateSignature(account, sigHash, signature);
        if (!valid) revert InvalidSignature();

        FrameTxLib.approveEmpty(scope);
    }

    /// @notice Validate with a non-root validator, reading it from SENDER frame data.
    /// @dev The validator address is extracted from the first argument of `validatedCall()`
    ///      in the SENDER frame. Since SENDER frame data is included in sigHash, the
    ///      validator selection is cryptographically bound to the signature — unlike passing
    ///      the validator in VERIFY frame calldata (which is elided from sigHash).
    /// @param signature Raw signature bytes (format depends on validator)
    /// @param scope Approval scope: 0=execution, 1=payment, 2=both
    function validateFromSenderFrame(bytes calldata signature, uint8 scope) external {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();
        if (!initialized) revert NotInitialized();

        uint256 senderFrame = _findValidatedCallFrame();
        // ABI offset 4 (skip selector) → validator address (first arg, left-padded to 32 bytes)
        IValidator8141 validator = IValidator8141(
            address(uint160(uint256(FrameTxLib.frameDataLoad(senderFrame, 4))))
        );

        if (!isValidatorInstalled[validator]) revert ValidatorNotInstalled();

        bytes32 sigHash = FrameTxLib.sigHash();
        address account = FrameTxLib.txSender();

        bool valid = validator.validateSignature(account, sigHash, signature);
        if (!valid) revert InvalidSignature();

        FrameTxLib.approveEmpty(scope);
    }

    // ── Execution (SENDER frame) ──────────────────────────────────────

    /// @notice Execute a single call. Called in a SENDER frame.
    function execute(address target, uint256 value, bytes calldata data) external {
        _executeWithConfig(msg.sig, target, value, data);
    }

    /// @notice Wrapper for non-root validator transactions. Called in a SENDER frame.
    /// @dev The first argument (validator) is not used in execution — it exists solely
    ///      as a sigHash-bound hint that `validateFromSenderFrame()` reads via TXPARAMLOAD
    ///      from the SENDER frame calldata. The `innerCalldata` is forwarded via self-call
    ///      to execute the actual operation (execute, executeBatch, etc.).
    /// @param innerCalldata ABI-encoded call to an execute function on this contract
    function validatedCall(
        IValidator8141 /* validator */,
        bytes calldata innerCalldata
    ) external returns (bytes memory) {
        if (msg.sender != address(this)) revert InvalidCaller();
        (bool ok, bytes memory ret) = address(this).call(innerCalldata);
        if (!ok) {
            assembly { revert(add(ret, 0x20), mload(ret)) }
        }
        return ret;
    }

    /// @notice Execute a batch of calls. Called in a SENDER frame.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external {
        bytes memory encoded = abi.encode(targets, values, datas);
        _executeWithConfigMemory(msg.sig, address(0), 0, encoded);
    }

    /// @notice Execute via DELEGATECALL (inherits caller storage, identity, and balance)
    /// @dev DANGER: Can modify kernel state. Should have strict ExecutionConfig restrictions.
    ///      Recommended: allowedFrameModes = VERIFY (1) for additional validation layer
    function executeDelegate(address target, bytes calldata data) external returns (bytes memory) {
        bytes memory result = _executeWithConfigMemory(msg.sig, target, 0, data);
        return result;
    }

    /// @notice Execute via STATICCALL (read-only, reverts on state changes)
    /// @dev Safe for queries. No value parameter (staticcall cannot send ETH)
    function executeStatic(address target, bytes calldata data) external view returns (bytes memory) {
        // Note: This function is view, so _executeWithConfigMemory needs special handling
        // For now, we'll implement a direct staticcall without hooks
        // A production implementation would need a view-compatible execution path

        (bool success, bytes memory result) = target.staticcall(data);
        if (!success) revert ExecutionFailed();
        return result;
    }

    /// @notice Execute via CALL with graceful error handling (TRY mode)
    /// @dev Does NOT revert on target failure. Returns (success, returnData)
    function executeTry(address target, uint256 value, bytes calldata data)
        external
        returns (bool success, bytes memory returnData)
    {
        bytes memory result = _executeWithConfigMemory(msg.sig, target, value, data);
        (success, returnData) = abi.decode(result, (bool, bytes));
    }

    /// @notice Batch execution with TRY mode for each call
    /// @dev Continues on failure. Returns array of (success, returnData) tuples
    function executeBatchTry(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external returns (bool[] memory successes, bytes[] memory returnDatas) {
        bytes memory encoded = abi.encode(targets, values, datas);
        bytes memory result = _executeWithConfigMemory(msg.sig, address(0), 0, encoded);
        (successes, returnDatas) = abi.decode(result, (bool[], bytes[]));
    }

    /// @notice Internal execution with config-based hooks and validation (calldata version)
    function _executeWithConfig(
        bytes4 selector,
        address target,
        uint256 value,
        bytes calldata data
    ) internal {
        _executeWithConfigMemory(selector, target, value, data);
    }

    /// @notice Internal execution with config-based hooks and validation (memory version)
    function _executeWithConfigMemory(
        bytes4 selector,
        address target,
        uint256 value,
        bytes memory data
    ) internal returns (bytes memory) {
        if (msg.sender != address(this)) revert InvalidCaller();

        ExecutionConfig storage config = executionConfig[selector];

        // 1. Frame mode enforcement (EIP-8141 unique)
        // Only enforce if config exists (allowedFrameModes != 0)
        if (config.allowedFrameModes != 0) {
            uint8 currentMode = FrameTxLib.currentFrameMode();
            if (config.allowedFrameModes & currentMode == 0) revert InvalidFrameMode();
        }

        // 2. Time-based validation (Kernel v3)
        if (config.validAfter != 0 || config.validUntil != 0) {
            if (block.timestamp < config.validAfter || block.timestamp > config.validUntil) {
                revert TimeRestriction();
            }
        }

        // 3. Pre-hooks
        IPreExecutionHook[] storage preHooks = _preHooks[selector];
        for (uint256 i = 0; i < preHooks.length; i++) {
            preHooks[i].preExecute(target, value, data);
        }

        // 4. Execute via executor or direct call
        bytes memory result;
        if (address(config.executor) != address(0)) {
            result = config.executor.executeWithData(target, value, data);
        } else {
            // Direct execution - dispatch based on selector
            if (selector == this.executeDelegate.selector) {
                // DELEGATECALL execution with storage protection
                if (config.allowedFrameModes == 0) revert DelegatecallNotConfigured();

                address rootValidatorBefore = address(rootValidator);

                (bool success, bytes memory ret) = target.delegatecall(data);
                if (!success) revert ExecutionFailed();

                // Verify no storage corruption
                if (address(rootValidator) != rootValidatorBefore) {
                    revert StorageCorruption("rootValidator modified");
                }

                result = ret;

            } else if (selector == this.executeTry.selector) {
                // TRY execution - don't revert on failure
                (bool success, bytes memory ret) = target.call{value: value}(data);
                result = abi.encode(success, ret);

            } else if (selector == this.executeBatchTry.selector) {
                // Batch TRY execution
                (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
                    abi.decode(data, (address[], uint256[], bytes[]));
                if (targets.length != values.length || values.length != datas.length) {
                    revert BatchLengthMismatch();
                }

                bool[] memory successes = new bool[](targets.length);
                bytes[] memory results = new bytes[](targets.length);

                for (uint256 i = 0; i < targets.length; i++) {
                    (successes[i], results[i]) = targets[i].call{value: values[i]}(datas[i]);
                }

                result = abi.encode(successes, results);

            } else if (selector == this.executeBatch.selector) {
                // Regular batch execution (reverts on failure)
                (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
                    abi.decode(data, (address[], uint256[], bytes[]));
                if (targets.length != values.length || values.length != datas.length) {
                    revert BatchLengthMismatch();
                }
                for (uint256 i = 0; i < targets.length; i++) {
                    (bool success,) = targets[i].call{value: values[i]}(datas[i]);
                    if (!success) revert ExecutionFailed();
                }
                result = "";

            } else {
                // Regular CALL execution
                (bool success, bytes memory ret) = target.call{value: value}(data);
                if (!success) revert ExecutionFailed();
                result = ret;
            }
        }

        // 5. Post-hooks
        IPostExecutionHook[] storage postHooks = _postHooks[selector];
        for (uint256 i = 0; i < postHooks.length; i++) {
            postHooks[i].postExecute(target, value, result);
        }

        return result;
    }

    // ── Module Management (SENDER frame) ──────────────────────────────

    /// @notice Install a new validator.
    function installValidator(IValidator8141 validator, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        if (isValidatorInstalled[validator]) revert ValidatorAlreadyInstalled();
        isValidatorInstalled[validator] = true;
        validator.onInstall(data);
        emit ValidatorInstalled(validator);
    }

    /// @notice Uninstall a validator (cannot uninstall root).
    function uninstallValidator(IValidator8141 validator) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        if (address(validator) == address(rootValidator)) revert CannotRemoveRootValidator();
        if (!isValidatorInstalled[validator]) revert ValidatorNotInstalled();
        isValidatorInstalled[validator] = false;
        validator.onUninstall();
        emit ValidatorUninstalled(validator);
    }

    /// @notice Change the root validator (atomic swap).
    function changeRootValidator(IValidator8141 newValidator, bytes calldata data) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        IValidator8141 oldValidator = rootValidator;
        isValidatorInstalled[oldValidator] = false;
        oldValidator.onUninstall();
        rootValidator = newValidator;
        isValidatorInstalled[newValidator] = true;
        newValidator.onInstall(data);
        emit RootValidatorChanged(oldValidator, newValidator);
    }

    // ── Unified Module System (Kernel v3 style) ──────────────────────

    /// @notice Install a module (validator, executor, hook, or fallback handler)
    function installModule(
        ModuleType moduleType,
        address module,
        bytes calldata config
    ) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        if (isModuleInstalled[module]) revert ModuleAlreadyInstalled();

        if (moduleType == ModuleType.VALIDATOR) {
            _installValidator(IValidator8141(module), config);
        } else if (moduleType == ModuleType.EXECUTOR) {
            _installExecutor(IExecutor(module), config);
        } else if (moduleType == ModuleType.PRE_HOOK) {
            _installPreHook(IPreExecutionHook(module), config);
        } else if (moduleType == ModuleType.POST_HOOK) {
            _installPostHook(IPostExecutionHook(module), config);
        } else if (moduleType == ModuleType.FALLBACK_HANDLER) {
            _installFallbackHandler(IFallbackHandler(module), config);
        }

        moduleTypes[module] = moduleType;
        isModuleInstalled[module] = true;

        // Add to module list for introspection
        _modulesByType[moduleType].push(module);
        _moduleIndex[module] = _modulesByType[moduleType].length;  // store index + 1

        emit ModuleInstalled(moduleType, module);
    }

    /// @notice Uninstall a module
    function uninstallModule(address module) external {
        if (msg.sender != address(this)) revert InvalidCaller();
        if (!isModuleInstalled[module]) revert ModuleNotInstalled();

        ModuleType moduleType = moduleTypes[module];

        if (moduleType == ModuleType.VALIDATOR) {
            IValidator8141 validator = IValidator8141(module);
            if (address(validator) == address(rootValidator)) revert CannotRemoveRootValidator();
            if (!isValidatorInstalled[validator]) revert ValidatorNotInstalled();
            isValidatorInstalled[validator] = false;
            validator.onUninstall();
        } else if (moduleType == ModuleType.EXECUTOR) {
            _uninstallExecutor(IExecutor(module));
        } else if (moduleType == ModuleType.PRE_HOOK) {
            _uninstallPreHook(IPreExecutionHook(module));
        } else if (moduleType == ModuleType.POST_HOOK) {
            _uninstallPostHook(IPostExecutionHook(module));
        } else if (moduleType == ModuleType.FALLBACK_HANDLER) {
            _uninstallFallbackHandler(IFallbackHandler(module));
        }

        // Remove from module list (swap-and-pop)
        address[] storage moduleList = _modulesByType[moduleType];
        uint256 index = _moduleIndex[module] - 1;  // convert back to 0-indexed
        uint256 lastIndex = moduleList.length - 1;

        if (index != lastIndex) {
            address lastModule = moduleList[lastIndex];
            moduleList[index] = lastModule;
            _moduleIndex[lastModule] = index + 1;  // update moved module's index
        }

        moduleList.pop();
        delete _moduleIndex[module];

        isModuleInstalled[module] = false;
        emit ModuleUninstalled(moduleType, module);
    }

    function _installValidator(IValidator8141 validator, bytes calldata config) internal {
        if (isValidatorInstalled[validator]) revert ValidatorAlreadyInstalled();
        isValidatorInstalled[validator] = true;
        validator.onInstall(config);
    }

    function _installExecutor(IExecutor executor, bytes calldata config) internal {
        // config = abi.encode(bytes4[] selectors, uint48 validAfter, uint48 validUntil, uint8 frameModes)
        (bytes4[] memory selectors, uint48 validAfter, uint48 validUntil, uint8 frameModes) =
            abi.decode(config, (bytes4[], uint48, uint48, uint8));

        for (uint256 i = 0; i < selectors.length; i++) {
            executionConfig[selectors[i]] = ExecutionConfig({
                validAfter: validAfter,
                validUntil: validUntil,
                executor: executor,
                allowedFrameModes: frameModes
            });
            _executorSelectors[address(executor)].push(selectors[i]);  // Track selectors
        }

        executor.onInstall(config);
    }

    function _installPreHook(IPreExecutionHook hook, bytes calldata config) internal {
        // config = abi.encode(bytes4[] selectors, bytes hookData)
        (bytes4[] memory selectors, bytes memory hookData) = abi.decode(config, (bytes4[], bytes));

        for (uint256 i = 0; i < selectors.length; i++) {
            _preHooks[selectors[i]].push(hook);
            _preHookSelectors[address(hook)].push(selectors[i]);  // Track selectors
        }

        hook.onInstall(hookData);
    }

    function _installPostHook(IPostExecutionHook hook, bytes calldata config) internal {
        // config = abi.encode(bytes4[] selectors, bytes hookData)
        (bytes4[] memory selectors, bytes memory hookData) = abi.decode(config, (bytes4[], bytes));

        for (uint256 i = 0; i < selectors.length; i++) {
            _postHooks[selectors[i]].push(hook);
            _postHookSelectors[address(hook)].push(selectors[i]);  // Track selectors
        }

        hook.onInstall(hookData);
    }

    function _installFallbackHandler(IFallbackHandler handler, bytes calldata config) internal {
        // config = abi.encode(bytes4[] selectors, bytes handlerData)
        (bytes4[] memory selectors, bytes memory handlerData) =
            abi.decode(config, (bytes4[], bytes));

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];

            // Prevent overwriting existing handlers
            if (_fallbackHandlers[selector] != address(0)) {
                revert HandlerAlreadyRegistered(selector);
            }

            _fallbackHandlers[selector] = address(handler);
            _handlerSelectors[address(handler)].push(selector);
        }

        handler.onInstall(handlerData);
    }

    /// @notice Uninstall an executor and clear its configs
    function _uninstallExecutor(IExecutor executor) internal {
        bytes4[] storage selectors = _executorSelectors[address(executor)];

        // Clear executionConfig for all selectors owned by this executor
        for (uint256 i = 0; i < selectors.length; i++) {
            delete executionConfig[selectors[i]];
        }

        // Clear selector tracking
        delete _executorSelectors[address(executor)];

        executor.onUninstall();
    }

    /// @notice Remove a pre-hook from all registered selectors
    function _uninstallPreHook(IPreExecutionHook hook) internal {
        bytes4[] storage selectors = _preHookSelectors[address(hook)];

        // Iterate through all selectors this hook is attached to
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            IPreExecutionHook[] storage hooks = _preHooks[selector];

            // Find and remove hook from array (swap-and-pop pattern)
            for (uint256 j = 0; j < hooks.length; j++) {
                if (hooks[j] == hook) {
                    // Swap with last element
                    hooks[j] = hooks[hooks.length - 1];
                    // Remove last element
                    hooks.pop();
                    break;
                }
            }
        }

        // Clear selector tracking
        delete _preHookSelectors[address(hook)];

        hook.onUninstall();
    }

    /// @notice Remove a post-hook from all registered selectors
    function _uninstallPostHook(IPostExecutionHook hook) internal {
        bytes4[] storage selectors = _postHookSelectors[address(hook)];

        // Iterate through all selectors this hook is attached to
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            IPostExecutionHook[] storage hooks = _postHooks[selector];

            // Find and remove hook from array (swap-and-pop pattern)
            for (uint256 j = 0; j < hooks.length; j++) {
                if (hooks[j] == hook) {
                    // Swap with last element
                    hooks[j] = hooks[hooks.length - 1];
                    // Remove last element
                    hooks.pop();
                    break;
                }
            }
        }

        // Clear selector tracking
        delete _postHookSelectors[address(hook)];

        hook.onUninstall();
    }

    /// @notice Uninstall a fallback handler
    function _uninstallFallbackHandler(IFallbackHandler handler) internal {
        bytes4[] storage selectors = _handlerSelectors[address(handler)];

        // Remove all selectors registered to this handler
        for (uint256 i = 0; i < selectors.length; i++) {
            delete _fallbackHandlers[selectors[i]];
        }

        delete _handlerSelectors[address(handler)];

        handler.onUninstall();
    }

    // ── Module Introspection ──────────────────────────────────────────

    /// @notice Get all installed modules of a specific type
    /// @param moduleType The type of modules to query
    /// @return modules Array of module addresses
    function getInstalledModules(ModuleType moduleType)
        external
        view
        returns (address[] memory)
    {
        return _modulesByType[moduleType];
    }

    /// @notice Get pre-execution hooks for a selector
    /// @param selector The function selector
    /// @return hooks Array of pre-execution hooks
    function getPreHooks(bytes4 selector)
        external
        view
        returns (IPreExecutionHook[] memory)
    {
        return _preHooks[selector];
    }

    /// @notice Get post-execution hooks for a selector
    /// @param selector The function selector
    /// @return hooks Array of post-execution hooks
    function getPostHooks(bytes4 selector)
        external
        view
        returns (IPostExecutionHook[] memory)
    {
        return _postHooks[selector];
    }

    /// @notice Get all selectors owned by an executor
    /// @param executor The executor address
    /// @return selectors Array of function selectors
    function getExecutorSelectors(address executor)
        external
        view
        returns (bytes4[] memory)
    {
        return _executorSelectors[executor];
    }

    /// @notice Get the fallback handler for a selector
    /// @param selector The function selector
    /// @return handler Address of the fallback handler (address(0) if none)
    function getFallbackHandler(bytes4 selector)
        external
        view
        returns (address)
    {
        return _fallbackHandlers[selector];
    }

    /// @notice Get all selectors handled by a fallback handler
    /// @param handler The handler address
    /// @return selectors Array of function selectors
    function getHandlerSelectors(address handler)
        external
        view
        returns (bytes4[] memory)
    {
        return _handlerSelectors[handler];
    }

    /// @notice Get all selectors a pre-hook is attached to
    /// @param hook The hook address
    /// @return selectors Array of function selectors
    function getPreHookSelectors(address hook)
        external
        view
        returns (bytes4[] memory)
    {
        return _preHookSelectors[hook];
    }

    /// @notice Get all selectors a post-hook is attached to
    /// @param hook The hook address
    /// @return selectors Array of function selectors
    function getPostHookSelectors(address hook)
        external
        view
        returns (bytes4[] memory)
    {
        return _postHookSelectors[hook];
    }

    // ── Internal: SENDER frame lookup ─────────────────────────────────

    /// @notice Find the SENDER frame that calls `validatedCall()`.
    /// @dev Iterates all frames to find a SENDER-mode frame whose calldata
    ///      starts with the `validatedCall` selector. Used by `validateFromSenderFrame`.
    function _findValidatedCallFrame() internal pure returns (uint256) {
        uint256 count = FrameTxLib.frameCount();
        for (uint256 i = 0; i < count; i++) {
            if (FrameTxLib.frameMode(i) == FRAME_MODE_SENDER
                && bytes4(FrameTxLib.frameDataLoad(i, 0)) == this.validatedCall.selector)
            {
                return i;
            }
        }
        revert NoValidatedCallFrame();
    }

    // ── Fallback ──────────────────────────────────────────────────────

    /// @notice Fallback function - routes to registered handlers
    /// @dev Called for unknown function selectors. Checks _fallbackHandlers mapping.
    fallback() external payable {
        bytes4 selector = msg.sig;
        address handler = _fallbackHandlers[selector];

        if (handler == address(0)) {
            revert NoHandlerForSelector(selector);
        }

        // Delegate to handler
        bytes memory result = IFallbackHandler(handler).handleFallback(selector, msg.data);

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }

    receive() external payable {}
}
