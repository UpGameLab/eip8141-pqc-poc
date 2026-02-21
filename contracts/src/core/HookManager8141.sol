// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../interfaces/IHook8141.sol";
import {IERC7579Account8141} from "../interfaces/IERC7579Account8141.sol";
import {ModuleLib8141} from "../utils/ModuleLib8141.sol";
import {MODULE_TYPE_HOOK} from "../types/Constants8141.sol";

/// @title HookManager8141
/// @notice Manages hook lifecycle and invocation for Kernel8141.
/// @dev Ported from Kernel v3 HookManager. Hooks wrap execution with preCheck/postCheck.
abstract contract HookManager8141 {
    function _doPreHook(IHook8141 hook, uint256 value, bytes calldata callData)
        internal
        returns (bytes memory context)
    {
        context = hook.preCheck(msg.sender, value, callData);
    }

    function _doPostHook(IHook8141 hook, bytes memory context) internal {
        hook.postCheck(context);
    }

    /// @notice Install a hook module.
    /// @dev If hook is not initialized, calls onInstall. If hookData[0] == 0xff, force re-install.
    /// @param hook The hook to install
    /// @param hookData Encoded as [1B flag][actual hookData]. 0xff forces onInstall call.
    function _installHook(IHook8141 hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (!hook.isInitialized(address(this)) || (hookData.length > 0 && bytes1(hookData[0]) == bytes1(0xff))) {
            hook.onInstall(hookData[1:]);
        }
        emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_HOOK, address(hook));
    }

    /// @notice Uninstall a hook module.
    /// @dev If hookData[0] == 0xff, calls onUninstall with remaining data.
    /// @param hook The hook to uninstall
    /// @param hookData Encoded as [1B flag][actual hookData]. 0xff triggers onUninstall call.
    function _uninstallHook(IHook8141 hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (bytes1(hookData[0]) == bytes1(0xff)) {
            ModuleLib8141.uninstallModule(address(hook), hookData[1:]);
        }
        emit IERC7579Account8141.ModuleUninstalled(MODULE_TYPE_HOOK, address(hook));
    }
}
