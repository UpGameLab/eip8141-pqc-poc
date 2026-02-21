// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../interfaces/IHook8141.sol";
import {IModule8141} from "../interfaces/IModule8141.sol";
import {IERC7579Account8141} from "../interfaces/IERC7579Account8141.sol";
import {EXECUTOR_STORAGE_SLOT, MODULE_TYPE_EXECUTOR} from "../types/Constants8141.sol";

/// @title ExecutorManager8141
/// @notice Manages executor module registry for Kernel8141.
/// @dev Ported from Kernel v3 ExecutorManager.
abstract contract ExecutorManager8141 {
    struct ExecutorConfig {
        IHook8141 hook; // address(0) = not installed, address(1) = no hook required
    }

    struct ExecutorStorage {
        mapping(address => ExecutorConfig) executorConfig;
    }

    function executorConfig(address executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(executor);
    }

    function _executorConfig(address executor) internal view returns (ExecutorConfig storage config) {
        ExecutorStorage storage es;
        bytes32 slot = EXECUTOR_STORAGE_SLOT;
        assembly {
            es.slot := slot
        }
        config = es.executorConfig[executor];
    }

    /// @notice Install an executor module with its associated hook.
    function _installExecutor(address executor, bytes calldata executorData, IHook8141 hook) internal {
        _installExecutorWithoutInit(executor, hook);
        if (executorData.length == 0) {
            (bool success,) =
                address(executor).call(abi.encodeWithSelector(IModule8141.onInstall.selector, executorData));
            // ignore return value for empty data (same as Kernel v3)
        } else {
            IModule8141(executor).onInstall(executorData);
        }
    }

    /// @notice Install executor hook config without calling onInstall.
    function _installExecutorWithoutInit(address executor, IHook8141 hook) internal {
        if (address(hook) == address(0)) {
            hook = IHook8141(address(1));
        }
        ExecutorConfig storage config = _executorConfig(executor);
        config.hook = hook;
        emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor));
    }

    /// @notice Clear executor configuration (during uninstall).
    /// @return hook The previous hook address
    function _clearExecutorData(address executor) internal returns (IHook8141 hook) {
        ExecutorConfig storage config = _executorConfig(executor);
        hook = config.hook;
        config.hook = IHook8141(address(0));
    }
}
