// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IExecutor8141} from "../../interfaces/IExecutor8141.sol";
import {MODULE_TYPE_EXECUTOR} from "../../types/Constants8141.sol";

/// @title DefaultExecutor
/// @notice Stateless executor module for Kernel8141.
/// @dev Migrated to IExecutor8141 (extends IModule8141).
///      In Kernel v3 pattern, executors are marker modules — they call
///      kernel.executeFromExecutor() rather than implementing execution logic.
contract DefaultExecutor is IExecutor8141 {
    function onInstall(bytes calldata) external payable override {}

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }
}
