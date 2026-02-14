// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IExecutor} from "../../interfaces/IExecutor.sol";

/// @title DefaultExecutor
/// @notice Stateless executor that performs simple CALL operations.
/// @dev Used as a fallback executor for standard execution.
contract DefaultExecutor is IExecutor {
    /// @inheritdoc IExecutor
    function executeWithData(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        (bool success, bytes memory ret) = target.call{value: value}(data);
        require(success, "DefaultExecutor: call failed");
        return ret;
    }

    /// @inheritdoc IExecutor
    function onInstall(bytes calldata) external pure {}

    /// @inheritdoc IExecutor
    function onUninstall() external pure {}

    /// @inheritdoc IExecutor
    function isInitialized(address) external pure returns (bool) {
        return true; // Stateless, always initialized
    }
}
