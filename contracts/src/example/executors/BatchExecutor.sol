// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IExecutor} from "../../interfaces/IExecutor.sol";

/// @title BatchExecutor
/// @notice Executor that performs atomic batch execution.
/// @dev Decodes an array of calls and executes them sequentially.
///      Reverts if any call fails.
contract BatchExecutor is IExecutor {
    error BatchLengthMismatch();
    error BatchCallFailed(uint256 index);

    /// @inheritdoc IExecutor
    /// @dev data is abi.encode(address[] targets, uint256[] values, bytes[] datas)
    function executeWithData(
        address, // target unused for batch
        uint256, // value unused for batch
        bytes calldata data
    ) external payable returns (bytes memory) {
        (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
            abi.decode(data, (address[], uint256[], bytes[]));

        if (targets.length != values.length || values.length != datas.length) {
            revert BatchLengthMismatch();
        }

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) revert BatchCallFailed(i);
        }

        return "";
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
