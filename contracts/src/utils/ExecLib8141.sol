// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "../types/Types8141.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    EXEC_MODE_DEFAULT
} from "../types/Constants8141.sol";
import {Execution} from "../types/Structs8141.sol";

/// @title ExecLib8141
/// @notice Execution helper library for Kernel8141 (ported from Kernel v3 ExecLib).
library ExecLib8141 {
    error ExecutionFailed();

    event TryExecuteUnsuccessful(uint256 batchExecutionIndex, bytes result);

    function execute(ExecMode execMode, bytes calldata executionCalldata)
        internal
        returns (bytes[] memory returnData)
    {
        (CallType callType, ExecType execType,,) = decode(execMode);

        if (callType == CALLTYPE_BATCH) {
            Execution[] calldata executions = decodeBatch(executionCalldata);
            if (execType == EXECTYPE_DEFAULT) returnData = _execute(executions);
            else if (execType == EXECTYPE_TRY) returnData = _tryExecute(executions);
            else revert("Unsupported");
        } else if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata callData) = decodeSingle(executionCalldata);
            returnData = new bytes[](1);
            if (execType == EXECTYPE_DEFAULT) {
                returnData[0] = _execute(target, value, callData);
            } else if (execType == EXECTYPE_TRY) {
                bool success;
                (success, returnData[0]) = _tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert("Unsupported");
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            returnData = new bytes[](1);
            (address delegate, bytes calldata callData) = decodeDelegate(executionCalldata);
            bool success;
            (success, returnData[0]) = _executeDelegatecall(delegate, callData);
            if (execType == EXECTYPE_TRY) {
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else if (execType == EXECTYPE_DEFAULT) {
                if (!success) revert("Delegatecall failed");
            } else {
                revert("Unsupported");
            }
        } else {
            revert("Unsupported");
        }
    }

    function _execute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);
        unchecked {
            for (uint256 i; i < length; i++) {
                Execution calldata exec = executions[i];
                result[i] = _execute(exec.target, exec.value, exec.callData);
            }
        }
    }

    function _tryExecute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);
        unchecked {
            for (uint256 i; i < length; i++) {
                Execution calldata exec = executions[i];
                bool success;
                (success, result[i]) = _tryExecute(exec.target, exec.value, exec.callData);
                if (!success) emit TryExecuteUnsuccessful(i, result[i]);
            }
        }
    }

    function _execute(address target, uint256 value, bytes calldata callData)
        internal
        returns (bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            if iszero(call(gas(), target, value, result, callData.length, codesize(), 0x00)) {
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    function _tryExecute(address target, uint256 value, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            success := call(gas(), target, value, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    function _executeDelegatecall(address delegate, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            success := delegatecall(gas(), delegate, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    // ── Encoding / Decoding ────────────────────────────────────────────

    function decode(ExecMode mode)
        internal
        pure
        returns (CallType _calltype, ExecType _execType, ExecModeSelector _modeSelector, ExecModePayload _modePayload)
    {
        assembly {
            _calltype := mode
            _execType := shl(8, mode)
            _modeSelector := shl(48, mode)
            _modePayload := shl(80, mode)
        }
    }

    function encode(CallType callType, ExecType execType, ExecModeSelector mode, ExecModePayload payload)
        internal
        pure
        returns (ExecMode)
    {
        return ExecMode.wrap(
            bytes32(abi.encodePacked(callType, execType, bytes4(0), ExecModeSelector.unwrap(mode), payload))
        );
    }

    function getCallType(ExecMode mode) internal pure returns (CallType calltype) {
        assembly {
            calltype := mode
        }
    }

    function decodeSingle(bytes calldata executionCalldata)
        internal
        pure
        returns (address target, uint256 value, bytes calldata callData)
    {
        target = address(bytes20(executionCalldata[0:20]));
        value = uint256(bytes32(executionCalldata[20:52]));
        callData = executionCalldata[52:];
    }

    function encodeSingle(address target, uint256 value, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(target, value, callData);
    }

    function decodeBatch(bytes calldata executionCalldata)
        internal
        pure
        returns (Execution[] calldata executions)
    {
        assembly {
            let offset := add(executionCalldata.offset, calldataload(executionCalldata.offset))
            executions.offset := add(offset, 0x20)
            executions.length := calldataload(offset)
        }
    }

    function encodeBatch(Execution[] memory executions) internal pure returns (bytes memory callData) {
        callData = abi.encode(executions);
    }

    function decodeDelegate(bytes calldata executionCalldata)
        internal
        pure
        returns (address delegate, bytes calldata callData)
    {
        delegate = address(bytes20(executionCalldata[0:20]));
        callData = executionCalldata[20:];
    }

    function doFallback2771Static(address fallbackHandler)
        internal
        view
        returns (bool success, bytes memory result)
    {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            success := staticcall(gas(), fallbackHandler, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }

    function doFallback2771Call(address target) internal returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            success := call(gas(), target, 0, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize())
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize())
            mstore(0x40, add(o, returndatasize()))
        }
    }
}
