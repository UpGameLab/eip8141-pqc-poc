// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IModule8141} from "../interfaces/IModule8141.sol";

/// @title ModuleLib8141
/// @notice Safe module uninstall helper (ported from Kernel v3 ModuleLib).
/// @dev Uses excessivelySafeCall pattern to prevent module from griefing uninstallation.
library ModuleLib8141 {
    event ModuleUninstallResult(address module, bool result);

    function uninstallModule(address module, bytes memory deinitData) internal returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            // onUninstall(bytes) selector = 0x8a91b0e3
            mstore(m, 0x8a91b0e300000000000000000000000000000000000000000000000000000000)
            mstore(add(m, 0x04), 0x20) // offset for bytes parameter
            mstore(add(m, 0x24), mload(deinitData)) // length
            let dataLen := mload(deinitData)
            // copy deinitData bytes
            let src := add(deinitData, 0x20)
            let dst := add(m, 0x44)
            for { let i := 0 } lt(i, dataLen) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
            let totalLen := add(0x44, dataLen)
            // excessively safe call: don't copy return data, limit gas to gasleft()
            result := call(gas(), module, 0, m, totalLen, 0, 0)
        }
        emit ModuleUninstallResult(module, result);
    }
}
