// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title StorageOracle
/// @notice Minimal contract that stores a value in slot 0.
///         Used to test STO-021: the MaliciousValidator reads this contract's
///         storage, which is not associated with the frame tx sender.
contract StorageOracle {
    uint256 public value;

    constructor(uint256 _value) {
        value = _value;
    }

    /// @notice Fallback: return slot 0 for any call (used by MaliciousValidator's staticcall).
    fallback() external {
        assembly {
            let v := sload(0)
            mstore(0x00, v)
            return(0x00, 0x20)
        }
    }
}
