// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator8141} from "../interfaces/IValidator8141.sol";
import {IPolicy8141} from "../interfaces/IPolicy8141.sol";
import {PassFlag, ValidationType, ValidationId, PermissionId, PolicyData} from "../types/Types8141.sol";
import {VALIDATION_TYPE_PERMISSION} from "../types/Constants8141.sol";

/// @title ValidatorLib8141
/// @notice Encoding/decoding utilities for ValidationId, PermissionId, PolicyData.
/// @dev Ported from ZeroDev Kernel v3 ValidationTypeLib.sol.
library ValidatorLib8141 {
    // ── Encoding ─────────────────────────────────────────────────────

    function encodeFlag(bool skipFrameTx, bool skipSignature) internal pure returns (PassFlag flag) {
        assembly {
            if skipFrameTx { flag := 0x0001000000000000000000000000000000000000000000000000000000000000 }
            if skipSignature { flag := or(flag, 0x0002000000000000000000000000000000000000000000000000000000000000) }
        }
    }

    function encodePolicyData(bool skipFrameTx, bool skipSig, address policy)
        internal
        pure
        returns (PolicyData data)
    {
        assembly {
            if skipFrameTx { data := 0x0001000000000000000000000000000000000000000000000000000000000000 }
            if skipSig { data := or(data, 0x0002000000000000000000000000000000000000000000000000000000000000) }
            data := or(data, shl(80, policy))
        }
    }

    function validatorToIdentifier(IValidator8141 validator) internal pure returns (ValidationId vId) {
        assembly {
            vId := 0x0100000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shl(88, validator))
        }
    }

    function permissionToIdentifier(PermissionId permissionId) internal pure returns (ValidationId vId) {
        assembly {
            vId := 0x0200000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shr(8, permissionId))
        }
    }

    // ── Decoding ─────────────────────────────────────────────────────

    function getType(ValidationId validator) internal pure returns (ValidationType vType) {
        assembly {
            vType := validator
        }
    }

    function getValidator(ValidationId validator) internal pure returns (IValidator8141 v) {
        assembly {
            v := shr(88, validator)
        }
    }

    function getPermissionId(ValidationId validator) internal pure returns (PermissionId id) {
        assembly {
            id := shl(8, validator)
        }
    }

    function decodePolicyData(PolicyData data) internal pure returns (PassFlag flag, IPolicy8141 policy) {
        assembly {
            flag := data
            policy := shr(80, data)
        }
    }

    function getPolicy(PolicyData data) internal pure returns (IPolicy8141 policy) {
        assembly {
            policy := shr(80, data)
        }
    }

    function getPermissionSkip(PolicyData data) internal pure returns (PassFlag flag) {
        assembly {
            flag := data
        }
    }

    /// @notice Decode ERC-1271 signature to extract ValidationId and remaining signature.
    /// @dev Format:
    ///   byte[0] = ValidationType
    ///     0x00 (Root): 1B prefix + sig
    ///     0x01 (Validator): 1B type + 20B validator address + sig
    ///     0x02 (Permission): 1B type + 4B permissionId + sig
    function decodeSignature(bytes calldata signature)
        internal
        pure
        returns (ValidationId vId, bytes calldata sig)
    {
        assembly {
            vId := calldataload(signature.offset)
            switch shr(248, vId)
            case 0 {
                // Root mode
                vId := 0x00
                sig.offset := add(signature.offset, 1)
                sig.length := sub(signature.length, 1)
            }
            case 1 {
                // Validator mode
                sig.offset := add(signature.offset, 21)
                sig.length := sub(signature.length, 21)
            }
            case 2 {
                // Permission mode — mask to 5 bytes (type + permissionId)
                vId := and(vId, 0xffffffffff000000000000000000000000000000000000000000000000000000)
                sig.offset := add(signature.offset, 5)
                sig.length := sub(signature.length, 5)
            }
            default { revert(0x00, 0x00) }
        }
    }
}
