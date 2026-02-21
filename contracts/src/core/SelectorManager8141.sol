// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../interfaces/IHook8141.sol";
import {IModule8141} from "../interfaces/IModule8141.sol";
import {IERC7579Account8141} from "../interfaces/IERC7579Account8141.sol";
import {CallType} from "../types/Types8141.sol";
import {
    SELECTOR_STORAGE_SLOT,
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    MODULE_TYPE_FALLBACK
} from "../types/Constants8141.sol";

/// @title SelectorManager8141
/// @notice Manages fallback selector routing for Kernel8141.
/// @dev Ported from Kernel v3 SelectorManager.
abstract contract SelectorManager8141 {
    error NotSupportedCallType();

    struct SelectorConfig {
        IHook8141 hook; // address(0) = not installed, address(1) = no hook required
        address target; // fallback handler address
        CallType callType; // CALL or DELEGATECALL
    }

    struct SelectorStorage {
        mapping(bytes4 => SelectorConfig) selectorConfig;
    }

    function selectorConfig(bytes4 selector) external view returns (SelectorConfig memory) {
        return _selectorConfig(selector);
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        config = _selectorStorage().selectorConfig[selector];
    }

    function _selectorStorage() internal pure returns (SelectorStorage storage ss) {
        bytes32 slot = SELECTOR_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
    }

    /// @notice Install a fallback handler for a selector.
    /// @dev selectorData format: [1B callType][...onInstall data]
    ///      If hook is address(0), it is upgraded to HOOK_ONLY_ENTRYPOINT sentinel.
    function _installSelector(bytes4 selector, address target, IHook8141 hook, bytes calldata selectorData) internal {
        if (address(hook) == address(0)) {
            hook = IHook8141(address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        CallType callType = CallType.wrap(bytes1(selectorData[0]));
        if (callType == CALLTYPE_SINGLE) {
            IModule8141(target).onInstall(selectorData[1:]);
            emit IERC7579Account8141.ModuleInstalled(MODULE_TYPE_FALLBACK, target);
        } else if (callType != CALLTYPE_DELEGATECALL) {
            revert NotSupportedCallType();
        }
        ss.hook = hook;
        ss.target = target;
        ss.callType = callType;
    }

    /// @notice Clear a selector's configuration (during uninstall).
    /// @return hook The previous hook address
    /// @return target The previous target address (only if callType was SINGLE)
    function _clearSelectorData(bytes4 selector) internal returns (IHook8141 hook, address target) {
        SelectorConfig storage ss = _selectorConfig(selector);
        hook = ss.hook;
        ss.hook = IHook8141(address(0));
        if (ss.callType == CALLTYPE_SINGLE) {
            target = ss.target;
        }
        ss.target = address(0);
        ss.callType = CallType.wrap(bytes1(0x00));
    }
}
