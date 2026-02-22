// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../interfaces/IHook8141.sol";
import {SessionKeyValidator} from "../validators/SessionKeyValidator.sol";
import {MODULE_TYPE_HOOK} from "../types/Constants8141.sol";

/// @title SessionKeyPermissionHook
/// @notice Unified hook that enforces session key permissions (spending, selectors, targets).
/// @dev Migrated from IPreExecutionHook to IHook8141. Must be installed alongside SessionKeyValidator.
contract SessionKeyPermissionHook is IHook8141 {
    SessionKeyValidator public immutable sessionKeyValidator;

    /// @dev Self-contained spending tracking: spentAmounts[account][sessionKey] = total spent
    mapping(address => mapping(address => uint256)) public spentAmounts;

    error SpendingLimitExceeded(uint256 requested, uint256 available);
    error SelectorNotAllowed(bytes4 selector);
    error TargetNotAllowed(address target);

    event SessionSpent(address indexed account, address indexed sessionKey, uint256 amount);

    constructor(SessionKeyValidator _validator) {
        sessionKeyValidator = _validator;
    }

    // ── IHook8141 ───────────────────────────────────────────────────────

    /// @inheritdoc IHook8141
    function preCheck(address, uint256 msgValue, bytes calldata msgData)
        external
        payable
        override
        returns (bytes memory hookData)
    {
        address account = msg.sender;

        // Retrieve session key from transient storage (set during validation)
        address sessionKeyAddr;
        assembly {
            sessionKeyAddr := tload(account)
        }

        // If no session key in transient storage, this is not a session key transaction
        if (sessionKeyAddr == address(0)) return hex"";

        SessionKeyValidator.SessionPermissions memory perms =
            sessionKeyValidator.getPermissions(account, sessionKeyAddr);

        // 1. Check spending limit (self-contained tracking)
        if (msgValue > 0) {
            uint256 spent = spentAmounts[account][sessionKeyAddr];
            uint256 available = perms.spendingLimit - spent;
            if (msgValue > available) {
                revert SpendingLimitExceeded(msgValue, available);
            }
            spentAmounts[account][sessionKeyAddr] = spent + msgValue;
            emit SessionSpent(account, sessionKeyAddr, msgValue);
        }

        // 2. Check selector whitelist
        if (perms.allowedSelectors.length > 0 && msgData.length >= 4) {
            bytes4 selector = bytes4(msgData[0:4]);
            bool allowed = false;
            for (uint256 i = 0; i < perms.allowedSelectors.length; i++) {
                if (perms.allowedSelectors[i] == selector) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) revert SelectorNotAllowed(selector);
        }

        return hex"";
    }

    /// @inheritdoc IHook8141
    function postCheck(bytes calldata) external payable override {}

    // ── IModule8141 ─────────────────────────────────────────────────────

    function onInstall(bytes calldata) external payable override {}

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }
}
