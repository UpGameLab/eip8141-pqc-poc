// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../interfaces/IHook8141.sol";
import {SessionKeyValidator} from "../validators/SessionKeyValidator.sol";
import {MODULE_TYPE_HOOK} from "../types/Constants8141.sol";
import {FrameTxLib} from "../../../FrameTxLib.sol";

/// @title SessionKeyPermissionHook
/// @notice Enforces session key permissions (spending limits, selector whitelist) as a DEFAULT frame.
/// @dev EIP-8141 native: the session key address is passed in the DEFAULT frame's calldata
///      via check(address sessionKey). The hook validates the session key is registered and
///      enforces permissions by reading the SENDER frame's execution data via frameDataLoad().
///
///      This avoids transient storage (forbidden in VERIFY frames) by having the transaction
///      builder include the session key in the DEFAULT frame calldata. The VERIFY frame's
///      sigHash binds all frame calldata, so the session key cannot be tampered with.
///
///      Frame pattern:
///        Frame 0: DEFAULT(this)   → check(sessionKey)    — enforce permissions
///        Frame 1: VERIFY(kernel)  → validate(sig, scope)  — signature validation
///        Frame 2: SENDER(kernel)  → execute(mode, data)
contract SessionKeyPermissionHook is IHook8141 {
    SessionKeyValidator public immutable sessionKeyValidator;

    /// @dev Self-contained spending tracking: spentAmounts[account][sessionKey] = total spent
    mapping(address => mapping(address => uint256)) public spentAmounts;

    error SpendingLimitExceeded(uint256 requested, uint256 available);
    error SelectorNotAllowed(bytes4 selector);
    error InvalidSessionKey();

    event SessionSpent(address indexed account, address indexed sessionKey, uint256 amount);

    constructor(SessionKeyValidator _validator) {
        sessionKeyValidator = _validator;
    }

    // ── DEFAULT frame entry point ───────────────────────────────────────

    /// @notice Called from a DEFAULT frame to enforce session key permissions.
    /// @param sessionKey The session key address (must match a registered session key).
    /// @dev The session key is passed in calldata by the transaction builder.
    ///      sigHash binds all frame calldata, so this value is integrity-protected.
    function check(address sessionKey) external {
        address account = FrameTxLib.txSender();

        // Validate session key is registered
        (address signer,,) = sessionKeyValidator.sessionKeys(account, sessionKey);
        if (signer == address(0)) revert InvalidSessionKey();

        SessionKeyValidator.SessionPermissions memory perms =
            sessionKeyValidator.getPermissions(account, sessionKey);

        // Find SENDER frame and extract execution data
        uint256 senderIdx = _findSenderFrame();

        // 1. Check spending limit
        uint256 totalValue = _extractValueFromSenderFrame(senderIdx);
        if (totalValue > 0) {
            uint256 spent = spentAmounts[account][sessionKey];
            uint256 available = perms.spendingLimit - spent;
            if (totalValue > available) {
                revert SpendingLimitExceeded(totalValue, available);
            }
            spentAmounts[account][sessionKey] = spent + totalValue;
            emit SessionSpent(account, sessionKey, totalValue);
        }

        // 2. Check selector whitelist from SENDER frame
        if (perms.allowedSelectors.length > 0) {
            bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderIdx, 0));
            bool allowed = false;
            for (uint256 i = 0; i < perms.allowedSelectors.length; i++) {
                if (perms.allowedSelectors[i] == senderSelector) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) revert SelectorNotAllowed(senderSelector);
        }
    }

    // ── IHook8141 (backward compatibility for fallback hooks) ───────────

    /// @inheritdoc IHook8141
    function preCheck(address, uint256, bytes calldata)
        external
        payable
        override
        returns (bytes memory)
    {
        // In frame-native mode, use check() in a DEFAULT frame instead.
        // This stub is kept for IHook8141 interface compliance.
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

    // ── Internal helpers ────────────────────────────────────────────────

    /// @dev Find the first SENDER frame.
    function _findSenderFrame() internal pure returns (uint256) {
        uint256 count = FrameTxLib.frameCount();
        for (uint256 i = 0; i < count; i++) {
            if (FrameTxLib.frameMode(i) == 2) return i; // SENDER mode
        }
        revert("No SENDER frame");
    }

    /// @dev Extract ETH value from SENDER frame's execute() calldata.
    ///      SINGLE mode: value at executionCalldata[20:52], frame offset 120.
    function _extractValueFromSenderFrame(uint256 idx) internal pure returns (uint256) {
        bytes32 execModeWord = FrameTxLib.frameDataLoad(idx, 4); // skip 4B selector
        uint8 callType = uint8(bytes1(execModeWord));
        if (callType == 0x00) {
            // SINGLE: value is at offset 120 (4+32+32+32+20)
            return uint256(FrameTxLib.frameDataLoad(idx, 120));
        }
        // BATCH and DELEGATECALL: not tracked for simplicity
        return 0;
    }
}
