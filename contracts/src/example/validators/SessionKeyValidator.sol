// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator8141} from "../../interfaces/IValidator8141.sol";
import {MODULE_TYPE_VALIDATOR, ERC1271_INVALID} from "../../types/Constants8141.sol";

/// @title SessionKeyValidator
/// @notice Validator for time-bounded, permission-restricted session keys.
/// @dev Migrated to IValidator8141 (extends IModule8141).
///      Uses transient storage to pass session key address to hooks.
contract SessionKeyValidator is IValidator8141 {
    struct SessionKey {
        address signer;
        uint48 validAfter;
        uint48 validUntil;
    }

    struct SessionPermissions {
        uint256 spendingLimit;
        uint256 spentAmount;
        bytes4[] allowedSelectors;
        address[] allowedTargets;
    }

    mapping(address => mapping(address => SessionKey)) public sessionKeys;
    mapping(address => mapping(address => SessionPermissions)) public sessionPermissions;
    mapping(address => address[]) internal _activeSessions;

    error SessionNotFound();
    error SessionExpired();
    error SessionNotYetValid();
    error SpendingLimitExceeded(uint256 requested, uint256 available);
    error SelectorNotAllowed(bytes4 selector);
    error TargetNotAllowed(address target);
    error InvalidSessionKey();
    error InvalidTimeWindow();
    error SessionKeyAlreadyExists();

    event SessionKeyAdded(
        address indexed account, address indexed sessionKey, uint48 validAfter, uint48 validUntil, uint256 spendingLimit
    );
    event SessionKeyRevoked(address indexed account, address indexed sessionKey);
    event SessionSpent(address indexed account, address indexed sessionKey, uint256 amount);

    // ── IValidator8141 ──────────────────────────────────────────────────

    /// @inheritdoc IValidator8141
    function validateSignature(address account, bytes32 sigHash, bytes calldata signature)
        external
        override
        returns (bool valid)
    {
        if (signature.length != 85) return false;

        address sessionKeyAddr = address(bytes20(signature[0:20]));
        bytes calldata sessionSig = signature[20:85];

        SessionKey storage session = sessionKeys[account][sessionKeyAddr];
        if (session.signer == address(0)) return false;
        if (block.timestamp < session.validAfter) return false;
        if (block.timestamp > session.validUntil) return false;

        bytes32 r = bytes32(sessionSig[0:32]);
        bytes32 s = bytes32(sessionSig[32:64]);
        uint8 v = uint8(sessionSig[64]);
        if (v < 27) v += 27;

        address signer = ecrecover(sigHash, v, r, s);
        if (signer != session.signer) return false;

        // Store session key in transient storage for hook to access
        assembly {
            tstore(account, sessionKeyAddr)
        }

        return true;
    }

    /// @inheritdoc IValidator8141
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC1271_INVALID; // Session keys don't support ERC-1271
    }

    // ── IModule8141 ─────────────────────────────────────────────────────

    function onInstall(bytes calldata) external payable override {}

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }

    // ── Session key management ──────────────────────────────────────────

    function addSessionKey(
        address sessionKey,
        uint48 validAfter,
        uint48 validUntil,
        uint256 spendingLimit,
        bytes4[] calldata allowedSelectors,
        address[] calldata allowedTargets
    ) external {
        address account = msg.sender;
        if (sessionKey == address(0)) revert InvalidSessionKey();
        if (validUntil <= validAfter) revert InvalidTimeWindow();
        if (sessionKeys[account][sessionKey].signer != address(0)) revert SessionKeyAlreadyExists();

        sessionKeys[account][sessionKey] =
            SessionKey({signer: sessionKey, validAfter: validAfter, validUntil: validUntil});

        sessionPermissions[account][sessionKey] = SessionPermissions({
            spendingLimit: spendingLimit,
            spentAmount: 0,
            allowedSelectors: allowedSelectors,
            allowedTargets: allowedTargets
        });

        _activeSessions[account].push(sessionKey);
        emit SessionKeyAdded(account, sessionKey, validAfter, validUntil, spendingLimit);
    }

    function revokeSessionKey(address sessionKey) external {
        address account = msg.sender;
        if (sessionKeys[account][sessionKey].signer == address(0)) revert SessionNotFound();

        delete sessionKeys[account][sessionKey];
        delete sessionPermissions[account][sessionKey];

        address[] storage sessions = _activeSessions[account];
        for (uint256 i = 0; i < sessions.length; i++) {
            if (sessions[i] == sessionKey) {
                sessions[i] = sessions[sessions.length - 1];
                sessions.pop();
                break;
            }
        }

        emit SessionKeyRevoked(account, sessionKey);
    }

    function recordSpending(address account, address sessionKey, uint256 amount) external {
        sessionPermissions[account][sessionKey].spentAmount += amount;
        emit SessionSpent(account, sessionKey, amount);
    }

    function getActiveSessions(address account) external view returns (address[] memory) {
        return _activeSessions[account];
    }

    function getPermissions(address account, address sessionKey)
        external
        view
        returns (SessionPermissions memory)
    {
        return sessionPermissions[account][sessionKey];
    }
}
