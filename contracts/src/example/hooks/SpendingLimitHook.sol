// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook8141} from "../../interfaces/IHook8141.sol";
import {MODULE_TYPE_HOOK} from "../../types/Constants8141.sol";

/// @title SpendingLimitHook
/// @notice Unified hook (preCheck/postCheck) that enforces daily spending limits.
/// @dev Migrated from IPreExecutionHook to IHook8141.
///      preCheck records pending spend, postCheck is a no-op (spend already committed).
contract SpendingLimitHook is IHook8141 {
    struct SpendingState {
        uint256 dailyLimit;
        uint256 spentToday;
        uint256 lastResetDay;
    }

    mapping(address => SpendingState) public spendingStates;

    error DailyLimitExceeded(uint256 requested, uint256 available);
    error InvalidDailyLimit();

    event DailyLimitSet(address indexed account, uint256 dailyLimit);
    event SpendingRecorded(address indexed account, uint256 amount, uint256 totalToday);

    // ── IHook8141 ───────────────────────────────────────────────────────

    /// @inheritdoc IHook8141
    function preCheck(address, uint256 msgValue, bytes calldata)
        external
        payable
        override
        returns (bytes memory hookData)
    {
        SpendingState storage state = spendingStates[msg.sender];

        // Reset if new day
        uint256 today = block.timestamp / 1 days;
        if (state.lastResetDay < today) {
            state.spentToday = 0;
            state.lastResetDay = today;
        }

        // Check limit
        uint256 available = state.dailyLimit - state.spentToday;
        if (msgValue > available) {
            revert DailyLimitExceeded(msgValue, available);
        }

        // Record spending
        state.spentToday += msgValue;
        emit SpendingRecorded(msg.sender, msgValue, state.spentToday);

        // Return context for postCheck (amount for potential rollback)
        return abi.encode(msgValue);
    }

    /// @inheritdoc IHook8141
    function postCheck(bytes calldata) external payable override {
        // Spending already committed in preCheck
    }

    // ── IModule8141 ─────────────────────────────────────────────────────

    function onInstall(bytes calldata data) external payable override {
        uint256 dailyLimit = abi.decode(data, (uint256));
        if (dailyLimit == 0) revert InvalidDailyLimit();

        spendingStates[msg.sender] =
            SpendingState({dailyLimit: dailyLimit, spentToday: 0, lastResetDay: block.timestamp / 1 days});

        emit DailyLimitSet(msg.sender, dailyLimit);
    }

    function onUninstall(bytes calldata) external payable override {
        delete spendingStates[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return spendingStates[account].dailyLimit > 0;
    }

    // ── Admin ───────────────────────────────────────────────────────────

    function setDailyLimit(uint256 newLimit) external {
        if (newLimit == 0) revert InvalidDailyLimit();
        spendingStates[msg.sender].dailyLimit = newLimit;
        emit DailyLimitSet(msg.sender, newLimit);
    }
}
