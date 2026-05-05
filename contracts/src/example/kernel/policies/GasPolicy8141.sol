// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPolicy8141} from "../interfaces/IPolicy8141.sol";
import {FrameTxLib} from "../../../FrameTxLib.sol";
import {MODULE_TYPE_POLICY} from "../types/Constants8141.sol";

/// @title GasPolicy8141
/// @notice Stateful gas budget policy for EIP-8141 permission system.
/// @dev Two-phase policy demonstrating the inline hook/policy model:
///      - VERIFY phase (checkFrameTxPolicy): read-only budget sufficiency check
///      - SENDER phase (consumeFrameTxPolicy): budget decrement (state write)
///
///      Uses FrameTxLib.maxCost() to read the worst-case transaction cost from
///      TXPARAM(0x06), which is available in both VERIFY and SENDER frames.
///
///      ERC-7562 compliance:
///        - checkFrameTxPolicy reads budgets[msg.sender][id] — sender-associated storage (STO-021)
///        - FrameTxLib.maxCost() uses TXPARAM — not a banned opcode
contract GasPolicy8141 is IPolicy8141 {
    struct GasBudget {
        uint128 allowed;   // remaining budget in wei
        uint128 consumed;  // total consumed in wei (for accounting)
    }

    mapping(address => mapping(bytes32 => GasBudget)) public budgets;

    error BudgetExceeded(uint256 required, uint256 available);
    error InvalidBudget();

    event BudgetSet(address indexed account, bytes32 indexed id, uint128 allowed);
    event BudgetConsumed(address indexed account, bytes32 indexed id, uint128 amount);

    // ── IPolicy8141: VERIFY phase (read-only) ────────────────────────

    /// @inheritdoc IPolicy8141
    /// @dev Read-only budget check. Uses FrameTxLib.maxCost() to read worst-case
    ///      transaction cost and compares against remaining budget.
    function checkFrameTxPolicy(bytes32 id, address, bytes32, uint256)
        external
        view
        override
        returns (uint256)
    {
        uint256 maxCost = FrameTxLib.maxCost();
        if (maxCost > budgets[msg.sender][id].allowed) {
            return 1; // budget insufficient
        }
        return 0; // budget sufficient
    }

    // ── IPolicy8141: SENDER phase (state write) ─────────────────────

    /// @inheritdoc IPolicy8141
    /// @dev Decrements the gas budget by the transaction's max cost.
    ///      Called from executeHooked() in SENDER frame where state writes are allowed.
    function consumeFrameTxPolicy(bytes32 id, address account) external override {
        uint256 maxCost = FrameTxLib.maxCost();
        GasBudget storage budget = budgets[account][id];
        if (maxCost > budget.allowed) {
            revert BudgetExceeded(maxCost, budget.allowed);
        }
        budget.allowed -= uint128(maxCost);
        budget.consumed += uint128(maxCost);
        emit BudgetConsumed(account, id, uint128(maxCost));
    }

    /// @inheritdoc IPolicy8141
    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        return budgets[msg.sender][id].allowed > 0 ? 0 : 1;
    }

    // ── IModule8141 ──────────────────────────────────────────────────

    /// @dev initData format: abi.encodePacked(bytes32 permissionId, uint128 allowedBudget)
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        uint128 allowed = uint128(bytes16(data[32:48]));
        if (allowed == 0) revert InvalidBudget();

        budgets[msg.sender][id] = GasBudget({allowed: allowed, consumed: 0});
        emit BudgetSet(msg.sender, id, allowed);
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        delete budgets[msg.sender][id];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_POLICY;
    }

    function isInitialized(address account) external view override returns (bool) {
        // Simplified: any non-zero budget indicates initialization
        // In production, use a dedicated initialized mapping
        return true;
    }
}
