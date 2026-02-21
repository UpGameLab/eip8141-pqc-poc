// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPolicy8141} from "../../interfaces/IPolicy8141.sol";
import {FrameTxLib} from "../../FrameTxLib.sol";
import {MODULE_TYPE_POLICY} from "../../types/Constants8141.sol";

/// @title SelectorPolicy8141
/// @notice Permission policy that restricts allowed function selectors.
/// @dev EIP-8141 native: uses frameDataLoad() to read SENDER frame selector directly.
///      This is more powerful than Kernel v3's approach which reads from PackedUserOperation.
contract SelectorPolicy8141 is IPolicy8141 {
    // permissionKey = keccak256(abi.encode(account, id))
    mapping(address => mapping(bytes32 => mapping(bytes4 => bool))) public allowedSelectors;

    error SelectorNotAllowed(bytes4 selector);

    event SelectorAllowed(address indexed account, bytes32 indexed id, bytes4 selector);
    event SelectorDisallowed(address indexed account, bytes32 indexed id, bytes4 selector);

    // ── IPolicy8141 ─────────────────────────────────────────────────────

    /// @inheritdoc IPolicy8141
    /// @dev EIP-8141 native: reads SENDER frame's first 4 bytes (selector) via cross-frame reading.
    function checkFrameTxPolicy(bytes32 id, address account, bytes32, uint256 senderFrameIndex)
        external
        payable
        override
        returns (uint256)
    {
        bytes4 selector = bytes4(FrameTxLib.frameDataLoad(senderFrameIndex, 0));
        if (!allowedSelectors[account][id][selector]) {
            return 1; // fail
        }
        return 0; // success
    }

    /// @inheritdoc IPolicy8141
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata)
        external
        pure
        override
        returns (uint256)
    {
        return 0; // Selector policy doesn't restrict ERC-1271 signatures
    }

    // ── IModule8141 ─────────────────────────────────────────────────────

    /// @dev initData format: abi.encodePacked(bytes32 permissionId, bytes4[] selectors)
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        uint256 selectorCount = (data.length - 32) / 4;
        for (uint256 i = 0; i < selectorCount; i++) {
            bytes4 selector = bytes4(data[32 + i * 4:36 + i * 4]);
            allowedSelectors[msg.sender][id][selector] = true;
            emit SelectorAllowed(msg.sender, id, selector);
        }
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        uint256 selectorCount = (data.length - 32) / 4;
        for (uint256 i = 0; i < selectorCount; i++) {
            bytes4 selector = bytes4(data[32 + i * 4:36 + i * 4]);
            delete allowedSelectors[msg.sender][id][selector];
            emit SelectorDisallowed(msg.sender, id, selector);
        }
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }
}
