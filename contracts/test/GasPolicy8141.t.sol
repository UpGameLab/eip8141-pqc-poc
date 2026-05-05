// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GasPolicy8141} from "../src/example/kernel/policies/GasPolicy8141.sol";

contract GasPolicy8141Test is Test {
    GasPolicy8141 policy;
    address account;
    bytes32 permId;

    function setUp() public {
        policy = new GasPolicy8141();
        account = makeAddr("account");
        permId = bytes32(uint256(1));

        // Install with 1 ETH budget
        vm.prank(account);
        policy.onInstall(abi.encodePacked(permId, uint128(1 ether)));
    }

    function test_onInstall_setsBudget() public view {
        (uint128 allowed, uint128 consumed) = policy.budgets(account, permId);
        assertEq(allowed, 1 ether);
        assertEq(consumed, 0);
    }

    function test_onInstall_revertsZeroBudget() public {
        vm.prank(makeAddr("other"));
        vm.expectRevert(GasPolicy8141.InvalidBudget.selector);
        policy.onInstall(abi.encodePacked(bytes32(uint256(2)), uint128(0)));
    }

    function test_onUninstall_clearsBudget() public {
        vm.prank(account);
        policy.onUninstall(abi.encodePacked(permId));

        (uint128 allowed, uint128 consumed) = policy.budgets(account, permId);
        assertEq(allowed, 0);
        assertEq(consumed, 0);
    }

    function test_isModuleType_policy() public view {
        assertTrue(policy.isModuleType(5)); // MODULE_TYPE_POLICY
        assertFalse(policy.isModuleType(4)); // MODULE_TYPE_HOOK
    }

    function test_consumeFrameTxPolicy_revertsWithoutEIP8141() public {
        // consumeFrameTxPolicy uses FrameTxLib.maxCost() which calls TXPARAM,
        // an EIP-8141 opcode unavailable in standard EVM. This reverts in unit tests.
        // Full integration testing requires E2E tests against the 8141-geth devnet.
        vm.prank(account);
        vm.expectRevert();
        policy.consumeFrameTxPolicy(permId, account);
    }

    function test_checkSignaturePolicy_passesWithBudget() public {
        vm.prank(account);
        uint256 result = policy.checkSignaturePolicy(permId, address(0), bytes32(0), "");
        assertEq(result, 0); // passes when budget > 0
    }

    function test_checkSignaturePolicy_failsWithoutBudget() public {
        // Uninstall to clear budget
        vm.prank(account);
        policy.onUninstall(abi.encodePacked(permId));

        vm.prank(account);
        uint256 result = policy.checkSignaturePolicy(permId, address(0), bytes32(0), "");
        assertEq(result, 1); // fails when budget == 0
    }

    function test_multiplePoliciesPerAccount() public {
        bytes32 permId2 = bytes32(uint256(2));

        vm.prank(account);
        policy.onInstall(abi.encodePacked(permId2, uint128(5 ether)));

        (uint128 allowed1,) = policy.budgets(account, permId);
        (uint128 allowed2,) = policy.budgets(account, permId2);

        assertEq(allowed1, 1 ether);
        assertEq(allowed2, 5 ether);
    }
}
