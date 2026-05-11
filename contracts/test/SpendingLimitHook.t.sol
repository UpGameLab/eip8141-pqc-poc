// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LocalTest} from "./TestHelpers.sol";
import {SpendingLimitHook} from "../src/example/kernel/hooks/SpendingLimitHook.sol";

contract SpendingLimitHookTest is LocalTest {
    SpendingLimitHook hook;
    address account;

    function setUp() public {
        hook = new SpendingLimitHook();
        account = makeAddr("account");

        vm.prank(account);
        hook.onInstall(abi.encode(10 ether)); // 10 ETH daily limit
    }

    function test_onInstall_setsLimit() public {
        (uint256 dailyLimit, uint256 spentToday, uint256 lastResetDay) = hook.spendingStates(account);
        assertEq(dailyLimit, 10 ether);
        assertEq(spentToday, 0);
        assertEq(lastResetDay, block.timestamp / 1 days);
    }

    function test_onInstall_revertsZeroLimit() public {
        vm.prank(makeAddr("other"));
        vm.expectRevert(SpendingLimitHook.InvalidDailyLimit.selector);
        hook.onInstall(abi.encode(0));
    }

    function test_isInitialized() public {
        assertTrue(hook.isInitialized(account));
        assertFalse(hook.isInitialized(address(0xdead)));
    }

    function test_isModuleType_hook() public {
        assertTrue(hook.isModuleType(4)); // MODULE_TYPE_HOOK
        assertFalse(hook.isModuleType(1)); // MODULE_TYPE_VALIDATOR
    }

    function test_onUninstall_clearsState() public {
        vm.prank(account);
        hook.onUninstall("");

        (uint256 dailyLimit,,) = hook.spendingStates(account);
        assertEq(dailyLimit, 0);
        assertFalse(hook.isInitialized(account));
    }

    function test_preCheck_allowsWithinLimit() public {
        vm.prank(account);
        hook.preCheck(address(0xdead), 5 ether, "");

        (, uint256 spentToday,) = hook.spendingStates(account);
        assertEq(spentToday, 5 ether);
    }

    function test_preCheck_allowsMultipleUnderLimit() public {
        vm.startPrank(account);
        hook.preCheck(address(0xdead), 3 ether, "");
        hook.preCheck(address(0xdead), 2 ether, "");
        hook.preCheck(address(0xdead), 5 ether, "");
        vm.stopPrank();

        (, uint256 spentToday,) = hook.spendingStates(account);
        assertEq(spentToday, 10 ether); // Exactly at limit
    }

    function test_preCheck_revertsOverLimit() public {
        vm.startPrank(account);
        hook.preCheck(address(0xdead), 6 ether, "");

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendingLimitHook.DailyLimitExceeded.selector,
                5 ether, // requested
                4 ether // available
            )
        );
        hook.preCheck(address(0xdead), 5 ether, "");
        vm.stopPrank();
    }

    function test_preCheck_resetsDaily() public {
        vm.prank(account);
        hook.preCheck(address(0xdead), 8 ether, "");

        (, uint256 spentBefore,) = hook.spendingStates(account);
        assertEq(spentBefore, 8 ether);

        // Advance time to next day
        vm.warp(block.timestamp + 1 days);

        vm.prank(account);
        hook.preCheck(address(0xdead), 7 ether, "");

        (, uint256 spentAfter,) = hook.spendingStates(account);
        assertEq(spentAfter, 7 ether); // Reset and new spending
    }

    function test_preCheck_returnsContext() public {
        vm.prank(account);
        bytes memory hookData = hook.preCheck(address(0xdead), 5 ether, "");
        uint256 amount = abi.decode(hookData, (uint256));
        assertEq(amount, 5 ether);
    }

    function test_postCheck_noop() public {
        vm.prank(account);
        hook.postCheck(""); // Should not revert
    }

    function test_setDailyLimit() public {
        vm.prank(account);
        hook.setDailyLimit(20 ether);

        (uint256 dailyLimit,,) = hook.spendingStates(account);
        assertEq(dailyLimit, 20 ether);
    }

    function test_setDailyLimit_revertsZero() public {
        vm.prank(account);
        vm.expectRevert(SpendingLimitHook.InvalidDailyLimit.selector);
        hook.setDailyLimit(0);
    }
}
