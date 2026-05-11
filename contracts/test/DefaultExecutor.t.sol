// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DefaultExecutor} from "../src/example/kernel/executors/DefaultExecutor.sol";

contract DefaultExecutorTest is Test {
    DefaultExecutor executor;

    function setUp() public {
        executor = new DefaultExecutor();
    }

    function test_isModuleType_executor() public {
        assertTrue(executor.isModuleType(2)); // MODULE_TYPE_EXECUTOR
    }

    function test_isModuleType_otherTypes() public {
        assertFalse(executor.isModuleType(1)); // MODULE_TYPE_VALIDATOR
        assertFalse(executor.isModuleType(3)); // MODULE_TYPE_FALLBACK
        assertFalse(executor.isModuleType(4)); // MODULE_TYPE_HOOK
    }

    function test_isInitialized_alwaysTrue() public {
        assertTrue(executor.isInitialized(address(0)));
        assertTrue(executor.isInitialized(address(this)));
        assertTrue(executor.isInitialized(address(0xdead)));
    }

    function test_onInstall_noop() public {
        executor.onInstall("");
        executor.onInstall(abi.encode(uint256(123)));
    }

    function test_onUninstall_noop() public {
        executor.onUninstall("");
    }
}
