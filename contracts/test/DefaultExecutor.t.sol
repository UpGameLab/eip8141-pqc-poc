// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DefaultExecutor} from "../src/example/executors/DefaultExecutor.sol";

contract DefaultExecutorTest is Test {
    DefaultExecutor executor;
    Counter counter;

    function setUp() public {
        executor = new DefaultExecutor();
        counter = new Counter();
    }

    function test_executeWithData_success() public {
        bytes memory callData = abi.encodeWithSelector(Counter.increment.selector);

        executor.executeWithData(address(counter), 0, callData);

        assertEq(counter.count(), 1);
    }

    function test_executeWithData_withValue() public {
        vm.deal(address(this), 1 ether);

        executor.executeWithData{value: 0.5 ether}(address(counter), 0.5 ether, "");

        assertEq(address(counter).balance, 0.5 ether);
    }

    function test_executeWithData_revertsOnFailure() public {
        Reverter reverter = new Reverter();
        bytes memory callData = abi.encodeWithSelector(Reverter.fail.selector);

        vm.expectRevert("DefaultExecutor: call failed");
        executor.executeWithData(address(reverter), 0, callData);
    }

    function test_isInitialized_alwaysTrue() public view {
        assertTrue(executor.isInitialized(address(0)));
        assertTrue(executor.isInitialized(address(this)));
        assertTrue(executor.isInitialized(address(0xdead)));
    }

    function test_onInstall_noop() public {
        executor.onInstall("");
        executor.onInstall(abi.encode(uint256(123)));
    }

    function test_onUninstall_noop() public {
        executor.onUninstall();
    }
}

contract Counter {
    uint256 public count;
    function increment() external { count++; }
    receive() external payable {}
}

contract Reverter {
    function fail() external pure { revert("always reverts"); }
}
