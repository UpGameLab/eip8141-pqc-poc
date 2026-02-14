// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BatchExecutor} from "../src/example/executors/BatchExecutor.sol";

contract BatchExecutorTest is Test {
    BatchExecutor executor;
    Counter counter;

    function setUp() public {
        executor = new BatchExecutor();
        counter = new Counter();
    }

    function test_executeWithData_multipleCalls() public {
        address[] memory targets = new address[](3);
        targets[0] = address(counter);
        targets[1] = address(counter);
        targets[2] = address(counter);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](3);
        datas[0] = abi.encodeWithSelector(Counter.increment.selector);
        datas[1] = abi.encodeWithSelector(Counter.increment.selector);
        datas[2] = abi.encodeWithSelector(Counter.increment.selector);

        bytes memory batchData = abi.encode(targets, values, datas);
        executor.executeWithData(address(0), 0, batchData);

        assertEq(counter.count(), 3);
    }

    function test_executeWithData_withValues() public {
        vm.deal(address(this), 10 ether);

        address[] memory targets = new address[](2);
        targets[0] = address(counter);
        targets[1] = address(0xdead);

        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;

        bytes[] memory datas = new bytes[](2);

        bytes memory batchData = abi.encode(targets, values, datas);
        executor.executeWithData{value: 3 ether}(address(0), 0, batchData);

        assertEq(address(counter).balance, 1 ether);
        assertEq(address(0xdead).balance, 2 ether);
    }

    function test_executeWithData_revertsOnLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1); // Mismatch
        bytes[] memory datas = new bytes[](2);

        bytes memory batchData = abi.encode(targets, values, datas);

        vm.expectRevert(BatchExecutor.BatchLengthMismatch.selector);
        executor.executeWithData(address(0), 0, batchData);
    }

    function test_executeWithData_revertsOnCallFailure() public {
        Reverter reverter = new Reverter();

        address[] memory targets = new address[](2);
        targets[0] = address(counter);
        targets[1] = address(reverter);

        uint256[] memory values = new uint256[](2);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(Counter.increment.selector);
        datas[1] = abi.encodeWithSelector(Reverter.fail.selector);

        bytes memory batchData = abi.encode(targets, values, datas);

        vm.expectRevert(abi.encodeWithSelector(BatchExecutor.BatchCallFailed.selector, 1));
        executor.executeWithData(address(0), 0, batchData);

        // First call should not have executed (atomic revert)
        assertEq(counter.count(), 0);
    }

    function test_isInitialized_alwaysTrue() public view {
        assertTrue(executor.isInitialized(address(0)));
        assertTrue(executor.isInitialized(address(this)));
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
