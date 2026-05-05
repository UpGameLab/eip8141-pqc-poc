// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Simple8141Account} from "../src/Simple8141Account.sol";

contract Simple8141AccountTest is Test {
    Simple8141Account account;
    address owner;

    function setUp() public {
        (owner,) = makeAddrAndKey("owner");
        account = new Simple8141Account(owner);
    }

    // ── Constructor ──────────────────────────────────────────────────

    function test_owner() public view {
        assertEq(account.owner(), owner);
    }

    // ── execute ──────────────────────────────────────────────────────

    function test_execute_revertsIfNotSelf() public {
        vm.expectRevert(Simple8141Account.InvalidCaller.selector);
        account.execute(address(0xdead), 0, "");
    }

    function test_execute_success() public {
        // Fund the account
        vm.deal(address(account), 1 ether);

        address target = address(0xdead);
        uint256 sendAmount = 0.5 ether;

        // Prank as the account itself (SENDER frame behavior)
        vm.prank(address(account));
        account.execute(target, sendAmount, "");

        assertEq(target.balance, sendAmount);
    }

    function test_execute_callWithData() public {
        // Deploy a simple counter target
        Counter counter = new Counter();

        vm.prank(address(account));
        account.execute(
            address(counter),
            0,
            abi.encodeWithSelector(Counter.increment.selector)
        );

        assertEq(counter.count(), 1);
    }

    function test_execute_revertsOnFailedCall() public {
        // Call a contract that always reverts
        Reverter reverter = new Reverter();

        vm.prank(address(account));
        vm.expectRevert(Simple8141Account.ExecutionFailed.selector);
        account.execute(address(reverter), 0, "");
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(account).balance, 1 ether);
    }

    // ── validate ─────────────────────────────────────────────────────
    // Note: validate() relies on EIP-8141 opcodes (TXPARAM, APPROVE)
    // which are not available in standard forge test EVM. Full validation
    // testing requires the custom geth devnet (see devnet/send_frame_tx.ts).

    function test_validate_revertsIfNotEntryPoint() public {
        vm.expectRevert(Simple8141Account.InvalidCaller.selector);
        account.validate(27, bytes32(0), bytes32(0), 2);
    }
}

// ── Helper contracts ────────────────────────────────────────────────

contract Counter {
    uint256 public count;
    function increment() external {
        count++;
    }
}

contract Reverter {
    fallback() external payable {
        revert("always reverts");
    }
}
