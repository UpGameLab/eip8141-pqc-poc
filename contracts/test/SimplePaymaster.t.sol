// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SimplePaymaster} from "../src/SimplePaymaster.sol";

contract SimplePaymasterTest is Test {
    SimplePaymaster paymaster;
    address paymasterSigner;

    function setUp() public {
        paymasterSigner = makeAddr("paymasterSigner");
        paymaster = new SimplePaymaster(paymasterSigner);
    }

    // ── Constructor ──────────────────────────────────────────────────

    function test_signer() public view {
        assertEq(paymaster.signer(), paymasterSigner);
    }

    // ── validate ─────────────────────────────────────────────────────
    // Note: validate() relies on EIP-8141 opcodes (TXPARAM, APPROVE)
    // which are not available in standard forge test EVM. Full validation
    // testing requires the custom geth devnet.

    function test_validate_revertsIfNotEntryPoint() public {
        bytes memory sig = new bytes(65);
        vm.expectRevert(SimplePaymaster.InvalidCaller.selector);
        paymaster.validate(sig);
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(paymaster).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(paymaster).balance, 1 ether);
    }
}
