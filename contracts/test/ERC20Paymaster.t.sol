// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20Paymaster} from "../src/ERC20Paymaster.sol";
import {BenchmarkToken} from "../src/BenchmarkToken.sol";

contract ERC20PaymasterTest is Test {
    ERC20Paymaster paymaster;
    BenchmarkToken token;
    address owner;
    address alice;

    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        paymaster = new ERC20Paymaster(owner);
        token = new BenchmarkToken();
    }

    // ── Constructor ──────────────────────────────────────────────────

    function test_owner() public view {
        assertEq(paymaster.owner(), owner);
    }

    // ── setExchangeRate ──────────────────────────────────────────────

    function test_setExchangeRate() public {
        vm.prank(owner);
        paymaster.setExchangeRate(address(token), 3000e6);
        assertEq(paymaster.exchangeRates(address(token)), 3000e6);
    }

    function test_setExchangeRate_disable() public {
        vm.startPrank(owner);
        paymaster.setExchangeRate(address(token), 3000e6);
        paymaster.setExchangeRate(address(token), 0);
        vm.stopPrank();
        assertEq(paymaster.exchangeRates(address(token)), 0);
    }

    function test_setExchangeRate_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(ERC20Paymaster.NotOwner.selector);
        paymaster.setExchangeRate(address(token), 3000e6);
    }

    // ── validate ─────────────────────────────────────────────────────
    // Note: validate() relies on EIP-8141 opcodes (TXPARAM, APPROVE)
    // which are not available in standard forge test EVM. Full validation
    // testing requires the custom geth devnet.

    function test_validate_revertsIfNotEntryPoint() public {
        vm.expectRevert(ERC20Paymaster.InvalidCaller.selector);
        paymaster.validate();
    }

    // ── postOp ───────────────────────────────────────────────────────

    function test_postOp_revertsIfNotEntryPoint() public {
        vm.expectRevert(ERC20Paymaster.InvalidCaller.selector);
        paymaster.postOp(2);
    }

    // ── withdrawETH ──────────────────────────────────────────────────

    function test_withdrawETH() public {
        vm.deal(address(paymaster), 1 ether);

        vm.prank(owner);
        paymaster.withdrawETH(alice, 1 ether);

        assertEq(address(paymaster).balance, 0);
        assertEq(alice.balance, 1 ether);
    }

    function test_withdrawETH_revertsIfNotOwner() public {
        vm.deal(address(paymaster), 1 ether);

        vm.prank(alice);
        vm.expectRevert(ERC20Paymaster.NotOwner.selector);
        paymaster.withdrawETH(alice, 1 ether);
    }

    // ── withdrawToken ────────────────────────────────────────────────

    function test_withdrawToken() public {
        token.mint(address(paymaster), 1000e18);

        vm.prank(owner);
        paymaster.withdrawToken(address(token), alice, 1000e18);

        assertEq(token.balanceOf(address(paymaster)), 0);
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function test_withdrawToken_revertsIfNotOwner() public {
        token.mint(address(paymaster), 1000e18);

        vm.prank(alice);
        vm.expectRevert(ERC20Paymaster.NotOwner.selector);
        paymaster.withdrawToken(address(token), alice, 1000e18);
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(paymaster).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(paymaster).balance, 1 ether);
    }
}
