// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Kernel8141} from "../src/example/Kernel8141.sol";
import {ECDSAValidator} from "../src/example/validators/ECDSAValidator.sol";
import {IValidator8141} from "../src/interfaces/IValidator8141.sol";

contract Kernel8141Test is Test {
    Kernel8141 kernel;
    ECDSAValidator ecdsaValidator;
    address owner;
    uint256 ownerKey;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        ecdsaValidator = new ECDSAValidator();
        kernel = new Kernel8141(ecdsaValidator, abi.encode(owner));
    }

    // ── Initialization ───────────────────────────────────────────────

    function test_initialized() public view {
        assertTrue(kernel.initialized());
    }

    function test_rootValidator() public view {
        assertEq(address(kernel.rootValidator()), address(ecdsaValidator));
    }

    function test_validatorInstalled() public view {
        assertTrue(kernel.isValidatorInstalled(ecdsaValidator));
    }

    function test_ecdsaValidatorOwnerSet() public view {
        assertEq(ecdsaValidator.owners(address(kernel)), owner);
    }

    function test_initialize_revertsIfAlreadyInitialized() public {
        vm.expectRevert(Kernel8141.AlreadyInitialized.selector);
        kernel.initialize(ecdsaValidator, abi.encode(owner));
    }

    // ── execute ──────────────────────────────────────────────────────

    function test_execute_revertsIfNotSelf() public {
        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.execute(address(0xdead), 0, "");
    }

    function test_execute_sendsEth() public {
        vm.deal(address(kernel), 1 ether);
        address target = address(0xdead);

        vm.prank(address(kernel));
        kernel.execute(target, 0.5 ether, "");

        assertEq(target.balance, 0.5 ether);
    }

    function test_execute_callWithData() public {
        Counter counter = new Counter();

        vm.prank(address(kernel));
        kernel.execute(
            address(counter),
            0,
            abi.encodeWithSelector(Counter.increment.selector)
        );

        assertEq(counter.count(), 1);
    }

    function test_execute_revertsOnFailedCall() public {
        Reverter reverter = new Reverter();

        vm.prank(address(kernel));
        vm.expectRevert(Kernel8141.ExecutionFailed.selector);
        kernel.execute(address(reverter), 0, abi.encodeWithSelector(Reverter.fail.selector));
    }

    // ── executeBatch ─────────────────────────────────────────────────

    function test_executeBatch_revertsIfNotSelf() public {
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory datas = new bytes[](0);

        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.executeBatch(targets, values, datas);
    }

    function test_executeBatch_multipleCalls() public {
        Counter counter = new Counter();

        address[] memory targets = new address[](2);
        targets[0] = address(counter);
        targets[1] = address(counter);

        uint256[] memory values = new uint256[](2);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(Counter.increment.selector);
        datas[1] = abi.encodeWithSelector(Counter.increment.selector);

        vm.prank(address(kernel));
        kernel.executeBatch(targets, values, datas);

        assertEq(counter.count(), 2);
    }

    function test_executeBatch_revertsOnLengthMismatch() public {
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](1);

        vm.prank(address(kernel));
        vm.expectRevert(Kernel8141.BatchLengthMismatch.selector);
        kernel.executeBatch(targets, values, datas);
    }

    // ── Module Management ────────────────────────────────────────────

    function test_installValidator() public {
        ECDSAValidator newValidator = new ECDSAValidator();
        address newOwner = makeAddr("newOwner");

        vm.prank(address(kernel));
        kernel.installValidator(newValidator, abi.encode(newOwner));

        assertTrue(kernel.isValidatorInstalled(newValidator));
        assertEq(newValidator.owners(address(kernel)), newOwner);
    }

    function test_installValidator_revertsIfNotSelf() public {
        ECDSAValidator newValidator = new ECDSAValidator();
        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.installValidator(newValidator, abi.encode(owner));
    }

    function test_installValidator_revertsIfAlreadyInstalled() public {
        vm.prank(address(kernel));
        vm.expectRevert(Kernel8141.ValidatorAlreadyInstalled.selector);
        kernel.installValidator(ecdsaValidator, abi.encode(owner));
    }

    function test_uninstallValidator() public {
        ECDSAValidator extra = new ECDSAValidator();

        vm.prank(address(kernel));
        kernel.installValidator(extra, abi.encode(owner));
        assertTrue(kernel.isValidatorInstalled(extra));

        vm.prank(address(kernel));
        kernel.uninstallValidator(extra);
        assertFalse(kernel.isValidatorInstalled(extra));
    }

    function test_uninstallValidator_revertsForRoot() public {
        vm.prank(address(kernel));
        vm.expectRevert(Kernel8141.CannotRemoveRootValidator.selector);
        kernel.uninstallValidator(ecdsaValidator);
    }

    function test_uninstallValidator_revertsIfNotInstalled() public {
        ECDSAValidator unknown = new ECDSAValidator();
        vm.prank(address(kernel));
        vm.expectRevert(Kernel8141.ValidatorNotInstalled.selector);
        kernel.uninstallValidator(unknown);
    }

    function test_changeRootValidator() public {
        ECDSAValidator newValidator = new ECDSAValidator();
        address newOwner = makeAddr("newOwner");

        vm.prank(address(kernel));
        kernel.changeRootValidator(newValidator, abi.encode(newOwner));

        assertEq(address(kernel.rootValidator()), address(newValidator));
        assertTrue(kernel.isValidatorInstalled(newValidator));
        assertFalse(kernel.isValidatorInstalled(ecdsaValidator));
        assertEq(newValidator.owners(address(kernel)), newOwner);
    }

    function test_changeRootValidator_revertsIfNotSelf() public {
        ECDSAValidator newValidator = new ECDSAValidator();
        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.changeRootValidator(newValidator, abi.encode(owner));
    }

    // ── validate ─────────────────────────────────────────────────────
    // Note: validate() relies on EIP-8141 opcodes (TXPARAMLOAD, APPROVE)
    // Full validation testing requires the custom geth devnet.

    function test_validate_revertsIfNotEntryPoint() public {
        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.validate(hex"", 2);
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(kernel).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(kernel).balance, 1 ether);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

contract Counter {
    uint256 public count;
    function increment() external { count++; }
}

contract Reverter {
    function fail() external pure { revert("always reverts"); }
}
