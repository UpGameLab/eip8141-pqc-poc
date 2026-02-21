// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ECDSAValidator} from "../src/example/validators/ECDSAValidator.sol";

contract ECDSAValidatorTest is Test {
    ECDSAValidator validator;
    address owner;
    uint256 ownerKey;
    address account;

    function setUp() public {
        validator = new ECDSAValidator();
        (owner, ownerKey) = makeAddrAndKey("owner");
        account = makeAddr("account");

        // Install validator as the account
        vm.prank(account);
        validator.onInstall(abi.encode(owner));
    }

    // ── onInstall / onUninstall ──────────────────────────────────────

    function test_onInstall_setsOwner() public view {
        assertEq(validator.owners(account), owner);
    }

    function test_onInstall_revertsZeroAddress() public {
        vm.prank(makeAddr("other"));
        vm.expectRevert(ECDSAValidator.InvalidOwner.selector);
        validator.onInstall(abi.encode(address(0)));
    }

    function test_isInitialized() public view {
        assertTrue(validator.isInitialized(account));
        assertFalse(validator.isInitialized(address(0xdead)));
    }

    function test_onUninstall_clearsOwner() public {
        vm.prank(account);
        validator.onUninstall();
        assertEq(validator.owners(account), address(0));
        assertFalse(validator.isInitialized(account));
    }

    // ── validateSignature ────────────────────────────────────────────

    function test_validateSignature_valid() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = validator.validateSignature(account, hash, signature);
        assertTrue(valid);
    }

    function test_validateSignature_wrongSigner() public {
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = validator.validateSignature(account, hash, signature);
        assertFalse(valid);
    }

    function test_validateSignature_invalidLength() public {
        bytes32 hash = keccak256("test message");
        bytes memory signature = hex"0011223344"; // 5 bytes, not 65

        bool valid = validator.validateSignature(account, hash, signature);
        assertFalse(valid);
    }

    function test_validateSignature_uninitializedAccount() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = validator.validateSignature(address(0xdead), hash, signature);
        assertFalse(valid);
    }

    function test_validateSignature_normalizedV() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        // Pass v as 0 or 1 (pre-EIP-155), should be normalized to 27/28
        uint8 rawV = v - 27;
        bytes memory signature = abi.encodePacked(r, s, rawV);

        bool valid = validator.validateSignature(account, hash, signature);
        assertTrue(valid);
    }

    // ── transferOwnership ────────────────────────────────────────────

    function test_transferOwnership() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(account);
        validator.transferOwnership(newOwner);

        assertEq(validator.owners(account), newOwner);
    }

    function test_transferOwnership_revertsZeroAddress() public {
        vm.prank(account);
        vm.expectRevert(ECDSAValidator.InvalidOwner.selector);
        validator.transferOwnership(address(0));
    }
}
