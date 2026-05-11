// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LocalTest} from "./TestHelpers.sol";
import {ECDSAValidator} from "../src/example/kernel/validators/ECDSAValidator.sol";

contract ECDSAValidatorTest is LocalTest {
    ECDSAValidator validator;
    address owner;
    uint256 ownerKey;
    address account;

    function setUp() public {
        validator = new ECDSAValidator();
        (owner, ownerKey) = makeAddrAndKey("owner");
        account = makeAddr("account");

        // Install validator as the account (data = abi.encodePacked(address))
        vm.prank(account);
        validator.onInstall(abi.encodePacked(owner));
    }

    // ── onInstall / onUninstall ──────────────────────────────────────

    function test_onInstall_setsOwner() public {
        (address storedOwner) = validator.ecdsaValidatorStorage(account);
        assertEq(storedOwner, owner);
    }

    function test_onInstall_revertsZeroAddress() public {
        vm.prank(makeAddr("other"));
        vm.expectRevert(ECDSAValidator.InvalidOwner.selector);
        validator.onInstall(abi.encodePacked(address(0)));
    }

    function test_isInitialized() public {
        assertTrue(validator.isInitialized(account));
        assertFalse(validator.isInitialized(address(0xdead)));
    }

    function test_onUninstall_clearsOwner() public {
        vm.prank(account);
        validator.onUninstall("");
        (address storedOwner) = validator.ecdsaValidatorStorage(account);
        assertEq(storedOwner, address(0));
        assertFalse(validator.isInitialized(account));
    }

    // ── isModuleType ────────────────────────────────────────────────

    function test_isModuleType_validator() public {
        assertTrue(validator.isModuleType(1)); // MODULE_TYPE_VALIDATOR
    }

    function test_isModuleType_hook() public {
        assertTrue(validator.isModuleType(4)); // MODULE_TYPE_HOOK
    }

    function test_isModuleType_other() public {
        assertFalse(validator.isModuleType(2)); // MODULE_TYPE_EXECUTOR
        assertFalse(validator.isModuleType(3)); // MODULE_TYPE_FALLBACK
    }

    // ── validateSignature ────────────────────────────────────────────

    function test_validateSignature_valid() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = validator.validateSignature(account, hash, signature);
        assertTrue(valid);
    }

    function test_validateSignature_validWithEthSignedMessageHash() public {
        bytes32 hash = keccak256("test message");
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ethHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should also validate with eth_sign prefix
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

    function test_validateSignature_uninitializedAccount() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = validator.validateSignature(address(0xdead), hash, signature);
        assertFalse(valid);
    }

    // ── isValidSignatureWithSender (ERC-1271) ────────────────────────

    function test_isValidSignatureWithSender_valid() public {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(account);
        bytes4 result = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(result, bytes4(0x1626ba7e)); // ERC1271_MAGICVALUE
    }

    function test_isValidSignatureWithSender_invalid() public {
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(account);
        bytes4 result = validator.isValidSignatureWithSender(address(0), hash, sig);
        assertEq(result, bytes4(0xffffffff)); // ERC1271_INVALID
    }

    // ── preCheck (IHook8141 — owner gate) ────────────────────────────

    function test_preCheck_allowsOwner() public {
        vm.prank(account);
        validator.preCheck(owner, 0, "");
    }

    function test_preCheck_revertsNonOwner() public {
        vm.prank(account);
        vm.expectRevert(ECDSAValidator.NotOwner.selector);
        validator.preCheck(address(0xbad), 0, "");
    }

    // ── transferOwnership ────────────────────────────────────────────

    function test_transferOwnership() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(account);
        validator.transferOwnership(newOwner);

        (address storedOwner) = validator.ecdsaValidatorStorage(account);
        assertEq(storedOwner, newOwner);
    }

    function test_transferOwnership_revertsZeroAddress() public {
        vm.prank(account);
        vm.expectRevert(ECDSAValidator.InvalidOwner.selector);
        validator.transferOwnership(address(0));
    }
}
