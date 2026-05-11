// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LocalTest} from "./TestHelpers.sol";
import {Kernel8141} from "../src/example/kernel/Kernel8141.sol";
import {Kernel8141Factory} from "../src/example/kernel/factory/Kernel8141Factory.sol";
import {ECDSAValidator} from "../src/example/kernel/validators/ECDSAValidator.sol";
import {IValidator8141} from "../src/example/kernel/interfaces/IValidator8141.sol";
import {IHook8141} from "../src/example/kernel/interfaces/IHook8141.sol";
import {ValidatorLib8141} from "../src/example/kernel/utils/ValidatorLib8141.sol";
import {ValidationId, ExecMode} from "../src/example/kernel/types/Types8141.sol";

contract Kernel8141Test is LocalTest {
    Kernel8141 kernel;
    Kernel8141Factory factory;
    ECDSAValidator ecdsaValidator;
    address owner;
    uint256 ownerKey;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        ecdsaValidator = new ECDSAValidator();

        // Deploy implementation + factory
        Kernel8141 impl = new Kernel8141();
        factory = new Kernel8141Factory(address(impl));

        // Create proxy via factory
        ValidationId rootVId = ValidatorLib8141.validatorToIdentifier(IValidator8141(address(ecdsaValidator)));
        bytes memory initData = abi.encodeCall(
            Kernel8141.initialize,
            (
                rootVId,
                IHook8141(address(1)), // HOOK_INSTALLED sentinel
                abi.encodePacked(owner),
                "",
                new bytes[](0)
            )
        );
        address account = factory.createAccount(initData, bytes32(0));
        kernel = Kernel8141(payable(account));
    }

    // ── Initialization ───────────────────────────────────────────────

    function test_initialize_setsRootValidator() public {
        assertTrue(kernel.isModuleInstalled(1, address(ecdsaValidator), ""));
    }

    function test_initialize_setsOwner() public {
        (address storedOwner) = ecdsaValidator.ecdsaValidatorStorage(address(kernel));
        assertEq(storedOwner, owner);
    }

    function test_initialize_revertsIfAlreadyInitialized() public {
        ValidationId rootVId = ValidatorLib8141.validatorToIdentifier(IValidator8141(address(ecdsaValidator)));
        vm.expectRevert(Kernel8141.AlreadyInitialized.selector);
        kernel.initialize(rootVId, IHook8141(address(1)), abi.encodePacked(owner), "", new bytes[](0));
    }

    // ── Factory ──────────────────────────────────────────────────────

    function test_factory_deterministicAddress() public {
        ValidationId rootVId = ValidatorLib8141.validatorToIdentifier(IValidator8141(address(ecdsaValidator)));
        bytes memory initData = abi.encodeCall(
            Kernel8141.initialize,
            (rootVId, IHook8141(address(1)), abi.encodePacked(owner), "", new bytes[](0))
        );
        address predicted = factory.getAddress(initData, bytes32(0));
        assertEq(predicted, address(kernel));
    }

    function test_factory_createAccount_idempotent() public {
        ValidationId rootVId = ValidatorLib8141.validatorToIdentifier(IValidator8141(address(ecdsaValidator)));
        bytes memory initData = abi.encodeCall(
            Kernel8141.initialize,
            (rootVId, IHook8141(address(1)), abi.encodePacked(owner), "", new bytes[](0))
        );
        // Second call returns same address without reverting
        address account2 = factory.createAccount(initData, bytes32(0));
        assertEq(account2, address(kernel));
    }

    // ── Introspection ────────────────────────────────────────────────

    function test_accountId() public {
        assertEq(kernel.accountId(), "kernel8141.v0.1.0");
    }

    function test_supportsModule() public {
        assertTrue(kernel.supportsModule(1)); // VALIDATOR
        assertTrue(kernel.supportsModule(2)); // EXECUTOR
        assertTrue(kernel.supportsModule(3)); // FALLBACK
        assertTrue(kernel.supportsModule(4)); // HOOK
        assertTrue(kernel.supportsModule(5)); // POLICY
        assertTrue(kernel.supportsModule(6)); // SIGNER
        assertFalse(kernel.supportsModule(0));
        assertFalse(kernel.supportsModule(7));
    }

    function test_isModuleInstalled_validator() public {
        assertTrue(kernel.isModuleInstalled(1, address(ecdsaValidator), ""));
        assertFalse(kernel.isModuleInstalled(1, address(0xdead), ""));
    }

    // ── Token receivers ──────────────────────────────────────────────

    function test_onERC721Received() public {
        bytes4 result = kernel.onERC721Received(address(0), address(0), 0, "");
        assertEq(result, kernel.onERC721Received.selector);
    }

    function test_onERC1155Received() public {
        bytes4 result = kernel.onERC1155Received(address(0), address(0), 0, 0, "");
        assertEq(result, kernel.onERC1155Received.selector);
    }

    function test_onERC1155BatchReceived() public {
        bytes4 result =
            kernel.onERC1155BatchReceived(address(0), address(0), new uint256[](0), new uint256[](0), "");
        assertEq(result, kernel.onERC1155BatchReceived.selector);
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(kernel).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(kernel).balance, 1 ether);
    }

    // ── execute requires msg.sender == address(this) ─────────────────

    function test_execute_revertsIfNotSelf() public {
        vm.expectRevert(Kernel8141.InvalidCaller.selector);
        kernel.execute(ExecMode.wrap(bytes32(0)), "");
    }

    // ── Module management via onlySelfOrRoot ─────────────────────────
    // ECDSAValidator implements IHook8141 (isModuleType(4)=true),
    // so owner can call kernel directly via rootValidator hook gate.

    function test_installModule_revertsIfNotSelfOrOwner() public {
        ECDSAValidator newValidator = new ECDSAValidator();
        vm.prank(address(0xbad));
        vm.expectRevert(ECDSAValidator.NotOwner.selector);
        kernel.installModule(1, address(newValidator), abi.encodePacked(address(1), abi.encode("", "", "")));
    }

    // Note: validate/execute require EIP-8141 opcodes not available in Forge.
    // Full E2E testing requires the EIP-8141 devnet.
}
