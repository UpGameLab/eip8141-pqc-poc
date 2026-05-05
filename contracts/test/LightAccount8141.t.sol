// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {LightAccount8141} from "../src/example/light-account/LightAccount8141.sol";
import {LightAccountFactory8141} from "../src/example/light-account/LightAccountFactory8141.sol";

contract LightAccount8141Test is Test {
    LightAccount8141 impl;
    LightAccountFactory8141 factory;
    LightAccount8141 wallet;

    uint256 ownerPk = 0x1111;
    address ownerAddr = vm.addr(ownerPk);

    uint256 newOwnerPk = 0x2222;
    address newOwnerAddr = vm.addr(newOwnerPk);

    function setUp() public {
        impl = new LightAccount8141();
        factory = new LightAccountFactory8141(address(impl));
        wallet = factory.createAccount(ownerAddr, 0);
        vm.deal(address(wallet), 10 ether);
    }

    // ── Factory Tests ─────────────────────────────────────────────────

    function test_FactoryDeploy() public view {
        assertEq(wallet.owner(), ownerAddr);
        assertTrue(address(wallet).code.length > 0);
    }

    function test_FactoryDeterministicAddress() public view {
        address predicted = factory.getAddress(ownerAddr, 0);
        assertEq(predicted, address(wallet));
    }

    function test_FactoryIdempotent() public {
        LightAccount8141 wallet2 = factory.createAccount(ownerAddr, 0);
        assertEq(address(wallet2), address(wallet));
    }

    function test_FactoryDifferentSalt() public {
        LightAccount8141 wallet2 = factory.createAccount(ownerAddr, 1);
        assertTrue(address(wallet2) != address(wallet));
        assertEq(wallet2.owner(), ownerAddr);
    }

    function test_FactoryDifferentOwner() public {
        LightAccount8141 wallet2 = factory.createAccount(newOwnerAddr, 0);
        assertTrue(address(wallet2) != address(wallet));
        assertEq(wallet2.owner(), newOwnerAddr);
    }

    function test_FactoryRevertsZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(LightAccountFactory8141.InvalidOwner.selector, address(0)));
        factory.createAccount(address(0), 0);
    }

    function test_InitCodeHash() public view {
        bytes32 hash = factory.initCodeHash();
        assertTrue(hash != bytes32(0));
    }

    // ── Initialization Tests ──────────────────────────────────────────

    function test_ImplLocked() public {
        // Implementation's owner is address(1) sentinel
        assertEq(impl.owner(), address(1));

        // Cannot re-initialize
        vm.expectRevert(LightAccount8141.InvalidInitialization.selector);
        impl.initialize(ownerAddr);
    }

    function test_InitializeRevertsIfAlreadyInitialized() public {
        vm.expectRevert(LightAccount8141.InvalidInitialization.selector);
        wallet.initialize(newOwnerAddr);
    }

    // ── Owner Tests ───────────────────────────────────────────────────

    function test_Owner() public view {
        assertEq(wallet.owner(), ownerAddr);
    }

    function test_TransferOwnership() public {
        vm.prank(ownerAddr);
        wallet.transferOwnership(newOwnerAddr);
        assertEq(wallet.owner(), newOwnerAddr);
    }

    function test_TransferOwnershipEvent() public {
        vm.expectEmit(true, true, false, false);
        emit LightAccount8141.OwnershipTransferred(ownerAddr, newOwnerAddr);
        vm.prank(ownerAddr);
        wallet.transferOwnership(newOwnerAddr);
    }

    function test_TransferOwnershipRevertsZeroAddress() public {
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(LightAccount8141.InvalidOwner.selector, address(0)));
        wallet.transferOwnership(address(0));
    }

    function test_TransferOwnershipRevertsSelf() public {
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(LightAccount8141.InvalidOwner.selector, address(wallet)));
        wallet.transferOwnership(address(wallet));
    }

    function test_TransferOwnershipRevertsSameOwner() public {
        vm.prank(ownerAddr);
        vm.expectRevert(abi.encodeWithSelector(LightAccount8141.InvalidOwner.selector, ownerAddr));
        wallet.transferOwnership(ownerAddr);
    }

    function test_TransferOwnershipRevertsUnauthorized() public {
        vm.prank(newOwnerAddr);
        vm.expectRevert(abi.encodeWithSelector(LightAccount8141.NotAuthorized.selector, newOwnerAddr));
        wallet.transferOwnership(newOwnerAddr);
    }

    // ── Execution Tests ───────────────────────────────────────────────

    function test_ExecuteAsOwner() public {
        address target = address(0xBEEF);
        vm.prank(ownerAddr);
        wallet.execute(target, 1 ether, "");
        assertEq(target.balance, 1 ether);
    }

    function test_ExecuteRevertsUnauthorized() public {
        vm.prank(newOwnerAddr);
        vm.expectRevert(abi.encodeWithSelector(LightAccount8141.NotAuthorized.selector, newOwnerAddr));
        wallet.execute(address(0xBEEF), 1 ether, "");
    }

    function test_ExecuteBatchNoValue() public {
        address target1 = address(0xBEEF);
        address target2 = address(0xCAFE);

        address[] memory dest = new address[](2);
        dest[0] = target1;
        dest[1] = target2;
        bytes[] memory func = new bytes[](2);
        func[0] = "";
        func[1] = "";

        vm.prank(ownerAddr);
        wallet.executeBatch(dest, func);
    }

    function test_ExecuteBatchWithValue() public {
        address target1 = address(0xBEEF);
        address target2 = address(0xCAFE);

        address[] memory dest = new address[](2);
        dest[0] = target1;
        dest[1] = target2;
        uint256[] memory value = new uint256[](2);
        value[0] = 1 ether;
        value[1] = 2 ether;
        bytes[] memory func = new bytes[](2);
        func[0] = "";
        func[1] = "";

        vm.prank(ownerAddr);
        wallet.executeBatch(dest, value, func);
        assertEq(target1.balance, 1 ether);
        assertEq(target2.balance, 2 ether);
    }

    function test_ExecuteBatchLengthMismatch() public {
        address[] memory dest = new address[](2);
        bytes[] memory func = new bytes[](1);
        vm.prank(ownerAddr);
        vm.expectRevert(LightAccount8141.ArrayLengthMismatch.selector);
        wallet.executeBatch(dest, func);
    }

    // ── ERC-1271 Tests ────────────────────────────────────────────────

    function test_GetMessageHash() public view {
        bytes32 hash1 = wallet.getMessageHash(abi.encode(keccak256("test")));
        assertTrue(hash1 != bytes32(0));

        bytes32 hash2 = wallet.getMessageHash(abi.encode(keccak256("other")));
        assertTrue(hash1 != hash2);
    }

    function test_DomainSeparator() public view {
        bytes32 ds = wallet.domainSeparator();
        assertTrue(ds != bytes32(0));

        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("LightAccount"),
                keccak256("2"),
                block.chainid,
                address(wallet)
            )
        );
        assertEq(ds, expected);
    }

    function test_Eip712Domain() public view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,,
        ) = wallet.eip712Domain();

        assertEq(fields, hex"0f");
        assertEq(keccak256(bytes(name)), keccak256("LightAccount"));
        assertEq(keccak256(bytes(version)), keccak256("2"));
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(wallet));
    }

    function test_IsValidSignatureEOA() public {
        bytes32 hash = keccak256("test message");
        bytes32 replaySafe = wallet.getMessageHash(abi.encode(hash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafe);
        bytes memory sig = abi.encodePacked(uint8(0), r, s, v); // 0 = EOA type

        bytes4 result = wallet.isValidSignature(hash, sig);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_IsValidSignatureInvalid() public {
        bytes32 hash = keccak256("test message");
        bytes32 replaySafe = wallet.getMessageHash(abi.encode(hash));

        // Sign with wrong key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwnerPk, replaySafe);
        bytes memory sig = abi.encodePacked(uint8(0), r, s, v);

        bytes4 result = wallet.isValidSignature(hash, sig);
        assertEq(result, bytes4(0xffffffff));
    }

    // ── Proxy Tests ───────────────────────────────────────────────────

    function test_Implementation() public view {
        address implAddr = wallet.implementation();
        assertEq(implAddr, address(impl));
    }

    // NOTE: validate() requires EIP-8141 TXPARAM opcode which is not available
    // in Forge's revm. It is tested via E2E on the custom geth devnet.
}
