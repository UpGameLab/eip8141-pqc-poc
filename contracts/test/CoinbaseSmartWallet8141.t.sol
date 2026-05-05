// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CoinbaseSmartWallet8141} from "../src/example/coinbase-smart-wallet/CoinbaseSmartWallet8141.sol";
import {CoinbaseSmartWalletFactory8141} from "../src/example/coinbase-smart-wallet/CoinbaseSmartWalletFactory8141.sol";

contract CoinbaseSmartWallet8141Test is Test {
    CoinbaseSmartWallet8141 impl;
    CoinbaseSmartWalletFactory8141 factory;
    CoinbaseSmartWallet8141 wallet;

    uint256 owner1Pk = 0x1111;
    uint256 owner2Pk = 0x2222;

    address owner1 = vm.addr(owner1Pk);
    address owner2 = vm.addr(owner2Pk);
    address owner3 = address(0x3333);

    function setUp() public {
        impl = new CoinbaseSmartWallet8141();
        factory = new CoinbaseSmartWalletFactory8141(address(impl));

        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(owner2);

        wallet = factory.createAccount(owners, 0);
        vm.deal(address(wallet), 10 ether);
    }

    function test_Initialize() public view {
        assertEq(wallet.nextOwnerIndex(), 2);
        assertTrue(wallet.isOwnerAddress(owner1));
        assertTrue(wallet.isOwnerAddress(owner2));
        assertFalse(wallet.isOwnerAddress(owner3));
        assertEq(wallet.ownerCount(), 2);
        assertEq(wallet.removedOwnersCount(), 0);
    }

    function test_OwnerAtIndex() public view {
        bytes memory owner1Bytes = wallet.ownerAtIndex(0);
        assertEq(owner1Bytes, abi.encode(owner1));

        bytes memory owner2Bytes = wallet.ownerAtIndex(1);
        assertEq(owner2Bytes, abi.encode(owner2));
    }

    function test_FactoryDeterministicAddress() public view {
        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(owner2);

        address predicted = factory.getAddress(owners, 0);
        assertEq(predicted, address(wallet));
    }

    function test_FactoryIdempotent() public {
        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(owner2);

        CoinbaseSmartWallet8141 wallet2 = factory.createAccount(owners, 0);
        assertEq(address(wallet2), address(wallet));
    }

    function test_FactoryDifferentNonce() public {
        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(owner2);

        CoinbaseSmartWallet8141 wallet2 = factory.createAccount(owners, 1);
        assertTrue(address(wallet2) != address(wallet));
        assertTrue(wallet2.isOwnerAddress(owner1));
    }

    function test_ImplementationLocked() public view {
        // Implementation should have address(0) as owner (sentinel)
        assertTrue(impl.isOwnerAddress(address(0)));
    }

    function test_InitializeRevertsIfAlreadyInitialized() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner3);

        vm.expectRevert(CoinbaseSmartWallet8141.Initialized.selector);
        wallet.initialize(owners);
    }

    // NOTE: addOwnerAddress, addOwnerPublicKey, removeOwnerAtIndex, removeLastOwner,
    // validate, validateCrossChain, executeWithoutChainIdValidation
    // require EIP-8141 TXPARAM opcode (via onlySenderFrameOrOwner or VERIFY mode)
    // which is not available in Forge's revm. These are tested via E2E on the custom geth devnet.

    function test_WebAuthnOwner() public {
        // Test creating wallet with WebAuthn public key as owner
        bytes32 x = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 y = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);

        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);

        CoinbaseSmartWallet8141 passkeyWallet = factory.createAccount(owners, 99);

        // Verify WebAuthn owner was added correctly
        assertEq(passkeyWallet.nextOwnerIndex(), 1);
        assertTrue(passkeyWallet.isOwnerPublicKey(x, y));
        assertFalse(passkeyWallet.isOwnerPublicKey(bytes32(uint256(x) + 1), y));

        bytes memory ownerBytes = passkeyWallet.ownerAtIndex(0);
        assertEq(ownerBytes, abi.encode(x, y));
        assertEq(ownerBytes.length, 64);
        assertEq(passkeyWallet.ownerCount(), 1);
    }

    function test_MixedOwners() public {
        // Test wallet with both Ethereum address and WebAuthn public key owners
        bytes32 x = bytes32(0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd);
        bytes32 y = bytes32(0xeeff0011eeff0011eeff0011eeff0011eeff0011eeff0011eeff0011eeff0011);

        bytes[] memory owners = new bytes[](3);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(x, y);
        owners[2] = abi.encode(owner2);

        CoinbaseSmartWallet8141 mixedWallet = factory.createAccount(owners, 42);

        // Verify all owners
        assertEq(mixedWallet.nextOwnerIndex(), 3);
        assertTrue(mixedWallet.isOwnerAddress(owner1));
        assertTrue(mixedWallet.isOwnerPublicKey(x, y));
        assertTrue(mixedWallet.isOwnerAddress(owner2));
        assertEq(mixedWallet.ownerCount(), 3);

        // Verify owner bytes
        assertEq(mixedWallet.ownerAtIndex(0), abi.encode(owner1));
        assertEq(mixedWallet.ownerAtIndex(1), abi.encode(x, y));
        assertEq(mixedWallet.ownerAtIndex(2), abi.encode(owner2));
    }

    function test_CanSkipChainIdValidation() public view {
        assertTrue(wallet.canSkipChainIdValidation(wallet.addOwnerAddress.selector));
        assertTrue(wallet.canSkipChainIdValidation(wallet.addOwnerPublicKey.selector));
        assertTrue(wallet.canSkipChainIdValidation(wallet.removeOwnerAtIndex.selector));
        assertTrue(wallet.canSkipChainIdValidation(wallet.removeLastOwner.selector));
        assertFalse(wallet.canSkipChainIdValidation(wallet.execute.selector));
        assertFalse(wallet.canSkipChainIdValidation(wallet.executeBatch.selector));
    }

    function test_ERC1271ReplaySafeHash() public view {
        bytes32 hash = keccak256("test");
        bytes32 safe1 = wallet.replaySafeHash(hash);
        assertTrue(safe1 != bytes32(0));

        // Different hash → different replay-safe hash
        bytes32 safe2 = wallet.replaySafeHash(keccak256("other"));
        assertTrue(safe1 != safe2);
    }

    function test_DomainSeparator() public view {
        bytes32 ds = wallet.domainSeparator();
        assertTrue(ds != bytes32(0));
    }

    function test_Eip712Domain() public view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            ,
        ) = wallet.eip712Domain();

        assertEq(fields, hex"0f");
        assertEq(keccak256(bytes(name)), keccak256(bytes("Coinbase Smart Wallet")));
        assertEq(keccak256(bytes(version)), keccak256(bytes("1")));
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(wallet));
    }

    function test_InitCodeHash() public view {
        bytes32 hash = factory.initCodeHash();
        assertTrue(hash != bytes32(0));
    }
}
