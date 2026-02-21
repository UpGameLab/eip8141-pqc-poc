// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CoinbaseSmartWallet8141} from "../src/example/CoinbaseSmartWallet8141.sol";

contract CoinbaseSmartWallet8141Test is Test {
    CoinbaseSmartWallet8141 wallet;

    uint256 owner1Pk = 0x1111;
    uint256 owner2Pk = 0x2222;

    address owner1 = vm.addr(owner1Pk);
    address owner2 = vm.addr(owner2Pk);
    address owner3 = address(0x3333);

    function setUp() public {
        bytes[] memory owners = new bytes[](2);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(owner2);

        wallet = new CoinbaseSmartWallet8141(owners);
        vm.deal(address(wallet), 10 ether);
    }

    function test_Initialize() public view {
        assertEq(wallet.nextOwnerIndex(), 2);
        assertTrue(wallet.isOwnerAddress(owner1));
        assertTrue(wallet.isOwnerAddress(owner2));
        assertFalse(wallet.isOwnerAddress(owner3));
    }

    function test_OwnerAtIndex() public view {
        bytes memory owner1Bytes = wallet.ownerAtIndex(0);
        assertEq(owner1Bytes, abi.encode(owner1));

        bytes memory owner2Bytes = wallet.ownerAtIndex(1);
        assertEq(owner2Bytes, abi.encode(owner2));
    }

    // NOTE: addOwnerAddress, addOwnerPublicKey, removeOwnerAtIndex, removeLastOwner
    // require EIP-8141 TXPARAMLOAD opcode (via onlyInSenderFrame modifier) which is
    // not available in Forge's revm. These are tested via E2E on the custom geth devnet.

    function test_WebAuthnOwner() public {
        // Test adding WebAuthn public key as owner
        uint256 x = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        uint256 y = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);

        CoinbaseSmartWallet8141 passkeyWallet = new CoinbaseSmartWallet8141(owners);

        // Verify WebAuthn owner was added correctly
        assertEq(passkeyWallet.nextOwnerIndex(), 1);
        assertTrue(passkeyWallet.isOwnerPublicKey(x, y));
        assertFalse(passkeyWallet.isOwnerPublicKey(x + 1, y));

        bytes memory ownerBytes = passkeyWallet.ownerAtIndex(0);
        assertEq(ownerBytes, abi.encode(x, y));
        assertEq(ownerBytes.length, 64);
    }

    function test_MixedOwners() public {
        // Test wallet with both Ethereum address and WebAuthn public key owners
        uint256 x = 0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd;
        uint256 y = 0xeeff0011eeff0011eeff0011eeff0011eeff0011eeff0011eeff0011eeff0011;

        bytes[] memory owners = new bytes[](3);
        owners[0] = abi.encode(owner1);
        owners[1] = abi.encode(x, y);
        owners[2] = abi.encode(owner2);

        CoinbaseSmartWallet8141 mixedWallet = new CoinbaseSmartWallet8141(owners);

        // Verify all owners
        assertEq(mixedWallet.nextOwnerIndex(), 3);
        assertTrue(mixedWallet.isOwnerAddress(owner1));
        assertTrue(mixedWallet.isOwnerPublicKey(x, y));
        assertTrue(mixedWallet.isOwnerAddress(owner2));

        // Verify owner bytes
        assertEq(mixedWallet.ownerAtIndex(0), abi.encode(owner1));
        assertEq(mixedWallet.ownerAtIndex(1), abi.encode(x, y));
        assertEq(mixedWallet.ownerAtIndex(2), abi.encode(owner2));
    }
}
