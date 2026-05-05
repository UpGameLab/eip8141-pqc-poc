// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    EmbeddedFalcon8141Account,
    EmbeddedFalcon8141AccountFactory
} from "../src/example/falcon/EmbeddedFalcon8141Account.sol";

contract EmbeddedFalcon8141AccountTest is Test {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;
    address internal constant H2P_PRECOMPILE = address(0xFA01);
    address internal constant CORE_PRECOMPILE = address(0xFA02);

    EmbeddedFalcon8141AccountFactory factory;
    EmbeddedFalcon8141Account account;
    bytes pk;

    function setUp() public {
        factory = new EmbeddedFalcon8141AccountFactory();
        pk = _samplePublicKey();

        account =
            factory.deploy(pk, H2P_PRECOMPILE, CORE_PRECOMPILE, EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG);
    }

    function test_factoryDeploysInitializedAccount() public view {
        assertTrue(account.initialized());
        assertEq(account.hashToPointPrecompile(), H2P_PRECOMPILE);
        assertEq(account.falconCorePrecompile(), CORE_PRECOMPILE);
        assertEq(uint8(account.hashToPointMode()), uint8(EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG));
        assertEq(account.algType(), account.ALG_TYPE_KECCAK_PRNG());
    }

    function test_publicKeyReadsOwnRuntimeSuffix() public view {
        assertEq(account.publicKey(), pk);
        assertEq(account.publicKeyHash(), keccak256(pk));

        bytes memory code = address(account).code;
        uint256 offset = code.length - pk.length;
        assertEq(account.publicKeyOffset(), offset);
        assertEq(_slice(code, offset, pk.length), pk);
    }

    function test_falconSignerUsesAlgTypePrefixedEmbeddedKey() public view {
        assertEq(account.falconSigner(), address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFB), pk))))));
    }

    function test_factorySupportsShake256Mode() public {
        EmbeddedFalcon8141Account shakeAccount =
            factory.deploy(pk, H2P_PRECOMPILE, CORE_PRECOMPILE, EmbeddedFalcon8141Account.HashToPointMode.SHAKE256);

        assertEq(shakeAccount.algType(), shakeAccount.ALG_TYPE_SHAKE256());
        assertEq(shakeAccount.falconSigner(), address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFA), pk))))));
    }

    function test_factoryRevertsWrongPublicKeyLength() public {
        vm.expectRevert(EmbeddedFalcon8141AccountFactory.InvalidPublicKeyLength.selector);
        factory.deploy(
            hex"1234", H2P_PRECOMPILE, CORE_PRECOMPILE, EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG
        );
    }

    function test_factoryRevertsZeroPrecompile() public {
        vm.expectRevert(EmbeddedFalcon8141AccountFactory.InvalidPrecompileConfig.selector);
        factory.deploy(pk, address(0), CORE_PRECOMPILE, EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG);

        vm.expectRevert(EmbeddedFalcon8141AccountFactory.InvalidPrecompileConfig.selector);
        factory.deploy(pk, H2P_PRECOMPILE, address(0), EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG);
    }

    function test_directDeploymentReverts() public {
        vm.expectRevert(EmbeddedFalcon8141Account.DirectDeploymentUnsupported.selector);
        new EmbeddedFalcon8141Account();
    }

    function test_initializeCannotRunTwice() public {
        vm.expectRevert(EmbeddedFalcon8141Account.AlreadyInitialized.selector);
        account.initialize(
            H2P_PRECOMPILE, CORE_PRECOMPILE, EmbeddedFalcon8141Account.HashToPointMode.KECCAK_PRNG, keccak256(pk)
        );
    }

    function test_validationDigestBindsScopeAndSigHash() public view {
        bytes32 sigHash = keccak256("frame tx");

        bytes32 executionDigest = account.validationDigest(sigHash, account.APPROVE_EXECUTION());
        bytes32 bothDigest = account.validationDigest(sigHash, account.APPROVE_PAYMENT_AND_EXECUTION());
        bytes32 otherTxDigest = account.validationDigest(keccak256("other frame tx"), account.APPROVE_EXECUTION());

        assertTrue(executionDigest != bothDigest);
        assertTrue(executionDigest != otherTxDigest);
    }

    function test_validationDigestRevertsInvalidScope() public {
        vm.expectRevert(EmbeddedFalcon8141Account.InvalidApprovalScope.selector);
        account.validationDigest(bytes32(0), 0);

        vm.expectRevert(EmbeddedFalcon8141Account.InvalidApprovalScope.selector);
        account.validationDigest(bytes32(0), 4);
    }

    function test_validateRevertsIfNotEntryPoint() public {
        vm.expectRevert(EmbeddedFalcon8141Account.InvalidCaller.selector);
        account.validate("", account.APPROVE_PAYMENT_AND_EXECUTION());
    }

    function test_validateRevertsInvalidSignatureLengthBeforeFrameOpcodes() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(EmbeddedFalcon8141Account.InvalidSignatureLength.selector);
        account.validate(hex"1234", account.APPROVE_PAYMENT_AND_EXECUTION());
    }

    function test_executeRevertsIfNotSelf() public {
        vm.expectRevert(EmbeddedFalcon8141Account.InvalidCaller.selector);
        account.execute(address(0xBEEF), 0, "");
    }

    function test_executeTransfersEth() public {
        vm.deal(address(account), 1 ether);

        vm.prank(address(account));
        account.execute(address(0xBEEF), 0.25 ether, "");

        assertEq(address(0xBEEF).balance, 0.25 ether);
    }

    function test_executeCallsTarget() public {
        EmbeddedCounter counter = new EmbeddedCounter();

        vm.prank(address(account));
        account.execute(address(counter), 0, abi.encodeCall(EmbeddedCounter.increment, ()));

        assertEq(counter.count(), 1);
    }

    function test_executeRevertsOnFailedCall() public {
        EmbeddedReverter reverter = new EmbeddedReverter();

        vm.prank(address(account));
        vm.expectRevert(EmbeddedFalcon8141Account.ExecutionFailed.selector);
        account.execute(address(reverter), 0, "");
    }

    function test_receiveEther() public {
        vm.deal(address(this), 1 ether);

        (bool ok,) = address(account).call{value: 1 ether}("");

        assertTrue(ok);
        assertEq(address(account).balance, 1 ether);
    }

    function _samplePublicKey() internal pure returns (bytes memory sample) {
        sample = new bytes(896);
        for (uint256 i; i < sample.length; ++i) {
            sample[i] = bytes1(uint8(i));
        }
    }

    function _slice(bytes memory data, uint256 offset, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i; i < length; ++i) {
            out[i] = data[offset + i];
        }
    }
}

contract EmbeddedCounter {
    uint256 public count;

    function increment() external {
        count++;
    }
}

contract EmbeddedReverter {
    fallback() external payable {
        revert("always reverts");
    }
}
