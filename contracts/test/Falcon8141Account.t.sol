// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Falcon8141Account} from "../src/example/falcon/Falcon8141Account.sol";

contract Falcon8141AccountTest is Test {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;
    address internal constant H2P_PRECOMPILE = address(0xFA01);
    address internal constant CORE_PRECOMPILE = address(0xFA02);

    Falcon8141Account account;
    address pkContract;
    bytes pk;

    function setUp() public {
        pk = _samplePublicKey();
        pkContract = address(0xF000);
        _etchPublicKey(pkContract, pk);

        account = new Falcon8141Account(
            pkContract, H2P_PRECOMPILE, CORE_PRECOMPILE, Falcon8141Account.HashToPointMode.KECCAK_PRNG
        );
    }

    function test_constructorStoresConfig() public view {
        assertEq(account.publicKeyContract(), pkContract);
        assertEq(account.hashToPointPrecompile(), H2P_PRECOMPILE);
        assertEq(account.falconCorePrecompile(), CORE_PRECOMPILE);
        assertEq(uint8(account.hashToPointMode()), uint8(Falcon8141Account.HashToPointMode.KECCAK_PRNG));
        assertEq(account.algType(), account.ALG_TYPE_KECCAK_PRNG());
        assertEq(account.publicKeyHash(), keccak256(pk));
        assertEq(account.falconSigner(), address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFB), pk))))));
    }

    function test_publicKeyReadsDataContract() public view {
        assertEq(account.publicKey(), pk);
    }

    function test_constructorSupportsShake256Mode() public {
        Falcon8141Account shakeAccount = new Falcon8141Account(
            pkContract, H2P_PRECOMPILE, CORE_PRECOMPILE, Falcon8141Account.HashToPointMode.SHAKE256
        );

        assertEq(shakeAccount.algType(), shakeAccount.ALG_TYPE_SHAKE256());
        assertEq(shakeAccount.falconSigner(), address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFA), pk))))));
    }

    function test_constructorRevertsWrongPublicKeyContractSize() public {
        address badPkContract = address(0xF001);
        vm.etch(badPkContract, pk);

        vm.expectRevert(Falcon8141Account.InvalidPublicKeyContract.selector);
        new Falcon8141Account(
            badPkContract, H2P_PRECOMPILE, CORE_PRECOMPILE, Falcon8141Account.HashToPointMode.KECCAK_PRNG
        );
    }

    function test_constructorRevertsZeroPrecompile() public {
        vm.expectRevert(Falcon8141Account.InvalidPrecompileConfig.selector);
        new Falcon8141Account(pkContract, address(0), CORE_PRECOMPILE, Falcon8141Account.HashToPointMode.KECCAK_PRNG);

        vm.expectRevert(Falcon8141Account.InvalidPrecompileConfig.selector);
        new Falcon8141Account(pkContract, H2P_PRECOMPILE, address(0), Falcon8141Account.HashToPointMode.KECCAK_PRNG);
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
        vm.expectRevert(Falcon8141Account.InvalidApprovalScope.selector);
        account.validationDigest(bytes32(0), 0);

        vm.expectRevert(Falcon8141Account.InvalidApprovalScope.selector);
        account.validationDigest(bytes32(0), 4);
    }

    function test_validateRevertsIfNotEntryPoint() public {
        vm.expectRevert(Falcon8141Account.InvalidCaller.selector);
        account.validate("", account.APPROVE_PAYMENT_AND_EXECUTION());
    }

    function test_validateRevertsInvalidSignatureLengthBeforeFrameOpcodes() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(Falcon8141Account.InvalidSignatureLength.selector);
        account.validate(hex"1234", account.APPROVE_PAYMENT_AND_EXECUTION());
    }

    function test_executeRevertsIfNotSelf() public {
        vm.expectRevert(Falcon8141Account.InvalidCaller.selector);
        account.execute(address(0xBEEF), 0, "");
    }

    function test_executeTransfersEth() public {
        vm.deal(address(account), 1 ether);

        vm.prank(address(account));
        account.execute(address(0xBEEF), 0.25 ether, "");

        assertEq(address(0xBEEF).balance, 0.25 ether);
    }

    function test_executeCallsTarget() public {
        Counter counter = new Counter();

        vm.prank(address(account));
        account.execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));

        assertEq(counter.count(), 1);
    }

    function test_executeRevertsOnFailedCall() public {
        Reverter reverter = new Reverter();

        vm.prank(address(account));
        vm.expectRevert(Falcon8141Account.ExecutionFailed.selector);
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

    function _etchPublicKey(address target, bytes memory publicKey) internal {
        vm.etch(target, bytes.concat(hex"00", publicKey));
    }
}

contract Counter {
    uint256 public count;

    function increment() external {
        count++;
    }
}

contract Reverter {
    fallback() external payable {
        revert("always reverts");
    }
}
