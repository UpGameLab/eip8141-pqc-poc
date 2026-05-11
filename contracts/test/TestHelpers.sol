// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

abstract contract LocalTest is Test {
    function makeAddr(string memory name) internal returns (address account) {
        (account,) = makeAddrAndKey(name);
    }

    function makeAddrAndKey(string memory name) internal returns (address account, uint256 privateKey) {
        privateKey = uint256(keccak256(abi.encodePacked(name)));
        account = vm.addr(privateKey);
        vm.label(account, name);
    }
}
