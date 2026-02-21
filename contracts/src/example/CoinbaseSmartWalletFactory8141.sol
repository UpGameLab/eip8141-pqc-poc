// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {CoinbaseSmartWallet8141} from "./CoinbaseSmartWallet8141.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title CoinbaseSmartWalletFactory8141
/// @notice Factory for deterministic ERC-1967 proxy deployment of CoinbaseSmartWallet8141.
/// @dev Ported from CoinbaseSmartWalletFactory (ERC-4337) with identical API.
contract CoinbaseSmartWalletFactory8141 {
    /// @notice Address of the implementation used for new accounts.
    address public immutable implementation;

    event AccountCreated(address indexed account, bytes[] owners, uint256 nonce);

    error ImplementationUndeployed();
    error OwnerRequired();

    constructor(address implementation_) payable {
        if (implementation_.code.length == 0) revert ImplementationUndeployed();
        implementation = implementation_;
    }

    /// @notice Deploys and initializes a CoinbaseSmartWallet8141 proxy (or returns existing).
    function createAccount(bytes[] calldata owners, uint256 nonce)
        external
        payable
        returns (CoinbaseSmartWallet8141 account)
    {
        if (owners.length == 0) revert OwnerRequired();

        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(owners, nonce));

        account = CoinbaseSmartWallet8141(payable(accountAddress));

        if (!alreadyDeployed) {
            emit AccountCreated(address(account), owners, nonce);
            account.initialize(owners);
        }
    }

    /// @notice Returns the deterministic address for the given owners and nonce.
    function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967(implementation, _getSalt(owners, nonce), address(this));
    }

    /// @notice Returns the init code hash of the ERC-1967 proxy.
    function initCodeHash() public view returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(owners, nonce));
    }
}
