// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IOracle} from "./IOracle.sol";

/// @title ManualOracle
/// @notice Owner-updatable price oracle.
/// @dev VERIFY-frame safe: does not use TIMESTAMP opcode.
///      Stores lastUpdated in storage (written during setPrice), read via SLOAD.
contract ManualOracle is IOracle {
    error NotOwner();
    error InvalidPrice();

    event PriceUpdated(int256 price);

    address public owner;
    int256 public price;
    uint256 public lastUpdated;

    constructor(int256 _price, address _owner) {
        if (_price <= 0) revert InvalidPrice();
        price = _price;
        lastUpdated = block.timestamp;
        owner = _owner;
    }

    function setPrice(int256 _price) external {
        if (msg.sender != owner) revert NotOwner();
        if (_price <= 0) revert InvalidPrice();
        price = _price;
        lastUpdated = block.timestamp;
        emit PriceUpdated(_price);
    }

    function decimals() external pure override returns (uint8) {
        return 8;
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (uint80(0), price, 0, lastUpdated, uint80(0));
    }
}
