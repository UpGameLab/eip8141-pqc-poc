// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IOracle} from "./IOracle.sol";

/// @title FixedOracle
/// @notice Immutable price oracle. Useful for stablecoins and testing.
/// @dev VERIFY-frame safe: does not use TIMESTAMP opcode.
///      Returns updatedAt=0 since the price is immutable and never stale.
contract FixedOracle is IOracle {
    int256 public immutable price;

    constructor(int256 _price) {
        price = _price;
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
        return (uint80(0), price, 0, 0, uint80(0));
    }
}
