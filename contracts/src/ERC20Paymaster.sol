// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "./FrameTxLib.sol";

/// @title ERC20Paymaster
/// @notice ERC-20 gas sponsor for EIP-8141 frame transactions.
///
/// @dev Allows users to pay gas fees with ERC-20 tokens instead of ETH.
///      The paymaster holds ETH to cover gas and receives ERC-20 tokens
///      as compensation from the transaction sender.
///
///      Frame transaction structure (5-frame):
///        Frame 0: VERIFY(sender, flags=2) → account.validate(v,r,s)     → APPROVE(execution)
///        Frame 1: VERIFY(paymaster)  → paymaster.validate()             → APPROVE(payment)
///        Frame 2: SENDER(erc20)      → token.transfer(paymaster, amount)
///        Frame 3: SENDER(account)    → account.execute(target, value, data)
///        Frame 4: DEFAULT(paymaster) → paymaster.postOp()
///
///      In Frame 1, the paymaster reads Frame 2's calldata via frameDataLoad()
///      to verify the ERC-20 transfer is valid before approving gas payment.
contract ERC20Paymaster {
    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;

    /// @dev ERC-20 transfer(address,uint256) selector.
    bytes4 internal constant TRANSFER_SELECTOR = 0xa9059cbb;

    address public owner;

    /// @notice Exchange rate per token: tokens per wei, scaled by 1e18.
    /// @dev A rate of 0 means the token is not accepted.
    ///      Example: if 1 ETH = 3000 USDC (6 decimals),
    ///      rate = 3000 * 1e6 * 1e18 / 1e18 = 3000e6.
    mapping(address token => uint256 rate) public exchangeRates;

    error InvalidCaller();
    error NotOwner();
    error InvalidTransferSelector();
    error InvalidRecipient();
    error TokenNotAccepted();
    error InsufficientPayment();
    error InsufficientTokenBalance();
    error TransferFrameFailed();
    error WithdrawFailed();

    constructor(address _owner) {
        owner = _owner;
    }

    // ─── VERIFY frame ─────────────────────────────────────────────────

    /// @notice Validation entry point, called in a VERIFY frame.
    /// @dev Reads the next frame's calldata to verify it is a valid
    ///      ERC-20 transfer to this contract with sufficient amount.
    ///      This function does NOT return — APPROVE terminates execution.
    function validate() external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();

        uint256 transferFrameIdx = FrameTxLib.currentFrameIndex() + 1;

        // 1. Verify selector is transfer(address,uint256)
        bytes4 selector = bytes4(FrameTxLib.frameDataLoad(transferFrameIdx, 0));
        if (selector != TRANSFER_SELECTOR) revert InvalidTransferSelector();

        // 2. Verify recipient is this contract
        address recipient = address(uint160(uint256(
            FrameTxLib.frameDataLoad(transferFrameIdx, 4)
        )));
        if (recipient != address(this)) revert InvalidRecipient();

        // 3. Verify token is accepted
        address token = FrameTxLib.frameTarget(transferFrameIdx);
        uint256 rate = exchangeRates[token];
        if (rate == 0) revert TokenNotAccepted();

        // 4. Verify amount covers gas cost
        uint256 amount = uint256(FrameTxLib.frameDataLoad(transferFrameIdx, 36));
        uint256 requiredAmount = FrameTxLib.maxCost() * rate / 1e18;
        if (amount < requiredAmount) revert InsufficientPayment();

        // 5. Verify sender has sufficient token balance
        address sender = FrameTxLib.txSender();
        (bool ok, bytes memory result) = token.staticcall(
            abi.encodeWithSelector(0x70a08231, sender) // balanceOf(address)
        );
        if (!ok || result.length < 32) revert InsufficientTokenBalance();
        uint256 balance = abi.decode(result, (uint256));
        if (balance < amount) revert InsufficientTokenBalance();

        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_PAYMENT);
    }

    // ─── DEFAULT frame (post-op) ──────────────────────────────────────

    /// @notice Post-operation hook, called in a DEFAULT frame after execution.
    /// @dev Verifies the ERC-20 transfer frame succeeded.
    /// @param transferFrameIdx The index of the ERC-20 transfer frame.
    function postOp(uint256 transferFrameIdx) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();

        uint8 status = FrameTxLib.frameStatus(transferFrameIdx);
        if (status != 1) revert TransferFrameFailed();
    }

    // ─── Admin ────────────────────────────────────────────────────────

    /// @notice Set the exchange rate for a token.
    /// @param token The ERC-20 token address.
    /// @param rate Tokens per wei, scaled by 1e18. Set to 0 to disable.
    function setExchangeRate(address token, uint256 rate) external {
        if (msg.sender != owner) revert NotOwner();
        exchangeRates[token] = rate;
    }

    /// @notice Withdraw ETH from the paymaster.
    function withdrawETH(address to, uint256 amount) external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
    }

    /// @notice Withdraw ERC-20 tokens from the paymaster.
    function withdrawToken(address token, address to, uint256 amount) external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok,) = token.call(
            abi.encodeWithSelector(TRANSFER_SELECTOR, to, amount)
        );
        if (!ok) revert WithdrawFailed();
    }

    receive() external payable {}
}
