// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FrameTxLib} from "./FrameTxLib.sol";
import {IOracle} from "./oracles/IOracle.sol";

/// @title ERC20PaymasterV8141
/// @notice Oracle-based ERC-20 gas sponsor for EIP-8141 frame transactions.
///
/// @dev Port of Pimlico's ERC20PaymasterV07 to EIP-8141. Uses Chainlink-compatible
///      oracles for token pricing instead of manual exchange rates.
///
///      Frame transaction structure (5-frame):
///        Frame 0: VERIFY(sender)     → account.validate(v,r,s, scope=0)     → APPROVE(execution)
///        Frame 1: VERIFY(paymaster)  → paymaster.validate()                  → APPROVE(payment)
///        Frame 2: SENDER(erc20)      → token.transfer(paymaster, amount)
///        Frame 3: SENDER(account)    → account.execute(target, value, data)
///        Frame 4: DEFAULT(paymaster) → paymaster.postOp(2)
///
///      STO-021 constraint: VERIFY frames cannot read scalar storage slots from
///      external contracts. Oracle prices are pre-computed via updateExchangeRate()
///      and stored in a mapping (STO-021 safe). The VERIFY frame only reads from
///      the mapping — no oracle calls, no scalar SLOAD.
///
///      Key differences from V07:
///        - No refund: EIP-8141 has no `actualGasCost` in postOp, so user pays maxCost-based amount
///        - No guarantor: VERIFY frames are read-only, can't pull tokens from third party
///        - Oracle pricing is cached: admin calls updateExchangeRate() to refresh prices
///        - Token limit mode available via validateWithLimit()
contract ERC20PaymasterV8141 {
    // ─── Constants ──────────────────────────────────────────────────

    address internal constant ENTRY_POINT = 0x00000000000000000000000000000000000000AA;
    bytes4 internal constant TRANSFER_SELECTOR = 0xa9059cbb;
    uint256 public constant PRICE_DENOMINATOR = 1e6;

    // ─── Immutables ─────────────────────────────────────────────────

    /// @notice The accepted ERC-20 token address.
    address public immutable token;

    /// @notice Pre-computed 10 ** token.decimals() for price math.
    uint256 public immutable tokenDecimals;

    /// @notice Oracle for TOKEN/USD price (8 decimals).
    IOracle public immutable tokenOracle;

    /// @notice Oracle for native asset (ETH)/USD price (8 decimals).
    IOracle public immutable nativeAssetOracle;

    /// @notice Maximum age of oracle data in seconds.
    uint32 public immutable stalenessThreshold;

    /// @notice Ceiling for priceMarkup. Owner can never exceed this.
    uint32 public immutable priceMarkupLimit;

    // ─── Mutable state ──────────────────────────────────────────────

    // NOTE: owner and priceMarkup (slot 0) are NEVER read during VERIFY frames.
    //       Only exchangeRates (mapping, STO-021 safe) is read during VERIFY.

    /// @notice Contract owner.
    address public owner;

    /// @notice Price markup (1e6 = 100%, 1.1e6 = 110%).
    uint32 public priceMarkup;

    /// @notice Cached exchange rate: tokens per wei, scaled by 1e18.
    /// @dev Pre-computed from oracles via updateExchangeRate(), includes markup.
    ///      VERIFY frames read only this mapping (STO-021 compliant).
    mapping(address => uint256) public exchangeRates;

    // ─── Errors ─────────────────────────────────────────────────────

    error InvalidCaller();
    error NotOwner();
    error InvalidTransferSelector();
    error InvalidRecipient();
    error TokenNotAccepted();
    error InsufficientPayment();
    error InsufficientTokenBalance();
    error TokenAmountTooHigh();
    error TokenLimitZero();
    error TransferFrameFailed();
    error WithdrawFailed();
    error OraclePriceNotPositive();
    error OraclePriceStale();
    error OracleDecimalsInvalid();
    error PriceMarkupTooLow();
    error PriceMarkupTooHigh();

    // ─── Events ─────────────────────────────────────────────────────

    event MarkupUpdated(uint32 priceMarkup);
    event ExchangeRateUpdated(address indexed token, uint256 rate);

    // ─── Constructor ────────────────────────────────────────────────

    constructor(
        address _token,
        IOracle _tokenOracle,
        IOracle _nativeAssetOracle,
        uint32 _stalenessThreshold,
        address _owner,
        uint32 _priceMarkupLimit,
        uint32 _priceMarkup
    ) {
        if (_tokenOracle.decimals() != 8 || _nativeAssetOracle.decimals() != 8) {
            revert OracleDecimalsInvalid();
        }
        if (_priceMarkup < 1e6) revert PriceMarkupTooLow();
        if (_priceMarkup > _priceMarkupLimit) revert PriceMarkupTooHigh();

        token = _token;
        tokenOracle = _tokenOracle;
        nativeAssetOracle = _nativeAssetOracle;
        stalenessThreshold = _stalenessThreshold;
        priceMarkupLimit = _priceMarkupLimit;
        priceMarkup = _priceMarkup;
        owner = _owner;

        // Query token decimals
        (bool ok, bytes memory result) = _token.staticcall(
            abi.encodeWithSelector(0x313ce567)
        );
        require(ok && result.length >= 32, "decimals() failed");
        uint8 dec = abi.decode(result, (uint8));
        uint256 tokenDec = 10 ** uint256(dec);
        tokenDecimals = tokenDec;

        // Compute and store initial exchange rate from oracles
        (, int256 tokenPrice,,,) = _tokenOracle.latestRoundData();
        (, int256 nativePrice,,,) = _nativeAssetOracle.latestRoundData();
        require(tokenPrice > 0 && nativePrice > 0, "invalid oracle price");
        exchangeRates[_token] = uint256(nativePrice) * tokenDec * _priceMarkup
            / (uint256(tokenPrice) * PRICE_DENOMINATOR);
    }

    // ─── VERIFY frame ───────────────────────────────────────────────

    /// @notice Validation entry point (mode 0: no token limit).
    function validate() external view {
        _validate(type(uint256).max);
    }

    /// @notice Validation entry point (mode 1: with token limit).
    /// @param tokenLimit Maximum token amount the sender is willing to pay.
    function validateWithLimit(uint256 tokenLimit) external view {
        if (tokenLimit == 0) revert TokenLimitZero();
        _validate(tokenLimit);
    }

    /// @dev VERIFY-frame safe: only reads immutables and mapping slots (no scalar SLOAD, no oracle calls).
    function _validate(uint256 tokenLimit) internal view {
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

        // 3. Verify token is the accepted token
        address frameToken = FrameTxLib.frameTarget(transferFrameIdx);
        if (frameToken != token) revert TokenNotAccepted();

        // 4. Read cached exchange rate from mapping (STO-021 safe)
        uint256 rate = exchangeRates[frameToken];
        if (rate == 0) revert TokenNotAccepted();

        // 5. Calculate required token amount
        uint256 requiredAmount = FrameTxLib.maxCost() * rate / 1e18;

        // 6. Verify transfer amount
        uint256 amount = uint256(FrameTxLib.frameDataLoad(transferFrameIdx, 36));
        if (amount < requiredAmount) revert InsufficientPayment();
        if (amount > tokenLimit) revert TokenAmountTooHigh();

        // 7. Verify sender has sufficient token balance
        address sender = FrameTxLib.txSender();
        (bool ok, bytes memory result) = frameToken.staticcall(
            abi.encodeWithSelector(0x70a08231, sender) // balanceOf(address)
        );
        if (!ok || result.length < 32) revert InsufficientTokenBalance();
        uint256 balance = abi.decode(result, (uint256));
        if (balance < amount) revert InsufficientTokenBalance();

        FrameTxLib.approveEmpty(FrameTxLib.SCOPE_PAYMENT);
    }

    // ─── DEFAULT frame (post-op) ────────────────────────────────────

    /// @notice Post-operation hook. Verifies the ERC-20 transfer succeeded.
    /// @param transferFrameIdx The index of the ERC-20 transfer frame.
    function postOp(uint256 transferFrameIdx) external view {
        if (msg.sender != ENTRY_POINT) revert InvalidCaller();

        uint8 status = FrameTxLib.frameStatus(transferFrameIdx);
        if (status != 1) revert TransferFrameFailed();
    }

    // ─── Price ──────────────────────────────────────────────────────

    /// @notice Get the current token price per native asset unit from oracles.
    /// @dev NOT for VERIFY frame use — reads from oracles (triggers external SLOAD).
    ///      Use exchangeRates(token) for the VERIFY-time cached rate.
    /// @return price Amount of token base units equivalent to 1e18 wei (no markup).
    function getPrice() public view returns (uint192) {
        uint192 tokenPrice = _fetchPrice(tokenOracle);
        uint192 nativeAssetPrice = _fetchPrice(nativeAssetOracle);
        return nativeAssetPrice * uint192(tokenDecimals) / tokenPrice;
    }

    /// @notice Get the required token amount for a given gas cost using the cached rate.
    /// @param gasCostWei Gas cost in wei.
    /// @return tokenAmount Required token amount (matches what VERIFY uses).
    function getTokenAmount(uint256 gasCostWei) external view returns (uint256) {
        uint256 rate = exchangeRates[token];
        return gasCostWei * rate / 1e18;
    }

    /// @notice Check oracle staleness (off-chain / admin use only, NOT for VERIFY frames).
    /// @dev Uses TIMESTAMP opcode — cannot be called from VERIFY frames.
    function checkOracleFreshness() external view {
        (, , , uint256 tokenUpdatedAt, ) = tokenOracle.latestRoundData();
        (, , , uint256 nativeUpdatedAt, ) = nativeAssetOracle.latestRoundData();
        if (block.timestamp > stalenessThreshold) {
            if (tokenUpdatedAt < block.timestamp - stalenessThreshold) revert OraclePriceStale();
            if (nativeUpdatedAt < block.timestamp - stalenessThreshold) revert OraclePriceStale();
        }
    }

    /// @dev Fetch price from an oracle and validate it. NOT for VERIFY frame use.
    function _fetchPrice(IOracle oracle) internal view returns (uint192) {
        (, int256 answer,,,) = oracle.latestRoundData();
        if (answer <= 0) revert OraclePriceNotPositive();
        return uint192(int192(answer));
    }

    // ─── Admin ──────────────────────────────────────────────────────

    /// @notice Update the cached exchange rate from oracles (includes current markup).
    /// @dev Reads oracle prices and computes:
    ///      rate = nativePrice * tokenDecimals * priceMarkup / (tokenPrice * PRICE_DENOMINATOR)
    function updateExchangeRate() external {
        if (msg.sender != owner) revert NotOwner();
        uint256 rate = _computeExchangeRate();
        exchangeRates[token] = rate;
        emit ExchangeRateUpdated(token, rate);
    }

    /// @notice Manually set the exchange rate (bypasses oracles).
    /// @param rate Tokens per wei, scaled by 1e18.
    function setExchangeRate(uint256 rate) external {
        if (msg.sender != owner) revert NotOwner();
        exchangeRates[token] = rate;
        emit ExchangeRateUpdated(token, rate);
    }

    /// @notice Update the price markup.
    /// @param _priceMarkup New markup (1e6 = 100%).
    function updateMarkup(uint32 _priceMarkup) external {
        if (msg.sender != owner) revert NotOwner();
        if (_priceMarkup < 1e6) revert PriceMarkupTooLow();
        if (_priceMarkup > priceMarkupLimit) revert PriceMarkupTooHigh();
        priceMarkup = _priceMarkup;
        emit MarkupUpdated(_priceMarkup);
    }

    /// @notice Withdraw ERC-20 tokens from the paymaster.
    function withdrawToken(address _token, address to, uint256 amount) external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok,) = _token.call(
            abi.encodeWithSelector(TRANSFER_SELECTOR, to, amount)
        );
        if (!ok) revert WithdrawFailed();
    }

    /// @notice Withdraw ETH from the paymaster.
    function withdrawETH(address to, uint256 amount) external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
    }

    receive() external payable {}

    // ─── Internal ───────────────────────────────────────────────────

    /// @dev Compute exchange rate from oracles with markup. NOT for VERIFY frame use.
    function _computeExchangeRate() internal view returns (uint256) {
        uint192 tokenPrice = _fetchPrice(tokenOracle);
        uint192 nativeAssetPrice = _fetchPrice(nativeAssetOracle);
        return uint256(nativeAssetPrice) * tokenDecimals * priceMarkup
            / (uint256(tokenPrice) * PRICE_DENOMINATOR);
    }
}
