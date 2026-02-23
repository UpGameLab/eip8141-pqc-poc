// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20PaymasterV8141} from "../src/ERC20PaymasterV8141.sol";
import {FixedOracle} from "../src/oracles/FixedOracle.sol";
import {ManualOracle} from "../src/oracles/ManualOracle.sol";
import {IOracle} from "../src/oracles/IOracle.sol";
import {BenchmarkToken} from "../src/BenchmarkToken.sol";

contract ERC20PaymasterV8141Test is Test {
    ERC20PaymasterV8141 paymaster;
    BenchmarkToken token;
    FixedOracle tokenOracle;
    FixedOracle nativeOracle;
    address owner;
    address alice;

    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        token = new BenchmarkToken();
        tokenOracle = new FixedOracle(1e8);      // $1
        nativeOracle = new FixedOracle(3000e8);   // $3000

        paymaster = new ERC20PaymasterV8141(
            address(token),
            tokenOracle,
            nativeOracle,
            3600,       // stalenessThreshold: 1 hour
            owner,
            2e6,        // priceMarkupLimit: 200%
            1_100_000   // priceMarkup: 110%
        );
    }

    // ── Constructor ──────────────────────────────────────────────────

    function test_constructor_setsImmutables() public view {
        assertEq(paymaster.token(), address(token));
        assertEq(paymaster.tokenDecimals(), 1e18);
        assertEq(address(paymaster.tokenOracle()), address(tokenOracle));
        assertEq(address(paymaster.nativeAssetOracle()), address(nativeOracle));
        assertEq(paymaster.stalenessThreshold(), 3600);
        assertEq(paymaster.priceMarkupLimit(), 2e6);
        assertEq(paymaster.priceMarkup(), 1_100_000);
        assertEq(paymaster.owner(), owner);
    }

    function test_constructor_setsInitialExchangeRate() public view {
        // rate = nativePrice * tokenDecimals * priceMarkup / (tokenPrice * PRICE_DENOMINATOR)
        //      = 3000e8 * 1e18 * 1_100_000 / (1e8 * 1e6)
        //      = 3300e18
        uint256 rate = paymaster.exchangeRates(address(token));
        assertEq(rate, 3300e18);
    }

    function test_constructor_revertsIfOracleDecimalsInvalid() public {
        BadDecimalsOracle badOracle = new BadDecimalsOracle();
        vm.expectRevert(ERC20PaymasterV8141.OracleDecimalsInvalid.selector);
        new ERC20PaymasterV8141(
            address(token), IOracle(address(badOracle)), nativeOracle,
            3600, owner, 2e6, 1_100_000
        );
    }

    function test_constructor_revertsIfMarkupTooLow() public {
        vm.expectRevert(ERC20PaymasterV8141.PriceMarkupTooLow.selector);
        new ERC20PaymasterV8141(
            address(token), tokenOracle, nativeOracle,
            3600, owner, 2e6, 999_999 // < 1e6
        );
    }

    function test_constructor_revertsIfMarkupTooHigh() public {
        vm.expectRevert(ERC20PaymasterV8141.PriceMarkupTooHigh.selector);
        new ERC20PaymasterV8141(
            address(token), tokenOracle, nativeOracle,
            3600, owner, 2e6, 2_000_001 // > priceMarkupLimit
        );
    }

    // ── getPrice ─────────────────────────────────────────────────────

    function test_getPrice() public view {
        // tokenPrice = 1e8, nativePrice = 3000e8, tokenDecimals = 1e18
        // price = 3000e8 * 1e18 / 1e8 = 3000e18
        uint192 price = paymaster.getPrice();
        assertEq(price, 3000e18);
    }

    function test_getPrice_equalPrices() public {
        // 1:1 rate
        FixedOracle oneToOne = new FixedOracle(1e8);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), oneToOne, oneToOne,
            3600, owner, 2e6, 1e6
        );
        // price = 1e8 * 1e18 / 1e8 = 1e18
        assertEq(pm.getPrice(), 1e18);
    }

    // ── getTokenAmount ───────────────────────────────────────────────

    function test_getTokenAmount() public view {
        // exchangeRate = 3300e18 (from constructor: 3000 * 1.1)
        // For 1 ETH (1e18 wei):
        // tokenAmount = 1e18 * 3300e18 / 1e18 = 3300e18
        uint256 amount = paymaster.getTokenAmount(1 ether);
        assertEq(amount, 3300e18);
    }

    // ── updateExchangeRate ──────────────────────────────────────────

    function test_updateExchangeRate() public {
        // Change the oracle prices via ManualOracle
        ManualOracle mTokenOracle = new ManualOracle(1e8, owner);
        ManualOracle mNativeOracle = new ManualOracle(2000e8, owner);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), IOracle(address(mTokenOracle)), IOracle(address(mNativeOracle)),
            3600, owner, 2e6, 1e6
        );

        // Initial rate = 2000e8 * 1e18 * 1e6 / (1e8 * 1e6) = 2000e18
        assertEq(pm.exchangeRates(address(token)), 2000e18);

        // Update native oracle price
        vm.prank(owner);
        mNativeOracle.setPrice(4000e8);

        // Rate is still cached at 2000e18
        assertEq(pm.exchangeRates(address(token)), 2000e18);

        // Refresh from oracles
        vm.prank(owner);
        pm.updateExchangeRate();

        // New rate = 4000e8 * 1e18 * 1e6 / (1e8 * 1e6) = 4000e18
        assertEq(pm.exchangeRates(address(token)), 4000e18);
    }

    function test_updateExchangeRate_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(ERC20PaymasterV8141.NotOwner.selector);
        paymaster.updateExchangeRate();
    }

    // ── setExchangeRate ─────────────────────────────────────────────

    function test_setExchangeRate() public {
        vm.prank(owner);
        paymaster.setExchangeRate(5000e18);
        assertEq(paymaster.exchangeRates(address(token)), 5000e18);
    }

    function test_setExchangeRate_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(ERC20PaymasterV8141.NotOwner.selector);
        paymaster.setExchangeRate(5000e18);
    }

    // ── updateMarkup ─────────────────────────────────────────────────

    function test_updateMarkup() public {
        vm.prank(owner);
        paymaster.updateMarkup(1_500_000); // 150%
        assertEq(paymaster.priceMarkup(), 1_500_000);
    }

    function test_updateMarkup_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit ERC20PaymasterV8141.MarkupUpdated(1_200_000);
        paymaster.updateMarkup(1_200_000);
    }

    function test_updateMarkup_revertsIfNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(ERC20PaymasterV8141.NotOwner.selector);
        paymaster.updateMarkup(1_500_000);
    }

    function test_updateMarkup_revertsIfTooLow() public {
        vm.prank(owner);
        vm.expectRevert(ERC20PaymasterV8141.PriceMarkupTooLow.selector);
        paymaster.updateMarkup(999_999);
    }

    function test_updateMarkup_revertsIfTooHigh() public {
        vm.prank(owner);
        vm.expectRevert(ERC20PaymasterV8141.PriceMarkupTooHigh.selector);
        paymaster.updateMarkup(2_000_001);
    }

    function test_updateMarkup_thenRefreshRate() public {
        // Update markup to 150%
        vm.prank(owner);
        paymaster.updateMarkup(1_500_000);

        // Rate still reflects old 110% markup: 3300e18
        assertEq(paymaster.exchangeRates(address(token)), 3300e18);

        // Refresh exchange rate — picks up new 150% markup
        vm.prank(owner);
        paymaster.updateExchangeRate();

        // New rate = 3000e8 * 1e18 * 1_500_000 / (1e8 * 1e6) = 4500e18
        assertEq(paymaster.exchangeRates(address(token)), 4500e18);
    }

    // ── validate / postOp access control ─────────────────────────────

    function test_validate_revertsIfNotEntryPoint() public {
        vm.expectRevert(ERC20PaymasterV8141.InvalidCaller.selector);
        paymaster.validate();
    }

    function test_validateWithLimit_revertsIfNotEntryPoint() public {
        vm.expectRevert(ERC20PaymasterV8141.InvalidCaller.selector);
        paymaster.validateWithLimit(1000e18);
    }

    function test_validateWithLimit_revertsIfZeroLimit() public {
        // TokenLimitZero is checked before InvalidCaller
        vm.expectRevert(ERC20PaymasterV8141.TokenLimitZero.selector);
        paymaster.validateWithLimit(0);
    }

    function test_postOp_revertsIfNotEntryPoint() public {
        vm.expectRevert(ERC20PaymasterV8141.InvalidCaller.selector);
        paymaster.postOp(2);
    }

    // ── withdrawToken ────────────────────────────────────────────────

    function test_withdrawToken() public {
        token.mint(address(paymaster), 1000e18);

        vm.prank(owner);
        paymaster.withdrawToken(address(token), alice, 1000e18);

        assertEq(token.balanceOf(address(paymaster)), 0);
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function test_withdrawToken_revertsIfNotOwner() public {
        token.mint(address(paymaster), 1000e18);
        vm.prank(alice);
        vm.expectRevert(ERC20PaymasterV8141.NotOwner.selector);
        paymaster.withdrawToken(address(token), alice, 1000e18);
    }

    // ── withdrawETH ──────────────────────────────────────────────────

    function test_withdrawETH() public {
        vm.deal(address(paymaster), 1 ether);

        vm.prank(owner);
        paymaster.withdrawETH(alice, 1 ether);

        assertEq(address(paymaster).balance, 0);
        assertEq(alice.balance, 1 ether);
    }

    function test_withdrawETH_revertsIfNotOwner() public {
        vm.deal(address(paymaster), 1 ether);
        vm.prank(alice);
        vm.expectRevert(ERC20PaymasterV8141.NotOwner.selector);
        paymaster.withdrawETH(alice, 1 ether);
    }

    // ── receive ──────────────────────────────────────────────────────

    function test_receive_ether() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(paymaster).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(paymaster).balance, 1 ether);
    }

    // ── ManualOracle ─────────────────────────────────────────────────

    function test_manualOracle() public {
        ManualOracle manual = new ManualOracle(2000e8, owner);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), tokenOracle, IOracle(address(manual)),
            3600, owner, 2e6, 1e6
        );
        // getPrice reads oracles directly: 2000e8 * 1e18 / 1e8 = 2000e18
        assertEq(pm.getPrice(), 2000e18);
        // cached rate: 2000e8 * 1e18 * 1e6 / (1e8 * 1e6) = 2000e18
        assertEq(pm.exchangeRates(address(token)), 2000e18);

        // Update oracle price
        vm.prank(owner);
        manual.setPrice(4000e8);

        // getPrice reflects new oracle value immediately
        assertEq(pm.getPrice(), 4000e18);
        // cached rate still old
        assertEq(pm.exchangeRates(address(token)), 2000e18);

        // Refresh cached rate from oracles
        vm.prank(owner);
        pm.updateExchangeRate();
        assertEq(pm.exchangeRates(address(token)), 4000e18);
    }

    function test_manualOracle_revertsIfInvalidPrice() public {
        vm.expectRevert(ManualOracle.InvalidPrice.selector);
        new ManualOracle(0, owner);
    }

    function test_manualOracle_revertsIfNotOwner() public {
        ManualOracle manual = new ManualOracle(1e8, owner);
        vm.prank(alice);
        vm.expectRevert(ManualOracle.NotOwner.selector);
        manual.setPrice(2e8);
    }

    // ── Oracle staleness ─────────────────────────────────────────────

    function test_getPrice_worksWithStaleOracle() public {
        // getPrice() reads oracles directly (for off-chain use), no staleness check
        vm.warp(100_000);
        StaleOracle stale = new StaleOracle(1e8, block.timestamp - 7200);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), IOracle(address(stale)), nativeOracle,
            3600, owner, 2e6, 1e6
        );
        // Should NOT revert — staleness is checked via checkOracleFreshness()
        pm.getPrice();
    }

    function test_checkOracleFreshness_revertsIfStale() public {
        vm.warp(100_000);
        StaleOracle stale = new StaleOracle(1e8, block.timestamp - 7200);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), IOracle(address(stale)), nativeOracle,
            3600, owner, 2e6, 1e6
        );
        vm.expectRevert(ERC20PaymasterV8141.OraclePriceStale.selector);
        pm.checkOracleFreshness();
    }

    function test_checkOracleFreshness_passesWhenFresh() public {
        vm.warp(100_000);
        ManualOracle freshToken = new ManualOracle(1e8, owner);
        ManualOracle freshNative = new ManualOracle(3000e8, owner);
        ERC20PaymasterV8141 pm = new ERC20PaymasterV8141(
            address(token), IOracle(address(freshToken)), IOracle(address(freshNative)),
            3600, owner, 2e6, 1e6
        );
        pm.checkOracleFreshness(); // should not revert
    }
}

// ── Test helpers ─────────────────────────────────────────────────────

contract BadDecimalsOracle is IOracle {
    function decimals() external pure override returns (uint8) {
        return 6; // not 8
    }
    function latestRoundData() external view override returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        return (0, 1e6, 0, block.timestamp, 0);
    }
}

contract StaleOracle is IOracle {
    int256 public price;
    uint256 public updatedAt;

    constructor(int256 _price, uint256 _updatedAt) {
        price = _price;
        updatedAt = _updatedAt;
    }

    function decimals() external pure override returns (uint8) {
        return 8;
    }

    function latestRoundData() external view override returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        return (0, price, 0, updatedAt, 0);
    }
}
