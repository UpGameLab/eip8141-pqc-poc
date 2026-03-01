/**
 * E2E: CoinbaseSmartWallet8141 Security Tests
 *
 * Tests for security fixes:
 * - K-06: Reject malleable (high-s) ECDSA signatures
 * - C-02: Reject address(0) owner during initialization
 * - Wrong signer rejection
 *
 * Usage: cd contracts && npx tsx e2e/coinbase/coinbase-security.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR } from "../helpers/config.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { walletAbi, factoryAbi } from "../helpers/abis/coinbase.js";
import { printReceipt, testHeader, testPassed, testFailed, summary, fatal, detail } from "../helpers/log.js";
import { deployCoinbaseTestbed } from "./setup.js";
import { createCoinbaseAccount, sendAndWait } from "../helpers/send-frame-tx.js";
import { buildUnsignedFrameTx, createMalleableSig, sendRawFrameTxExpectFail } from "../helpers/security.js";

async function main() {
  const ctx = await deployCoinbaseTestbed();
  let passed = 0;
  let total = 0;

  const senderCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [DEAD_ADDR, 0n, "0x"],
  });

  // ── Test 1: Reject malleable (high-s) ECDSA signature ───────────────
  testHeader(++total, "Reject malleable (high-s) ECDSA signature");
  {
    const { tx, sigHash } = await buildUnsignedFrameTx(ctx.publicClient, ctx.walletAddr, senderCalldata);
    const { malleableSig, originalS, highS } = await createMalleableSig(sigHash, DEV_KEY);

    detail(`Original s:  0x${originalS.toString(16).slice(0, 16)}...`);
    detail(`Malleable s: 0x${highS.toString(16).slice(0, 16)}...`);

    const signatureWrapper = encodeAbiParameters(
      parseAbiParameters("uint256, bytes"),
      [0n, malleableSig],
    );
    tx.frames[0].data = encodeFunctionData({
      abi: walletAbi,
      functionName: "validate",
      args: [signatureWrapper, 2],
    });

    const rejected = await sendRawFrameTxExpectFail(ctx.publicClient, tx);
    if (rejected) {
      passed++;
      testPassed("Malleable signature correctly rejected");
    } else {
      testFailed("Malleable signature was NOT rejected — K-06 fix missing!");
    }
  }

  // ── Test 2: Reject wrong signer ──────────────────────────────────────
  testHeader(++total, "Reject wrong signer");
  {
    const { tx, sigHash } = await buildUnsignedFrameTx(ctx.publicClient, ctx.walletAddr, senderCalldata);

    // Sign with a different key (not the registered owner)
    const wrongOwner = privateKeyToAccount(SECOND_OWNER_KEY);
    const wrongSig = await wrongOwner.sign({ hash: sigHash });

    const signatureWrapper = encodeAbiParameters(
      parseAbiParameters("uint256, bytes"),
      [0n, wrongSig],
    );
    tx.frames[0].data = encodeFunctionData({
      abi: walletAbi,
      functionName: "validate",
      args: [signatureWrapper, 2],
    });

    const rejected = await sendRawFrameTxExpectFail(ctx.publicClient, tx);
    if (rejected) {
      passed++;
      testPassed("Wrong signer correctly rejected");
    } else {
      testFailed("Wrong signer was NOT rejected!");
    }
  }

  // ── Test 3: Reject address(0) owner during factory initialization ───
  testHeader(++total, "Reject address(0) owner during initialization (C-02)");
  {
    const { publicClient, walletClient } = ctx;

    // Deploy fresh impl + factory for isolated test
    const implBytecode = loadBytecode("CoinbaseSmartWallet8141");
    const { address: implAddr } = await deployContract(
      walletClient, publicClient, implBytecode, 5_000_000n, "CoinbaseSmartWallet8141 (test)"
    );
    const factoryBytecode = loadBytecode("CoinbaseSmartWalletFactory8141");
    const factoryConstructorArgs = encodeAbiParameters(
      parseAbiParameters("address"),
      [implAddr]
    );
    const factoryDeployData = (factoryBytecode + factoryConstructorArgs.slice(2)) as Hex;
    const { address: factoryAddr } = await deployContract(
      walletClient, publicClient, factoryDeployData, 3_000_000n, "Factory (test)"
    );

    // Try to create account with address(0) as owner
    const zeroOwners = [
      encodeAbiParameters(parseAbiParameters("address"), [
        "0x0000000000000000000000000000000000000000" as Address,
      ]),
    ];

    try {
      const createData = encodeFunctionData({
        abi: factoryAbi,
        functionName: "createAccount",
        args: [zeroOwners, 99n], // different nonce
      });
      const createHash = await walletClient.sendTransaction({
        to: factoryAddr,
        data: createData,
        gas: 5_000_000n,
        maxFeePerGas: 10_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: createHash });
      if (receipt.status === "success") {
        testFailed("address(0) owner was NOT rejected — C-02 fix missing!");
      } else {
        passed++;
        testPassed("address(0) owner correctly rejected (tx reverted)");
      }
    } catch (err: any) {
      passed++;
      detail(`Rejected: ${err.message?.slice(0, 80) || err}`);
      testPassed("address(0) owner correctly rejected");
    }
  }

  // ── Test 4: Valid signature still works (sanity check) ──────────────
  testHeader(++total, "Valid signature still accepted (sanity check)");
  {
    const account = createCoinbaseAccount(ctx.walletAddr, 0, DEV_KEY);
    const receipt = await sendAndWait(ctx.publicClient, account, senderCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.walletAddr, { expectVerifyStatus: "0x4|0x2" });
    passed++;
    testPassed("Valid signature accepted");
  }

  summary("Coinbase Security", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
