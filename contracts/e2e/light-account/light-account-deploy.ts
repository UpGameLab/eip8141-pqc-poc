/**
 * E2E: LightAccount8141 — deploy + verify + execute in one frame tx
 *
 * Demonstrates deploying a LightAccount proxy via factory in a DEFAULT frame,
 * then validating and executing in the same frame transaction.
 *
 *   Frame 0: DEFAULT(factory) → LightAccountFactory8141.createAccount(owner, salt)
 *   Frame 1: VERIFY(sender)   → account.validate(sig, scope=3) → APPROVE
 *   Frame 2: SENDER(sender)   → account.execute(...)
 *
 * Usage: cd contracts && npx tsx e2e/light-account/light-account-deploy.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { DEV_KEY, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, fundAccount, waitForReceipt } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { walletAbi, factoryAbi } from "../helpers/abis/light-account.js";
import { createLightAccount, sendAndWait } from "../helpers/send-frame-tx.js";
import { printReceipt, banner, sectionHeader, info, step, success, testHeader, testPassed, summary, fatal } from "../helpers/log.js";

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("LightAccount8141 Deploy-in-one-tx E2E");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy infrastructure (L1 txs) ──
  sectionHeader("Deploy Infrastructure");

  const { address: implAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("LightAccount8141"), 5_000_000n, "LightAccount8141 (impl)"
  );

  const factoryBytecode = loadBytecode("LightAccountFactory8141");
  const factoryCtorArgs = encodeAbiParameters(parseAbiParameters("address"), [implAddr]);
  const factoryDeployData = (factoryBytecode + factoryCtorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 3_000_000n, "LightAccountFactory8141"
  );

  // ── Predict deterministic address ──
  sectionHeader("Predict Account Address");
  const walletAddr = await publicClient.readContract({
    address: factoryAddr,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [devAddr, 0n],
  }) as Address;
  step(`Predicted wallet address: ${walletAddr}`);

  // ── Pre-fund predicted address ──
  sectionHeader("Pre-fund Predicted Address");
  await fundAccount(walletClient, publicClient, walletAddr);

  // ── Deploy + Verify + Execute in one frame tx ──
  testHeader(1, "Deploy + Verify + Execute in one frame tx");

  const factoryCalldata = encodeFunctionData({
    abi: factoryAbi,
    functionName: "createAccount",
    args: [devAddr, 0n],
  });

  const account = createLightAccount(walletAddr, DEV_KEY, {
    deploy: {
      target: factoryAddr,
      data: factoryCalldata,
      gasLimit: 500_000n,
    },
  });

  const senderCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [DEAD_ADDR, 0n, "0x"],
  });

  step("Sending 3-frame tx: DEFAULT(factory) → VERIFY → SENDER...");
  const receipt = await sendAndWait(publicClient, account, senderCalldata);
  printReceipt(receipt);
  verifyReceipt(receipt, walletAddr, {
    expectFrameCount: 3,
    verifyFrameIndex: 1,
    senderFrameIndex: 2,
    expectVerifyStatus: "0x4|0x2",
  });

  // Verify the account was deployed
  const code = await publicClient.getCode({ address: walletAddr });
  if (!code || code === "0x") throw new Error("Account not deployed after frame tx");
  success(`LightAccount8141 deployed and executed at ${walletAddr}`);

  testPassed("Deploy-in-one-tx");
  summary("LightAccount Deploy", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
