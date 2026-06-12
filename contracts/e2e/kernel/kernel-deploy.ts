/**
 * E2E: Kernel8141 — deploy + verify + execute in one frame tx
 *
 * Demonstrates deploying a Kernel8141 proxy via factory in a DEFAULT frame,
 * then validating and executing in the same frame transaction.
 *
 *   Frame 0: DEFAULT(factory)  → Kernel8141Factory.createAccount(initData, salt)
 *   Frame 1: VERIFY(sender)    → kernel.validate(sig, scope=3) → APPROVE
 *   Frame 2: SENDER(sender)    → kernel.execute(...)
 *
 * Usage: cd contracts && npx tsx e2e/kernel/kernel-deploy.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { DEV_KEY, DEAD_ADDR, HOOK_INSTALLED } from "../helpers/config.js";
import { createTestClients, fundAccount, waitForReceipt } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi, factoryAbi } from "../helpers/abis/kernel.js";
import { encodeExecMode, encodeSingleExec } from "../helpers/exec-encoding.js";
import { createKernelAccount, sendAndWait } from "../helpers/send-frame-tx.js";
import { printReceipt, banner, sectionHeader, info, step, success, testHeader, testPassed, summary, fatal } from "../helpers/log.js";

const CALLTYPE_SINGLE = "0x00" as Hex;
const EXECTYPE_DEFAULT = "0x00" as Hex;

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Kernel8141 Deploy-in-one-tx E2E");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy infrastructure (L1 txs) ──
  sectionHeader("Deploy Infrastructure");

  const { address: validatorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("ECDSAValidator"), 3_000_000n, "ECDSAValidator"
  );

  const { address: implAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("Kernel8141"), 10_000_000n, "Kernel8141 (impl)"
  );

  const factoryBytecode = loadBytecode("Kernel8141Factory");
  const factoryCtorArgs = encodeAbiParameters(parseAbiParameters("address"), [implAddr]);
  const factoryDeployData = (factoryBytecode + factoryCtorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 5_000_000n, "Kernel8141Factory"
  );

  // ── Predict deterministic address ──
  sectionHeader("Predict Account Address");
  const rootVId = `0x01${validatorAddr.slice(2)}` as Hex;
  const salt = "0x0000000000000000000000000000000000000000000000000000000000000001" as Hex;

  const initData = encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [rootVId, HOOK_INSTALLED, devAddr, "0x", []],
  });

  const kernelAddr = await publicClient.readContract({
    address: factoryAddr,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [initData, salt],
  }) as Address;
  step(`Predicted kernel address: ${kernelAddr}`);

  // ── Pre-fund predicted address ──
  sectionHeader("Pre-fund Predicted Address");
  await fundAccount(walletClient, publicClient, kernelAddr);

  // ── Deploy + Verify + Execute in one frame tx ──
  testHeader(1, "Deploy + Verify + Execute in one frame tx");

  const factoryCalldata = encodeFunctionData({
    abi: factoryAbi,
    functionName: "createAccount",
    args: [initData, salt],
  });

  const account = createKernelAccount(kernelAddr, DEV_KEY, {
    deploy: {
      target: factoryAddr,
      data: factoryCalldata,
      gasLimit: 500_000n,
    },
  });

  const execMode = encodeExecMode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT);
  const execCalldata = encodeSingleExec(DEAD_ADDR, 0n);
  const senderCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [execMode, execCalldata],
  });

  step("Sending 3-frame tx: DEFAULT(factory) → VERIFY → SENDER...");
  const receipt = await sendAndWait(publicClient, account, senderCalldata);
  printReceipt(receipt);
  verifyReceipt(receipt, kernelAddr, {
    expectFrameCount: 3,
    verifyFrameIndex: 1,
    senderFrameIndex: 2,
    expectVerifyStatus: "0x4|0x2",
  });

  // Verify the account was deployed
  const code = await publicClient.getCode({ address: kernelAddr });
  if (!code || code === "0x") throw new Error("Kernel not deployed after frame tx");
  success(`Kernel8141 deployed and executed at ${kernelAddr}`);

  testPassed("Deploy-in-one-tx");
  summary("Kernel Deploy", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
