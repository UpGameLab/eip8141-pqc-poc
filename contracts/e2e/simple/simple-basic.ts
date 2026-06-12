/**
 * E2E: Simple8141Account — deploy + verify + execute in one frame tx
 *
 * Demonstrates EIP-8141 Example 1b: account deployment, validation, and
 * execution all happen in a single frame transaction (type 0x06).
 *
 *   Frame 0: DEFAULT(deployer) → Create2Deployer.deploy(salt, initCode)
 *   Frame 1: VERIFY(sender)    → account.validate(v, r, s, scope=3) → APPROVE
 *   Frame 2: SENDER(target)    → call to DEAD_ADDR
 *
 * Usage: cd contracts && npx tsx e2e/simple/simple-basic.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toSimple8141Account } from "viem/eip8141";
import { DEV_KEY, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { deployerAbi } from "../helpers/abis/deployer.js";
import { printReceipt, banner, sectionHeader, info, step, success, testHeader, testPassed, summary, fatal } from "../helpers/log.js";

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  const owner = privateKeyToAccount(DEV_KEY);

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Simple8141Account E2E (Deploy-in-one-tx)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy Create2Deployer (infrastructure, L1 tx) ──
  sectionHeader("Deploy Create2Deployer");
  const { address: deployerAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("Create2Deployer"), 1_000_000n, "Create2Deployer"
  );

  // ── Compute deterministic account address ──
  sectionHeader("Predict Account Address");
  const initCode = loadBytecode("Simple8141Account");
  const constructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const fullInitCode = (initCode + constructorArg.slice(2)) as Hex;
  const salt = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;

  const predictedAddr = await publicClient.readContract({
    address: deployerAddr,
    abi: deployerAbi,
    functionName: "getAddress",
    args: [salt, fullInitCode],
  }) as Address;
  step(`Predicted address: ${predictedAddr}`);

  // ── Pre-fund the predicted address (ETH must be there for gas payment) ──
  sectionHeader("Pre-fund Predicted Address");
  await fundAccount(walletClient, publicClient, predictedAddr);

  // ── Send deploy-in-one-tx frame transaction ──
  testHeader(1, "Deploy + Verify + Execute in one frame tx");

  const deployCalldata = encodeFunctionData({
    abi: deployerAbi,
    functionName: "deploy",
    args: [salt, fullInitCode],
  });

  const baseAccount = toSimple8141Account({
    address: predictedAddr,
    owner,
    verifyGasLimit: 200_000n,
    senderGasLimit: 50_000n,
  });

  const account = {
    ...baseAccount,
    getDeployFrame: async () => ({
      mode: "default" as const,
      target: deployerAddr,
      gasLimit: 500_000n,
      data: deployCalldata,
    }),
  };

  step("Sending 3-frame tx: DEFAULT(deploy) → VERIFY → SENDER...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);
  verifyReceipt(receipt, predictedAddr, {
    expectFrameCount: 3,
    verifyFrameIndex: 1,
    senderFrameIndex: 2,
  });

  // Verify the account was actually deployed
  const code = await publicClient.getCode({ address: predictedAddr });
  if (!code || code === "0x") throw new Error("Account not deployed after frame tx");
  success(`Account deployed and executed at ${predictedAddr}`);

  testPassed("Deploy-in-one-tx");
  summary("Simple8141 Deploy", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
