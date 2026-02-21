/**
 * E2E: Simple8141Account basic frame transaction
 *
 * Usage: cd contracts && npx tsx e2e/simple/simple-basic.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  getContractAddress,
  hexToBytes,
  formatEther,
  type Hex,
  type Address,
  type Hash,
} from "viem";
import {
  CHAIN_ID,
  DEV_KEY,
  DEAD_ADDR,
  FRAME_MODE_VERIFY,
  FRAME_MODE_SENDER,
  CHAIN_DEF,
} from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { printReceipt, verifyReceipt } from "../helpers/receipt.js";
import { SIMPLE_VALIDATE_SELECTOR } from "../helpers/abis/simple.js";
import { banner, sectionHeader, info, step, success, testHeader, testPassed, summary, fatal } from "../helpers/log.js";

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Simple8141Account E2E");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // Deploy
  sectionHeader("📦 Deploy Simple8141Account");
  const ownerAddr = devAddr;
  const initCode = loadBytecode("Simple8141Account");
  const constructorArg = encodeAbiParameters(parseAbiParameters("address"), [ownerAddr]);
  const deployData = (initCode + constructorArg.slice(2)) as Hex;

  const deployNonce = await publicClient.getTransactionCount({ address: devAddr });
  const simple8141AccountAddr = getContractAddress({ from: devAddr, nonce: BigInt(deployNonce) });

  const deployHash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    data: deployData,
    gas: 2_000_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });

  const deployReceipt = await waitForReceipt(publicClient, deployHash);
  if (deployReceipt.status !== "0x1") throw new Error(`Deploy failed: status=${deployReceipt.status}`);
  success(`Deployed at ${simple8141AccountAddr}`);

  // Fund
  sectionHeader("💰 Fund Account");
  await fundAccount(walletClient, publicClient, simple8141AccountAddr);

  // Build FrameTx
  testHeader(1, "Send basic frame transaction");

  const accountNonce = await publicClient.getTransactionCount({ address: simple8141AccountAddr });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce: BigInt(accountNonce),
    sender: simple8141AccountAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  step("Computing sigHash and signing...");
  const sigHash = computeSigHash(frameTxParams);
  const { r, s, v } = signFrameHash(sigHash, DEV_KEY);

  // Manually construct validate(uint8 v, bytes32 r, bytes32 s, uint8 scope) calldata
  const validateSelector = hexToBytes(SIMPLE_VALIDATE_SELECTOR as Hex);
  const calldata = new Uint8Array(4 + 32 * 4);
  calldata.set(validateSelector, 0);
  calldata[35] = v + 27;

  const rHex = r.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);

  const sHex = s.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);

  calldata[131] = 2; // scope=2 (both)

  if (calldata.length !== 132) throw new Error(`Calldata length mismatch: got ${calldata.length}, want 132`);

  frameTxParams.frames[0].data = calldata;

  step("Sending frame transaction...");
  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;

  const frameReceipt = await waitForReceipt(publicClient, txHash);
  printReceipt(frameReceipt);
  verifyReceipt(frameReceipt, simple8141AccountAddr);
  testPassed("Basic frame transaction");

  summary("Simple8141", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
