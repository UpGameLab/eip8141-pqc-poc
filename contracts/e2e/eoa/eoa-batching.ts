/**
 * E2E: EOA Batching — multiple calls in one frame transaction (no smart account)
 *
 * Uses EIP-8141 default code to authorize multiple direct SENDER frames.
 * No contract deployment needed — the EOA acts directly.
 *
 * Frame layout:
 *   Frame 0: VERIFY(sender) → ECDSA verify → APPROVE(0x3, both)
 *   Frames 1-3: SENDER(sender) → one direct transfer per frame
 *
 * Usage: cd contracts && npx tsx e2e/eoa/eoa-batching.ts
 */

import { formatEther, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEV_KEY, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, waitForReceipt } from "../helpers/client.js";
import {
  banner, sectionHeader, info, step, success,
  testHeader, testPassed, summary, fatal, printReceipt,
} from "../helpers/log.js";

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  const owner = privateKeyToAccount(DEV_KEY);

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("EOA Batching E2E (Default Code)");
  info(`Dev account (EOA): ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Test 1: Batch 3 ETH transfers in one frame tx ──
  testHeader(1, "Batch 3 ETH transfers via default code");

  // LocalAccount passed directly — auto-wrapped to toEoaFrameAccount internally
  const account = owner;

  const targets = [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003",
  ] as const;

  // Get balances before
  const balancesBefore = await Promise.all(
    targets.map((t) => publicClient.getBalance({ address: t }))
  );

  step("Sending 4-frame tx: VERIFY(ECDSA) → 3 direct SENDER transfers...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: targets.map((to) => ({ to, value: 1n })),
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);

  // Verify receipt
  if (receipt.status !== "0x1") {
    throw new Error(`TX failed: status=${receipt.status}`);
  }
  if (receipt.type !== "0x6") {
    throw new Error(`Wrong type: got ${receipt.type}, want 0x6`);
  }
  success("Transaction succeeded");

  // Verify frame count: VERIFY + 3 SENDER frames = 4
  if (!receipt.frameReceipts || receipt.frameReceipts.length !== 4) {
    throw new Error(
      `Frame count: got ${receipt.frameReceipts?.length ?? 0}, want 4`
    );
  }
  success("4 frame receipts present");

  // Frame 0: VERIFY → APPROVED_BOTH (0x4)
  const frame0Status = receipt.frameReceipts[0].status;
  if (frame0Status !== "0x4") {
    throw new Error(`Frame 0 (VERIFY): got ${frame0Status}, want 0x4`);
  }
  success("Frame 0: APPROVED_BOTH (0x4)");

  for (let i = 1; i < 4; i++) {
    const frameStatus = receipt.frameReceipts[i].status;
    if (frameStatus !== "0x1") {
      throw new Error(`Frame ${i} (SENDER): got ${frameStatus}, want 0x1`);
    }
  }
  success("Frames 1-3: direct SENDER transfers SUCCESS (0x1)");

  // Verify payer is the EOA
  if (receipt.payer && receipt.payer.toLowerCase() !== devAddr.toLowerCase()) {
    throw new Error(`Wrong payer: got ${receipt.payer}, want ${devAddr}`);
  }
  success(`Payer is EOA: ${devAddr}`);

  // Verify balances increased
  const balancesAfter = await Promise.all(
    targets.map((t) => publicClient.getBalance({ address: t }))
  );
  for (let i = 0; i < targets.length; i++) {
    if (balancesAfter[i] - balancesBefore[i] !== 1n) {
      throw new Error(
        `Target ${targets[i]} balance delta: got ${balancesAfter[i] - balancesBefore[i]}, want 1`
      );
    }
  }
  success("All 3 targets received 1 wei each");

  testPassed("EOA Batching");
  summary("EOA Batching", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
