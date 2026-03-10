/**
 * E2E: EOA Batching — multiple calls in one frame transaction (no smart account)
 *
 * Uses EIP-8141 default code to batch multiple calls into a single SENDER frame
 * via RLP encoding. No contract deployment needed — the EOA acts directly.
 *
 * Frame layout:
 *   Frame 0: VERIFY(sender) → ECDSA verify → APPROVE(0x2, both)
 *   Frame 1: SENDER(sender) → RLP batch [[addr1,val1,data1], [addr2,val2,data2]]
 *
 * Usage: cd contracts && npx tsx e2e/eoa/eoa-batching.ts
 */

import { formatEther, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toEoaFrameAccount } from "viem/eip8141";
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

  const account = toEoaFrameAccount({
    owner,
    verifyGasLimit: 100_000n,
    senderGasLimit: 200_000n,
    scope: 2,
  });

  const targets = [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003",
  ] as const;

  // Get balances before
  const balancesBefore = await Promise.all(
    targets.map((t) => publicClient.getBalance({ address: t }))
  );

  step("Sending 2-frame tx: VERIFY(ECDSA) → SENDER(RLP batch)...");
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

  // Verify frame count: VERIFY + SENDER = 2
  if (!receipt.frameReceipts || receipt.frameReceipts.length !== 2) {
    throw new Error(
      `Frame count: got ${receipt.frameReceipts?.length ?? 0}, want 2`
    );
  }
  success("2 frame receipts present");

  // Frame 0: VERIFY → APPROVED_BOTH (0x4)
  const frame0Status = receipt.frameReceipts[0].status;
  if (frame0Status !== "0x4") {
    throw new Error(`Frame 0 (VERIFY): got ${frame0Status}, want 0x4`);
  }
  success("Frame 0: APPROVED_BOTH (0x4)");

  // Frame 1: SENDER → SUCCESS (0x1)
  const frame1Status = receipt.frameReceipts[1].status;
  if (frame1Status !== "0x1") {
    throw new Error(`Frame 1 (SENDER): got ${frame1Status}, want 0x1`);
  }
  success("Frame 1: SENDER batch SUCCESS (0x1)");

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
