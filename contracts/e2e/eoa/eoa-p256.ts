/**
 * E2E: EOA P256 — passkey-style signing via EIP-8141 default code
 *
 * Uses P256 (secp256r1) signature type in the default code.
 * The EOA address is derived as keccak256(qx || qy)[12:].
 *
 * Frame layout:
 *   Frame 0: VERIFY(sender) → P256 verify → APPROVE(0x2, both)
 *   Frame 1: SENDER(sender) → RLP batch: ETH transfer
 *
 * Usage: cd contracts && npx tsx e2e/eoa/eoa-p256.ts
 */

import { formatEther, keccak256, concatHex, type Hex, type Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toEoaFrameAccount } from "viem/eip8141";
import { p256 } from "@noble/curves/p256";
import { DEV_KEY, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import {
  banner, sectionHeader, info, step, success,
  testHeader, testPassed, summary, fatal, printReceipt,
} from "../helpers/log.js";

// ── P256 key helpers ─────────────────────────────────────────────────

function generateP256Key() {
  const privKey = p256.utils.randomPrivateKey();
  const pubKey = p256.getPublicKey(privKey, false); // uncompressed: 0x04 + x(32) + y(32)

  const x = (`0x${Buffer.from(pubKey.slice(1, 33)).toString("hex")}`) as Hex;
  const y = (`0x${Buffer.from(pubKey.slice(33, 65)).toString("hex")}`) as Hex;

  // EOA address for P256: keccak256(x || y)[12:]
  const address = (`0x${keccak256(concatHex([x, y])).slice(26)}`) as Address;

  return {
    privKey: (`0x${Buffer.from(privKey).toString("hex")}`) as Hex,
    publicKey: { x, y },
    address,
  };
}

async function p256Sign(hash: Hex, privKey: Hex): Promise<{ r: Hex; s: Hex }> {
  const sig = p256.sign(hash.slice(2), privKey.slice(2));
  return {
    r: (`0x${sig.r.toString(16).padStart(64, "0")}`) as Hex,
    s: (`0x${sig.s.toString(16).padStart(64, "0")}`) as Hex,
  };
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("EOA P256 E2E (Default Code, Passkey)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── 1. Generate P256 key pair ──
  sectionHeader("Generate P256 Key Pair");
  const { privKey, publicKey, address: p256Addr } = generateP256Key();
  step(`P256 EOA address: ${p256Addr}`);
  info(`Public key X: ${publicKey.x.slice(0, 18)}...`);
  info(`Public key Y: ${publicKey.y.slice(0, 18)}...`);

  // ── 2. Fund the P256 EOA ──
  sectionHeader("Fund P256 EOA");
  await fundAccount(walletClient, publicClient, p256Addr);

  // ── 3. Send frame tx with P256 signature ──
  testHeader(1, "P256 Verify + Execute (ETH transfer)");

  const account = toEoaFrameAccount({
    signatureType: "p256",
    sign: (hash: Hex) => p256Sign(hash, privKey),
    publicKey,
    verifyGasLimit: 100_000n,
    senderGasLimit: 100_000n,
    scope: 2,
  });

  // Verify derived address matches
  if (account.address.toLowerCase() !== p256Addr.toLowerCase()) {
    throw new Error(
      `Address mismatch: account=${account.address}, expected=${p256Addr}`
    );
  }
  success(`Address derived correctly: ${account.address}`);

  const targetBalance = await publicClient.getBalance({ address: DEAD_ADDR });

  step("Sending 2-frame tx: VERIFY(P256) → SENDER(transfer)...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR, value: 1n }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);

  // Verify receipt
  if (receipt.status !== "0x1") {
    throw new Error(`TX failed: status=${receipt.status}`);
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
  success("Frame 1: SENDER SUCCESS (0x1)");

  // Verify ETH was transferred
  const newTargetBalance = await publicClient.getBalance({ address: DEAD_ADDR });
  if (newTargetBalance - targetBalance !== 1n) {
    throw new Error(
      `Balance delta: got ${newTargetBalance - targetBalance}, want 1`
    );
  }
  success("1 wei transferred to DEAD_ADDR");

  testPassed("EOA P256");
  summary("EOA P256", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
