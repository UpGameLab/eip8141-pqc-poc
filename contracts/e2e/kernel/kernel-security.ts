/**
 * E2E: Kernel8141 Security Tests
 *
 * Tests for security fixes:
 * - K-06: Reject malleable (high-s) ECDSA signatures
 * - Wrong signer rejection
 *
 * Usage: cd contracts && npx tsx e2e/kernel/kernel-security.ts
 */

import {
  encodeFunctionData,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR } from "../helpers/config.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi } from "../helpers/abis/kernel.js";
import { printReceipt, testHeader, testPassed, testFailed, summary, fatal, detail } from "../helpers/log.js";
import { deployKernelTestbed } from "./setup.js";
import { encodeExecMode, encodeSingleExec } from "../helpers/exec-encoding.js";
import { createKernelAccount, sendAndWait } from "../helpers/send-frame-tx.js";
import { buildUnsignedFrameTx, createMalleableSig, sendRawFrameTxExpectFail } from "../helpers/security.js";

async function main() {
  const ctx = await deployKernelTestbed();
  let passed = 0;
  let total = 0;

  // Use a no-op SENDER call for all tests
  const execMode = encodeExecMode("0x00" as Hex, "0x00" as Hex);
  const senderCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [execMode, encodeSingleExec(DEAD_ADDR, 0n)],
  });

  // ── Test 1: Reject malleable (high-s) ECDSA signature ───────────────
  testHeader(++total, "Reject malleable (high-s) ECDSA signature");
  {
    const { tx, sigHash } = await buildUnsignedFrameTx(ctx.publicClient, ctx.kernelAddr, senderCalldata);
    const { malleableSig, originalS, highS } = await createMalleableSig(sigHash, DEV_KEY);

    detail(`Original s:  0x${originalS.toString(16).slice(0, 16)}...`);
    detail(`Malleable s: 0x${highS.toString(16).slice(0, 16)}...`);
    detail(`Half-n:      0x7fffffffffffffffffffffffffffffff5d576e73...`);

    // Set VERIFY frame data with the malleable signature
    tx.frames[0].data = encodeFunctionData({
      abi: kernelAbi,
      functionName: "validate",
      args: [malleableSig, 2],
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
    const { tx, sigHash } = await buildUnsignedFrameTx(ctx.publicClient, ctx.kernelAddr, senderCalldata);

    // Sign with a different key (not the registered owner)
    const wrongOwner = privateKeyToAccount(SECOND_OWNER_KEY);
    const wrongSig = await wrongOwner.sign({ hash: sigHash });

    tx.frames[0].data = encodeFunctionData({
      abi: kernelAbi,
      functionName: "validate",
      args: [wrongSig, 2],
    });

    const rejected = await sendRawFrameTxExpectFail(ctx.publicClient, tx);
    if (rejected) {
      passed++;
      testPassed("Wrong signer correctly rejected");
    } else {
      testFailed("Wrong signer was NOT rejected!");
    }
  }

  // ── Test 3: Valid signature still works ──────────────────────────────
  testHeader(++total, "Valid signature still accepted (sanity check)");
  {
    const account = createKernelAccount(ctx.kernelAddr);
    const receipt = await sendAndWait(ctx.publicClient, account, senderCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    passed++;
    testPassed("Valid signature accepted");
  }

  summary("Kernel Security", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
