/**
 * E2E: LightAccount8141 Security Tests
 *
 * Tests for security fixes:
 * - K-06: Reject malleable (high-s) ECDSA signatures
 * - Wrong signer rejection
 *
 * Usage: cd contracts && npx tsx e2e/light-account/light-account-security.ts
 */

import {
  encodeFunctionData,
  concatHex,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR } from "../helpers/config.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { walletAbi } from "../helpers/abis/light-account.js";
import { printReceipt, testHeader, testPassed, testFailed, summary, fatal, detail } from "../helpers/log.js";
import { deployLightAccountTestbed, type LightAccountTestContext } from "./setup.js";
import { createLightAccount, sendAndWait } from "../helpers/send-frame-tx.js";
import { buildUnsignedFrameTx, createMalleableSig, sendRawFrameTxExpectFail } from "../helpers/security.js";

async function main() {
  const ctx = await deployLightAccountTestbed();
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
    const { malleableSig: ecdsaSig, originalS, highS } = await createMalleableSig(sigHash, DEV_KEY);
    // Prepend 0x00 (SignatureType.EOA) to the 65-byte ECDSA sig
    const malleableSig = concatHex(["0x00", ecdsaSig]);

    detail(`Original s:  0x${originalS.toString(16).slice(0, 16)}...`);
    detail(`Malleable s: 0x${highS.toString(16).slice(0, 16)}...`);
    detail(`Half-n:      0x7fffffffffffffffffffffffffffffff5d576e73...`);

    tx.frames[0].data = encodeFunctionData({
      abi: walletAbi,
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
    const { tx, sigHash } = await buildUnsignedFrameTx(ctx.publicClient, ctx.walletAddr, senderCalldata);

    // Sign with a different key (not the registered owner)
    const wrongOwner = privateKeyToAccount(SECOND_OWNER_KEY);
    const wrongRawSig = await wrongOwner.sign({ hash: sigHash });
    // Prepend 0x00 (SignatureType.EOA) to the 65-byte ECDSA sig
    const wrongSig = concatHex(["0x00", wrongRawSig]);

    tx.frames[0].data = encodeFunctionData({
      abi: walletAbi,
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

  // ── Test 3: Valid signature still works (sanity check) ──────────────
  testHeader(++total, "Valid signature still accepted (sanity check)");
  {
    const account = createLightAccount(ctx.walletAddr);
    const receipt = await sendAndWait(ctx.publicClient, account, senderCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.walletAddr, { expectVerifyStatus: "0x4|0x2" });
    passed++;
    testPassed("Valid signature accepted");
  }

  summary("LightAccount Security", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
