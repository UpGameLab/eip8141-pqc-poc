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
  parseSignature,
  type Hex,
  type Hash,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  computeSigHash,
  serializeFrameTransaction,
  type TransactionSerializableFrame,
} from "viem/eip8141";
import { CHAIN_ID, DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR } from "../helpers/config.js";
import { waitForReceipt } from "../helpers/client.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { walletAbi } from "../helpers/abis/light-account.js";
import { printReceipt, testHeader, testPassed, testFailed, summary, fatal, detail } from "../helpers/log.js";
import { deployLightAccountTestbed, type LightAccountTestContext } from "./setup.js";
import { createLightAccount, sendAndWait } from "../helpers/send-frame-tx.js";

// secp256k1 curve order
const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/** Build a frame tx and return the params + sigHash (without signing). */
async function buildFrameTxParams(
  ctx: LightAccountTestContext,
  senderCalldata: Hex,
): Promise<{ tx: TransactionSerializableFrame; sigHash: Hex }> {
  const { publicClient, walletAddr } = ctx;
  const nonce = await publicClient.getTransactionCount({ address: walletAddr });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

  const tx: TransactionSerializableFrame = {
    chainId: CHAIN_ID,
    nonce,
    sender: walletAddr,
    maxPriorityFeePerGas: 1_000_000_000n,
    maxFeePerGas: gasFeeCap,
    frames: [
      { mode: "verify", target: null, gasLimit: 300_000n, data: "0x" },
      { mode: "sender", target: null, gasLimit: 500_000n, data: senderCalldata },
    ],
    type: "frame",
  };

  const sigHash = computeSigHash(tx);
  return { tx, sigHash };
}

/** Send a frame tx with a pre-built typed signature. Expects failure (revert/rejection). */
async function sendFrameTxExpectFail(
  ctx: LightAccountTestContext,
  tx: TransactionSerializableFrame,
  typedSig: Hex,
): Promise<boolean> {
  const validateCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "validate",
    args: [typedSig, 2],
  });
  tx.frames[0].data = validateCalldata;

  const rawTx = serializeFrameTransaction(tx);
  try {
    const txHash = (await ctx.publicClient.request({
      method: "eth_sendRawTransaction" as any,
      params: [rawTx],
    })) as Hash;

    // If tx was accepted, check receipt for failure
    const receipt = await waitForReceipt(ctx.publicClient, txHash);
    detail(`Receipt status: ${receipt.status}`);
    if (receipt.frameReceipts) {
      for (let i = 0; i < receipt.frameReceipts.length; i++) {
        detail(`  Frame[${i}] status: ${receipt.frameReceipts[i].status}`);
      }
    }

    // VERIFY frame must fail for the security check to pass
    const verifyStatus = receipt.frameReceipts?.[0]?.status;
    const senderStatus = receipt.frameReceipts?.[1]?.status;
    if (verifyStatus === "0x0") return true;
    if (senderStatus === "0x0") return true;
    if (receipt.status !== "0x1") return true;
    return false;
  } catch (err: any) {
    // Transaction rejected by node — expected behavior
    detail(`Rejected: ${err.message?.slice(0, 80) || err}`);
    return true;
  }
}

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
    const { tx, sigHash } = await buildFrameTxParams(ctx, senderCalldata);

    // Sign normally (low-s, as viem enforces)
    const owner = privateKeyToAccount(DEV_KEY);
    const serializedSig = await owner.sign({ hash: sigHash });
    const { r, s: sHex, yParity } = parseSignature(serializedSig);

    const s = BigInt(sHex);

    // Create high-s variant: s_high = n - s, v_flipped = 1 - yParity
    const sHigh = SECP256K1_N - s;
    const vFlipped = 1 - yParity;

    const rHexStr = r.slice(2);
    const sHighHex = sHigh.toString(16).padStart(64, "0");
    const ecdsaSig = ("0x" + rHexStr + sHighHex + vFlipped.toString(16).padStart(2, "0")) as Hex;
    // Prepend 0x00 (SignatureType.EOA) to the 65-byte ECDSA sig
    const malleableSig = concatHex(["0x00", ecdsaSig]);

    detail(`Original s:  0x${s.toString(16).slice(0, 16)}...`);
    detail(`Malleable s: 0x${sHigh.toString(16).slice(0, 16)}...`);
    detail(`Half-n:      0x7fffffffffffffffffffffffffffffff5d576e73...`);

    const rejected = await sendFrameTxExpectFail(ctx, tx, malleableSig);
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
    const { tx, sigHash } = await buildFrameTxParams(ctx, senderCalldata);

    // Sign with a different key (not the registered owner)
    const wrongOwner = privateKeyToAccount(SECOND_OWNER_KEY);
    const wrongRawSig = await wrongOwner.sign({ hash: sigHash });
    // Prepend 0x00 (SignatureType.EOA) to the 65-byte ECDSA sig
    const wrongSig = concatHex(["0x00", wrongRawSig]);

    const rejected = await sendFrameTxExpectFail(ctx, tx, wrongSig);
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
