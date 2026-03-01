/**
 * Shared helpers for security (malleable signature) tests.
 */

import {
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
import { CHAIN_ID } from "./config.js";
import { waitForReceipt } from "./client.js";
import { detail } from "./log.js";

// secp256k1 curve order
export const SECP256K1_N =
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/** Build a standard unsigned 2-frame tx (VERIFY + SENDER) and compute sigHash. */
export async function buildUnsignedFrameTx(
  publicClient: any,
  sender: Address,
  senderCalldata: Hex,
): Promise<{ tx: TransactionSerializableFrame; sigHash: Hex }> {
  const [nonce, block] = await Promise.all([
    publicClient.getTransactionCount({ address: sender }),
    publicClient.getBlock(),
  ]);
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

  const tx: TransactionSerializableFrame = {
    chainId: CHAIN_ID,
    nonce,
    sender,
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

/**
 * Create a malleable (high-s) ECDSA signature from a valid one.
 * Returns the raw 65-byte malleable sig (r || s_high || v_flipped).
 */
export async function createMalleableSig(
  sigHash: Hex,
  privKey: Hex,
): Promise<{ malleableSig: Hex; originalS: bigint; highS: bigint }> {
  const owner = privateKeyToAccount(privKey);
  const serializedSig = await owner.sign({ hash: sigHash });
  const { r, s: sHex, yParity } = parseSignature(serializedSig);

  const originalS = BigInt(sHex);
  const highS = SECP256K1_N - originalS;
  const vFlipped = 1 - yParity;

  const rHexStr = r.slice(2);
  const sHighHex = highS.toString(16).padStart(64, "0");
  const malleableSig = ("0x" + rHexStr + sHighHex + vFlipped.toString(16).padStart(2, "0")) as Hex;

  return { malleableSig, originalS, highS };
}

/**
 * Send a raw frame tx and expect it to fail (VERIFY revert or node rejection).
 * Returns true if the tx was correctly rejected/failed.
 */
export async function sendRawFrameTxExpectFail(
  publicClient: any,
  tx: TransactionSerializableFrame,
): Promise<boolean> {
  const rawTx = serializeFrameTransaction(tx);
  try {
    const txHash = (await publicClient.request({
      method: "eth_sendRawTransaction" as any,
      params: [rawTx],
    })) as Hash;

    const receipt = await waitForReceipt(publicClient, txHash);
    detail(`Receipt status: ${receipt.status}`);
    if (receipt.frameReceipts) {
      for (let i = 0; i < receipt.frameReceipts.length; i++) {
        detail(`  Frame[${i}] status: ${receipt.frameReceipts[i].status}`);
      }
    }

    const verifyStatus = receipt.frameReceipts?.[0]?.status;
    const senderStatus = receipt.frameReceipts?.[1]?.status;
    if (verifyStatus === "0x0") return true;
    if (senderStatus === "0x0") return true;
    if (receipt.status !== "0x1") return true;
    return false;
  } catch (err: any) {
    detail(`Rejected: ${err.message?.slice(0, 80) || err}`);
    return true;
  }
}
