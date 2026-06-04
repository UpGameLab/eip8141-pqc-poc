/**
 * E2E: CoinbaseSmartWallet8141 WebAuthn P256 owner execution
 *
 * Usage: cd contracts && npx tsx e2e/coinbase/coinbase-webauthn.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  type Hex,
  type Hash,
} from "viem";
import {
  computeSigHash,
  serializeFrameTransaction,
  type TransactionSerializableFrame,
} from "viem/eip8141";
import { CHAIN_ID, DEAD_ADDR } from "../helpers/config.js";
import { waitForReceipt } from "../helpers/client.js";
import { signWithWebAuthn } from "../helpers/webauthn.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { walletAbi } from "../helpers/abis/coinbase.js";
import { printReceipt, testHeader, testPassed, summary, fatal } from "../helpers/log.js";
import { deployCoinbaseTestbed } from "./setup.js";

async function main() {
  const ctx = await deployCoinbaseTestbed();

  testHeader(1, "Execute with P256 WebAuthn Owner");
  {
    const senderCalldata = encodeFunctionData({
      abi: walletAbi,
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    });

    const nonce = await ctx.publicClient.getTransactionCount({ address: ctx.walletAddr });
    const block = await ctx.publicClient.getBlock();
    const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

    const tx: TransactionSerializableFrame = {
      chainId: CHAIN_ID,
      nonce,
      sender: ctx.walletAddr,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: gasFeeCap,
      frames: [
        { mode: "verify", flags: 2, target: null, gasLimit: 300_000n, data: "0x" },
        { mode: "sender", target: null, gasLimit: 500_000n, data: senderCalldata },
      ],
      type: "frame",
    };

    const sigHash = computeSigHash(tx);
    const webAuthnAuth = signWithWebAuthn(sigHash, ctx.p256PrivKey);

    const signatureWrapper = encodeAbiParameters(
      parseAbiParameters("uint256, bytes"),
      [2n, webAuthnAuth]
    );
    const validateCalldata = encodeFunctionData({
      abi: walletAbi,
      functionName: "validate",
      args: [signatureWrapper, 2],
    });
    tx.frames[0].data = validateCalldata;

    const rawTx = serializeFrameTransaction(tx);
    const txHash = (await ctx.publicClient.request({
      method: "eth_sendRawTransaction" as any,
      params: [rawTx],
    })) as Hash;

    const receipt = await waitForReceipt(ctx.publicClient, txHash);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.walletAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("P256 WebAuthn Owner executed successfully");
  }

  summary("Coinbase WebAuthn", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
