/**
 * E2E: CoinbaseSmartWallet8141 WebAuthn P256 owner execution
 *
 * Usage: cd contracts && npx tsx e2e/coinbase/coinbase-webauthn.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  type Hex,
  type Hash,
} from "viem";
import { CHAIN_ID, DEAD_ADDR, FRAME_MODE_VERIFY, FRAME_MODE_SENDER } from "../helpers/config.js";
import { waitForReceipt } from "../helpers/client.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signWithWebAuthn } from "../helpers/webauthn.js";
import { printReceipt, verifyReceipt } from "../helpers/receipt.js";
import { walletAbi } from "../helpers/abis/coinbase.js";
import { testHeader, testPassed, summary, fatal } from "../helpers/log.js";
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

    const frameTxParams: FrameTxParams = {
      chainId: BigInt(CHAIN_ID),
      nonce: BigInt(nonce),
      sender: ctx.walletAddr,
      gasTipCap: 1_000_000_000n,
      gasFeeCap,
      frames: [
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 300_000n, data: new Uint8Array(0) },
        { mode: FRAME_MODE_SENDER, target: null, gasLimit: 500_000n, data: hexToBytes(senderCalldata) },
      ],
      blobFeeCap: 0n,
      blobHashes: [],
    };

    const sigHash = computeSigHash(frameTxParams);
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
    frameTxParams.frames[0].data = hexToBytes(validateCalldata);

    const rawTx = encodeFrameTx(frameTxParams);
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
