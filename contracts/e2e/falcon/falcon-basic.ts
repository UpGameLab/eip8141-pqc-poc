/**
 * E2E: Falcon EOA via EIP-8141 default code.
 *
 * Usage: cd contracts && npx tsx e2e/falcon/falcon-basic.ts
 */

import { formatEther, type Address, type Hex } from "viem";
import { toFrameAccount } from "viem/eip8141";
import type { FrameAccount } from "viem/eip8141";
import { DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, fundAccount, waitForReceipt } from "../helpers/client.js";
import { verifyReceipt } from "../helpers/receipt.js";
import {
  FALCON_PK_SIZE,
  FALCON_SIG_SIZE,
  FALCON_SIG_TYPE_SHAKE256,
  buildFalconVerifyData,
  deriveFalconAddress,
  falconSign,
  generateFalconKeypair,
  toHex,
  type FalconEoaScope,
  type FalconSigType,
} from "../helpers/falcon-eth.js";
import {
  banner,
  fatal,
  info,
  printReceipt,
  sectionHeader,
  step,
  success,
  summary,
  testHeader,
  testPassed,
} from "../helpers/log.js";

function createFalconEoaAccount(params: {
  address: Address;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  sigType?: FalconSigType;
  scope?: FalconEoaScope;
  verifyGas?: bigint;
  senderGas?: bigint;
}): FrameAccount {
  const {
    address,
    publicKey,
    secretKey,
    sigType = FALCON_SIG_TYPE_SHAKE256,
    scope = 2,
    verifyGas = 250_000n,
    senderGas = 100_000n,
  } = params;

  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = falconSign(sigHash, secretKey, sigType, scope);
      return [
        {
          mode: "verify" as const,
          flags: scope,
          target: null,
          gasLimit: verifyGas,
          value: 0n,
          data: buildFalconVerifyData(publicKey, sig, scope, sigType),
        },
      ];
    },
    encodeCalls: (calls) =>
      calls.map((call) => ({
        mode: "sender" as const,
        flags: call.flags ?? 0,
        target: call.to,
        gasLimit: senderGas,
        value: call.value ?? 0n,
        data: call.data ?? ("0x" as Hex),
      })),
  });
}

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Falcon EOA E2E (Default Code)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  sectionHeader("Generate Falcon-512 Key Pair");
  const t0 = Date.now();
  const { pk, sk } = generateFalconKeypair();
  const falconAddr = deriveFalconAddress(pk);
  step(`KeyGen complete (${Date.now() - t0}ms)`);
  info(`Public key: ${pk.length} bytes (expected ${FALCON_PK_SIZE})`);
  info(`Secret key: ${sk.length} bytes`);
  info(`Signature size: ${FALCON_SIG_SIZE} bytes`);
  info(`Public key prefix: ${toHex(pk).slice(0, 18)}...`);
  info(`Falcon EOA address: ${falconAddr}`);

  sectionHeader("Fund Falcon EOA");
  await fundAccount(walletClient, publicClient, falconAddr);

  const account = createFalconEoaAccount({
    address: falconAddr,
    publicKey: pk,
    secretKey: sk,
  });

  if (account.address.toLowerCase() !== falconAddr.toLowerCase()) {
    throw new Error(`Address mismatch: account=${account.address}, expected=${falconAddr}`);
  }
  success(`Address derived correctly: ${account.address}`);

  testHeader(1, "Falcon Verify + Execute (ETH transfer)");
  const targetBalance = await publicClient.getBalance({ address: DEAD_ADDR });

  step("Sending 2-frame tx: VERIFY(Falcon) + SENDER(transfer)...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR, value: 1n }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);
  verifyReceipt(receipt, falconAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  const newTargetBalance = await publicClient.getBalance({ address: DEAD_ADDR });
  if (newTargetBalance - targetBalance !== 1n) {
    throw new Error(`Balance delta: got ${newTargetBalance - targetBalance}, want 1`);
  }
  success("1 wei transferred to DEAD_ADDR");
  testPassed("Falcon EOA");

  testHeader(2, "Second Falcon EOA transaction (key reuse)");
  const targetBalance2 = await publicClient.getBalance({ address: DEAD_ADDR });

  step("Sending another frame tx with the same Falcon key...");
  const txHash2 = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR, value: 1n }],
  });

  const receipt2 = await waitForReceipt(publicClient, txHash2);
  verifyReceipt(receipt2, falconAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  const newTargetBalance2 = await publicClient.getBalance({ address: DEAD_ADDR });
  if (newTargetBalance2 - targetBalance2 !== 1n) {
    throw new Error(`Balance delta: got ${newTargetBalance2 - targetBalance2}, want 1`);
  }
  success("Second transaction verified with the same Falcon key");
  testPassed("Falcon EOA Key Reuse");

  summary("Falcon EOA", 2);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
