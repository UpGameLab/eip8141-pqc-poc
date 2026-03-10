/**
 * E2E: EOA Gas Sponsoring — sponsor pays gas with ETH, no token needed
 *
 * Uses EIP-8141 default code with scope=0 (execution only) so a separate
 * sponsor contract can pay gas via APPROVE(0x1).
 *
 * Frame layout:
 *   Frame 0: VERIFY(sender)  → ECDSA verify → APPROVE(0x0, execution only)
 *   Frame 1: VERIFY(sponsor) → sponsor.validate(sig) → APPROVE(0x1, payment)
 *   Frame 2: SENDER(sender)  → RLP batch: user's intended call
 *
 * Usage: cd contracts && npx tsx e2e/eoa/eoa-sponsor.ts
 */

import { formatEther, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toEoaFrameAccount } from "viem/eip8141";
import type { FramePaymaster } from "viem/eip8141";
import { DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import {
  banner, sectionHeader, info, step, success,
  testHeader, testPassed, summary, fatal, printReceipt,
} from "../helpers/log.js";

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  // EOA user — uses SECOND_OWNER_KEY so it's different from the dev/funder
  const userKey = SECOND_OWNER_KEY;
  const user = privateKeyToAccount(userKey);
  // Sponsor signer — the dev account signs for the sponsor
  const sponsorSigner = privateKeyToAccount(DEV_KEY);

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("EOA Gas Sponsoring E2E (Default Code)");
  info(`Dev account: ${devAddr}`);
  info(`User EOA: ${user.address}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy SimplePaymaster (sponsor) ──
  sectionHeader("Deploy SimplePaymaster");
  const paymasterBytecode = loadBytecode("SimplePaymaster");
  // Constructor takes the trusted signer address
  const { encodeAbiParameters, parseAbiParameters } = await import("viem");
  const constructorArg = encodeAbiParameters(
    parseAbiParameters("address"),
    [sponsorSigner.address],
  );
  const initCode = (paymasterBytecode + constructorArg.slice(2)) as Hex;
  const { address: sponsorAddr } = await deployContract(
    walletClient, publicClient, initCode, 1_000_000n, "SimplePaymaster"
  );

  // Fund sponsor with ETH (so it can pay gas)
  sectionHeader("Fund Sponsor");
  await fundAccount(walletClient, publicClient, sponsorAddr, "10");

  // ── Test: Sponsored EOA transaction ──
  testHeader(1, "EOA tx with gas sponsoring (no tokens)");

  // User's EOA account — scope=0 (execution only, sponsor pays gas)
  const account = toEoaFrameAccount({
    owner: user,
    verifyGasLimit: 100_000n,
    senderGasLimit: 100_000n,
    scope: 0,
  });

  // Sponsor paymaster — signs the sigHash to authorize gas payment
  const { encodeFunctionData } = await import("viem");
  const paymaster: FramePaymaster = {
    address: sponsorAddr,
    async signFrameTransaction({ sigHash }) {
      // Sign the sigHash with the sponsor's signer key
      const sig = await sponsorSigner.sign!({ hash: sigHash });
      // encode validate(bytes signature) calldata
      const data = encodeFunctionData({
        abi: [{
          type: "function",
          name: "validate",
          inputs: [{ name: "signature", type: "bytes" }],
          outputs: [],
          stateMutability: "view",
        }],
        functionName: "validate",
        args: [sig],
      });
      return {
        mode: "verify" as const,
        target: sponsorAddr,
        gasLimit: 200_000n,
        data,
      };
    },
  };

  step("Sending 3-frame tx: VERIFY(user,scope=0) → VERIFY(sponsor) → SENDER...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    paymaster,
    calls: [{ to: DEAD_ADDR }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);

  // Verify receipt
  if (receipt.status !== "0x1") {
    throw new Error(`TX failed: status=${receipt.status}`);
  }
  success("Transaction succeeded");

  // Verify frame count: VERIFY(user) + VERIFY(sponsor) + SENDER = 3
  if (!receipt.frameReceipts || receipt.frameReceipts.length !== 3) {
    throw new Error(
      `Frame count: got ${receipt.frameReceipts?.length ?? 0}, want 3`
    );
  }
  success("3 frame receipts present");

  // Frame 0: VERIFY(user) → APPROVED_EXECUTION (0x2)
  const frame0Status = receipt.frameReceipts[0].status;
  if (frame0Status !== "0x2") {
    throw new Error(`Frame 0 (VERIFY/user): got ${frame0Status}, want 0x2`);
  }
  success("Frame 0: APPROVED_EXECUTION (0x2)");

  // Frame 1: VERIFY(sponsor) → APPROVED_PAYMENT (0x3)
  const frame1Status = receipt.frameReceipts[1].status;
  if (frame1Status !== "0x3") {
    throw new Error(`Frame 1 (VERIFY/sponsor): got ${frame1Status}, want 0x3`);
  }
  success("Frame 1: APPROVED_PAYMENT (0x3)");

  // Frame 2: SENDER → SUCCESS (0x1)
  const frame2Status = receipt.frameReceipts[2].status;
  if (frame2Status !== "0x1") {
    throw new Error(`Frame 2 (SENDER): got ${frame2Status}, want 0x1`);
  }
  success("Frame 2: SENDER SUCCESS (0x1)");

  // Verify payer is the sponsor (not the user)
  if (receipt.payer) {
    if (receipt.payer.toLowerCase() !== sponsorAddr.toLowerCase()) {
      throw new Error(`Wrong payer: got ${receipt.payer}, want ${sponsorAddr}`);
    }
    success(`Payer is sponsor: ${sponsorAddr}`);
  }

  testPassed("EOA Gas Sponsoring");
  summary("EOA Sponsor", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
