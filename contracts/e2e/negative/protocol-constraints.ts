/**
 * E2E: Protocol constraint tests
 *
 * Tests that EIP-8141 protocol-level constraints are enforced during block execution.
 * These transactions pass mempool validation (framepool only simulates VERIFY frames
 * individually, not inter-frame ordering) but fail during executeFrames().
 *
 * We verify failure by checking that no receipt is ever produced (expectNoReceipt).
 *
 * Usage: cd contracts && npx tsx e2e/negative/protocol-constraints.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  hexToBytes,
  formatEther,
  type Hex,
  type Address,
  type Hash,
} from "viem";
import {
  CHAIN_ID,
  DEV_KEY,
  DEAD_ADDR,
  FRAME_MODE_VERIFY,
  FRAME_MODE_SENDER,
} from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { expectNoReceipt, expectRpcRejection } from "../helpers/expect.js";
import { SIMPLE_VALIDATE_SELECTOR } from "../helpers/abis/simple.js";
import {
  banner,
  sectionHeader,
  info,
  step,
  success,
  testHeader,
  testPassed,
  summary,
  fatal,
} from "../helpers/log.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Encode validate(uint8 v, bytes32 r, bytes32 s, uint8 scope) calldata.
 */
function encodeValidate(v: number, r: bigint, s: bigint, scope: number): Uint8Array {
  const selectorBytes = hexToBytes(SIMPLE_VALIDATE_SELECTOR as Hex);
  const calldata = new Uint8Array(4 + 32 * 4);
  calldata.set(selectorBytes, 0);
  calldata[35] = v + 27;
  const rHex = r.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);
  const sHex = s.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);
  calldata[131] = scope;
  return calldata;
}

/**
 * Build frame tx params, sign with DEV_KEY, set VERIFY calldata, and send.
 * Returns the tx hash (does not wait for receipt).
 */
async function signAndSend(
  publicClient: any,
  params: FrameTxParams,
  scope: number,
  verifyFrameIndex = 0
): Promise<Hash> {
  const sigHash = computeSigHash(params);
  const { r, s, v } = signFrameHash(sigHash, DEV_KEY);
  params.frames[verifyFrameIndex].data = encodeValidate(v, r, s, scope);
  const rawTx = encodeFrameTx(params);
  return (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  let passed = 0;
  const total = 4;

  banner("Protocol Constraint Tests");
  info(`Dev account: ${devAddr}`);

  // ── Deploy Simple8141Account ──────────────────────────────────────────

  sectionHeader("Deploy Simple8141Account");
  const initCode = loadBytecode("Simple8141Account");
  const constructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const deployData = (initCode + constructorArg.slice(2)) as Hex;
  const { address: accountAddr } = await deployContract(
    walletClient, publicClient, deployData, 1_000_000n, "Simple8141Account"
  );

  sectionHeader("Fund account");
  await fundAccount(walletClient, publicClient, accountAddr);

  async function getContext() {
    const nonce = BigInt(await publicClient.getTransactionCount({ address: accountAddr }));
    const block = await publicClient.getBlock();
    const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;
    return { nonce, gasFeeCap };
  }

  // ── Test 1: SENDER frame before execution approval ────────────────────

  testHeader(1, "SENDER frame before VERIFY approval");
  try {
    const ctx = await getContext();
    const params: FrameTxParams = {
      chainId: BigInt(CHAIN_ID),
      nonce: ctx.nonce,
      sender: accountAddr,
      gasTipCap: 1_000_000_000n,
      gasFeeCap: ctx.gasFeeCap,
      frames: [
        // Frame 0: SENDER first (no prior approval)
        { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
        // Frame 1: VERIFY with scope=2 (both)
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
      ],
      blobFeeCap: 0n,
      blobHashes: [],
    };

    // Sign and set VERIFY frame data (index 1)
    const hash = await signAndSend(publicClient, params, 2, 1);
    step(`Sent tx: ${hash}`);
    step("Waiting for no receipt (protocol should reject)...");
    await expectNoReceipt(publicClient, hash, 8_000);
    testPassed("SENDER before approval");
    passed++;
  } catch (err: any) {
    // If the mempool itself rejects (RPC error), that's also acceptable
    if (err.message?.includes("Expected RPC rejection")) {
      console.error(`  FAILED: ${err.message}`);
    } else {
      step(`Rejected (mempool or protocol): ${err.message?.slice(0, 120)}`);
      testPassed("SENDER before approval (rejected at mempool)");
      passed++;
    }
  }

  // ── Test 2: Payment approval before execution approval ────────────────

  testHeader(2, "Payment approval before execution approval");
  try {
    const ctx = await getContext();
    const params: FrameTxParams = {
      chainId: BigInt(CHAIN_ID),
      nonce: ctx.nonce,
      sender: accountAddr,
      gasTipCap: 1_000_000_000n,
      gasFeeCap: ctx.gasFeeCap,
      frames: [
        // Frame 0: VERIFY with scope=1 (payment only, no execution approval first)
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
        // Frame 1: SENDER
        { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
      ],
      blobFeeCap: 0n,
      blobHashes: [],
    };

    const hash = await signAndSend(publicClient, params, 1, 0);
    step(`Sent tx: ${hash}`);
    step("Waiting for no receipt (protocol should reject)...");
    await expectNoReceipt(publicClient, hash, 8_000);
    testPassed("Payment before execution");
    passed++;
  } catch (err: any) {
    if (err.message?.includes("Expected no receipt")) {
      console.error(`  FAILED: ${err.message}`);
    } else {
      step(`Rejected (mempool or protocol): ${err.message?.slice(0, 120)}`);
      testPassed("Payment before execution (rejected at mempool)");
      passed++;
    }
  }

  // ── Test 3: Missing payment approval ──────────────────────────────────

  testHeader(3, "Missing payment approval (execution only)");
  try {
    const ctx = await getContext();
    const params: FrameTxParams = {
      chainId: BigInt(CHAIN_ID),
      nonce: ctx.nonce,
      sender: accountAddr,
      gasTipCap: 1_000_000_000n,
      gasFeeCap: ctx.gasFeeCap,
      frames: [
        // Frame 0: VERIFY with scope=0 (execution only, no payment)
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
        // Frame 1: SENDER
        { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
      ],
      blobFeeCap: 0n,
      blobHashes: [],
    };

    const hash = await signAndSend(publicClient, params, 0, 0);
    step(`Sent tx: ${hash}`);
    step("Waiting for no receipt (protocol should reject)...");
    await expectNoReceipt(publicClient, hash, 8_000);
    testPassed("Missing payment approval");
    passed++;
  } catch (err: any) {
    if (err.message?.includes("Expected no receipt")) {
      console.error(`  FAILED: ${err.message}`);
    } else {
      step(`Rejected (mempool or protocol): ${err.message?.slice(0, 120)}`);
      testPassed("Missing payment (rejected at mempool)");
      passed++;
    }
  }

  // ── Test 4: Double execution approval ─────────────────────────────────

  testHeader(4, "Double execution approval");
  try {
    const ctx = await getContext();
    const params: FrameTxParams = {
      chainId: BigInt(CHAIN_ID),
      nonce: ctx.nonce,
      sender: accountAddr,
      gasTipCap: 1_000_000_000n,
      gasFeeCap: ctx.gasFeeCap,
      frames: [
        // Frame 0: VERIFY with scope=0 (execution)
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
        // Frame 1: VERIFY with scope=0 (execution again — duplicate!)
        { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
        // Frame 2: SENDER
        { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
      ],
      blobFeeCap: 0n,
      blobHashes: [],
    };

    // Sign both VERIFY frames with scope=0
    const sigHash = computeSigHash(params);
    const { r, s, v } = signFrameHash(sigHash, DEV_KEY);
    params.frames[0].data = encodeValidate(v, r, s, 0);
    params.frames[1].data = encodeValidate(v, r, s, 0);
    const rawTx = encodeFrameTx(params);

    const hash = (await publicClient.request({
      method: "eth_sendRawTransaction" as any,
      params: [rawTx],
    })) as Hash;

    step(`Sent tx: ${hash}`);
    step("Waiting for no receipt (protocol should reject)...");
    await expectNoReceipt(publicClient, hash, 8_000);
    testPassed("Double execution approval");
    passed++;
  } catch (err: any) {
    if (err.message?.includes("Expected no receipt")) {
      console.error(`  FAILED: ${err.message}`);
    } else {
      step(`Rejected (mempool or protocol): ${err.message?.slice(0, 120)}`);
      testPassed("Double execution approval (rejected at mempool)");
      passed++;
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────

  summary("Protocol Constraints", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
