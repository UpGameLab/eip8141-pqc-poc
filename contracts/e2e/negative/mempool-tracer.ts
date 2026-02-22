/**
 * E2E: Mempool tracer rejection tests
 *
 * Tests that the ERC-7562 validation tracer correctly rejects VERIFY frames
 * that use banned opcodes, access unassociated storage, fail to APPROVE, etc.
 *
 * All tests expect eth_sendRawTransaction to return an RPC error.
 *
 * Usage: cd contracts && npx tsx e2e/negative/mempool-tracer.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  getContractAddress,
  hexToBytes,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import {
  CHAIN_ID,
  DEV_KEY,
  OWNER2_KEY,
  DEAD_ADDR,
  FRAME_MODE_VERIFY,
  FRAME_MODE_SENDER,
} from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { expectRpcRejection } from "../helpers/expect.js";
import {
  MALICIOUS_VALIDATE_TIMESTAMP,
  MALICIOUS_VALIDATE_COINBASE,
  MALICIOUS_VALIDATE_NUMBER,
  MALICIOUS_VALIDATE_ORIGIN,
  MALICIOUS_VALIDATE_SELFBALANCE,
  MALICIOUS_VALIDATE_BALANCE,
  MALICIOUS_VALIDATE_EXTCODE_NO_CODE,
  MALICIOUS_VALIDATE_GAS_NOT_CALL,
  MALICIOUS_VALIDATE_EXTERNAL_STORAGE,
  MALICIOUS_VALIDATE,
  NO_APPROVE_VALIDATE,
} from "../helpers/abis/malicious.js";
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
 * Build a standard 2-frame tx (VERIFY + SENDER) and encode validate calldata.
 * The selector determines which validate_* function is called.
 * Returns { frameTxParams, calldata } with VERIFY frame data still empty
 * (calldata needs to be set after computing sigHash + signing).
 */
function buildFrameTxParams(
  sender: Address,
  nonce: bigint,
  gasFeeCap: bigint,
  verifyGasLimit = 200_000n
): FrameTxParams {
  return {
    chainId: BigInt(CHAIN_ID),
    nonce,
    sender,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: verifyGasLimit, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: DEAD_ADDR as Address | null, gasLimit: 50_000n, data: new Uint8Array(0) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };
}

/**
 * Encode validate calldata with 3-arg selector: selector(v, r, s)
 * Used for most MaliciousValidator validate_* functions.
 */
function encodeValidate3(selector: string, v: number, r: bigint, s: bigint): Uint8Array {
  const selectorBytes = hexToBytes(selector as Hex);
  const calldata = new Uint8Array(4 + 32 * 3);
  calldata.set(selectorBytes, 0);
  // v in last byte of first 32-byte word
  calldata[35] = v + 27;
  // r
  const rHex = r.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);
  // s
  const sHex = s.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);
  return calldata;
}

/**
 * Encode validate calldata with 4-arg selector: selector(v, r, s, scope)
 * Used for MaliciousValidator.validate and Simple8141Account.validate.
 */
function encodeValidate4(selector: string, v: number, r: bigint, s: bigint, scope: number): Uint8Array {
  const selectorBytes = hexToBytes(selector as Hex);
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
 * Encode validate_external_storage calldata: selector(v, r, s, target)
 */
function encodeValidateExternalStorage(
  selector: string,
  v: number,
  r: bigint,
  s: bigint,
  target: Address
): Uint8Array {
  const selectorBytes = hexToBytes(selector as Hex);
  const calldata = new Uint8Array(4 + 32 * 4);
  calldata.set(selectorBytes, 0);
  calldata[35] = v + 27;
  const rHex = r.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);
  const sHex = s.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);
  // target address in last 20 bytes of 4th word
  const targetBytes = hexToBytes(target as Hex);
  calldata.set(targetBytes, 100 + 12); // offset 100 + 12 bytes padding
  return calldata;
}

/**
 * Sign and send a frame tx, expecting RPC rejection.
 */
async function sendExpectingRejection(
  publicClient: any,
  params: FrameTxParams,
  privKey: Hex,
  calldataBuilder: (v: number, r: bigint, s: bigint) => Uint8Array,
  expectedError?: string
): Promise<string> {
  const sigHash = computeSigHash(params);
  const { r, s, v } = signFrameHash(sigHash, privKey);
  params.frames[0].data = calldataBuilder(v, r, s);
  const rawTx = encodeFrameTx(params);

  return expectRpcRejection(async () => {
    await publicClient.request({
      method: "eth_sendRawTransaction" as any,
      params: [rawTx],
    });
  }, expectedError);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  let passed = 0;
  const total = 12;

  banner("Mempool Tracer Rejection Tests");
  info(`Dev account: ${devAddr}`);

  // ── Deploy contracts ──────────────────────────────────────────────────

  sectionHeader("Deploy test contracts");

  // MaliciousValidator
  const maliciousInitCode = loadBytecode("MaliciousValidator");
  const maliciousConstructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const maliciousDeployData = (maliciousInitCode + maliciousConstructorArg.slice(2)) as Hex;
  const { address: maliciousAddr } = await deployContract(
    walletClient, publicClient, maliciousDeployData, 3_000_000n, "MaliciousValidator"
  );

  // StorageOracle
  const storageInitCode = loadBytecode("StorageOracle");
  const storageConstructorArg = encodeAbiParameters(parseAbiParameters("uint256"), [42n]);
  const storageDeployData = (storageInitCode + storageConstructorArg.slice(2)) as Hex;
  const { address: storageOracleAddr } = await deployContract(
    walletClient, publicClient, storageDeployData, 1_000_000n, "StorageOracle"
  );

  // NoApproveValidator
  const noApproveInitCode = loadBytecode("NoApproveValidator");
  const noApproveConstructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const noApproveDeployData = (noApproveInitCode + noApproveConstructorArg.slice(2)) as Hex;
  const { address: noApproveAddr } = await deployContract(
    walletClient, publicClient, noApproveDeployData, 1_000_000n, "NoApproveValidator"
  );

  // Simple8141Account (for tests 9, 12)
  const simpleInitCode = loadBytecode("Simple8141Account");
  const simpleConstructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const simpleDeployData = (simpleInitCode + simpleConstructorArg.slice(2)) as Hex;
  const { address: simpleAddr } = await deployContract(
    walletClient, publicClient, simpleDeployData, 1_000_000n, "Simple8141Account"
  );

  // Fund all accounts
  sectionHeader("Fund accounts");
  await fundAccount(walletClient, publicClient, maliciousAddr);
  await fundAccount(walletClient, publicClient, noApproveAddr);
  await fundAccount(walletClient, publicClient, simpleAddr);

  // Helper to get nonce + gasFeeCap for an account
  async function getContext(sender: Address) {
    const nonce = BigInt(await publicClient.getTransactionCount({ address: sender }));
    const block = await publicClient.getBlock();
    const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;
    return { nonce, gasFeeCap };
  }

  // ── Test 1: OP-011 TIMESTAMP ──────────────────────────────────────────

  testHeader(1, "OP-011: TIMESTAMP banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_TIMESTAMP, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-011 TIMESTAMP");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 2: OP-011 COINBASE ───────────────────────────────────────────

  testHeader(2, "OP-011: COINBASE banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_COINBASE, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-011 COINBASE");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 3: OP-011 NUMBER ────────────────────────────────────────────

  testHeader(3, "OP-011: NUMBER banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_NUMBER, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-011 NUMBER");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 4: OP-011 ORIGIN ────────────────────────────────────────────

  testHeader(4, "OP-011: ORIGIN banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_ORIGIN, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-011 ORIGIN");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 5: OP-080 SELFBALANCE ───────────────────────────────────────

  testHeader(5, "OP-080: SELFBALANCE banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_SELFBALANCE, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-080 SELFBALANCE");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 6: OP-080 BALANCE ───────────────────────────────────────────

  testHeader(6, "OP-080: BALANCE banned in VERIFY");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_BALANCE, v, r, s),
      "banned opcode"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-080 BALANCE");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 7: OP-041 EXTCODESIZE on codeless address ───────────────────

  testHeader(7, "OP-041: EXTCODESIZE on codeless target");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_EXTCODE_NO_CODE, v, r, s),
      "op-041"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-041 EXTCODESIZE");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 8: OP-012 GAS not before CALL ────────────────────────────────

  testHeader(8, "OP-012: GAS not immediately before CALL");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(MALICIOUS_VALIDATE_GAS_NOT_CALL, v, r, s),
      "op-012"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-012 GAS");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 9: OP-020 Out-of-gas ─────────────────────────────────────────

  testHeader(9, "OP-020: Out-of-gas in VERIFY frame");
  try {
    const ctx = await getContext(simpleAddr);
    // Use very low gas for VERIFY frame to force OOG
    const params = buildFrameTxParams(simpleAddr, ctx.nonce, ctx.gasFeeCap, 100n);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate4(SIMPLE_VALIDATE_SELECTOR, v, r, s, 2),
      "op-020"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("OP-020 Out-of-gas");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 10: STO-021 Unassociated external storage ────────────────────

  testHeader(10, "STO-021: Unassociated external storage read");
  try {
    const ctx = await getContext(maliciousAddr);
    const params = buildFrameTxParams(maliciousAddr, ctx.nonce, ctx.gasFeeCap);
    const sigHash = computeSigHash(params);
    const { r, s, v } = signFrameHash(sigHash, DEV_KEY);
    params.frames[0].data = encodeValidateExternalStorage(
      MALICIOUS_VALIDATE_EXTERNAL_STORAGE, v, r, s, storageOracleAddr
    );
    const rawTx = encodeFrameTx(params);
    const msg = await expectRpcRejection(async () => {
      await publicClient.request({
        method: "eth_sendRawTransaction" as any,
        params: [rawTx],
      });
    }, "sto-021");
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("STO-021 Storage");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 11: VERIFY frame without APPROVE ─────────────────────────────

  testHeader(11, "VERIFY frame returns without APPROVE");
  try {
    const ctx = await getContext(noApproveAddr);
    const params = buildFrameTxParams(noApproveAddr, ctx.nonce, ctx.gasFeeCap);
    const msg = await sendExpectingRejection(
      publicClient, params, DEV_KEY,
      (v, r, s) => encodeValidate3(NO_APPROVE_VALIDATE, v, r, s),
      "approve"
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("No APPROVE");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Test 12: Invalid signature (wrong key) ────────────────────────────

  testHeader(12, "Invalid signature (wrong private key)");
  try {
    const ctx = await getContext(simpleAddr);
    const params = buildFrameTxParams(simpleAddr, ctx.nonce, ctx.gasFeeCap);
    // Sign with OWNER2_KEY instead of DEV_KEY — ecrecover will return wrong address
    const msg = await sendExpectingRejection(
      publicClient, params, OWNER2_KEY,
      (v, r, s) => encodeValidate4(SIMPLE_VALIDATE_SELECTOR, v, r, s, 2)
    );
    step(`Rejected: ${msg.slice(0, 120)}`);
    testPassed("Invalid signature");
    passed++;
  } catch (err: any) {
    console.error(`  FAILED: ${err.message}`);
  }

  // ── Summary ──────────────────────────────────────────────────────────

  summary("Mempool Tracer", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
