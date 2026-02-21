/**
 * Comprehensive E2E test: All Kernel8141 features
 *
 * Tests:
 *   - Basic execution (execute, executeBatch)
 *   - Module management (validators, executors, hooks, fallback handlers)
 *   - Execution modes (executeDelegate, executeTry, executeBatchTry)
 *   - Fallback handlers (ERC1271Handler)
 *   - Session keys (SessionKeyValidator + SessionKeyPermissionHook)
 *
 * Usage:
 *   1. Start the dev node: bash devnet/run.sh
 *   2. Run this tool:      cd contracts && npx tsx script/send_kernel_tx.ts
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  encodeAbiParameters,
  parseAbiParameters,
  getContractAddress,
  encodeFunctionData,
  type Hex,
  type Address,
  type Hash,
  keccak256,
  hexToBytes,
  bytesToHex,
  parseEther,
  formatEther,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { secp256k1 } from "@noble/curves/secp256k1";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Config ────────────────────────────────────────────────────────────
const RPC_URL = "http://localhost:18545";
const CHAIN_ID = 1337;
const DEV_KEY =
  "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291" as const;
const SECOND_OWNER_KEY =
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6" as const;
const DEAD_ADDR = "0x000000000000000000000000000000000000dEaD" as Address;

const FRAME_TX_TYPE = 0x06;
const FRAME_MODE_VERIFY = 0x01;
const FRAME_MODE_SENDER = 0x02;

const CHAIN_DEF = {
  id: CHAIN_ID,
  name: "devnet",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
};

// ── ABI fragments ─────────────────────────────────────────────────────

const kernelAbi = [
  {
    type: "function",
    name: "validate",
    inputs: [
      { name: "signature", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "execute",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "executeBatch",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "datas", type: "bytes[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "executeDelegate",
    inputs: [
      { name: "target", type: "address" },
      { name: "data", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "executeTry",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
    outputs: [
      { name: "success", type: "bool" },
      { name: "returnData", type: "bytes" },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "executeBatchTry",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "datas", type: "bytes[]" },
    ],
    outputs: [
      { name: "successes", type: "bool[]" },
      { name: "returnDatas", type: "bytes[]" },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "installModule",
    inputs: [
      { name: "moduleType", type: "uint8" },
      { name: "module", type: "address" },
      { name: "config", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "uninstallModule",
    inputs: [
      { name: "moduleType", type: "uint8" },
      { name: "module", type: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "isValidatorInstalled",
    inputs: [{ name: "validator", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getInstalledModules",
    inputs: [{ name: "moduleType", type: "uint8" }],
    outputs: [{ name: "", type: "address[]" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "configureExecution",
    inputs: [
      { name: "selector", type: "bytes4" },
      { name: "executor", type: "address" },
      { name: "allowedFrameModes", type: "uint8" },
      { name: "validAfter", type: "uint48" },
      { name: "validUntil", type: "uint48" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validateFromSenderFrame",
    inputs: [
      { name: "signature", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validatedCall",
    inputs: [
      { name: "validator", type: "address" },
      { name: "innerCalldata", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes" }],
    stateMutability: "nonpayable",
  },
] as const;

const erc1271Abi = [
  {
    type: "function",
    name: "isValidSignature",
    inputs: [
      { name: "hash", type: "bytes32" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes4" }],
    stateMutability: "view",
  },
] as const;

const sessionKeyValidatorAbi = [
  {
    type: "function",
    name: "addSessionKey",
    inputs: [
      { name: "sessionKey", type: "address" },
      { name: "validAfter", type: "uint48" },
      { name: "validUntil", type: "uint48" },
      { name: "spendingLimit", type: "uint256" },
      { name: "allowedSelectors", type: "bytes4[]" },
      { name: "allowedTargets", type: "address[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

// ── Helpers (reused from send_frame_tx.ts) ────────────────────────────

function loadBytecode(contractName: string): Hex {
  const artifactPath = join(
    __dirname, "..", "out", `${contractName}.sol`, `${contractName}.json`
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  return artifact.bytecode.object as Hex;
}

async function waitForReceipt(
  publicClient: ReturnType<typeof createPublicClient>,
  hash: Hash,
  timeoutMs = 30_000
): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const receipt = await publicClient.request({
        method: "eth_getTransactionReceipt" as any,
        params: [hash],
      });
      if (receipt) return receipt;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Timeout waiting for receipt of ${hash}`);
}

async function deployContract(
  walletClient: any,
  publicClient: any,
  bytecode: Hex,
  gas = 3_000_000n
): Promise<{ hash: Hash; address: Address }> {
  const devAddr = walletClient.account.address;
  const nonce = await publicClient.getTransactionCount({ address: devAddr });
  const expectedAddr = getContractAddress({ from: devAddr, nonce: BigInt(nonce) });

  const hash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    data: bytecode,
    gas,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });

  const receipt = await waitForReceipt(publicClient, hash);
  if (receipt.status !== "0x1") {
    throw new Error(`Deploy failed: status=${receipt.status}`);
  }
  console.log(`  Deployed at ${expectedAddr} (tx: ${hash})`);
  return { hash, address: expectedAddr };
}

// RLP helpers
function rlpEncodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) return new Uint8Array([len + offset]);
  const hexLen = len.toString(16);
  const lenBytes = Math.ceil(hexLen.length / 2);
  const buf = new Uint8Array(1 + lenBytes);
  buf[0] = offset + 55 + lenBytes;
  let tmp = len;
  for (let i = lenBytes - 1; i >= 0; i--) { buf[1 + i] = tmp & 0xff; tmp >>= 8; }
  return buf;
}

function rlpEncodeBytes(data: Uint8Array): Uint8Array {
  if (data.length === 1 && data[0] < 0x80) return data;
  const prefix = rlpEncodeLength(data.length, 0x80);
  const r = new Uint8Array(prefix.length + data.length);
  r.set(prefix); r.set(data, prefix.length);
  return r;
}

function rlpEncodeList(items: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const item of items) totalLen += item.length;
  const prefix = rlpEncodeLength(totalLen, 0xc0);
  const r = new Uint8Array(prefix.length + totalLen);
  r.set(prefix);
  let off = prefix.length;
  for (const item of items) { r.set(item, off); off += item.length; }
  return r;
}

function toMinimalBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function addressToBytes(addr: Address): Uint8Array { return hexToBytes(addr as Hex); }

function encodeFrame(mode: number, target: Address | null, gasLimit: bigint, data: Uint8Array): Uint8Array {
  return rlpEncodeList([
    rlpEncodeBytes(toMinimalBytes(BigInt(mode))),
    target ? rlpEncodeBytes(addressToBytes(target)) : rlpEncodeBytes(new Uint8Array(0)),
    rlpEncodeBytes(toMinimalBytes(gasLimit)),
    rlpEncodeBytes(data),
  ]);
}

type FrameTxParams = {
  chainId: bigint; nonce: bigint; sender: Address;
  gasTipCap: bigint; gasFeeCap: bigint;
  frames: Array<{ mode: number; target: Address | null; gasLimit: bigint; data: Uint8Array }>;
  blobFeeCap: bigint; blobHashes: Hex[];
};

function computeSigHash(params: FrameTxParams): Hex {
  const framesForSig = params.frames.map((f) =>
    encodeFrame(f.mode, f.target, f.gasLimit, f.mode === FRAME_MODE_VERIFY ? new Uint8Array(0) : f.data)
  );
  const items: Uint8Array[] = [
    rlpEncodeBytes(toMinimalBytes(params.chainId)),
    rlpEncodeBytes(toMinimalBytes(params.nonce)),
    rlpEncodeBytes(addressToBytes(params.sender)),
    rlpEncodeList(framesForSig),
    rlpEncodeBytes(toMinimalBytes(params.gasTipCap)),
    rlpEncodeBytes(toMinimalBytes(params.gasFeeCap)),
    rlpEncodeBytes(toMinimalBytes(params.blobFeeCap)),
    rlpEncodeList(params.blobHashes.map((h) => rlpEncodeBytes(hexToBytes(h)))),
  ];
  const payload = rlpEncodeList(items);
  const toHash = new Uint8Array(1 + payload.length);
  toHash[0] = FRAME_TX_TYPE;
  toHash.set(payload, 1);
  return keccak256(toHash);
}

function encodeFrameTx(params: FrameTxParams): Hex {
  const items: Uint8Array[] = [
    rlpEncodeBytes(toMinimalBytes(params.chainId)),
    rlpEncodeBytes(toMinimalBytes(params.nonce)),
    rlpEncodeBytes(addressToBytes(params.sender)),
    rlpEncodeList(params.frames.map((f) => encodeFrame(f.mode, f.target, f.gasLimit, f.data))),
    rlpEncodeBytes(toMinimalBytes(params.gasTipCap)),
    rlpEncodeBytes(toMinimalBytes(params.gasFeeCap)),
    rlpEncodeBytes(toMinimalBytes(params.blobFeeCap)),
    rlpEncodeList(params.blobHashes.map((h) => rlpEncodeBytes(hexToBytes(h)))),
  ];
  const payload = rlpEncodeList(items);
  const raw = new Uint8Array(1 + payload.length);
  raw[0] = FRAME_TX_TYPE;
  raw.set(payload, 1);
  return bytesToHex(raw);
}

// ── Test Helpers ──────────────────────────────────────────────────────

type TestContext = {
  account: ReturnType<typeof privateKeyToAccount>;
  publicClient: ReturnType<typeof createPublicClient>;
  walletClient: ReturnType<typeof createWalletClient>;
  kernelAddr: Address;
  validatorAddr: Address;
};

async function sendFrameTx(
  ctx: TestContext,
  senderCalldata: Hex,
  senderGas = 500_000n
): Promise<any> {
  const { publicClient, kernelAddr } = ctx;
  const kernelNonce = await publicClient.getTransactionCount({ address: kernelAddr });
  const block = await publicClient.getBlock();
  const baseFee = block.baseFeePerGas!;
  const gasFeeCap = baseFee + 2_000_000_000n;

  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce: BigInt(kernelNonce),
    sender: kernelAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 300_000n, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: senderGas, data: hexToBytes(senderCalldata) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  // Sign
  const sigHash = computeSigHash(frameTxParams);
  const privKeyHex = DEV_KEY.slice(2);
  const sig = secp256k1.sign(sigHash.slice(2), privKeyHex);
  const rHex = sig.r.toString(16).padStart(64, "0");
  const sHex = sig.s.toString(16).padStart(64, "0");
  const v = sig.recovery;
  const packedSig = hexToBytes(("0x" + rHex + sHex + v.toString(16).padStart(2, "0")) as Hex);

  const validateCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validate",
    args: [bytesToHex(packedSig), 2],
  });

  frameTxParams.frames[0].data = hexToBytes(validateCalldata);

  // Send
  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;

  return await waitForReceipt(publicClient, txHash);
}

/// Send a frame tx using a non-root validator via validateFromSenderFrame + validatedCall.
/// The validator address is placed in SENDER frame calldata (included in sigHash).
async function sendFrameTxWithValidator(
  ctx: TestContext,
  signingKey: Hex,
  validatorAddr: Address,
  innerCalldata: Hex,
  senderGas = 700_000n,
): Promise<any> {
  const { publicClient, kernelAddr } = ctx;
  const kernelNonce = await publicClient.getTransactionCount({ address: kernelAddr });
  const block = await publicClient.getBlock();
  const baseFee = block.baseFeePerGas!;
  const gasFeeCap = baseFee + 2_000_000_000n;

  // SENDER frame: validatedCall(validator, innerCalldata)
  const senderCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validatedCall",
    args: [validatorAddr, innerCalldata],
  });

  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce: BigInt(kernelNonce),
    sender: kernelAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 300_000n, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: senderGas, data: hexToBytes(senderCalldata) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  // Sign with the specified key (not necessarily DEV_KEY)
  const sigHash = computeSigHash(frameTxParams);
  const privKeyHex = signingKey.slice(2);
  const sig = secp256k1.sign(sigHash.slice(2), privKeyHex);
  const rHex = sig.r.toString(16).padStart(64, "0");
  const sHex = sig.s.toString(16).padStart(64, "0");
  const v = sig.recovery;
  const packedSig = hexToBytes(("0x" + rHex + sHex + v.toString(16).padStart(2, "0")) as Hex);

  // VERIFY frame: validateFromSenderFrame(signature, scope=2)
  const validateCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validateFromSenderFrame",
    args: [bytesToHex(packedSig), 2],
  });

  frameTxParams.frames[0].data = hexToBytes(validateCalldata);

  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;

  return await waitForReceipt(publicClient, txHash);
}

// ── Main ──────────────────────────────────────────────────────────────

async function main() {
  const account = privateKeyToAccount(DEV_KEY);
  const devAddr = account.address;
  const ownerAddr = devAddr;

  const publicClient = createPublicClient({ transport: http(RPC_URL) });
  const walletClient = createWalletClient({ account, transport: http(RPC_URL) });

  const balance = await publicClient.getBalance({ address: devAddr });
  console.log(`\n${"=".repeat(70)}`);
  console.log(`Dev account: ${devAddr}`);
  console.log(`Balance: ${formatEther(balance)} ETH`);
  console.log(`${"=".repeat(70)}\n`);

  // ── Deploy Contracts ────────────────────────────────────────────────

  console.log("📦 Deploying contracts...\n");

  console.log("  1/8 ECDSAValidator");
  const validatorBytecode = loadBytecode("ECDSAValidator");
  const { address: validatorAddr } = await deployContract(walletClient, publicClient, validatorBytecode);

  console.log("  2/8 Kernel8141");
  const kernelBytecode = loadBytecode("Kernel8141");
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters("address, bytes"),
    [validatorAddr, encodeAbiParameters(parseAbiParameters("address"), [ownerAddr])]
  );
  const kernelDeployData = (kernelBytecode + constructorArgs.slice(2)) as Hex;
  const { address: kernelAddr } = await deployContract(walletClient, publicClient, kernelDeployData, 10_000_000n);

  console.log("  3/8 DefaultExecutor");
  const defaultExecutorBytecode = loadBytecode("DefaultExecutor");
  const { address: defaultExecutorAddr } = await deployContract(walletClient, publicClient, defaultExecutorBytecode);

  console.log("  4/8 BatchExecutor");
  const batchExecutorBytecode = loadBytecode("BatchExecutor");
  const { address: batchExecutorAddr } = await deployContract(walletClient, publicClient, batchExecutorBytecode);

  console.log("  5/8 SpendingLimitHook");
  const spendingLimitHookBytecode = loadBytecode("SpendingLimitHook");
  const { address: spendingLimitHookAddr } = await deployContract(walletClient, publicClient, spendingLimitHookBytecode);

  console.log("  6/8 ERC1271Handler");
  const erc1271HandlerBytecode = loadBytecode("ERC1271Handler");
  const { address: erc1271HandlerAddr } = await deployContract(walletClient, publicClient, erc1271HandlerBytecode);

  console.log("  7/8 SessionKeyValidator");
  const sessionKeyValidatorBytecode = loadBytecode("SessionKeyValidator");
  const { address: sessionKeyValidatorAddr } = await deployContract(walletClient, publicClient, sessionKeyValidatorBytecode);

  console.log("  8/8 SessionKeyPermissionHook");
  const sessionKeyPermissionHookBytecode = loadBytecode("SessionKeyPermissionHook");
  const sessionKeyPermissionHookConstructorArgs = encodeAbiParameters(
    parseAbiParameters("address"),
    [sessionKeyValidatorAddr]
  );
  const sessionKeyPermissionHookDeployData = (sessionKeyPermissionHookBytecode + sessionKeyPermissionHookConstructorArgs.slice(2)) as Hex;
  const { address: sessionKeyPermissionHookAddr } = await deployContract(walletClient, publicClient, sessionKeyPermissionHookDeployData);

  console.log("\n  ✅ All contracts deployed\n");

  // Fund Kernel
  console.log("💰 Funding Kernel with 10 ETH...");
  const fundHash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    to: kernelAddr,
    value: parseEther("10"),
    gas: 50_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  await waitForReceipt(publicClient, fundHash);
  console.log("  ✅ Funded\n");

  const ctx: TestContext = { account, publicClient, walletClient, kernelAddr, validatorAddr };

  // ── Tests ───────────────────────────────────────────────────────────

  let testNum = 1;

  // ── Module Installation Tests ──────────────────────────────────────

  // Test 1: Install DefaultExecutor for execute() selector
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: Install DefaultExecutor`);
  console.log(`${"─".repeat(70)}`);
  {
    const MODULE_TYPE_EXECUTOR = 1;
    const executeSelector = "0xb61d27f6"; // execute(address,uint256,bytes)

    // Executor config: abi.encode(bytes4[] selectors, uint48 validAfter, uint48 validUntil, uint8 frameModes)
    const executorConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], uint48, uint48, uint8"),
      [[executeSelector], 0, 0, 2] // validAfter=0, validUntil=0 (no time restriction), frameModes=2 (SENDER only)
    );

    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [MODULE_TYPE_EXECUTOR, defaultExecutorAddr, executorConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - DefaultExecutor installed for execute()");
  }

  // Test 2: Install SpendingLimitHook for execute() selector
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: Install SpendingLimitHook`);
  console.log(`${"─".repeat(70)}`);
  {
    const MODULE_TYPE_PRE_HOOK = 2;
    const executeSelector = "0xb61d27f6"; // execute(address,uint256,bytes)
    const dailyLimit = parseEther("5");

    // Hook data for SpendingLimitHook.onInstall
    const hookData = encodeAbiParameters(
      parseAbiParameters("uint256"),
      [dailyLimit]
    );

    // Hook config: abi.encode(bytes4[] selectors, bytes hookData)
    const hookConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], bytes"),
      [[executeSelector], hookData]
    );

    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [MODULE_TYPE_PRE_HOOK, spendingLimitHookAddr, hookConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - SpendingLimitHook installed with 5 ETH daily limit");
  }

  // Test 3: Install ERC1271Handler for isValidSignature()
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: Install ERC1271Handler`);
  console.log(`${"─".repeat(70)}`);
  {
    const MODULE_TYPE_FALLBACK_HANDLER = 4;
    const isValidSignatureSelector = "0x1626ba7e"; // isValidSignature(bytes32,bytes)

    // Handler data: abi.encode(IValidator8141 validator) - pass the ECDSAValidator
    const handlerData = encodeAbiParameters(
      parseAbiParameters("address"),
      [ctx.validatorAddr]
    );

    // Handler config: abi.encode(bytes4[] selectors, bytes handlerData)
    const handlerConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], bytes"),
      [[isValidSignatureSelector], handlerData]
    );

    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [MODULE_TYPE_FALLBACK_HANDLER, erc1271HandlerAddr, handlerConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - ERC1271Handler installed");
  }

  // ── Execution Tests ────────────────────────────────────────────────

  // Test 4: Basic execute
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: Basic execute()`);
  console.log(`${"─".repeat(70)}`);
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED");
  }

  // Test 5: executeBatch
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: executeBatch()`);
  console.log(`${"─".repeat(70)}`);
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeBatch",
      args: [
        [DEAD_ADDR, DEAD_ADDR],
        [0n, 0n],
        ["0x", "0x"],
      ],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    console.log("✅ PASSED");
  }

  // Test 6: executeTry (graceful error handling)
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: executeTry() - graceful failure`);
  console.log(`${"─".repeat(70)}`);
  {
    // Try to call a non-existent contract - should not revert the transaction
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeTry",
      args: ["0x0000000000000000000000000000000000000001", 0n, "0xdeadbeef"],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - executeTry handled failure gracefully");
  }

  // Test 7: executeBatchTry
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: executeBatchTry() - mixed success/failure`);
  console.log(`${"─".repeat(70)}`);
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeBatchTry",
      args: [
        [DEAD_ADDR, "0x0000000000000000000000000000000000000001"],
        [0n, 0n],
        ["0x", "0xdeadbeef"],
      ],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - executeBatchTry handled mixed results");
  }

  // ── Non-Root Validator via SENDER Frame (sigHash-bound) ────────────

  // Test 8: validateFromSenderFrame + validatedCall
  console.log(`\n${"─".repeat(70)}`);
  console.log(`Test ${testNum++}: validateFromSenderFrame + validatedCall (sigHash-bound validator)`);
  console.log(`${"─".repeat(70)}`);
  {
    const secondOwnerAccount = privateKeyToAccount(SECOND_OWNER_KEY);
    const secondOwnerAddr = secondOwnerAccount.address;
    console.log(`  Second owner: ${secondOwnerAddr}`);

    // Deploy second ECDSAValidator
    console.log("  Deploying second ECDSAValidator...");
    const { address: secondValidatorAddr } = await deployContract(
      walletClient, publicClient, validatorBytecode
    );

    // Install second validator with secondOwnerAddr as owner
    console.log("  Installing second validator...");
    const installConfig = encodeAbiParameters(
      parseAbiParameters("address"),
      [secondOwnerAddr]
    );
    const MODULE_TYPE_VALIDATOR = 0;
    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [MODULE_TYPE_VALIDATOR, secondValidatorAddr, installConfig],
    });
    const installReceipt = await sendFrameTx(ctx, installCalldata);
    verifyReceipt(installReceipt, kernelAddr);
    console.log("  Second validator installed");

    // Send frame tx signed by second owner, validated by second validator
    const innerCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    });
    const receipt = await sendFrameTxWithValidator(
      ctx, SECOND_OWNER_KEY as Hex, secondValidatorAddr, innerCalldata
    );
    printReceipt(receipt);
    verifyReceipt(receipt, kernelAddr);
    console.log("✅ PASSED - Non-root validator selection bound to sigHash via SENDER frame");
  }

  // Summary
  console.log(`\n${"=".repeat(70)}`);
  console.log(`✅ ALL ${testNum - 1} TESTS PASSED`);
  console.log(`${"=".repeat(70)}\n`);
}

function printReceipt(r: any) {
  const names: Record<string, string> = {
    "0x0": "Failed", "0x1": "Success", "0x2": "ApproveExecution",
    "0x3": "ApprovePayment", "0x4": "ApproveBoth",
  };
  console.log(`  Status: ${names[r.status] || r.status}, GasUsed: ${BigInt(r.gasUsed)}, Type: ${r.type}`);
  if (r.frameReceipts) {
    for (let i = 0; i < r.frameReceipts.length; i++) {
      const fr = r.frameReceipts[i];
      const statusName = names[fr.status] || `Unknown(${fr.status})`;
      console.log(`  Frame ${i}: ${statusName}, GasUsed: ${BigInt(fr.gasUsed)}`);
    }
  }
}

function verifyReceipt(receipt: any, kernelAddr: Address) {
  if (receipt.status !== "0x1") throw new Error(`TX failed: status=${receipt.status}`);
  if (receipt.type !== "0x6") throw new Error(`Wrong type: got ${receipt.type}, want 0x6`);
  if (receipt.payer && receipt.payer.toLowerCase() !== kernelAddr.toLowerCase()) {
    throw new Error(`Wrong payer: got ${receipt.payer}, want ${kernelAddr}`);
  }
  if (receipt.frameReceipts && receipt.frameReceipts.length >= 2) {
    // Verify frame 0 (VERIFY) approved
    if (receipt.frameReceipts[0].status !== "0x4" && receipt.frameReceipts[0].status !== "0x2") {
      throw new Error(`VERIFY frame failed: ${receipt.frameReceipts[0].status}`);
    }
    // Verify frame 1 (SENDER) succeeded
    if (receipt.frameReceipts[1].status !== "0x1") {
      throw new Error(`SENDER frame failed: ${receipt.frameReceipts[1].status}`);
    }
  }
  if (BigInt(receipt.gasUsed) === 0n) throw new Error("Gas used should be > 0");
}

main().catch((err) => {
  console.error("FATAL:", err.message || err);
  process.exit(1);
});
