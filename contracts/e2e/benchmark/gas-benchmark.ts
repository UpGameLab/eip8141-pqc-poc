/**
 * EIP-8141 Gas Benchmark
 *
 * Measures gas costs for ETH transfer and ERC20 transfer across
 * Simple8141Account, Kernel8141, and CoinbaseSmartWallet8141.
 *
 * Usage: cd contracts && npx tsx e2e/benchmark/gas-benchmark.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  bytesToHex,
  type Hex,
  type Address,
  type Hash,
} from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  CHAIN_ID,
  DEV_KEY,
  DEAD_ADDR,
  CHAIN_DEF,
  FRAME_MODE_VERIFY,
  FRAME_MODE_SENDER,
} from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi } from "../helpers/abis/kernel.js";
import { walletAbi } from "../helpers/abis/coinbase.js";
import { SIMPLE_VALIDATE_SELECTOR, simpleAccountAbi } from "../helpers/abis/simple.js";
import { benchmarkTokenAbi } from "../helpers/abis/benchmark-token.js";
import { banner, sectionHeader, info, step, success, fatal } from "../helpers/log.js";

// ─── Types ───────────────────────────────────────────────────

type GasResult = {
  label: string;
  totalGas: bigint;
  verifyGas: bigint;
  senderGas: bigint;
};

// ─── ANSI colors ─────────────────────────────────────────────

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
};

// ─── Helpers ─────────────────────────────────────────────────

const { publicClient, walletClient, devAddr } = createTestClients();

async function getFrameTxBase(sender: Address) {
  const nonce = await publicClient.getTransactionCount({ address: sender });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;
  return { nonce: BigInt(nonce), gasFeeCap };
}

function extractGas(receipt: any): { totalGas: bigint; verifyGas: bigint; senderGas: bigint } {
  return {
    totalGas: BigInt(receipt.gasUsed),
    verifyGas: BigInt(receipt.frameReceipts[0].gasUsed),
    senderGas: BigInt(receipt.frameReceipts[1].gasUsed),
  };
}

/** Send a regular L1 tx (for minting tokens, etc.) */
async function sendTx(to: Address, data: Hex): Promise<void> {
  const hash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    to,
    data,
    gas: 200_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  const receipt = await waitForReceipt(publicClient, hash);
  if (receipt.status !== "0x1") throw new Error(`Tx failed: ${hash}`);
}

// ─── Simple8141Account ──────────────────────────────────────

async function deploySimple(): Promise<Address> {
  const bytecode = loadBytecode("Simple8141Account");
  const constructorArg = encodeAbiParameters(parseAbiParameters("address"), [devAddr]);
  const deployData = (bytecode + constructorArg.slice(2)) as Hex;
  const { address } = await deployContract(walletClient, publicClient, deployData, 2_000_000n, "Simple8141Account");
  return address;
}

function buildSimpleValidateCalldata(sigHash: Hex): Uint8Array {
  const { r, s, v } = signFrameHash(sigHash, DEV_KEY);
  const selector = hexToBytes(SIMPLE_VALIDATE_SELECTOR as Hex);
  const calldata = new Uint8Array(4 + 32 * 4);
  calldata.set(selector, 0);
  calldata[35] = v + 27;
  const rHex = r.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);
  const sHex = s.toString(16).padStart(64, "0");
  calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);
  calldata[131] = 2; // scope=2 (both)
  return calldata;
}

async function sendSimpleFrameTx(accountAddr: Address, senderCalldata: Hex): Promise<any> {
  const { nonce, gasFeeCap } = await getFrameTxBase(accountAddr);
  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce,
    sender: accountAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: 200_000n, data: hexToBytes(senderCalldata) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  const sigHash = computeSigHash(frameTxParams);
  frameTxParams.frames[0].data = buildSimpleValidateCalldata(sigHash);

  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;
  return await waitForReceipt(publicClient, txHash);
}

// ─── Kernel8141 ─────────────────────────────────────────────

async function deployKernel(): Promise<{ kernelAddr: Address; validatorAddr: Address }> {
  const validatorBytecode = loadBytecode("ECDSAValidator");
  const { address: validatorAddr } = await deployContract(
    walletClient, publicClient, validatorBytecode, 3_000_000n, "ECDSAValidator"
  );

  const kernelBytecode = loadBytecode("Kernel8141");
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters("address, bytes"),
    [validatorAddr, encodeAbiParameters(parseAbiParameters("address"), [devAddr])]
  );
  const deployData = (kernelBytecode + constructorArgs.slice(2)) as Hex;
  const { address: kernelAddr } = await deployContract(
    walletClient, publicClient, deployData, 10_000_000n, "Kernel8141"
  );
  return { kernelAddr, validatorAddr };
}

async function sendKernelFrameTx(kernelAddr: Address, senderCalldata: Hex): Promise<any> {
  const { nonce, gasFeeCap } = await getFrameTxBase(kernelAddr);
  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce,
    sender: kernelAddr,
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
  const sig = secp256k1.sign(sigHash.slice(2), DEV_KEY.slice(2));
  const rHex = sig.r.toString(16).padStart(64, "0");
  const sHex = sig.s.toString(16).padStart(64, "0");
  const v = sig.recovery;
  const ecdsaSig = hexToBytes(("0x" + rHex + sHex + v.toString(16).padStart(2, "0")) as Hex);

  const validateCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validate",
    args: [bytesToHex(ecdsaSig), 2],
  });
  frameTxParams.frames[0].data = hexToBytes(validateCalldata);

  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;
  return await waitForReceipt(publicClient, txHash);
}

// ─── CoinbaseSmartWallet8141 ────────────────────────────────

async function deployCoinbase(): Promise<Address> {
  const bytecode = loadBytecode("CoinbaseSmartWallet8141");
  const owners = [
    encodeAbiParameters(parseAbiParameters("address"), [devAddr]),
  ];
  const constructorArgs = encodeAbiParameters(parseAbiParameters("bytes[]"), [owners]);
  const deployData = (bytecode + constructorArgs.slice(2)) as Hex;
  const { address } = await deployContract(
    walletClient, publicClient, deployData, 5_000_000n, "CoinbaseSmartWallet8141"
  );
  return address;
}

async function sendCoinbaseFrameTx(walletAddr: Address, senderCalldata: Hex): Promise<any> {
  const { nonce, gasFeeCap } = await getFrameTxBase(walletAddr);
  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce,
    sender: walletAddr,
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
  const sig = secp256k1.sign(sigHash.slice(2), DEV_KEY.slice(2));
  const rHex = sig.r.toString(16).padStart(64, "0");
  const sHex = sig.s.toString(16).padStart(64, "0");
  const v = sig.recovery;
  const ecdsaSig = hexToBytes(("0x" + rHex + sHex + v.toString(16).padStart(2, "0")) as Hex);

  const signatureWrapper = encodeAbiParameters(
    parseAbiParameters("uint256, bytes"),
    [0n, bytesToHex(ecdsaSig)]
  );
  const validateCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "validate",
    args: [signatureWrapper, 2],
  });
  frameTxParams.frames[0].data = hexToBytes(validateCalldata);

  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;
  return await waitForReceipt(publicClient, txHash);
}

// ─── Table output ───────────────────────────────────────────

function pad(s: string, len: number, align: "left" | "right" = "right"): string {
  if (align === "left") return s.padEnd(len);
  return s.padStart(len);
}

function fmtGas(gas: bigint): string {
  return gas.toLocaleString();
}

function printTable(results: GasResult[]) {
  const col0 = 20;
  const col1 = 12;
  const col2 = 12;
  const col3 = 12;
  const width = col0 + col1 + col2 + col3 + 7; // 7 = borders + padding

  console.log(`\n${c.cyan}┌${"─".repeat(width)}┐${c.reset}`);
  console.log(
    `${c.cyan}│${c.reset} ${c.bold}${pad("Operation", col0, "left")}${c.reset}` +
    ` ${c.cyan}│${c.reset} ${c.bold}${pad("Total Gas", col1)}${c.reset}` +
    ` ${c.cyan}│${c.reset} ${c.bold}${pad("Verify Gas", col2)}${c.reset}` +
    ` ${c.cyan}│${c.reset} ${c.bold}${pad("Sender Gas", col3)}${c.reset}` +
    ` ${c.cyan}│${c.reset}`
  );
  console.log(
    `${c.cyan}├${"─".repeat(col0 + 2)}┼${"─".repeat(col1 + 2)}┼${"─".repeat(col2 + 2)}┼${"─".repeat(col3 + 2)}┤${c.reset}`
  );

  for (const r of results) {
    const isHeader = r.totalGas === 0n;
    if (isHeader) {
      console.log(
        `${c.cyan}│${c.reset} ${c.yellow}${c.bold}${pad(r.label, col0, "left")}${c.reset}` +
        ` ${c.cyan}│${c.reset} ${pad("", col1)}` +
        ` ${c.cyan}│${c.reset} ${pad("", col2)}` +
        ` ${c.cyan}│${c.reset} ${pad("", col3)}` +
        ` ${c.cyan}│${c.reset}`
      );
    } else {
      console.log(
        `${c.cyan}│${c.reset} ${pad(r.label, col0, "left")}` +
        ` ${c.cyan}│${c.reset} ${c.green}${pad(fmtGas(r.totalGas), col1)}${c.reset}` +
        ` ${c.cyan}│${c.reset} ${c.dim}${pad(fmtGas(r.verifyGas), col2)}${c.reset}` +
        ` ${c.cyan}│${c.reset} ${c.dim}${pad(fmtGas(r.senderGas), col3)}${c.reset}` +
        ` ${c.cyan}│${c.reset}`
      );
    }
  }

  console.log(`${c.cyan}└${"─".repeat(col0 + 2)}┴${"─".repeat(col1 + 2)}┴${"─".repeat(col2 + 2)}┴${"─".repeat(col3 + 2)}┘${c.reset}\n`);
}

// ─── Main ───────────────────────────────────────────────────

async function main() {
  banner("EIP-8141 Gas Benchmark");

  const results: GasResult[] = [];

  // ── Deploy BenchmarkToken ──
  sectionHeader("📦 Deploy BenchmarkToken");
  const tokenBytecode = loadBytecode("BenchmarkToken");
  const { address: tokenAddr } = await deployContract(
    walletClient, publicClient, tokenBytecode, 3_000_000n, "BenchmarkToken"
  );

  // ── Build common calldata ──
  const ethTransferCalldata = (target: Address) =>
    encodeFunctionData({
      abi: simpleAccountAbi,
      functionName: "execute",
      args: [target, 1n, "0x"],
    });

  const erc20TransferCalldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_ADDR, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: simpleAccountAbi,
      functionName: "execute",
      args: [token, 0n, innerData],
    });
  };

  // Kernel and Coinbase use their own ABIs for execute
  const kernelEthCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [DEAD_ADDR, 1n, "0x"],
  });
  const kernelErc20Calldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_ADDR, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [token, 0n, innerData],
    });
  };

  const coinbaseEthCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [DEAD_ADDR, 1n, "0x"],
  });
  const coinbaseErc20Calldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_ADDR, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: walletAbi,
      functionName: "execute",
      args: [token, 0n, innerData],
    });
  };

  // ═════════════════════════════════════════════════════════════
  // Simple8141Account
  // ═════════════════════════════════════════════════════════════
  sectionHeader("🔑 Simple8141Account");

  step("Deploying...");
  const simpleAddr = await deploySimple();
  await fundAccount(walletClient, publicClient, simpleAddr);

  step("Minting tokens...");
  const mintCalldata = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "mint",
    args: [simpleAddr, 1_000_000_000_000_000_000_000n],
  });
  await sendTx(tokenAddr, mintCalldata);
  success("1,000 BMK minted");

  step("ETH transfer...");
  const simpleEthReceipt = await sendSimpleFrameTx(simpleAddr, ethTransferCalldata(DEAD_ADDR));
  verifyReceipt(simpleEthReceipt, simpleAddr);
  const simpleEth = extractGas(simpleEthReceipt);
  success(`Total: ${fmtGas(simpleEth.totalGas)}`);

  step("ERC20 transfer...");
  const simpleErc20Receipt = await sendSimpleFrameTx(simpleAddr, erc20TransferCalldata(tokenAddr));
  verifyReceipt(simpleErc20Receipt, simpleAddr);
  const simpleErc20 = extractGas(simpleErc20Receipt);
  success(`Total: ${fmtGas(simpleErc20.totalGas)}`);

  results.push(
    { label: "Simple8141", totalGas: 0n, verifyGas: 0n, senderGas: 0n },
    { label: "  ETH transfer", ...simpleEth },
    { label: "  ERC20 transfer", ...simpleErc20 },
  );

  // ═════════════════════════════════════════════════════════════
  // Kernel8141
  // ═════════════════════════════════════════════════════════════
  sectionHeader("🔑 Kernel8141");

  step("Deploying...");
  const { kernelAddr } = await deployKernel();
  await fundAccount(walletClient, publicClient, kernelAddr);

  step("Minting tokens...");
  const kernelMintCalldata = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "mint",
    args: [kernelAddr, 1_000_000_000_000_000_000_000n],
  });
  await sendTx(tokenAddr, kernelMintCalldata);
  success("1,000 BMK minted");

  step("ETH transfer...");
  const kernelEthReceipt = await sendKernelFrameTx(kernelAddr, kernelEthCalldata);
  verifyReceipt(kernelEthReceipt, kernelAddr);
  const kernelEth = extractGas(kernelEthReceipt);
  success(`Total: ${fmtGas(kernelEth.totalGas)}`);

  step("ERC20 transfer...");
  const kernelErc20Receipt = await sendKernelFrameTx(kernelAddr, kernelErc20Calldata(tokenAddr));
  verifyReceipt(kernelErc20Receipt, kernelAddr);
  const kernelErc20 = extractGas(kernelErc20Receipt);
  success(`Total: ${fmtGas(kernelErc20.totalGas)}`);

  results.push(
    { label: "Kernel8141", totalGas: 0n, verifyGas: 0n, senderGas: 0n },
    { label: "  ETH transfer", ...kernelEth },
    { label: "  ERC20 transfer", ...kernelErc20 },
  );

  // ═════════════════════════════════════════════════════════════
  // CoinbaseSmartWallet8141
  // ═════════════════════════════════════════════════════════════
  sectionHeader("🔑 CoinbaseSmartWallet8141");

  step("Deploying...");
  const coinbaseAddr = await deployCoinbase();
  await fundAccount(walletClient, publicClient, coinbaseAddr);

  step("Minting tokens...");
  const coinbaseMintCalldata = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "mint",
    args: [coinbaseAddr, 1_000_000_000_000_000_000_000n],
  });
  await sendTx(tokenAddr, coinbaseMintCalldata);
  success("1,000 BMK minted");

  step("ETH transfer...");
  const coinbaseEthReceipt = await sendCoinbaseFrameTx(coinbaseAddr, coinbaseEthCalldata);
  verifyReceipt(coinbaseEthReceipt, coinbaseAddr);
  const coinbaseEth = extractGas(coinbaseEthReceipt);
  success(`Total: ${fmtGas(coinbaseEth.totalGas)}`);

  step("ERC20 transfer...");
  const coinbaseErc20Receipt = await sendCoinbaseFrameTx(coinbaseAddr, coinbaseErc20Calldata(tokenAddr));
  verifyReceipt(coinbaseErc20Receipt, coinbaseAddr);
  const coinbaseErc20 = extractGas(coinbaseErc20Receipt);
  success(`Total: ${fmtGas(coinbaseErc20.totalGas)}`);

  results.push(
    { label: "Coinbase", totalGas: 0n, verifyGas: 0n, senderGas: 0n },
    { label: "  ETH transfer", ...coinbaseEth },
    { label: "  ERC20 transfer", ...coinbaseErc20 },
  );

  // ═════════════════════════════════════════════════════════════
  // Results
  // ═════════════════════════════════════════════════════════════
  banner("📊 Results");
  printTable(results);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
