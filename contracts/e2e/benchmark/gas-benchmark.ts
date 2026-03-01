/**
 * EIP-8141 Gas Benchmark
 *
 * Measures gas costs for ETH transfer and ERC20 transfer across
 * Simple8141Account, Kernel8141, CoinbaseSmartWallet8141, and LightAccount8141.
 *
 * Usage: cd contracts && npx tsx e2e/benchmark/gas-benchmark.ts
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toSimple8141Account } from "viem/eip8141";
import { DEV_KEY, HOOK_INSTALLED } from "../helpers/config.js";
import { encodeExecMode, encodeSingleExec } from "../helpers/exec-encoding.js";

// Per-account recipient addresses to avoid SSTORE zero→non-zero bias
const DEAD_SIMPLE   = "0x000000000000000000000000000000000000deA1" as Address;
const DEAD_KERNEL   = "0x000000000000000000000000000000000000dEa2" as Address;
const DEAD_COINBASE = "0x000000000000000000000000000000000000DEA3" as Address;
const DEAD_LIGHT    = "0x000000000000000000000000000000000000DeA4" as Address;
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi, factoryAbi } from "../helpers/abis/kernel.js";
import { walletAbi, factoryAbi as coinbaseFactoryAbi } from "../helpers/abis/coinbase.js";
import { walletAbi as lightWalletAbi, factoryAbi as lightFactoryAbi } from "../helpers/abis/light-account.js";
import { benchmarkTokenAbi } from "../helpers/abis/benchmark-token.js";
import { banner, sectionHeader, info, step, success, fatal } from "../helpers/log.js";
import { createKernelAccount, createCoinbaseAccount, createLightAccount, sendAndWait } from "../helpers/send-frame-tx.js";

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

// ─── Kernel8141 ─────────────────────────────────────────────

async function deployKernel(): Promise<{ kernelAddr: Address; validatorAddr: Address }> {
  const { address: validatorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("ECDSAValidator"), 3_000_000n, "ECDSAValidator"
  );

  const { address: implAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("Kernel8141"), 10_000_000n, "Kernel8141 (impl)"
  );

  const factoryBytecode = loadBytecode("Kernel8141Factory");
  const factoryCtorArgs = encodeAbiParameters(parseAbiParameters("address"), [implAddr]);
  const factoryDeployData = (factoryBytecode + factoryCtorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 5_000_000n, "Kernel8141Factory"
  );

  const rootVId = `0x01${validatorAddr.slice(2)}` as Hex;
  const salt = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
  const initData = encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [rootVId, HOOK_INSTALLED, devAddr, "0x", []],
  });

  const kernelAddr = await (publicClient as any).readContract({
    address: factoryAddr,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [initData, salt],
  }) as Address;

  const createHash = await walletClient.sendTransaction({
    to: factoryAddr,
    data: encodeFunctionData({
      abi: factoryAbi,
      functionName: "createAccount",
      args: [initData, salt],
    }),
    gas: 5_000_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  } as any);
  const receipt = await waitForReceipt(publicClient, createHash);
  if (receipt.status !== "0x1") throw new Error("Factory createAccount failed");

  return { kernelAddr, validatorAddr };
}

// ─── CoinbaseSmartWallet8141 ────────────────────────────────

async function deployCoinbase(): Promise<Address> {
  // Deploy implementation
  const implBytecode = loadBytecode("CoinbaseSmartWallet8141");
  const { address: implAddr } = await deployContract(
    walletClient, publicClient, implBytecode, 5_000_000n, "CoinbaseSmartWallet8141 (impl)"
  );

  // Deploy factory
  const factoryBytecode = loadBytecode("CoinbaseSmartWalletFactory8141");
  const factoryCtorArgs = encodeAbiParameters(parseAbiParameters("address"), [implAddr]);
  const factoryDeployData = (factoryBytecode + factoryCtorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 3_000_000n, "CoinbaseSmartWalletFactory8141"
  );

  // Create account via factory
  const owners = [
    encodeAbiParameters(parseAbiParameters("address"), [devAddr]),
  ];
  const createHash = await walletClient.sendTransaction({
    to: factoryAddr,
    data: encodeFunctionData({
      abi: coinbaseFactoryAbi,
      functionName: "createAccount",
      args: [owners, 0n],
    }),
    gas: 5_000_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  } as any);
  const receipt = await waitForReceipt(publicClient, createHash);
  if (receipt.status !== "0x1") throw new Error("Coinbase factory createAccount failed");

  // Get deterministic address
  const walletAddr = await (publicClient as any).readContract({
    address: factoryAddr,
    abi: coinbaseFactoryAbi,
    functionName: "getAddress",
    args: [owners, 0n],
  }) as Address;

  return walletAddr;
}

// ─── LightAccount8141 ───────────────────────────────────────

async function deployLightAccount(): Promise<Address> {
  const implBytecode = loadBytecode("LightAccount8141");
  const { address: implAddr } = await deployContract(
    walletClient, publicClient, implBytecode, 5_000_000n, "LightAccount8141 (impl)"
  );

  const factoryBytecode = loadBytecode("LightAccountFactory8141");
  const factoryCtorArgs = encodeAbiParameters(parseAbiParameters("address"), [implAddr]);
  const factoryDeployData = (factoryBytecode + factoryCtorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 3_000_000n, "LightAccountFactory8141"
  );

  const createHash = await walletClient.sendTransaction({
    to: factoryAddr,
    data: encodeFunctionData({
      abi: lightFactoryAbi,
      functionName: "createAccount",
      args: [devAddr, 0n],
    }),
    gas: 5_000_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  } as any);
  const receipt = await waitForReceipt(publicClient, createHash);
  if (receipt.status !== "0x1") throw new Error("LightAccount factory createAccount failed");

  const walletAddr = await (publicClient as any).readContract({
    address: factoryAddr,
    abi: lightFactoryAbi,
    functionName: "getAddress",
    args: [devAddr, 0n],
  }) as Address;

  return walletAddr;
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

  // ── Build sender calldata (Kernel / Coinbase / LightAccount) ──
  // Kernel uses execute(bytes32 execMode, bytes executionCalldata)
  // ExecMode: single + default = 0x0000...
  // Single exec calldata: abi.encodePacked(target(20B), value(32B), calldata)
  const EXEC_MODE_SINGLE = encodeExecMode("0x00" as Hex, "0x00" as Hex);
  const kernelEthCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [EXEC_MODE_SINGLE, encodeSingleExec(DEAD_KERNEL, 1n)],
  });
  const kernelErc20Calldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_KERNEL, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [EXEC_MODE_SINGLE, encodeSingleExec(token, 0n, innerData)],
    });
  };

  const coinbaseEthCalldata = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [DEAD_COINBASE, 1n, "0x"],
  });
  const coinbaseErc20Calldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_COINBASE, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: walletAbi,
      functionName: "execute",
      args: [token, 0n, innerData],
    });
  };

  const lightEthCalldata = encodeFunctionData({
    abi: lightWalletAbi,
    functionName: "execute",
    args: [DEAD_LIGHT, 1n, "0x"],
  });
  const lightErc20Calldata = (token: Address) => {
    const innerData = encodeFunctionData({
      abi: benchmarkTokenAbi,
      functionName: "transfer",
      args: [DEAD_LIGHT, 1_000_000_000_000_000_000n],
    });
    return encodeFunctionData({
      abi: lightWalletAbi,
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

  const owner = privateKeyToAccount(DEV_KEY);
  const simpleAccount = toSimple8141Account({
    address: simpleAddr,
    owner,
    verifyGasLimit: 200_000n,
    senderGasLimit: 200_000n,
  });

  step("ETH transfer...");
  const simpleEthHash = await publicClient.sendFrameTransaction({
    account: simpleAccount,
    calls: [{ to: DEAD_SIMPLE, value: 1n }],
  });
  const simpleEthReceipt = await waitForReceipt(publicClient, simpleEthHash);
  verifyReceipt(simpleEthReceipt, simpleAddr);
  const simpleEth = extractGas(simpleEthReceipt);
  success(`Total: ${fmtGas(simpleEth.totalGas)}`);

  step("ERC20 transfer...");
  const erc20Data = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "transfer",
    args: [DEAD_SIMPLE, 1_000_000_000_000_000_000n],
  });
  const simpleErc20Hash = await publicClient.sendFrameTransaction({
    account: simpleAccount,
    calls: [{ to: tokenAddr, data: erc20Data }],
  });
  const simpleErc20Receipt = await waitForReceipt(publicClient, simpleErc20Hash);
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

  const kernelAccount = createKernelAccount(kernelAddr);

  step("ETH transfer...");
  const kernelEthReceipt = await sendAndWait(publicClient, kernelAccount, kernelEthCalldata);
  verifyReceipt(kernelEthReceipt, kernelAddr);
  const kernelEth = extractGas(kernelEthReceipt);
  success(`Total: ${fmtGas(kernelEth.totalGas)}`);

  step("ERC20 transfer...");
  const kernelErc20Receipt = await sendAndWait(publicClient, kernelAccount, kernelErc20Calldata(tokenAddr));
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

  const coinbaseAccount = createCoinbaseAccount(coinbaseAddr, 0, DEV_KEY);

  step("ETH transfer...");
  const coinbaseEthReceipt = await sendAndWait(publicClient, coinbaseAccount, coinbaseEthCalldata);
  verifyReceipt(coinbaseEthReceipt, coinbaseAddr);
  const coinbaseEth = extractGas(coinbaseEthReceipt);
  success(`Total: ${fmtGas(coinbaseEth.totalGas)}`);

  step("ERC20 transfer...");
  const coinbaseErc20Receipt = await sendAndWait(publicClient, coinbaseAccount, coinbaseErc20Calldata(tokenAddr));
  verifyReceipt(coinbaseErc20Receipt, coinbaseAddr);
  const coinbaseErc20 = extractGas(coinbaseErc20Receipt);
  success(`Total: ${fmtGas(coinbaseErc20.totalGas)}`);

  results.push(
    { label: "Coinbase", totalGas: 0n, verifyGas: 0n, senderGas: 0n },
    { label: "  ETH transfer", ...coinbaseEth },
    { label: "  ERC20 transfer", ...coinbaseErc20 },
  );

  // ═════════════════════════════════════════════════════════════
  // LightAccount8141
  // ═════════════════════════════════════════════════════════════
  sectionHeader("🔑 LightAccount8141");

  step("Deploying...");
  const lightAddr = await deployLightAccount();
  await fundAccount(walletClient, publicClient, lightAddr);

  step("Minting tokens...");
  const lightMintCalldata = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "mint",
    args: [lightAddr, 1_000_000_000_000_000_000_000n],
  });
  await sendTx(tokenAddr, lightMintCalldata);
  success("1,000 BMK minted");

  const lightAccount = createLightAccount(lightAddr);

  step("ETH transfer...");
  const lightEthReceipt = await sendAndWait(publicClient, lightAccount, lightEthCalldata);
  verifyReceipt(lightEthReceipt, lightAddr);
  const lightEth = extractGas(lightEthReceipt);
  success(`Total: ${fmtGas(lightEth.totalGas)}`);

  step("ERC20 transfer...");
  const lightErc20Receipt = await sendAndWait(publicClient, lightAccount, lightErc20Calldata(tokenAddr));
  verifyReceipt(lightErc20Receipt, lightAddr);
  const lightErc20 = extractGas(lightErc20Receipt);
  success(`Total: ${fmtGas(lightErc20.totalGas)}`);

  results.push(
    { label: "LightAccount", totalGas: 0n, verifyGas: 0n, senderGas: 0n },
    { label: "  ETH transfer", ...lightEth },
    { label: "  ERC20 transfer", ...lightErc20 },
  );

  // ═════════════════════════════════════════════════════════════
  // Results
  // ═════════════════════════════════════════════════════════════
  banner("📊 Results");
  printTable(results);
  writeMarkdownReport(results);
}

function writeMarkdownReport(results: GasResult[]) {
  const timestamp = new Date().toISOString().replace(/T/, " ").replace(/\..+/, " UTC");
  const lines: string[] = [
    "# EIP-8141 Gas Benchmark Results",
    "",
    `> Generated: ${timestamp}`,
    "",
    "| Account | Operation | Total Gas | Verify Gas | Sender Gas |",
    "|---|---|---:|---:|---:|",
  ];

  for (const r of results) {
    if (r.totalGas === 0n) continue;
    const account = r.label.startsWith("  ") ? "" : r.label;
    const op = r.label.trim();
    // Find the parent header for indented rows
    const parentLabel = r.label.startsWith("  ")
      ? results.slice(0, results.indexOf(r)).reverse().find((x) => x.totalGas === 0n)?.label ?? ""
      : "";
    const acct = r.label.startsWith("  ") ? parentLabel : r.label;
    lines.push(
      `| ${acct} | ${op} | ${fmtGas(r.totalGas)} | ${fmtGas(r.verifyGas)} | ${fmtGas(r.senderGas)} |`
    );
  }

  lines.push("");

  const outDir = path.resolve(__dirname, "../../..");
  const outPath = path.join(outDir, "BENCHMARK.md");
  fs.writeFileSync(outPath, lines.join("\n") + "\n");
  success(`Report saved to ${outPath}`);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
