/**
 * E2E: SpendingLimitHook lifecycle test (inline hook pattern)
 *
 * Tests that SpendingLimitHook enforces daily spending limits using the
 * inline hook model, where hook pre/post are called inside the SENDER frame:
 *
 *   Frame 0: VERIFY(kernel)  → kernel.validate(sig, 1)     — validates signature, enforces executeHooked selector
 *   Frame 1: SENDER(kernel)  → kernel.executeHooked(vId, mode, data) — hook pre/post + execution (atomic)
 *
 * Usage: cd contracts && npx tsx e2e/kernel-hooked/spending-limit.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  bytesToHex,
  parseEther,
  formatEther,
  padHex,
  type Hex,
  type Hash,
  type Address,
} from "viem";
import { CHAIN_ID, DEV_KEY, DEAD_ADDR, FRAME_MODE_VERIFY, FRAME_MODE_SENDER, CHAIN_DEF } from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { printReceipt, verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi, factoryAbi } from "../helpers/abis/kernel.js";
import { banner, sectionHeader, testHeader, step, info, testPassed, summary, fatal } from "../helpers/log.js";

// ── ExecMode / execution calldata encoding ───────────────────────────
function encodeSingleExec(target: Address, value: bigint, data: Hex = "0x"): Hex {
  const targetHex = target.slice(2).toLowerCase().padStart(40, "0");
  const valueHex = value.toString(16).padStart(64, "0");
  const dataHex = data.slice(2);
  return `0x${targetHex}${valueHex}${dataHex}` as Hex;
}

// ── Frame TX helpers ────────────────────────────────────────────────

/**
 * Send a 2-frame hooked transaction (inline hook pattern):
 *   Frame 0: VERIFY(kernel) → kernel.validate(sig, 1)
 *   Frame 1: SENDER(kernel) → kernel.executeHooked(vId, mode, data)
 */
async function sendHookedFrameTx(
  publicClient: any,
  kernelAddr: Address,
  rootVId: Hex,
  senderCalldata: Hex,
  senderGas = 500_000n
): Promise<any> {
  const kernelNonce = await publicClient.getTransactionCount({ address: kernelAddr });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce: BigInt(kernelNonce),
    sender: kernelAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      // Frame 0: VERIFY — kernel.validate() (data excluded from sigHash per spec)
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 300_000n, data: new Uint8Array(0) },
      // Frame 1: SENDER — kernel.executeHooked() (hook pre/post + execution, atomic)
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: senderGas, data: hexToBytes(senderCalldata) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  // Compute sigHash (VERIFY data stays empty, SENDER data included)
  const sigHash = computeSigHash(frameTxParams);
  const { packed: packedSig } = signFrameHash(sigHash, DEV_KEY);
  const validateCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validate",
    args: [bytesToHex(packedSig), 1],  // scope=1: approve frames 0-1
  });
  // Set VERIFY frame data (frame index 0)
  frameTxParams.frames[0].data = hexToBytes(validateCalldata);

  const rawTx = encodeFrameTx(frameTxParams);
  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;

  return waitForReceipt(publicClient, txHash);
}

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("SpendingLimitHook E2E (Inline Hook)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy contracts ───────────────────────────────────────────────
  sectionHeader("📦 Deploy Contracts");

  const { address: validatorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("ECDSAValidator"), 3_000_000n, "ECDSAValidator"
  );

  const { address: hookAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("SpendingLimitHook"), 3_000_000n, "SpendingLimitHook"
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

  // ── Create account with SpendingLimitHook as root validator's hook ─
  const rootVId = `0x01${validatorAddr.slice(2)}` as Hex;
  const salt = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;

  // hookData = [0x00 flag byte][abi.encode(uint256 dailyLimit)]
  const hookInstallData = encodeAbiParameters(parseAbiParameters("uint256"), [parseEther("5")]);
  const hookData = ("0x00" + hookInstallData.slice(2)) as Hex;

  const initData = encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [
      rootVId,      // bytes21 _rootValidator
      hookAddr,     // IHook8141 hook (SpendingLimitHook)
      devAddr,      // bytes validatorData (ECDSAValidator: abi.encodePacked(owner))
      hookData,     // bytes hookData (SpendingLimitHook: abi.encode(5 ether))
      [],           // bytes[] initConfig
    ],
  });

  const kernelAddr = await (publicClient as any).readContract({
    address: factoryAddr,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [initData, salt],
  }) as Address;
  step(`Predicted kernel address: ${kernelAddr}`);

  const createHash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
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
  const createReceipt = await waitForReceipt(publicClient, createHash);
  if (createReceipt.status !== "0x1") throw new Error("Factory createAccount failed");
  info(`Kernel created with SpendingLimitHook (5 ETH daily limit)`);

  sectionHeader("💰 Fund Kernel");
  await fundAccount(walletClient, publicClient, kernelAddr);

  // ── Tests ──────────────────────────────────────────────────────────
  const EXEC_MODE_SINGLE_DEFAULT = padHex("0x0000" as Hex, { size: 32, dir: "right" });

  // Test 1: Transfer 3 ETH with inline hook pattern
  testHeader(1, "Transfer 3 ETH (VERIFY→SENDER, inline hook)");
  {
    const execCalldata = encodeSingleExec(DEAD_ADDR, parseEther("3"));
    const senderCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeHooked",
      args: [rootVId, EXEC_MODE_SINGLE_DEFAULT, execCalldata],
    });
    const receipt = await sendHookedFrameTx(publicClient, kernelAddr, rootVId, senderCalldata);
    printReceipt(receipt);
    if (receipt.status !== "0x1") throw new Error("Transfer should succeed (within 5 ETH limit)");
    testPassed("3 ETH transferred with inline hook (VERIFY→SENDER)");
  }

  // Test 2: Transfer 1.5 ETH — cumulative 4.5 ETH, still within daily limit
  testHeader(2, "Transfer 1.5 ETH (cumulative 4.5 ETH, within limit)");
  {
    const execCalldata = encodeSingleExec(DEAD_ADDR, parseEther("1.5"));
    const senderCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeHooked",
      args: [rootVId, EXEC_MODE_SINGLE_DEFAULT, execCalldata],
    });
    const receipt = await sendHookedFrameTx(publicClient, kernelAddr, rootVId, senderCalldata);
    printReceipt(receipt);
    if (receipt.status !== "0x1") throw new Error("Transfer should succeed (4.5 ETH < 5 ETH limit)");
    testPassed("1.5 ETH transferred (cumulative spending enforcement verified)");
  }

  // Test 3: Zero-value call with inline hook
  testHeader(3, "Zero-value call (inline hook, no spending)");
  {
    const execCalldata = encodeSingleExec(DEAD_ADDR, 0n);
    const senderCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeHooked",
      args: [rootVId, EXEC_MODE_SINGLE_DEFAULT, execCalldata],
    });
    const receipt = await sendHookedFrameTx(publicClient, kernelAddr, rootVId, senderCalldata);
    printReceipt(receipt);
    if (receipt.status !== "0x1") throw new Error("Zero-value call should succeed");
    testPassed("Zero-value call succeeded with inline hook");
  }

  summary("SpendingLimitHook (Inline Hook)", 3);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
