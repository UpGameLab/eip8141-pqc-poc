/**
 * E2E: ERC20Paymaster — 5-frame sponsored transaction
 *
 * Frame structure:
 *   Frame 0: VERIFY(sender)     → validate(v,r,s, scope=0) → APPROVE(execution)
 *   Frame 1: VERIFY(paymaster)  → validate()               → APPROVE(payment)
 *   Frame 2: SENDER(erc20)      → token.transfer(paymaster, amount)
 *   Frame 3: SENDER(account)    → account.execute(DEAD_ADDR, 0, 0x)
 *   Frame 4: DEFAULT(paymaster) → postOp(2)
 *
 * Usage: cd contracts && npx tsx e2e/simple/simple-paymaster.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  formatEther,
  toFunctionSelector,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toSimple8141Account } from "viem/eip8141";
import type { FramePaymaster } from "viem/eip8141";
import { DEV_KEY, DEAD_ADDR } from "../helpers/config.js";

import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { benchmarkTokenAbi } from "../helpers/abis/benchmark-token.js";
import {
  printReceipt,
  banner, sectionHeader, info, step, success,
  testHeader, testPassed, summary, detail, fatal,
} from "../helpers/log.js";

// ── Selectors ─────────────────────────────────────────────────────

const PAYMASTER_VALIDATE_SELECTOR = toFunctionSelector("validate()");
const SET_EXCHANGE_RATE_SELECTOR = toFunctionSelector("setExchangeRate(address,uint256)");

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  const owner = privateKeyToAccount(DEV_KEY);

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("ERC20Paymaster E2E (5-frame Sponsored Tx)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy contracts ──────────────────────────────────────────────

  sectionHeader("Deploy Contracts");

  // 1. Simple8141Account
  const accountInitCode = loadBytecode("Simple8141Account");
  const accountConstructorArg = encodeAbiParameters(
    parseAbiParameters("address"),
    [devAddr]
  );
  const accountDeployData = (accountInitCode + accountConstructorArg.slice(2)) as Hex;
  const { address: accountAddr } = await deployContract(
    walletClient, publicClient, accountDeployData, 2_000_000n, "Simple8141Account"
  );

  // 2. BenchmarkToken
  const tokenInitCode = loadBytecode("BenchmarkToken");
  const { address: tokenAddr } = await deployContract(
    walletClient, publicClient, tokenInitCode, 2_000_000n, "BenchmarkToken"
  );

  // 3. ERC20Paymaster
  const paymasterInitCode = loadBytecode("ERC20Paymaster");
  const paymasterConstructorArg = encodeAbiParameters(
    parseAbiParameters("address"),
    [devAddr] // owner = dev account
  );
  const paymasterDeployData = (paymasterInitCode + paymasterConstructorArg.slice(2)) as Hex;
  const { address: paymasterAddr } = await deployContract(
    walletClient, publicClient, paymasterDeployData, 2_000_000n, "ERC20Paymaster"
  );

  // ── Setup ─────────────────────────────────────────────────────────

  sectionHeader("Setup");

  // Fund paymaster with ETH (to cover gas)
  await fundAccount(walletClient, publicClient, paymasterAddr, "10");

  // Mint tokens to the smart account
  step("Minting tokens to smart account...");
  const mintData = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "mint",
    args: [accountAddr, 1000n * 10n ** 18n],
  });
  const mintHash = await walletClient.sendTransaction({
    to: tokenAddr,
    data: mintData,
    gas: 100_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  await waitForReceipt(publicClient, mintHash);
  success("Minted 1000 BMK to smart account");

  // Set exchange rate: 1 token per wei (rate = 1e18)
  step("Setting exchange rate...");
  const setRateData = encodeAbiParameters(
    parseAbiParameters("address, uint256"),
    [tokenAddr, 10n ** 18n]
  );
  const setRateCalldata = (SET_EXCHANGE_RATE_SELECTOR + setRateData.slice(2)) as Hex;
  const setRateHash = await walletClient.sendTransaction({
    to: paymasterAddr,
    data: setRateCalldata,
    gas: 100_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  await waitForReceipt(publicClient, setRateHash);
  success("Exchange rate set: 1 BMK = 1 wei");

  // ── Test: 5-frame sponsored transaction ───────────────────────────

  testHeader(1, "5-frame ERC20 sponsored transaction");

  const tokenAmount = 10n ** 18n;

  // ERC20 transfer calldata — transfer(paymaster, amount)
  const transferCalldata = encodeFunctionData({
    abi: benchmarkTokenAbi,
    functionName: "transfer",
    args: [paymasterAddr, tokenAmount],
  });

  // postOp calldata
  const postOpCalldata = encodeFunctionData({
    abi: [{ type: "function", name: "postOp", inputs: [{ name: "idx", type: "uint256" }], outputs: [], stateMutability: "nonpayable" }],
    functionName: "postOp",
    args: [2n],
  });

  // Create Simple8141Account with execution scope; paymaster handles payment.
  const account = toSimple8141Account({
    address: accountAddr,
    owner,
    verifyGasLimit: 200_000n,
    senderGasLimit: 100_000n,
    scope: 2,
  });

  // Create paymaster
  const paymaster: FramePaymaster = {
    address: paymasterAddr,
    async signFrameTransaction() {
      return {
        mode: "verify" as const,
        flags: 1,
        target: paymasterAddr,
        gasLimit: 200_000n,
        data: PAYMASTER_VALIDATE_SELECTOR,
      };
    },
    getPostOpFrame() {
      return {
        mode: "default" as const,
        target: paymasterAddr,
        gasLimit: 100_000n,
        data: postOpCalldata,
      };
    },
  };

  step("Sending 5-frame sponsored transaction...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    paymaster,
    calls: [
      { to: tokenAddr, data: transferCalldata },
      { to: DEAD_ADDR },
    ],
  });
  detail(`txHash: ${txHash}`);

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);

  // ── Verify ────────────────────────────────────────────────────────

  step("Verifying receipt...");

  if (receipt.status !== "0x1") {
    throw new Error(`TX failed: status=${receipt.status}`);
  }
  success("Transaction succeeded");

  if (receipt.type !== "0x6") {
    throw new Error(`Wrong type: got ${receipt.type}, want 0x6`);
  }

  if (receipt.payer) {
    if (receipt.payer.toLowerCase() !== paymasterAddr.toLowerCase()) {
      throw new Error(`Wrong payer: got ${receipt.payer}, want ${paymasterAddr}`);
    }
    success(`Payer is paymaster: ${paymasterAddr}`);
  }

  if (!receipt.frameReceipts || receipt.frameReceipts.length !== 5) {
    throw new Error(
      `Frame count: got ${receipt.frameReceipts?.length ?? 0}, want 5`
    );
  }
  success("5 frame receipts present");

  // Frame 0: VERIFY(sender) → APPROVED_EXECUTION (0x2)
  const frame0Status = receipt.frameReceipts[0].status;
  if (frame0Status !== "0x2") {
    throw new Error(`Frame 0 (VERIFY/sender): got ${frame0Status}, want 0x2`);
  }
  success("Frame 0: APPROVED_EXECUTION (0x2)");

  // Frame 1: VERIFY(paymaster) → APPROVED_PAYMENT (0x3)
  const frame1Status = receipt.frameReceipts[1].status;
  if (frame1Status !== "0x3") {
    throw new Error(`Frame 1 (VERIFY/paymaster): got ${frame1Status}, want 0x3`);
  }
  success("Frame 1: APPROVED_PAYMENT (0x3)");

  // Frame 2: SENDER(ERC20 transfer) → SUCCESS (0x1)
  const frame2Status = receipt.frameReceipts[2].status;
  if (frame2Status !== "0x1") {
    throw new Error(`Frame 2 (SENDER/transfer): got ${frame2Status}, want 0x1`);
  }
  success("Frame 2: ERC20 transfer SUCCESS (0x1)");

  // Frame 3: SENDER(execute) → SUCCESS (0x1)
  const frame3Status = receipt.frameReceipts[3].status;
  if (frame3Status !== "0x1") {
    throw new Error(`Frame 3 (SENDER/execute): got ${frame3Status}, want 0x1`);
  }
  success("Frame 3: Execute SUCCESS (0x1)");

  // Frame 4: DEFAULT(postOp) → SUCCESS (0x1)
  const frame4Status = receipt.frameReceipts[4].status;
  if (frame4Status !== "0x1") {
    throw new Error(`Frame 4 (DEFAULT/postOp): got ${frame4Status}, want 0x1`);
  }
  success("Frame 4: PostOp SUCCESS (0x1)");

  // Verify token balances
  step("Verifying token balances...");
  const accountTokenBalance = await publicClient.readContract({
    address: tokenAddr,
    abi: benchmarkTokenAbi,
    functionName: "balanceOf",
    args: [accountAddr],
  }) as bigint;
  const paymasterTokenBalance = await publicClient.readContract({
    address: tokenAddr,
    abi: benchmarkTokenAbi,
    functionName: "balanceOf",
    args: [paymasterAddr],
  }) as bigint;

  detail(`Account token balance: ${accountTokenBalance}`);
  detail(`Paymaster token balance: ${paymasterTokenBalance}`);

  if (paymasterTokenBalance !== tokenAmount) {
    throw new Error(
      `Paymaster token balance: got ${paymasterTokenBalance}, want ${tokenAmount}`
    );
  }
  success(`Paymaster received ${tokenAmount} BMK tokens`);

  if (accountTokenBalance !== 1000n * 10n ** 18n - tokenAmount) {
    throw new Error(
      `Account token balance: got ${accountTokenBalance}, want ${1000n * 10n ** 18n - tokenAmount}`
    );
  }
  success("Account token balance decreased correctly");

  testPassed("5-frame ERC20 sponsored transaction");
  summary("ERC20Paymaster", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
