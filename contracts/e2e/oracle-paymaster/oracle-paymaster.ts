/**
 * E2E: ERC20PaymasterV8141 — Oracle-based 5-frame sponsored transaction
 *
 * Frame structure:
 *   Frame 0: VERIFY(sender)     → validate(v,r,s, scope=0)          → APPROVE(execution)
 *   Frame 1: VERIFY(paymaster)  → paymaster.validate()               → APPROVE(payment)
 *   Frame 2: SENDER(erc20)      → token.transfer(paymaster, amount)
 *   Frame 3: SENDER(account)    → account.execute(DEAD_ADDR, 0, 0x)
 *   Frame 4: DEFAULT(paymaster) → paymaster.postOp(2)
 *
 * Usage: cd contracts && npx tsx e2e/oracle-paymaster/oracle-paymaster.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  formatEther,
  keccak256,
  toHex,
  type Hex,
  type Address,
  type Hash,
} from "viem";
import {
  CHAIN_ID,
  DEV_KEY,
  DEAD_ADDR,
  FRAME_MODE_DEFAULT,
  FRAME_MODE_VERIFY,
  FRAME_MODE_SENDER,
  CHAIN_DEF,
} from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { printReceipt } from "../helpers/receipt.js";
import { SIMPLE_VALIDATE_SELECTOR } from "../helpers/abis/simple.js";
import { benchmarkTokenAbi } from "../helpers/abis/benchmark-token.js";
import {
  banner, sectionHeader, info, step, success,
  testHeader, testPassed, testFailed, summary, detail, fatal,
} from "../helpers/log.js";

// ── Selectors ─────────────────────────────────────────────────────

// ERC20PaymasterV8141.validate() — no args
const PAYMASTER_VALIDATE_SELECTOR = keccak256(
  toHex(new TextEncoder().encode("validate()"))
).slice(0, 10) as Hex;

// ERC20PaymasterV8141.validateWithLimit(uint256)
const PAYMASTER_VALIDATE_WITH_LIMIT_SELECTOR = keccak256(
  toHex(new TextEncoder().encode("validateWithLimit(uint256)"))
).slice(0, 10) as Hex;

// ERC20PaymasterV8141.postOp(uint256)
const PAYMASTER_POSTOP_SELECTOR = keccak256(
  toHex(new TextEncoder().encode("postOp(uint256)"))
).slice(0, 10) as Hex;

// ERC20 transfer(address,uint256)
const ERC20_TRANSFER_SELECTOR = "0xa9059cbb" as Hex;

// ── Test ABI fragments ───────────────────────────────────────────

const paymasterAbi = [
  {
    type: "function",
    name: "getPrice",
    inputs: [],
    outputs: [{ name: "", type: "uint192" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getTokenAmount",
    inputs: [{ name: "gasCostWei", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "priceMarkup",
    inputs: [],
    outputs: [{ name: "", type: "uint32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "owner",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "token",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "exchangeRates",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
] as const;

let testsPassed = 0;
let testsFailed = 0;

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("ERC20PaymasterV8141 E2E (Oracle-based 5-frame Sponsored Tx)");
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

  // 3. FixedOracle for token ($1 = 1e8)
  const oracleInitCode = loadBytecode("FixedOracle");
  const tokenOracleCtorArg = encodeAbiParameters(
    parseAbiParameters("int256"),
    [BigInt(1e8)] // $1
  );
  const { address: tokenOracleAddr } = await deployContract(
    walletClient, publicClient,
    (oracleInitCode + tokenOracleCtorArg.slice(2)) as Hex,
    1_000_000n, "FixedOracle (token=$1)"
  );

  // 4. FixedOracle for native asset ($1 = 1e8 for 1:1 testing)
  const nativeOracleCtorArg = encodeAbiParameters(
    parseAbiParameters("int256"),
    [BigInt(1e8)] // $1 (1:1 rate for simplicity)
  );
  const { address: nativeOracleAddr } = await deployContract(
    walletClient, publicClient,
    (oracleInitCode + nativeOracleCtorArg.slice(2)) as Hex,
    1_000_000n, "FixedOracle (ETH=$1)"
  );

  // 5. ERC20PaymasterV8141
  const paymasterInitCode = loadBytecode("ERC20PaymasterV8141");
  // constructor(address _token, IOracle _tokenOracle, IOracle _nativeAssetOracle,
  //             uint32 _stalenessThreshold, address _owner, uint32 _priceMarkupLimit, uint32 _priceMarkup)
  const paymasterCtorArg = encodeAbiParameters(
    parseAbiParameters("address, address, address, uint32, address, uint32, uint32"),
    [
      tokenAddr,          // token
      tokenOracleAddr,    // tokenOracle
      nativeOracleAddr,   // nativeAssetOracle
      3600,               // stalenessThreshold: 1 hour
      devAddr,            // owner
      2_000_000,          // priceMarkupLimit: 200%
      1_100_000,          // priceMarkup: 110%
    ]
  );
  const { address: paymasterAddr } = await deployContract(
    walletClient, publicClient,
    (paymasterInitCode + paymasterCtorArg.slice(2)) as Hex,
    5_000_000n, "ERC20PaymasterV8141"
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
    args: [accountAddr, 1_000_000n * 10n ** 18n], // 1M tokens
  });
  const mintHash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    to: tokenAddr,
    data: mintData,
    gas: 100_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  await waitForReceipt(publicClient, mintHash);
  success("Minted 1,000,000 BMK to smart account");

  // Verify paymaster config
  step("Verifying paymaster configuration...");
  const paymasterOwner = await publicClient.readContract({
    address: paymasterAddr,
    abi: paymasterAbi,
    functionName: "owner",
  });
  if ((paymasterOwner as string).toLowerCase() !== devAddr.toLowerCase()) {
    throw new Error(`Owner mismatch: ${paymasterOwner} != ${devAddr}`);
  }

  const paymasterToken = await publicClient.readContract({
    address: paymasterAddr,
    abi: paymasterAbi,
    functionName: "token",
  });
  if ((paymasterToken as string).toLowerCase() !== tokenAddr.toLowerCase()) {
    throw new Error(`Token mismatch: ${paymasterToken} != ${tokenAddr}`);
  }

  const price = await publicClient.readContract({
    address: paymasterAddr,
    abi: paymasterAbi,
    functionName: "getPrice",
  }) as bigint;
  detail(`Oracle price: ${price} (tokens per 1 ETH in base units)`);
  // 1:1 rate, 18 decimals → price should be 1e18
  if (price !== BigInt(1e18)) {
    throw new Error(`Unexpected price: ${price}, want 1e18`);
  }

  // Verify cached exchange rate (includes 110% markup)
  const exchangeRate = await publicClient.readContract({
    address: paymasterAddr,
    abi: paymasterAbi,
    functionName: "exchangeRates",
    args: [tokenAddr],
  }) as bigint;
  detail(`Cached exchange rate: ${exchangeRate} (tokens per wei * 1e18, with markup)`);
  // 1:1 rate * 110% markup = 1.1e18
  const expectedRate = BigInt(1e18) * 1_100_000n / 1_000_000n;
  if (exchangeRate !== expectedRate) {
    throw new Error(`Unexpected exchange rate: ${exchangeRate}, want ${expectedRate}`);
  }
  success("Paymaster configured correctly (1:1 rate, 110% markup, exchange rate cached)");

  // ── Test 1: Basic oracle-priced sponsored transaction ─────────────

  await runSponsoredTxTest(
    publicClient, walletClient, devAddr,
    accountAddr, tokenAddr, paymasterAddr,
    "validate()", PAYMASTER_VALIDATE_SELECTOR, undefined
  );

  // ── Test 2: Sponsored transaction with token limit ────────────────

  await runSponsoredTxTest(
    publicClient, walletClient, devAddr,
    accountAddr, tokenAddr, paymasterAddr,
    "validateWithLimit(uint256)", PAYMASTER_VALIDATE_WITH_LIMIT_SELECTOR, 100n * 10n ** 18n
  );

  // ── Test 3: Token limit too low (should fail at mempool/validation) ──

  testHeader(3, "Token limit too low (rejection expected)");
  try {
    // Use a very small limit that can't cover gas
    await runSponsoredTxTestRaw(
      publicClient, walletClient, devAddr,
      accountAddr, tokenAddr, paymasterAddr,
      PAYMASTER_VALIDATE_WITH_LIMIT_SELECTOR, 1n, // 1 wei limit — too small
      true // expectFailure
    );
    testPassed("Token limit too low correctly rejected");
    testsPassed++;
  } catch (err: any) {
    testFailed(`Token limit rejection: ${err.message}`);
    testsFailed++;
  }

  summary("ERC20PaymasterV8141", testsPassed + testsFailed);
}

async function runSponsoredTxTest(
  publicClient: any, walletClient: any, devAddr: Address,
  accountAddr: Address, tokenAddr: Address, paymasterAddr: Address,
  validateFnName: string, validateSelector: Hex, tokenLimit: bigint | undefined,
) {
  const testNum = tokenLimit ? 2 : 1;
  const testName = tokenLimit
    ? `Oracle-priced sponsored tx with token limit (${tokenLimit})`
    : "Basic oracle-priced sponsored tx (no limit)";
  testHeader(testNum, testName);

  try {
    await runSponsoredTxTestRaw(
      publicClient, walletClient, devAddr,
      accountAddr, tokenAddr, paymasterAddr,
      validateSelector, tokenLimit,
      false
    );
    testPassed(testName);
    testsPassed++;
  } catch (err: any) {
    testFailed(`${testName}: ${err.message}`);
    testsFailed++;
  }
}

async function runSponsoredTxTestRaw(
  publicClient: any, walletClient: any, devAddr: Address,
  accountAddr: Address, tokenAddr: Address, paymasterAddr: Address,
  validateSelector: Hex, tokenLimit: bigint | undefined,
  expectFailure: boolean,
) {
  const accountNonce = await publicClient.getTransactionCount({ address: accountAddr });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

  // Calculate token amount: must cover maxCost * markup
  // With 1:1 rate and 110% markup, amount = totalGasLimit * gasFeeCap * 1.1
  // Overestimate generously for safety
  const totalGas = 200_000n + 200_000n + 100_000n + 100_000n + 100_000n; // all frames
  const maxCostEstimate = totalGas * gasFeeCap;
  const tokenAmount = tokenLimit !== undefined && tokenLimit < maxCostEstimate * 2n
    ? tokenLimit // Use the limit (for failure test)
    : maxCostEstimate * 2n; // 2x overestimate for safety

  // Frame 2: ERC20 transfer calldata — transfer(paymaster, amount)
  const transferData = encodeAbiParameters(
    parseAbiParameters("address, uint256"),
    [paymasterAddr, tokenAmount]
  );
  const transferCalldata = hexToBytes(
    (ERC20_TRANSFER_SELECTOR + transferData.slice(2)) as Hex
  );

  // Frame 3: account.execute(DEAD_ADDR, 0, 0x) — simple no-op call
  const executeCalldata = hexToBytes(
    encodeFunctionData({
      abi: [{
        type: "function", name: "execute",
        inputs: [
          { name: "target", type: "address" },
          { name: "value", type: "uint256" },
          { name: "data", type: "bytes" },
        ],
        outputs: [], stateMutability: "nonpayable",
      }],
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    })
  );

  // Frame 4: postOp(2) — transfer frame index = 2
  const postOpData = encodeAbiParameters(
    parseAbiParameters("uint256"),
    [2n]
  );
  const postOpCalldata = hexToBytes(
    (PAYMASTER_POSTOP_SELECTOR + postOpData.slice(2)) as Hex
  );

  const frameTxParams: FrameTxParams = {
    chainId: BigInt(CHAIN_ID),
    nonce: BigInt(accountNonce),
    sender: accountAddr,
    gasTipCap: 1_000_000_000n,
    gasFeeCap,
    frames: [
      // Frame 0: VERIFY(sender) — data filled after signing
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 200_000n, data: new Uint8Array(0) },
      // Frame 1: VERIFY(paymaster) — data filled after signing
      { mode: FRAME_MODE_VERIFY, target: paymasterAddr, gasLimit: 200_000n, data: new Uint8Array(0) },
      // Frame 2: SENDER(ERC20) — transfer tokens to paymaster
      { mode: FRAME_MODE_SENDER, target: tokenAddr, gasLimit: 100_000n, data: transferCalldata },
      // Frame 3: SENDER(account) — execute user's call
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: 100_000n, data: executeCalldata },
      // Frame 4: DEFAULT(paymaster) — post-op
      { mode: FRAME_MODE_DEFAULT, target: paymasterAddr, gasLimit: 100_000n, data: postOpCalldata },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  // Sign
  step("Computing sigHash and signing...");
  const sigHash = computeSigHash(frameTxParams);
  detail(`sigHash: ${sigHash}`);
  const { r, s, v } = signFrameHash(sigHash, DEV_KEY);

  // Build Frame 0 calldata: validate(uint8 v, bytes32 r, bytes32 s, uint8 scope)
  // scope = 0 (EXECUTION only)
  const frame0Selector = hexToBytes(SIMPLE_VALIDATE_SELECTOR as Hex);
  const frame0Calldata = new Uint8Array(4 + 32 * 4);
  frame0Calldata.set(frame0Selector, 0);
  frame0Calldata[35] = v + 27;
  const rHex = r.toString(16).padStart(64, "0");
  frame0Calldata.set(hexToBytes(("0x" + rHex) as Hex), 36);
  const sHex = s.toString(16).padStart(64, "0");
  frame0Calldata.set(hexToBytes(("0x" + sHex) as Hex), 68);
  frame0Calldata[131] = 0; // scope = 0 (execution only)
  frameTxParams.frames[0].data = frame0Calldata;

  // Build Frame 1 calldata: validate() or validateWithLimit(tokenLimit)
  if (tokenLimit !== undefined) {
    const limitData = encodeAbiParameters(
      parseAbiParameters("uint256"),
      [tokenLimit]
    );
    frameTxParams.frames[1].data = hexToBytes(
      (validateSelector + limitData.slice(2)) as Hex
    );
  } else {
    frameTxParams.frames[1].data = hexToBytes(validateSelector);
  }

  // Send
  step("Sending 5-frame sponsored transaction...");
  const rawTx = encodeFrameTx(frameTxParams);

  if (expectFailure) {
    try {
      const txHash = (await publicClient.request({
        method: "eth_sendRawTransaction" as any,
        params: [rawTx],
      })) as Hash;
      // If we get a hash, wait for receipt and check it failed
      const receipt = await waitForReceipt(publicClient, txHash);
      if (receipt.status === "0x1") {
        throw new Error("Expected failure but transaction succeeded");
      }
      success("Transaction correctly failed on-chain");
    } catch (err: any) {
      if (err.message?.includes("Expected failure")) throw err;
      // RPC rejection is also acceptable
      success(`Transaction correctly rejected: ${err.message?.slice(0, 80)}`);
    }
    return;
  }

  const txHash = (await publicClient.request({
    method: "eth_sendRawTransaction" as any,
    params: [rawTx],
  })) as Hash;
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

  // Payer should be the paymaster
  if (receipt.payer) {
    if (receipt.payer.toLowerCase() !== paymasterAddr.toLowerCase()) {
      throw new Error(`Wrong payer: got ${receipt.payer}, want ${paymasterAddr}`);
    }
    success(`Payer is paymaster: ${paymasterAddr}`);
  }

  // Frame count
  if (!receipt.frameReceipts || receipt.frameReceipts.length !== 5) {
    throw new Error(`Frame count: got ${receipt.frameReceipts?.length ?? 0}, want 5`);
  }
  success("5 frame receipts present");

  // Frame statuses
  const expectedStatuses = ["0x2", "0x3", "0x1", "0x1", "0x1"];
  const frameLabels = [
    "VERIFY(sender): APPROVED_EXECUTION",
    "VERIFY(paymaster): APPROVED_PAYMENT",
    "SENDER(transfer): SUCCESS",
    "SENDER(execute): SUCCESS",
    "DEFAULT(postOp): SUCCESS",
  ];
  for (let i = 0; i < 5; i++) {
    const actual = receipt.frameReceipts[i].status;
    if (actual !== expectedStatuses[i]) {
      throw new Error(`Frame ${i} (${frameLabels[i]}): got ${actual}, want ${expectedStatuses[i]}`);
    }
    success(`Frame ${i}: ${frameLabels[i]} (${expectedStatuses[i]})`);
  }

  // Verify token balances
  step("Verifying token balances...");
  const paymasterTokenBalance = await publicClient.readContract({
    address: tokenAddr,
    abi: benchmarkTokenAbi,
    functionName: "balanceOf",
    args: [paymasterAddr],
  }) as bigint;
  detail(`Paymaster token balance: ${paymasterTokenBalance}`);

  if (paymasterTokenBalance < tokenAmount) {
    // Paymaster may have accumulated from multiple tests
    // Just check it received at least the transfer amount
    throw new Error(`Paymaster didn't receive tokens: ${paymasterTokenBalance}`);
  }
  success("Paymaster received tokens from sponsored transaction");
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
