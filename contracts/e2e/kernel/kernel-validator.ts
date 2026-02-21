/**
 * E2E: Kernel8141 non-root validator via SENDER frame cross-read
 *
 * Usage: cd contracts && npx tsx e2e/kernel/kernel-validator.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  bytesToHex,
  type Hex,
  type Hash,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { CHAIN_ID, DEV_KEY, SECOND_OWNER_KEY, DEAD_ADDR, FRAME_MODE_VERIFY, FRAME_MODE_SENDER } from "../helpers/config.js";
import { waitForReceipt } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { printReceipt, verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi } from "../helpers/abis/kernel.js";
import { sectionHeader, testHeader, step, info, testPassed, summary, fatal } from "../helpers/log.js";
import { deployKernelTestbed, type KernelTestContext } from "./setup.js";

async function sendFrameTx(
  ctx: KernelTestContext,
  senderCalldata: Hex,
  senderGas = 500_000n
): Promise<any> {
  const { publicClient, kernelAddr } = ctx;
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
      { mode: FRAME_MODE_VERIFY, target: null, gasLimit: 300_000n, data: new Uint8Array(0) },
      { mode: FRAME_MODE_SENDER, target: null, gasLimit: senderGas, data: hexToBytes(senderCalldata) },
    ],
    blobFeeCap: 0n,
    blobHashes: [],
  };

  const sigHash = computeSigHash(frameTxParams);
  const { packed: packedSig } = signFrameHash(sigHash, DEV_KEY);
  const validateCalldata = encodeFunctionData({
    abi: kernelAbi,
    functionName: "validate",
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

async function sendFrameTxWithValidator(
  ctx: KernelTestContext,
  signingKey: Hex,
  validatorAddr: Address,
  innerCalldata: Hex,
  senderGas = 700_000n
): Promise<any> {
  const { publicClient, kernelAddr } = ctx;
  const kernelNonce = await publicClient.getTransactionCount({ address: kernelAddr });
  const block = await publicClient.getBlock();
  const gasFeeCap = block.baseFeePerGas! + 2_000_000_000n;

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

  const sigHash = computeSigHash(frameTxParams);
  const { packed: packedSig } = signFrameHash(sigHash, signingKey);
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

async function main() {
  const ctx = await deployKernelTestbed();

  sectionHeader("🔧 Setup: Install DefaultExecutor");
  {
    const executorConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], uint48, uint48, uint8"),
      [["0xb61d27f6"], 0, 0, 2]
    );
    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [1, ctx.defaultExecutorAddr, executorConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
  }

  testHeader(1, "validateFromSenderFrame + validatedCall (sigHash-bound)");
  {
    const secondOwnerAccount = privateKeyToAccount(SECOND_OWNER_KEY);
    const secondOwnerAddr = secondOwnerAccount.address;
    info(`Second owner: ${secondOwnerAddr}`);

    step("Deploying second ECDSAValidator...");
    const validatorBytecode = loadBytecode("ECDSAValidator");
    const { address: secondValidatorAddr } = await deployContract(
      ctx.walletClient, ctx.publicClient, validatorBytecode, 3_000_000n, "ECDSAValidator #2"
    );

    step("Installing second validator...");
    const installConfig = encodeAbiParameters(parseAbiParameters("address"), [secondOwnerAddr]);
    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [0, secondValidatorAddr, installConfig],
    });
    const installReceipt = await sendFrameTx(ctx, installCalldata);
    verifyReceipt(installReceipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });

    step("Sending frame tx with non-root validator...");
    const innerCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    });
    const receipt = await sendFrameTxWithValidator(
      ctx, SECOND_OWNER_KEY as Hex, secondValidatorAddr, innerCalldata
    );
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("Non-root validator bound to sigHash via SENDER frame");
  }

  summary("Kernel Validator", 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
