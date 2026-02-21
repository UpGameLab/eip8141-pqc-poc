/**
 * E2E: Kernel8141 module management and execution tests (Tests 1-7)
 *
 * Usage: cd contracts && npx tsx e2e/kernel/kernel-basic.ts
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  hexToBytes,
  bytesToHex,
  parseEther,
  type Hex,
  type Hash,
} from "viem";
import { CHAIN_ID, DEV_KEY, DEAD_ADDR, FRAME_MODE_VERIFY, FRAME_MODE_SENDER } from "../helpers/config.js";
import { waitForReceipt } from "../helpers/client.js";
import { computeSigHash, encodeFrameTx, type FrameTxParams } from "../helpers/frame-tx.js";
import { signFrameHash } from "../helpers/signing.js";
import { printReceipt, verifyReceipt } from "../helpers/receipt.js";
import { kernelAbi } from "../helpers/abis/kernel.js";
import { testHeader, testPassed, summary, fatal } from "../helpers/log.js";
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

async function main() {
  const ctx = await deployKernelTestbed();
  let testNum = 1;

  testHeader(testNum++, "Install DefaultExecutor");
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
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("DefaultExecutor installed for execute()");
  }

  testHeader(testNum++, "Install SpendingLimitHook");
  {
    const hookData = encodeAbiParameters(parseAbiParameters("uint256"), [parseEther("5")]);
    const hookConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], bytes"),
      [["0xb61d27f6"], hookData]
    );
    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [2, ctx.hookAddr, hookConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("SpendingLimitHook installed (5 ETH daily limit)");
  }

  testHeader(testNum++, "Install ERC1271Handler");
  {
    const handlerData = encodeAbiParameters(parseAbiParameters("address"), [ctx.validatorAddr]);
    const handlerConfig = encodeAbiParameters(
      parseAbiParameters("bytes4[], bytes"),
      [["0x1626ba7e"], handlerData]
    );
    const installCalldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "installModule",
      args: [4, ctx.handlerAddr, handlerConfig],
    });
    const receipt = await sendFrameTx(ctx, installCalldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("ERC1271Handler installed");
  }

  testHeader(testNum++, "Basic execute()");
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "execute",
      args: [DEAD_ADDR, 0n, "0x"],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed();
  }

  testHeader(testNum++, "executeBatch()");
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeBatch",
      args: [[DEAD_ADDR, DEAD_ADDR], [0n, 0n], ["0x", "0x"]],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed();
  }

  testHeader(testNum++, "executeTry() — graceful failure");
  {
    const calldata = encodeFunctionData({
      abi: kernelAbi,
      functionName: "executeTry",
      args: ["0x0000000000000000000000000000000000000001", 0n, "0xdeadbeef"],
    });
    const receipt = await sendFrameTx(ctx, calldata);
    printReceipt(receipt);
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("executeTry handled failure gracefully");
  }

  testHeader(testNum++, "executeBatchTry() — mixed success/failure");
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
    verifyReceipt(receipt, ctx.kernelAddr, { expectVerifyStatus: "0x4|0x2" });
    testPassed("executeBatchTry handled mixed results");
  }

  summary("Kernel Basic", testNum - 1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
