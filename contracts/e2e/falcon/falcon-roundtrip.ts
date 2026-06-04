/**
 * E2E: Falcon8141Account smart account via EIP-8052 precompiles.
 *
 * Usage: cd contracts && npx tsx e2e/falcon/falcon-roundtrip.ts
 */

import {
  encodeAbiParameters,
  encodeFunctionData,
  formatEther,
  keccak256,
  parseAbiParameters,
  toBytes,
  type Address,
  type Hex,
} from "viem";
import { toFrameAccount } from "viem/eip8141";
import type { FrameAccount } from "viem/eip8141";
import { CHAIN_ID, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, fundAccount, waitForReceipt } from "../helpers/client.js";
import { deployContract, loadBytecode } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import {
  FALCON_ALG_TYPE_SHAKE256,
  FALCON_PK_SIZE,
  FALCON_SIG_SIZE,
  deriveFalconAddress,
  falconSignDigest,
  generateFalconKeypair,
  toHex,
  type FalconEoaScope,
} from "../helpers/falcon-eth.js";
import {
  banner,
  fatal,
  info,
  printReceipt,
  sectionHeader,
  step,
  success,
  summary,
  testHeader,
  testPassed,
} from "../helpers/log.js";

const HASH_TO_POINT_SHAKE256 =
  "0x0000000000000000000000000000000000000014" as Address;
const FALCON_CORE =
  "0x0000000000000000000000000000000000000016" as Address;
const HASH_TO_POINT_MODE_SHAKE256 = 0;

const VALIDATION_DOMAIN = keccak256(
  toBytes("Falcon8141Account.validation.v1"),
);

const falconAccountAbi = [
  {
    type: "function",
    name: "validate",
    inputs: [
      { name: "signature", type: "bytes" },
      { name: "approvalScope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "view",
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
] as const;

function sstore2CreationCode(data: Uint8Array): Hex {
  const runtimeLen = data.length + 1;
  const header = new Uint8Array([
    0x61,
    (runtimeLen >> 8) & 0xff,
    runtimeLen & 0xff,
    0x80,
    0x60,
    0x0a,
    0x3d,
    0x39,
    0x3d,
    0xf3,
    0x00,
  ]);
  const bytecode = new Uint8Array(header.length + data.length);
  bytecode.set(header);
  bytecode.set(data, header.length);
  return toHex(bytecode);
}

function falconValidationDigest(params: {
  account: Address;
  sigHash: Hex;
  scope: FalconEoaScope;
}): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32,uint256,address,uint8,bytes32,uint8"),
      [
        VALIDATION_DOMAIN,
        BigInt(CHAIN_ID),
        params.account,
        FALCON_ALG_TYPE_SHAKE256,
        params.sigHash,
        params.scope,
      ],
    ),
  );
}

function createFalconSmartAccount(params: {
  address: Address;
  secretKey: Uint8Array;
  scope?: FalconEoaScope;
  verifyGas?: bigint;
  senderGas?: bigint;
}): FrameAccount {
  const {
    address,
    secretKey,
    scope = 2,
    verifyGas = 500_000n,
    senderGas = 100_000n,
  } = params;

  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const digest = falconValidationDigest({ account: address, sigHash, scope });
      const sig = falconSignDigest(digest, secretKey);

      return [
        {
          mode: "verify" as const,
          flags: scope,
          target: null,
          gasLimit: verifyGas,
          data: encodeFunctionData({
            abi: falconAccountAbi,
            functionName: "validate",
            args: [toHex(sig), scope],
          }),
        },
      ];
    },
    encodeCalls: (calls) =>
      calls.map((call) => ({
        mode: "sender" as const,
        target: null,
        gasLimit: senderGas,
        data: encodeFunctionData({
          abi: falconAccountAbi,
          functionName: "execute",
          args: [call.to, call.value ?? 0n, call.data ?? ("0x" as Hex)],
        }),
      })),
  });
}

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Falcon8141Account E2E (Smart Account)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  sectionHeader("Generate Falcon-512 Key Pair");
  const t0 = Date.now();
  const { pk, sk } = generateFalconKeypair();
  const signerAddr = deriveFalconAddress(pk);
  step(`KeyGen complete (${Date.now() - t0}ms)`);
  info(`Public key: ${pk.length} bytes (expected ${FALCON_PK_SIZE})`);
  info(`Secret key: ${sk.length} bytes`);
  info(`Signature size: ${FALCON_SIG_SIZE} bytes`);
  info(`Public key prefix: ${toHex(pk).slice(0, 18)}...`);
  info(`Falcon signer address: ${signerAddr}`);

  sectionHeader("Deploy Falcon PK Data Contract");
  const pkCreationCode = sstore2CreationCode(pk);
  const { address: pkContractAddr } = await deployContract(
    walletClient,
    publicClient,
    pkCreationCode,
    300_000n,
    "Falcon PK Data Contract",
  );

  sectionHeader("Deploy Falcon8141Account");
  const bytecode = loadBytecode("Falcon8141Account");
  const constructorArg = encodeAbiParameters(
    parseAbiParameters("address,address,address,uint8"),
    [
      pkContractAddr,
      HASH_TO_POINT_SHAKE256,
      FALCON_CORE,
      HASH_TO_POINT_MODE_SHAKE256,
    ],
  );
  const initCode = `${bytecode}${constructorArg.slice(2)}` as Hex;
  const { address: accountAddr } = await deployContract(
    walletClient,
    publicClient,
    initCode,
    700_000n,
    "Falcon8141Account",
  );

  sectionHeader("Fund Falcon Smart Account");
  await fundAccount(walletClient, publicClient, accountAddr);

  const account = createFalconSmartAccount({
    address: accountAddr,
    secretKey: sk,
  });

  testHeader(1, "Falcon Smart Account Verify + Execute");
  const targetBalance = await publicClient.getBalance({ address: DEAD_ADDR });

  step("Sending 2-frame tx: VERIFY(Falcon) + SENDER(transfer)...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR, value: 1n }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);
  printReceipt(receipt);
  verifyReceipt(receipt, accountAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  const newTargetBalance = await publicClient.getBalance({ address: DEAD_ADDR });
  if (newTargetBalance - targetBalance !== 1n) {
    throw new Error(`Balance delta: got ${newTargetBalance - targetBalance}, want 1`);
  }
  success("1 wei transferred to DEAD_ADDR");
  testPassed("Falcon Smart Account");

  testHeader(2, "Second Falcon smart account transaction (key reuse)");
  const targetBalance2 = await publicClient.getBalance({ address: DEAD_ADDR });

  step("Sending another frame tx with the same Falcon key...");
  const txHash2 = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR, value: 1n }],
  });

  const receipt2 = await waitForReceipt(publicClient, txHash2);
  verifyReceipt(receipt2, accountAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  const newTargetBalance2 = await publicClient.getBalance({ address: DEAD_ADDR });
  if (newTargetBalance2 - targetBalance2 !== 1n) {
    throw new Error(`Balance delta: got ${newTargetBalance2 - targetBalance2}, want 1`);
  }
  success("Second transaction verified with the same Falcon key");
  testPassed("Falcon Smart Account Key Reuse");

  summary("Falcon Smart Account", 2);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
