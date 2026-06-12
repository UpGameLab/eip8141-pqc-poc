/**
 * E2E: Falcon invalid-input rejection tests.
 *
 * Usage: cd contracts && npx tsx e2e/falcon/falcon-negative.ts
 */

import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  formatEther,
  keccak256,
  numberToHex,
  parseAbiParameters,
  toBytes,
  toRlp,
  type Address,
  type Hex,
} from "viem";
import { toFrameAccount, type FrameAccount } from "viem/eip8141";
import { CHAIN_ID, DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, fundAccount } from "../helpers/client.js";
import { deployContract, loadBytecode } from "../helpers/deploy.js";
import { expectRpcRejection } from "../helpers/expect.js";
import {
  FALCON_ALG_TYPE_SHAKE256,
  FALCON_SIG_TYPE_SHAKE256,
  deriveFalconAddress,
  falconEoaPrefix,
  falconSign,
  falconSignDigest,
  generateFalconKeypair,
  toHex,
  type FalconEoaScope,
} from "../helpers/falcon-eth.js";
import {
  banner,
  fail,
  info,
  sectionHeader,
  step,
  summary,
  testFailed,
  testHeader,
  testPassed,
  fatal,
} from "../helpers/log.js";

const HASH_TO_POINT_SHAKE256 =
  "0x0000000000000000000000000000000000000014" as Address;
const FALCON_CORE =
  "0x0000000000000000000000000000000000000016" as Address;
const HASH_TO_POINT_MODE_SHAKE256 = 0;
const SCOPE: FalconEoaScope = 3;

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

function toRlpQuantity(value: bigint): Hex {
  return value === 0n ? "0x" : numberToHex(value);
}

function buildFalconEoaSenderData(
  calls: { to: Address; value?: bigint; data?: Hex }[],
): Hex {
  return concatHex([
    "0x02",
    toRlp(
      calls.map((call) => [
        call.to,
        toRlpQuantity(call.value ?? 0n),
        call.data ?? ("0x" as Hex),
      ]),
    ),
  ]);
}

function buildRawFalconVerifyData(params: {
  publicKey: Uint8Array;
  signature: Uint8Array;
  sigType?: number;
}): Hex {
  return concatHex([
    numberToHex(falconEoaPrefix(SCOPE), { size: 1 }),
    numberToHex(params.sigType ?? FALCON_SIG_TYPE_SHAKE256, { size: 1 }),
    toHex(params.publicKey),
    toHex(params.signature),
  ]);
}

function createFalconEoaAccount(
  address: Address,
  buildVerifyData: (sigHash: Hex) => Hex,
): FrameAccount {
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      return [{
        mode: "verify" as const,
        flags: SCOPE,
        target: null,
        gasLimit: 250_000n,
        value: 0n,
        data: buildVerifyData(sigHash),
      }];
    },
    encodeCalls: (calls) => [{
      mode: "sender" as const,
      flags: 0,
      target: null,
      gasLimit: 100_000n,
      value: 0n,
      data: buildFalconEoaSenderData(calls),
    }],
  });
}

function falconValidationDigest(account: Address, sigHash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32,uint256,address,uint8,bytes32,uint8"),
      [
        VALIDATION_DOMAIN,
        BigInt(CHAIN_ID),
        account,
        FALCON_ALG_TYPE_SHAKE256,
        sigHash,
        SCOPE,
      ],
    ),
  );
}

function createFalconSmartAccount(
  address: Address,
  signDigest: (digest: Hex) => Uint8Array,
): FrameAccount {
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const signature = signDigest(falconValidationDigest(address, sigHash));
      return [{
        mode: "verify" as const,
        flags: SCOPE,
        target: null,
        gasLimit: 500_000n,
        data: encodeFunctionData({
          abi: falconAccountAbi,
          functionName: "validate",
          args: [toHex(signature), SCOPE],
        }),
      }];
    },
    encodeCalls: (calls) =>
      calls.map((call) => ({
        mode: "sender" as const,
        target: null,
        gasLimit: 100_000n,
        data: encodeFunctionData({
          abi: falconAccountAbi,
          functionName: "execute",
          args: [call.to, call.value ?? 0n, call.data ?? ("0x" as Hex)],
        }),
      })),
  });
}

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

function tamperSignature(signature: Uint8Array): Uint8Array {
  const tampered = new Uint8Array(signature);
  tampered[Math.floor(tampered.length / 2)] ^= 0x01;
  return tampered;
}

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();
  let passed = 0;
  const total = 6;

  banner("Falcon Negative E2E");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(await publicClient.getBalance({ address: devAddr }))} ETH`);

  sectionHeader("Generate Falcon Test Keys");
  const validKey = generateFalconKeypair();
  const wrongKey = generateFalconKeypair();
  const falconEoaAddress = deriveFalconAddress(validKey.pk);
  await fundAccount(walletClient, publicClient, falconEoaAddress);

  sectionHeader("Deploy Falcon8141Account");
  const { address: pkContractAddr } = await deployContract(
    walletClient,
    publicClient,
    sstore2CreationCode(validKey.pk),
    300_000n,
    "Falcon PK Data Contract",
  );
  const constructorArg = encodeAbiParameters(
    parseAbiParameters("address,address,address,uint8"),
    [
      pkContractAddr,
      HASH_TO_POINT_SHAKE256,
      FALCON_CORE,
      HASH_TO_POINT_MODE_SHAKE256,
    ],
  );
  const initCode = `${loadBytecode("Falcon8141Account")}${constructorArg.slice(2)}` as Hex;
  const { address: smartAccountAddress } = await deployContract(
    walletClient,
    publicClient,
    initCode,
    700_000n,
    "Falcon8141Account",
  );
  await fundAccount(walletClient, publicClient, smartAccountAddress);

  async function expectRejected(
    testNumber: number,
    label: string,
    account: FrameAccount,
  ): Promise<void> {
    testHeader(testNumber, label);
    try {
      const message = await expectRpcRejection(async () => {
        await publicClient.sendFrameTransaction({
          account,
          calls: [{ to: DEAD_ADDR, value: 1n }],
        });
      }, "VERIFY frame 0 execution failed");
      step(`Rejected: ${message.slice(0, 120)}`);
      testPassed(label);
      passed++;
    } catch (err: any) {
      fail(err.message || String(err));
      testFailed(label);
    }
  }

  await expectRejected(
    1,
    "Falcon EOA wrong signature",
    createFalconEoaAccount(falconEoaAddress, (sigHash) => {
      const signature = falconSign(sigHash, wrongKey.sk, FALCON_SIG_TYPE_SHAKE256, SCOPE);
      return buildRawFalconVerifyData({ publicKey: validKey.pk, signature });
    }),
  );

  await expectRejected(
    2,
    "Falcon EOA tampered signature",
    createFalconEoaAccount(falconEoaAddress, (sigHash) => {
      const signature = tamperSignature(
        falconSign(sigHash, validKey.sk, FALCON_SIG_TYPE_SHAKE256, SCOPE),
      );
      return buildRawFalconVerifyData({ publicKey: validKey.pk, signature });
    }),
  );

  await expectRejected(
    3,
    "Falcon EOA wrong sig_type",
    createFalconEoaAccount(falconEoaAddress, (sigHash) => {
      const signature = falconSign(sigHash, validKey.sk, FALCON_SIG_TYPE_SHAKE256, SCOPE);
      return buildRawFalconVerifyData({
        publicKey: validKey.pk,
        signature,
        sigType: 0x99,
      });
    }),
  );

  await expectRejected(
    4,
    "Falcon EOA truncated public key",
    createFalconEoaAccount(falconEoaAddress, (sigHash) => {
      const signature = falconSign(sigHash, validKey.sk, FALCON_SIG_TYPE_SHAKE256, SCOPE);
      return buildRawFalconVerifyData({
        publicKey: validKey.pk.slice(0, 100),
        signature,
      });
    }),
  );

  await expectRejected(
    5,
    "Falcon8141Account wrong signature",
    createFalconSmartAccount(smartAccountAddress, (digest) =>
      falconSignDigest(digest, wrongKey.sk),
    ),
  );

  await expectRejected(
    6,
    "Falcon8141Account tampered signature",
    createFalconSmartAccount(smartAccountAddress, (digest) =>
      tamperSignature(falconSignDigest(digest, validKey.sk)),
    ),
  );

  summary("Falcon Negative", passed, total);
  if (passed < total) process.exit(1);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
