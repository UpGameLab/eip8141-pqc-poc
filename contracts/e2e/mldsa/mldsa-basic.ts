/**
 * E2E: MLDSA8141Account — post-quantum smart account with ML-DSA-ETH verification
 *
 * Demonstrates EIP-8141 + EIP-8051 integration:
 *   1. Generate ML-DSA-ETH key pair (Keccak PRNG variant)
 *   2. Deploy PK data contract via SSTORE2 pattern (code storage, no SSTOREs)
 *   3. Deploy MLDSA8141Account referencing the PK data contract
 *   4. Send frame transaction verified by VERIFY_MLDSA_ETH precompile (0x13)
 *
 * Frame layout:
 *   Frame 0: VERIFY(account) → validate(mldsaSig, scope=2) → APPROVE(both)
 *   Frame 1: SENDER(target)  → ETH transfer to DEAD_ADDR
 *
 * Usage: cd contracts && npx tsx e2e/mldsa/mldsa-basic.ts
 */

import {
  encodeFunctionData,
  encodeAbiParameters,
  parseAbiParameters,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { toFrameAccount } from "viem/eip8141";
import type { FrameAccount } from "viem/eip8141";
import { DEAD_ADDR } from "../helpers/config.js";
import { createTestClients, waitForReceipt, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { verifyReceipt } from "../helpers/receipt.js";
import {
  keygen,
  sign,
  toHex,
  fromHex,
  MLDSA_PK_SIZE,
  MLDSA_SIG_SIZE,
} from "../helpers/mldsa-eth.js";
import {
  banner,
  sectionHeader,
  info,
  step,
  success,
  testHeader,
  testPassed,
  summary,
  fatal,
} from "../helpers/log.js";

// ── ABI for MLDSA8141Account ─────────────────────────────────────────

const mldsaAccountAbi = [
  {
    type: "function",
    name: "validate",
    inputs: [
      { name: "signature", type: "bytes" },
      { name: "scope", type: "uint8" },
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

// ── SSTORE2: deploy data as contract bytecode ────────────────────────

/**
 * Build creation bytecode that deploys `0x00 || data` as runtime code.
 *
 * Creation code (11 bytes):
 *   PUSH2 runtimeLen | DUP1 | PUSH1 0x0b | RETURNDATASIZE | CODECOPY | RETURNDATASIZE | RETURN
 * Runtime code:
 *   0x00 (STOP) | data
 */
function sstore2CreationCode(data: Uint8Array): Hex {
  const runtimeLen = data.length + 1; // +1 for STOP prefix
  const header = new Uint8Array([
    0x61, (runtimeLen >> 8) & 0xff, runtimeLen & 0xff, // PUSH2 runtimeLen
    0x80,       // DUP1
    0x60, 0x0a, // PUSH1 10 (creation code size)
    0x3d,       // RETURNDATASIZE (push 0 as destOffset)
    0x39,       // CODECOPY
    0x3d,       // RETURNDATASIZE (push 0 as offset)
    0xf3,       // RETURN
    0x00,       // STOP (runtime code prefix)
  ]);
  const bytecode = new Uint8Array(header.length + data.length);
  bytecode.set(header);
  bytecode.set(data, header.length);
  return toHex(bytecode);
}

// ── MLDSA Account Factory ────────────────────────────────────────────

function createMLDSAAccount(params: {
  address: Address;
  secretKey: Uint8Array;
  verifyGas?: bigint;
  senderGas?: bigint;
}): FrameAccount {
  const { address, secretKey, verifyGas = 500_000n, senderGas = 100_000n } = params;

  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      // Sign the sigHash using ML-DSA-ETH
      const msgBytes = fromHex(sigHash as Hex);
      const sigBytes = sign(secretKey, msgBytes);
      const sigHex = toHex(sigBytes);

      // Encode validate(bytes signature, uint8 scope) calldata
      const data = encodeFunctionData({
        abi: mldsaAccountAbi,
        functionName: "validate",
        args: [sigHex, 2], // scope=BOTH
      });

      return [
        {
          mode: "verify" as const,
          flags: 2,
          target: null,
          gasLimit: verifyGas,
          data,
        },
      ];
    },
    encodeCalls: (calls) =>
      calls.map((c) => ({
        mode: "sender" as const,
        target: null,
        gasLimit: senderGas,
        data: encodeFunctionData({
          abi: mldsaAccountAbi,
          functionName: "execute",
          args: [c.to, c.value ?? 0n, c.data ?? ("0x" as Hex)],
        }),
      })),
  });
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("MLDSA8141Account E2E (Post-Quantum)");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── 1. Generate ML-DSA-ETH key pair ──
  sectionHeader("Generate ML-DSA-ETH Key Pair");
  const t0 = Date.now();
  const { expandedPK, secretKey } = keygen();
  step(`KeyGen complete (${Date.now() - t0}ms)`);
  info(`Expanded PK: ${MLDSA_PK_SIZE} bytes`);
  info(`PK prefix: ${toHex(expandedPK).slice(0, 18)}...`);

  // ── 2. Deploy PK data contract (SSTORE2 pattern) ──
  // Stores the 20,512-byte expanded PK as contract bytecode.
  // Much cheaper than 641 SSTOREs and fits within block gas limit.
  sectionHeader("Deploy PK Data Contract (SSTORE2)");
  const pkCreationCode = sstore2CreationCode(expandedPK);
  const { address: pkContractAddr } = await deployContract(
    walletClient,
    publicClient,
    pkCreationCode,
    5_000_000n,
    "PK Data Contract",
  );

  // ── 3. Deploy MLDSA8141Account ──
  sectionHeader("Deploy MLDSA8141Account");
  const bytecode = loadBytecode("MLDSA8141Account");
  const constructorArg = encodeAbiParameters(
    parseAbiParameters("address"),
    [pkContractAddr],
  );
  const initCode = (bytecode + constructorArg.slice(2)) as Hex;
  const { address: accountAddr } = await deployContract(
    walletClient,
    publicClient,
    initCode,
    500_000n,
    "MLDSA8141Account",
  );

  // ── 4. Fund the account ──
  sectionHeader("Fund Account");
  await fundAccount(walletClient, publicClient, accountAddr);

  // ── 5. Send frame transaction: VERIFY + SENDER ──
  testHeader(1, "ML-DSA-ETH Verify + Execute (ETH transfer)");

  const account = createMLDSAAccount({
    address: accountAddr,
    secretKey,
    verifyGas: 500_000n,
    senderGas: 50_000n,
  });

  step("Sending 2-frame tx: VERIFY(ML-DSA) → SENDER(transfer)...");
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR }],
  });

  const receipt = await waitForReceipt(publicClient, txHash);

  // Import printReceipt for detailed output
  const { printReceipt } = await import("../helpers/log.js");
  printReceipt(receipt);

  verifyReceipt(receipt, accountAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  // Check gas used by VERIFY frame
  if (receipt.frameReceipts) {
    const verifyGasUsed = BigInt(receipt.frameReceipts[0].gasUsed);
    info(`VERIFY frame gas: ${verifyGasUsed.toLocaleString()} (EXTCODECOPY + precompile)`);
  }

  success(`Post-quantum ML-DSA-ETH transaction verified at ${accountAddr}`);
  testPassed("ML-DSA-ETH Verify + Execute");

  // ── 6. Second transaction to prove key reuse works ──
  testHeader(2, "Second ML-DSA-ETH transaction (key reuse)");

  step("Sending another frame tx with same key pair...");
  const txHash2 = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: DEAD_ADDR }],
  });

  const receipt2 = await waitForReceipt(publicClient, txHash2);
  verifyReceipt(receipt2, accountAddr, {
    expectFrameCount: 2,
    verifyFrameIndex: 0,
    senderFrameIndex: 1,
  });

  success("Second transaction verified with same ML-DSA key");
  testPassed("Key Reuse");

  summary("MLDSA Deploy", 2);
}

main().catch((err) => {
  fatal(err);
  process.exit(1);
});
