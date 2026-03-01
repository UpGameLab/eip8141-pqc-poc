/**
 * Account factories and frame transaction helpers using viem/eip8141.
 *
 * Each factory wraps toFrameAccount() with the appropriate VERIFY and SENDER
 * encoding for its account type.
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  concatHex,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { toFrameAccount } from "viem/eip8141";
import type { FrameAccount, FramePaymaster } from "viem/eip8141";
import { DEV_KEY } from "./config.js";
import { kernelAbi } from "./abis/kernel.js";
import { walletAbi as coinbaseAbi } from "./abis/coinbase.js";
import { walletAbi as lightAccountAbi } from "./abis/light-account.js";
import { waitForReceipt } from "./client.js";

// Re-export types for convenience
export type { FrameAccount, FramePaymaster };

// ── Shared options ──────────────────────────────────────────────────

export interface AccountOptions {
  scope?: number;
  verifyGas?: bigint;
  senderGas?: bigint;
}

/** Shared encodeCalls: map each call to a SENDER frame targeting the sender itself. */
function defaultEncodeCalls(senderGas: bigint) {
  return (calls: { data?: Hex }[]) =>
    calls.map((c) => ({
      mode: "sender" as const,
      target: null,
      gasLimit: senderGas,
      data: c.data ?? ("0x" as Hex),
    }));
}

// ── Kernel ──────────────────────────────────────────────────────────

/** Root validator: validate(packedSig, scope) */
export function createKernelAccount(
  address: Address,
  privKey: Hex = DEV_KEY,
  opts: AccountOptions = {},
): FrameAccount {
  const { scope = 2, verifyGas = 300_000n, senderGas = 500_000n } = opts;
  const owner = privateKeyToAccount(privKey);
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = await owner.sign({ hash: sigHash });
      const data = encodeFunctionData({
        abi: kernelAbi,
        functionName: "validate",
        args: [sig, scope],
      });
      return [{ mode: "verify" as const, target: null, gasLimit: verifyGas, data }];
    },
    encodeCalls: defaultEncodeCalls(senderGas),
  });
}

/** Non-root validator: validateFromSenderFrame([0x01][validatorAddr][sig], scope) */
export function createKernelValidatorAccount(
  address: Address,
  validatorAddr: Address,
  privKey: Hex,
  opts: AccountOptions = {},
): FrameAccount {
  const { scope = 2, verifyGas = 300_000n, senderGas = 700_000n } = opts;
  const owner = privateKeyToAccount(privKey);
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = await owner.sign({ hash: sigHash });
      const sigPrefix = `0x01${validatorAddr.slice(2)}` as Hex;
      const prefixedSig = concatHex([sigPrefix, sig]);
      const data = encodeFunctionData({
        abi: kernelAbi,
        functionName: "validateFromSenderFrame",
        args: [prefixedSig, scope],
      });
      return [{ mode: "verify" as const, target: null, gasLimit: verifyGas, data }];
    },
    encodeCalls: defaultEncodeCalls(senderGas),
  });
}

/** Permission: validatePermission([0x02][permId][0xff][sig], scope) */
export function createKernelPermissionAccount(
  address: Address,
  permissionId: Hex,
  privKey: Hex,
  opts: AccountOptions = {},
): FrameAccount {
  const { scope = 2, verifyGas = 300_000n, senderGas = 500_000n } = opts;
  const owner = privateKeyToAccount(privKey);
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = await owner.sign({ hash: sigHash });
      const permSig = concatHex([permissionId, "0xff", sig]);
      const fullSig = concatHex(["0x02", permSig]);
      const data = encodeFunctionData({
        abi: kernelAbi,
        functionName: "validatePermission",
        args: [fullSig, scope],
      });
      return [{ mode: "verify" as const, target: null, gasLimit: verifyGas, data }];
    },
    encodeCalls: defaultEncodeCalls(senderGas),
  });
}

// ── Coinbase ────────────────────────────────────────────────────────

/** Coinbase: validate(abiEncode(ownerIndex, sig), scope) */
export function createCoinbaseAccount(
  address: Address,
  ownerIndex: number,
  privKey: Hex,
  opts: AccountOptions = {},
): FrameAccount {
  const { scope = 2, verifyGas = 300_000n, senderGas = 500_000n } = opts;
  const owner = privateKeyToAccount(privKey);
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = await owner.sign({ hash: sigHash });
      const signatureWrapper = encodeAbiParameters(
        parseAbiParameters("uint256, bytes"),
        [BigInt(ownerIndex), sig],
      );
      const data = encodeFunctionData({
        abi: coinbaseAbi,
        functionName: "validate",
        args: [signatureWrapper, scope],
      });
      return [{ mode: "verify" as const, target: null, gasLimit: verifyGas, data }];
    },
    encodeCalls: defaultEncodeCalls(senderGas),
  });
}

// ── LightAccount ────────────────────────────────────────────────────

/** LightAccount: validate([0x00 (EOA)][65B sig], scope) */
export function createLightAccount(
  address: Address,
  privKey: Hex = DEV_KEY,
  opts: AccountOptions = {},
): FrameAccount {
  const { scope = 2, verifyGas = 300_000n, senderGas = 500_000n } = opts;
  const owner = privateKeyToAccount(privKey);
  return toFrameAccount({
    address,
    async signFrameTransaction({ sigHash }) {
      const sig = await owner.sign({ hash: sigHash });
      // Prepend 0x00 (SignatureType.EOA) to the 65-byte signature
      const typedSig = concatHex(["0x00", sig]);
      const data = encodeFunctionData({
        abi: lightAccountAbi,
        functionName: "validate",
        args: [typedSig, scope],
      });
      return [{ mode: "verify" as const, target: null, gasLimit: verifyGas, data }];
    },
    encodeCalls: defaultEncodeCalls(senderGas),
  });
}

// ── Convenience: send + wait ────────────────────────────────────────

/** Send a frame transaction and wait for the receipt. */
export async function sendAndWait(
  publicClient: any,
  account: FrameAccount,
  senderCalldata: Hex,
): Promise<any> {
  const txHash = await publicClient.sendFrameTransaction({
    account,
    calls: [{ to: account.address, data: senderCalldata }],
  });
  return await waitForReceipt(publicClient, txHash);
}
