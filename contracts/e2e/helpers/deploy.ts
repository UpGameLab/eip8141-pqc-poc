import { getContractAddress, type Hex, type Address, type Hash } from "viem";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { CHAIN_DEF } from "./config.js";
import { waitForReceipt } from "./client.js";
import { deploy as logDeploy } from "./log.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Load compiled bytecode from forge output artifacts. */
export function loadBytecode(contractName: string): Hex {
  const artifactPath = join(
    __dirname,
    "..",
    "..",
    "out",
    `${contractName}.sol`,
    `${contractName}.json`
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  return artifact.bytecode.object as Hex;
}

/** Deploy a contract and return its address. */
export async function deployContract(
  walletClient: any,
  publicClient: any,
  bytecode: Hex,
  gas = 3_000_000n,
  label?: string
): Promise<{ hash: Hash; address: Address }> {
  const devAddr = walletClient.account.address;
  const nonce = await publicClient.getTransactionCount({ address: devAddr });
  const expectedAddr = getContractAddress({
    from: devAddr,
    nonce: BigInt(nonce),
  });

  const hash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    data: bytecode,
    gas,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });

  const receipt = await waitForReceipt(publicClient, hash);
  if (receipt.status !== "0x1") {
    throw new Error(`Deploy failed: status=${receipt.status}, tx=${hash}`);
  }
  logDeploy(label || "Contract", expectedAddr, hash);
  return { hash, address: expectedAddr };
}
