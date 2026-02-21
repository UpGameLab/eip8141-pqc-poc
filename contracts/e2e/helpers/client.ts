import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  type Hash,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { RPC_URL, DEV_KEY, CHAIN_DEF } from "./config.js";
import { fund as logFund } from "./log.js";

export async function waitForReceipt(
  publicClient: any,
  hash: Hash,
  timeoutMs = 60_000
): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const receipt = await publicClient.request({
        method: "eth_getTransactionReceipt" as any,
        params: [hash],
      });
      if (receipt) return receipt;
    } catch (e) {
      // Receipt not yet available, retry
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Timeout waiting for receipt of ${hash}`);
}

export function createTestClients() {
  const account = privateKeyToAccount(DEV_KEY);
  const devAddr = account.address;
  const publicClient = createPublicClient({ transport: http(RPC_URL) });
  const walletClient = createWalletClient({ account, transport: http(RPC_URL) });
  return { account, publicClient, walletClient, devAddr };
}

export async function fundAccount(
  walletClient: any,
  publicClient: any,
  to: Address,
  ethAmount = "10"
): Promise<void> {
  const fundHash = await walletClient.sendTransaction({
    chain: CHAIN_DEF,
    to,
    value: parseEther(ethAmount),
    gas: 50_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  await waitForReceipt(publicClient, fundHash);
  logFund(to, `${ethAmount} ETH`);
}
