import type { Hash } from "viem";

/**
 * Expect that calling fn() throws an RPC error (mempool rejection).
 * Returns the error message for further assertion.
 */
export async function expectRpcRejection(
  fn: () => Promise<any>,
  expectedSubstring?: string
): Promise<string> {
  try {
    await fn();
    throw new Error("__EXPECTED_REJECTION__");
  } catch (err: any) {
    const msg = err.message || String(err);
    if (msg.includes("__EXPECTED_REJECTION__")) {
      throw new Error("Expected RPC rejection but call succeeded");
    }
    if (expectedSubstring && !msg.toLowerCase().includes(expectedSubstring.toLowerCase())) {
      throw new Error(
        `Expected error containing "${expectedSubstring}" but got:\n  ${msg.slice(0, 200)}`
      );
    }
    return msg;
  }
}

/**
 * Expect that a transaction hash never produces a receipt.
 * Used for protocol-level failures where tx enters mempool but miner drops it.
 */
export async function expectNoReceipt(
  publicClient: any,
  hash: Hash,
  timeoutMs = 10_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const receipt = await publicClient.request({
        method: "eth_getTransactionReceipt" as any,
        params: [hash],
      });
      if (receipt) {
        throw new Error(
          `Expected no receipt but got one: status=${receipt.status}`
        );
      }
    } catch (e: any) {
      if (e.message?.includes("Expected no receipt")) throw e;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  // Timeout reached without receipt — success
}
