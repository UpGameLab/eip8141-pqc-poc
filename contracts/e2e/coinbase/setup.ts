import {
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { p256 } from "@noble/curves/p256";
import { OWNER2_KEY } from "../helpers/config.js";
import { createTestClients, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { walletAbi, factoryAbi } from "../helpers/abis/coinbase.js";
import { banner, sectionHeader, info, success, detail } from "../helpers/log.js";

export type CoinbaseTestContext = {
  publicClient: any;
  walletClient: any;
  devAddr: Address;
  owner2Addr: Address;
  walletAddr: Address;
  factoryAddr: Address;
  implAddr: Address;
  p256PrivKey: Hex;
  p256X: bigint;
  p256Y: bigint;
};

/** Deploy CoinbaseSmartWallet8141 via Factory with 3 owners (2 ECDSA + 1 P256) and fund with 10 ETH. */
export async function deployCoinbaseTestbed(): Promise<CoinbaseTestContext> {
  const { publicClient, walletClient, devAddr } = createTestClients();
  const owner2Account = privateKeyToAccount(OWNER2_KEY);
  const owner2Addr = owner2Account.address;

  const p256PrivKey = ("0x" + "3".repeat(64)) as Hex;
  const p256PubKey = p256.getPublicKey(p256PrivKey.slice(2), false);
  const p256X = BigInt("0x" + Buffer.from(p256PubKey.slice(1, 33)).toString("hex"));
  const p256Y = BigInt("0x" + Buffer.from(p256PubKey.slice(33, 65)).toString("hex"));

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("CoinbaseSmartWallet8141 E2E");
  info(`Owner 1 (ECDSA): ${devAddr}`);
  info(`Owner 2 (ECDSA): ${owner2Addr}`);
  info(`Owner 3 (P256):  x=${p256X.toString(16).slice(0, 16)}...`);
  info(`Balance: ${formatEther(balance)} ETH`);

  // ── Deploy Implementation ──
  sectionHeader("Deploy Implementation");
  const implBytecode = loadBytecode("CoinbaseSmartWallet8141");
  const { address: implAddr } = await deployContract(
    walletClient, publicClient, implBytecode, 5_000_000n, "CoinbaseSmartWallet8141 (impl)"
  );

  // ── Deploy Factory ──
  sectionHeader("Deploy Factory");
  const factoryBytecode = loadBytecode("CoinbaseSmartWalletFactory8141");
  const factoryConstructorArgs = encodeAbiParameters(
    parseAbiParameters("address"),
    [implAddr]
  );
  const factoryDeployData = (factoryBytecode + factoryConstructorArgs.slice(2)) as Hex;
  const { address: factoryAddr } = await deployContract(
    walletClient, publicClient, factoryDeployData, 3_000_000n, "CoinbaseSmartWalletFactory8141"
  );

  // ── Create Account via Factory ──
  sectionHeader("Create Account via Factory");
  const owners = [
    encodeAbiParameters(parseAbiParameters("address"), [devAddr]),
    encodeAbiParameters(parseAbiParameters("address"), [owner2Addr]),
    encodeAbiParameters(parseAbiParameters("bytes32, bytes32"), [
      ("0x" + p256X.toString(16).padStart(64, "0")) as Hex,
      ("0x" + p256Y.toString(16).padStart(64, "0")) as Hex,
    ]),
  ];

  // Predict deterministic address
  const walletAddr = await publicClient.readContract({
    address: factoryAddr,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [owners, 0n],
  }) as Address;
  detail(`Predicted wallet address: ${walletAddr}`);

  // Deploy via factory
  const createData = encodeFunctionData({
    abi: factoryAbi,
    functionName: "createAccount",
    args: [owners, 0n],
  });
  const createHash = await walletClient.sendTransaction({
    to: factoryAddr,
    data: createData,
    gas: 5_000_000n,
    maxFeePerGas: 10_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
  });
  const createReceipt = await publicClient.waitForTransactionReceipt({ hash: createHash });
  if (createReceipt.status !== "success") {
    throw new Error(`Factory createAccount failed: tx=${createHash}`);
  }
  success(`Account created at ${walletAddr}`);

  // ── Verify Owners ──
  sectionHeader("Verify Owners");
  const isOwner1 = await publicClient.readContract({ address: walletAddr, abi: walletAbi, functionName: "isOwnerAddress", args: [devAddr] });
  const isOwner2 = await publicClient.readContract({ address: walletAddr, abi: walletAbi, functionName: "isOwnerAddress", args: [owner2Addr] });
  const isOwner3 = await publicClient.readContract({
    address: walletAddr, abi: walletAbi, functionName: "isOwnerPublicKey",
    args: [
      ("0x" + p256X.toString(16).padStart(64, "0")) as Hex,
      ("0x" + p256Y.toString(16).padStart(64, "0")) as Hex,
    ],
  });
  const ownerCount = await publicClient.readContract({ address: walletAddr, abi: walletAbi, functionName: "ownerCount" });

  detail(`Owner 1 (ECDSA): ${isOwner1 ? "OK" : "FAIL"}`);
  detail(`Owner 2 (ECDSA): ${isOwner2 ? "OK" : "FAIL"}`);
  detail(`Owner 3 (P256):  ${isOwner3 ? "OK" : "FAIL"}`);
  detail(`Owner count: ${ownerCount}`);

  if (!isOwner1 || !isOwner2 || !isOwner3) throw new Error("Owner verification failed");
  if (Number(ownerCount) !== 3) throw new Error(`Expected 3 owners, got ${ownerCount}`);
  success("All owners verified");

  // ── Fund Wallet ──
  sectionHeader("Fund Wallet");
  await fundAccount(walletClient, publicClient, walletAddr);

  return { publicClient, walletClient, devAddr, owner2Addr, walletAddr, factoryAddr, implAddr, p256PrivKey, p256X, p256Y };
}
