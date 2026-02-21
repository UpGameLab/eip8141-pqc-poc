import {
  encodeAbiParameters,
  parseAbiParameters,
  formatEther,
  type Hex,
  type Address,
} from "viem";
import { createTestClients, fundAccount } from "../helpers/client.js";
import { loadBytecode, deployContract } from "../helpers/deploy.js";
import { banner, sectionHeader, info, success } from "../helpers/log.js";

export type KernelTestContext = {
  publicClient: any;
  walletClient: any;
  devAddr: Address;
  kernelAddr: Address;
  validatorAddr: Address;
  defaultExecutorAddr: Address;
  batchExecutorAddr: Address;
  hookAddr: Address;
  handlerAddr: Address;
  sessionKeyValidatorAddr: Address;
  sessionKeyPermissionHookAddr: Address;
};

/** Deploy all 8 Kernel8141 contracts and fund the kernel with 10 ETH. */
export async function deployKernelTestbed(): Promise<KernelTestContext> {
  const { publicClient, walletClient, devAddr } = createTestClients();

  const balance = await publicClient.getBalance({ address: devAddr });
  banner("Kernel8141 E2E");
  info(`Dev account: ${devAddr}`);
  info(`Balance: ${formatEther(balance)} ETH`);

  sectionHeader("📦 Deploy Contracts (8)");

  const validatorBytecode = loadBytecode("ECDSAValidator");
  const { address: validatorAddr } = await deployContract(
    walletClient, publicClient, validatorBytecode, 3_000_000n, "ECDSAValidator"
  );

  const kernelBytecode = loadBytecode("Kernel8141");
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters("address, bytes"),
    [validatorAddr, encodeAbiParameters(parseAbiParameters("address"), [devAddr])]
  );
  const kernelDeployData = (kernelBytecode + constructorArgs.slice(2)) as Hex;
  const { address: kernelAddr } = await deployContract(
    walletClient, publicClient, kernelDeployData, 10_000_000n, "Kernel8141"
  );

  const { address: defaultExecutorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("DefaultExecutor"), 3_000_000n, "DefaultExecutor"
  );

  const { address: batchExecutorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("BatchExecutor"), 3_000_000n, "BatchExecutor"
  );

  const { address: hookAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("SpendingLimitHook"), 3_000_000n, "SpendingLimitHook"
  );

  const { address: handlerAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("ERC1271Handler"), 3_000_000n, "ERC1271Handler"
  );

  const { address: sessionKeyValidatorAddr } = await deployContract(
    walletClient, publicClient, loadBytecode("SessionKeyValidator"), 3_000_000n, "SessionKeyValidator"
  );

  const hookConstructorArgs = encodeAbiParameters(
    parseAbiParameters("address"),
    [sessionKeyValidatorAddr]
  );
  const hookDeployData = (loadBytecode("SessionKeyPermissionHook") + hookConstructorArgs.slice(2)) as Hex;
  const { address: sessionKeyPermissionHookAddr } = await deployContract(
    walletClient, publicClient, hookDeployData, 3_000_000n, "SessionKeyPermissionHook"
  );

  success("All 8 contracts deployed");

  sectionHeader("💰 Fund Kernel");
  await fundAccount(walletClient, publicClient, kernelAddr);

  return {
    publicClient, walletClient, devAddr,
    kernelAddr, validatorAddr, defaultExecutorAddr, batchExecutorAddr,
    hookAddr, handlerAddr, sessionKeyValidatorAddr, sessionKeyPermissionHookAddr,
  };
}
