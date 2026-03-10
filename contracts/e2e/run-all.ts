/**
 * Run all E2E test suites sequentially.
 *
 * Usage: cd contracts && npx tsx e2e/run-all.ts
 */

import { execSync } from "child_process";
import { c } from "./helpers/log.js";

const suites = [
  { file: "e2e/simple/simple-basic.ts", name: "Simple8141 Deploy" },
  { file: "e2e/simple/simple-paymaster.ts", name: "Simple Paymaster" },
  { file: "e2e/kernel/kernel-deploy.ts", name: "Kernel Deploy" },
  { file: "e2e/kernel/kernel-basic.ts", name: "Kernel Basic" },
  { file: "e2e/kernel/kernel-validator.ts", name: "Kernel Validator" },
  { file: "e2e/kernel/kernel-security.ts", name: "Kernel Security" },
  { file: "e2e/kernel/kernel-permission.ts", name: "Kernel Permission" },
  { file: "e2e/kernel-hooked/spending-limit.ts", name: "SpendingLimitHook" },
  { file: "e2e/coinbase/coinbase-deploy.ts", name: "Coinbase Deploy" },
  { file: "e2e/coinbase/coinbase-security.ts", name: "Coinbase Security" },
  { file: "e2e/light-account/light-account-deploy.ts", name: "LightAccount Deploy" },
  { file: "e2e/light-account/light-account-security.ts", name: "LightAccount Security" },
  { file: "e2e/mldsa/mldsa-basic.ts", name: "MLDSA Deploy" },
  { file: "e2e/eoa/eoa-batching.ts", name: "EOA Batching" },
  { file: "e2e/eoa/eoa-sponsor.ts", name: "EOA Sponsor" },
  { file: "e2e/eoa/eoa-p256.ts", name: "EOA P256" },
  { file: "e2e/benchmark/gas-benchmark.ts", name: "Gas Benchmark" },
];

let passed = 0;
let failed = 0;

const line = "━".repeat(60);
console.log(`\n${c.cyan}${c.bold}${line}${c.reset}`);
console.log(`${c.cyan}${c.bold}  🚀 EIP-8141 E2E Test Suite${c.reset}`);
console.log(`${c.cyan}${c.bold}${line}${c.reset}\n`);

for (const suite of suites) {
  console.log(`${c.cyan}▶${c.reset} ${c.bold}${suite.name}${c.reset} ${c.dim}(${suite.file})${c.reset}`);
  try {
    execSync(`npx tsx ${suite.file}`, { stdio: "inherit", cwd: process.cwd() });
    passed++;
  } catch {
    failed++;
    console.error(`\n  ${c.bgRed}${c.bold} FAILED ${c.reset} ${c.red}${suite.name}${c.reset}\n`);
  }
}

console.log(`\n${line}`);
if (failed === 0) {
  console.log(`${c.bgGreen}${c.bold} 🎉 ALL ${passed} SUITES PASSED ${c.reset}`);
} else {
  console.log(`${c.bgRed}${c.bold} 💥 ${failed} FAILED ${c.reset}, ${c.green}${passed} passed${c.reset} / ${suites.length} total`);
}
console.log(`${line}\n`);

if (failed > 0) process.exit(1);
