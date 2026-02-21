/**
 * Run all E2E test suites sequentially.
 *
 * Usage: cd contracts && npx tsx e2e/run-all.ts
 */

import { execSync } from "child_process";

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  bgGreen: "\x1b[42m",
  bgRed: "\x1b[41m",
};

const suites = [
  { file: "e2e/simple/simple-basic.ts", name: "Simple8141" },
  { file: "e2e/kernel/kernel-basic.ts", name: "Kernel Basic" },
  { file: "e2e/kernel/kernel-validator.ts", name: "Kernel Validator" },
  { file: "e2e/kernel-hooked/spending-limit.ts", name: "SpendingLimitHook" },
  { file: "e2e/coinbase/coinbase-ecdsa.ts", name: "Coinbase ECDSA" },
  { file: "e2e/coinbase/coinbase-webauthn.ts", name: "Coinbase WebAuthn" },
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
