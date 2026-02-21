// ANSI color codes
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  bgGreen: "\x1b[42m",
  bgRed: "\x1b[41m",
  bgBlue: "\x1b[44m",
  bgYellow: "\x1b[43m",
};

export function banner(title: string) {
  const line = "━".repeat(60);
  console.log(`\n${c.cyan}${line}${c.reset}`);
  console.log(`${c.bold}${c.cyan}  ${title}${c.reset}`);
  console.log(`${c.cyan}${line}${c.reset}\n`);
}

export function sectionHeader(title: string) {
  console.log(`\n${c.blue}┌${"─".repeat(58)}┐${c.reset}`);
  console.log(`${c.blue}│${c.reset} ${c.bold}${title}${c.reset}`);
  console.log(`${c.blue}└${"─".repeat(58)}┘${c.reset}`);
}

export function testHeader(num: number | string, title: string) {
  console.log(
    `\n${c.magenta}▸ Test ${num}:${c.reset} ${c.bold}${title}${c.reset}`
  );
}

export function info(msg: string) {
  console.log(`  ${c.cyan}ℹ${c.reset} ${msg}`);
}

export function step(msg: string) {
  console.log(`  ${c.blue}→${c.reset} ${msg}`);
}

export function detail(msg: string) {
  console.log(`  ${c.gray}  ${msg}${c.reset}`);
}

export function success(msg: string) {
  console.log(`  ${c.green}✔${c.reset} ${c.green}${msg}${c.reset}`);
}

export function fail(msg: string) {
  console.log(`  ${c.red}✘${c.reset} ${c.red}${msg}${c.reset}`);
}

export function warn(msg: string) {
  console.log(`  ${c.yellow}⚠${c.reset} ${c.yellow}${msg}${c.reset}`);
}

export function deploy(name: string, address: string, tx?: string) {
  console.log(
    `  ${c.blue}📦${c.reset} ${c.bold}${name}${c.reset} ${c.dim}→${c.reset} ${c.cyan}${address}${c.reset}`
  );
  if (tx) console.log(`     ${c.gray}tx: ${tx}${c.reset}`);
}

export function fund(target: string, amount: string) {
  console.log(
    `  ${c.yellow}💰${c.reset} Funded ${c.cyan}${target.slice(0, 10)}...${c.reset} with ${c.bold}${amount}${c.reset}`
  );
}

export function txResult(label: string, status: string, gasUsed: bigint) {
  const statusColor = status === "0x1" ? c.green : status === "0x0" ? c.red : c.yellow;
  const statusIcon = status === "0x1" ? "✔" : status === "0x0" ? "✘" : "◉";
  console.log(
    `  ${statusColor}${statusIcon}${c.reset} ${label}: ${statusColor}${status}${c.reset} ${c.gray}(gas: ${gasUsed.toLocaleString()})${c.reset}`
  );
}

const FRAME_STATUS: Record<string, { name: string; color: string; icon: string }> = {
  "0x0": { name: "Failed", color: c.red, icon: "✘" },
  "0x1": { name: "Success", color: c.green, icon: "✔" },
  "0x2": { name: "ApproveExec", color: c.green, icon: "◉" },
  "0x3": { name: "ApprovePay", color: c.green, icon: "◉" },
  "0x4": { name: "ApproveBoth", color: c.green, icon: "◉" },
};

export function printReceipt(r: any) {
  const outerStatus = FRAME_STATUS[r.status] || { name: r.status, color: c.white, icon: "?" };
  console.log(
    `  ${c.dim}┌ Receipt${c.reset}`
  );
  console.log(
    `  ${c.dim}│${c.reset} Status: ${outerStatus.color}${outerStatus.icon} ${outerStatus.name}${c.reset}  Type: ${c.cyan}${r.type}${c.reset}  Gas: ${c.gray}${BigInt(r.gasUsed).toLocaleString()}${c.reset}`
  );
  if (r.payer) {
    console.log(`  ${c.dim}│${c.reset} Payer:  ${c.cyan}${r.payer}${c.reset}`);
  }
  if (r.frameReceipts) {
    for (let i = 0; i < r.frameReceipts.length; i++) {
      const fr = r.frameReceipts[i];
      const fs = FRAME_STATUS[fr.status] || { name: `Unknown(${fr.status})`, color: c.yellow, icon: "?" };
      const frameLabel = i === 0 ? "VERIFY" : i === 1 ? "SENDER" : `Frame${i}`;
      console.log(
        `  ${c.dim}│${c.reset} ${c.dim}${frameLabel}:${c.reset} ${fs.color}${fs.icon} ${fs.name}${c.reset}  ${c.gray}gas: ${BigInt(fr.gasUsed).toLocaleString()}${c.reset}`
      );
    }
  }
  console.log(`  ${c.dim}└${"─".repeat(40)}${c.reset}`);
}

export function testPassed(label?: string) {
  const msg = label ? `PASSED — ${label}` : "PASSED";
  console.log(`\n  ${c.bgGreen}${c.bold} ${msg} ${c.reset}\n`);
}

export function testFailed(label?: string) {
  const msg = label ? `FAILED — ${label}` : "FAILED";
  console.log(`\n  ${c.bgRed}${c.bold} ${msg} ${c.reset}\n`);
}

export function summary(suiteName: string, passed: number, total?: number) {
  const count = total ?? passed;
  const line = "━".repeat(60);
  console.log(`\n${c.green}${line}${c.reset}`);
  console.log(
    `${c.bold}${c.green}  🎉 ${suiteName}: ${passed}/${count} tests passed${c.reset}`
  );
  console.log(`${c.green}${line}${c.reset}\n`);
}

export function fatal(err: any) {
  console.error(`\n${c.red}${c.bold}💥 FATAL: ${err.message || err}${c.reset}`);
  if (err.stack) {
    console.error(`${c.gray}${err.stack}${c.reset}`);
  }
}
