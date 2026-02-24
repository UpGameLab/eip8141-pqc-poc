# EIP-8141 Proof of Concept

> **This is experimental, proof-of-concept code. It is NOT production-ready and may contain bugs.
> Do not use in any environment where real assets are at risk.**

A reference implementation for [EIP-8141](https://github.com/ethereum/EIPs/pull/8141) (Frame Transactions), demonstrating native account abstraction on Ethereum with a modified geth client and Solidity compiler.

## Repository Structure

```
├── 8141-geth/             # Modified go-ethereum with frame transaction support
├── solidity-eip8141/      # Modified solc with EIP-8141 opcodes (APPROVE, TXPARAMLOAD, ...)
├── contracts/             # Solidity smart contracts (Foundry)
│   ├── src/
│   │   ├── FrameTxLib.sol            # Library wrapping EIP-8141 opcodes
│   │   ├── Simple8141Account.sol     # Minimal single-owner smart account
│   │   ├── SimplePaymaster.sol       # Gas sponsorship paymaster
│   │   ├── ERC20Paymaster.sol        # ERC20 token paymaster
│   │   └── example/
│   │       ├── kernel/                       # Kernel v3-style modular account
│   │       │   ├── Kernel8141.sol
│   │       │   ├── validators/               # ECDSA, SessionKey validators
│   │       │   ├── executors/                # Default, Batch executors
│   │       │   ├── hooks/                    # SpendingLimit, SessionKeyPermission hooks
│   │       │   └── handlers/                 # ERC-1271 fallback handler
│   │       ├── coinbase-smart-wallet/        # Coinbase-style smart wallet
│   │       │   └── CoinbaseSmartWallet8141.sol
│   │       └── light-account/                # Alchemy LightAccount port
│   │           └── LightAccount8141.sol
│   ├── test/              # Forge unit tests
│   └── e2e/               # TypeScript E2E tests (viem)
├── devnet/                # Dev network launch script
├── build/                 # Build output (geth, solc binaries)
└── Makefile
```

## Prerequisites

- Go 1.21+
- CMake 3.13+
- [Foundry](https://getfoundry.sh)
- Node.js 18+ (for E2E tests)

## Build

Build the modified geth and solc from submodules:

```bash
make build
```

This will:
1. Pull git submodules (`8141-geth`, `solidity-eip8141`)
2. Build geth → `build/bin/geth`
3. Build solc → `build/bin/solc`

You can also build individually:

```bash
make build-geth
make build-solc
```

## Contracts

Build and test the Solidity contracts (requires `build/bin/solc`):

```bash
make contracts   # forge build
make test        # forge test -vv
```

## Devnet

Start a local dev node with EIP-8141 support:

```bash
make devnet        # starts geth --dev on port 18545
make devnet-stop   # stops the dev node
```

## E2E Tests

E2E tests run against the local devnet. Start the devnet first, then:

```bash
make e2e                   # run all E2E tests
make e2e-simple            # Simple8141Account basic flow
make e2e-kernel            # Kernel8141 basic flow
make e2e-kernel-validator  # Kernel8141 validator swap
make e2e-hooked            # SpendingLimitHook
make e2e-coinbase-ecdsa    # CoinbaseSmartWallet ECDSA
make e2e-coinbase-webauthn # CoinbaseSmartWallet WebAuthn
make e2e-light-account     # LightAccount ECDSA
make benchmark             # Gas benchmarks
```

## Gas Benchmark

EIP-8141 frame transactions achieve significant gas savings compared to ERC-4337 UserOperations by eliminating the application-layer EntryPoint overhead. Validation and execution happen as native protocol operations (VERIFY/SENDER frames) rather than nested contract calls.

Run `make benchmark` against the local devnet to reproduce:

| Account | Operation | Total Gas | Verify | Sender |
|---|---|---:|---:|---:|
| Simple8141 | ETH transfer | 58,017 | 5,854 | 34,803 |
| Simple8141 | ERC20 transfer | 56,760 | 5,854 | 32,814 |
| Kernel8141 | ETH transfer | 74,911 | 20,657 | 36,486 |
| Kernel8141 | ERC20 transfer | 73,425 | 20,657 | 34,384 |
| Coinbase | ETH transfer | 71,248 | 17,311 | 35,869 |
| Coinbase | ERC20 transfer | 70,137 | 17,311 | 34,002 |
| LightAccount | ETH transfer | 64,612 | 11,579 | 35,405 |
| LightAccount | ERC20 transfer | 63,486 | 11,579 | 33,535 |

> These numbers include first-time costs: account creation for the ETH recipient (G_newaccount = 25,000 gas) and zero-to-non-zero SSTORE for the ERC20 recipient balance (20,000 gas). In steady-state (sending to existing accounts with non-zero balances), total gas is roughly **~25,000 lower for ETH** and **~17,000 lower for ERC20** transfers. Each account uses a separate recipient address to ensure fair comparison regardless of benchmark execution order.

## Disclaimer

This repository is a **proof-of-concept** for research and demonstration purposes only.
It may contain bugs, incomplete features, and unaudited code.
Do not deploy or use any part of this codebase in production or with real funds.
