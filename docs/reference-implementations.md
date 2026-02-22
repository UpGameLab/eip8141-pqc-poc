# Reference Implementations

This repository contains six smart contract implementations demonstrating EIP-8141 frame transactions: three standalone contracts and three ports of production ERC-4337 accounts.

## FrameTxLib

`contracts/src/FrameTxLib.sol`

Solidity wrapper library for EIP-8141 opcodes. All functions are `internal pure` with inline assembly, providing zero-overhead abstractions:

- **APPROVE**: `approveEmpty(scope)`, `approveWithData(scope, offset, length)`
- **TXPARAM**: `sigHash()`, `txSender()`, `nonce()`, `maxCost()`, `frameCount()`, `currentFrameIndex()`, `currentFrameMode()`
- **Frame inspection**: `frameTarget(idx)`, `frameDataLoad(idx, offset)`, `frameDataSize(idx)`, `frameData(idx)`, `frameGas(idx)`, `frameMode(idx)`, `frameStatus(idx)`
- **Scope constants**: `SCOPE_EXECUTION` (0), `SCOPE_PAYMENT` (1), `SCOPE_BOTH` (2)

---

## Standalone Contracts

### Simple8141Account

`contracts/src/Simple8141Account.sol` (~67 lines)

Minimal single-owner ECDSA account.

**Validation (VERIFY frame):**
```
validate(v, r, s, scope)
  -> sigHash = FrameTxLib.sigHash()
  -> ecrecover(sigHash, v, r, s) == owner
  -> APPROVE(scope)
```

**Execution (SENDER frame):**
```
execute(target, value, data)
  -> target.call{value}(data)
```

**vs ERC-4337:** No UserOperation struct parsing, no entrypoint simulation, no hash computation. The protocol provides `sigHash` directly, and frame sequencing replaces entrypoint orchestration.

### SimplePaymaster

`contracts/src/SimplePaymaster.sol` (~52 lines)

Off-chain signer-approved gas sponsor for ETH-only sponsorship.

**Validation (VERIFY frame):**
```
validate(signature)
  -> ecrecover(FrameTxLib.sigHash(), v, r, s) == signer
  -> APPROVE(SCOPE_PAYMENT)
```

**vs ERC-4337:** No EntryPoint deposit/stake management. No balance tracking. The protocol handles gas collection directly from the paymaster's ETH balance when APPROVE(payment) is called.

### ERC20Paymaster

`contracts/src/ERC20Paymaster.sol` (~122 lines)

ERC-20 token gas sponsor using cross-frame introspection.

**Validation (VERIFY frame):**
```
validate()
  -> nextFrame = currentFrameIndex() + 1
  -> verify frameDataLoad(nextFrame, 0) == transfer selector
  -> verify transfer recipient == address(this)
  -> verify token is accepted (exchangeRates[token] > 0)
  -> verify amount >= maxCost * rate / 1e18
  -> verify sender balanceOf(token) >= amount
  -> APPROVE(SCOPE_PAYMENT)
```

The paymaster reads the next frame's calldata via `frameDataLoad()` to verify the ERC-20 transfer is valid before approving payment. This is a pattern unique to EIP-8141 — the paymaster can inspect future frames without any off-chain coordination.

**Post-op (DEFAULT frame):**
```
postOp(transferFrameIdx)
  -> verify frameStatus(transferFrameIdx) == SUCCESS
```

**vs ERC-4337 (Pimlico ERC20PaymasterV07):**

| | ERC-4337 (Pimlico) | EIP-8141 |
|---|---|---|
| Payment model | Pull (`transferFrom`) | Push (user calls `transfer`) |
| Token approval | User must `approve()` paymaster | Not needed |
| Refunds | `postOp` refunds excess based on `actualGasCost` | No refund — user pays `maxCost` amount |
| Oracle | On-chain oracle for pricing | `exchangeRates` mapping (oracle possible) |
| Signature | Optional (mode 0 = no sig) | Not required |
| Guarantor | Supported (modes 2, 3) | Not applicable |

The key limitation: EIP-8141 has no `actualGasCost` available to any frame, so exact-cost refunds aren't possible. Users pay based on `maxCost` (worst case).

---

## Ported ERC-4337 Accounts

### CoinbaseSmartWallet8141

`contracts/src/example/coinbase-smart-wallet/` (~519 lines)

Port of [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet). Multi-owner account supporting ECDSA and WebAuthn (passkeys).

**Owners:** Two types stored as `bytes[]`:
- Ethereum address (32 bytes) — ECDSA validation via `ecrecover`
- P256 public key (64 bytes) — WebAuthn validation via RIP-7212 precompile

**Validation modes:**
- `validate(signature, scope)` — standard sigHash validation with owner index routing
- `validateCrossChain(signature, scope)` — reads SENDER frame calldata via `frameDataLoad()` to compute a chain-agnostic hash for cross-chain replay protection

**Execution:**
- `execute(target, value, data)` — single call
- `executeBatch(Call[])` — batch calls
- `executeWithoutChainIdValidation(bytes[])` — cross-chain replayable calls (restricted selector set)

**vs Original (ERC-4337):**

| | Coinbase SW (4337) | CoinbaseSmartWallet8141 |
|---|---|---|
| Signature hash | Computed from UserOp fields | Protocol-provided `sigHash` |
| Cross-chain | Off-chain hash wrapping | `frameDataLoad()` to read SENDER calldata |
| Execution entry | `executeUserOp()` via EntryPoint | Direct `execute()` in SENDER frame |
| Owner management | Same | Same (`addOwnerAddress`, `addOwnerPublicKey`) |
| ERC-1271 | Same | Same |
| Proxy pattern | UUPS (ERC-1967) | UUPS (ERC-1967) |

### LightAccount8141

`contracts/src/example/light-account/` (~367 lines)

Port of [Alchemy LightAccount](https://github.com/alchemyplatform/light-account). Single-owner account with EOA and contract owner support.

**Signature types:**
- `0x00` prefix — EOA owner, ECDSA via `ecrecover`
- `0x01` prefix — Contract owner, ERC-1271 via `isValidSignature()`

**Execution:**
- `execute(dest, value, func)` — single call
- `executeBatch(dest[], func[])` / `executeBatch(dest[], value[], func[])` — batch
- `performCreate(value, initCode)` — CREATE deployment
- `performCreate2(value, initCode, salt)` — CREATE2 deployment

**vs Original (ERC-4337):**

| | LightAccount (4337) | LightAccount8141 |
|---|---|---|
| Signature hash | Computed from UserOp | Protocol-provided `sigHash` |
| Execution entry | Via EntryPoint callback | Direct SENDER frame calls |
| Contract owners | ERC-1271 supported | Same |
| CREATE/CREATE2 | Via calldata encoding | Direct `performCreate`/`performCreate2` |

### Kernel8141

`contracts/src/example/kernel/` (~700 lines core + modules)

Port of [Kernel v3](https://github.com/zerodevapp/kernel) by ZeroDev. Fully modular account with pluggable validators, executors, hooks, and policies — redesigned around EIP-8141's frame-native architecture.

The key architectural difference from Kernel v3: **hooks execute as independent DEFAULT frames** rather than being orchestrated by the account contract. The VERIFY frame structurally verifies that required hook frames exist in the transaction, and execution proceeds without hook calls.

**Architecture:**
```
Kernel8141
  -> ValidationManager8141  (validation, enable mode, ERC-1271)
      -> SelectorManager8141   (fallback routing by selector)
      -> HookManager8141       (pre/post hooks for fallback/executor paths)
      -> ExecutorManager8141   (executor module registry)
```

**Module types:**
| Type | Interface | Purpose |
|------|-----------|---------|
| VALIDATOR (1) | `IValidator8141` | Signature validation |
| EXECUTOR (2) | `IExecutor8141` | Alternative execution flows |
| FALLBACK (3) | — | Selector-based call routing |
| HOOK (4) | `IHook8141` | Pre/post execution wrappers |
| POLICY (5) | `IPolicy8141` | Permission constraints |
| SIGNER (6) | `ISigner8141` | Permission signature verification |

#### Frame Transaction Patterns

Kernel8141 supports five frame transaction patterns:

**Pattern 1: Simple transaction (root validator, no hook)**
```
Frame 0: VERIFY(kernel)  -> validate(sig, scope=2)          -> APPROVE(both)
Frame 1: SENDER(kernel)  -> execute(mode, data)
```

**Pattern 2: Root validator + hook (frame-native)**
```
Frame 0: DEFAULT(hook)   -> hook.check()                    [pre-check]
Frame 1: VERIFY(kernel)  -> validate(sig, scope=2)          -> APPROVE(both)
Frame 2: SENDER(kernel)  -> execute(mode, data)
```
The hook runs in its own DEFAULT frame before VERIFY. The VERIFY frame verifies that a DEFAULT frame targeting the required hook exists in the transaction via `_verifyHookFrames()`. The SENDER frame executes directly — no hook orchestration needed.

**Pattern 3: Non-root validator (sigHash-bound selector ACL)**
```
Frame 0: VERIFY(kernel)  -> validateFromSenderFrame(sig, scope=2)  -> APPROVE(both)
Frame 1: SENDER(kernel)  -> validatedCall(validator, data)
```
The VERIFY frame reads the SENDER frame's selector via `frameDataLoad()` and checks it against the validator's allowed selector set.

**Pattern 4: Enable mode (install validator in one transaction)**
```
Frame 0: VERIFY(kernel)  -> validateWithEnable(enableData, sig, scope=2)  -> APPROVE(both)
Frame 1: DEFAULT(kernel) -> enableInstall(enableData, vId)                [sstore]
Frame 2: SENDER(kernel)  -> execute(mode, data)
```
Since VERIFY frames are read-only, enable mode is split: VERIFY verifies the enable signature (view-only), then a DEFAULT frame performs the actual validator installation (`sstore`). The DEFAULT frame calls `_requirePriorVerifyApproval()` to ensure a preceding VERIFY frame approved the transaction.

**Pattern 5: Permission-based validation**
```
Frame 0: VERIFY(kernel)  -> validatePermission(sig, scope=2)  -> APPROVE(both)
Frame 1: SENDER(kernel)  -> execute(mode, data)
```

#### Frame-Native Hook Architecture

In Kernel v3 (ERC-4337), hooks are orchestrated by the account: `execute()` calls `hook.preCheck()`, runs the execution, then calls `hook.postCheck()`. The account is the hook orchestrator.

In Kernel8141, hooks are **independent frame participants**:

1. **Hook = DEFAULT frame.** The hook contract runs in its own DEFAULT frame, called directly by the protocol. It uses `FrameTxLib.txSender()` to identify the account and `frameDataLoad()` to read execution parameters from the SENDER frame.

2. **VERIFY verifies frame structure.** The `_verifyHookFrames()` function checks that a DEFAULT frame targeting the required hook exists in the transaction. This is a structural check only — it cannot verify runtime success because during mempool VERIFY simulation, DEFAULT frames have not yet executed (`FrameResults` are zero-initialized by the framepool).

3. **SENDER executes directly.** `execute()` and `validatedCall()` contain no hook calls — just the execution logic. This simplifies the execution path and reduces gas.

**SpendingLimitHook example** (`SpendingLimitHook.sol`):

The hook implements a dual interface — `check()` for frame-native use and `preCheck()`/`postCheck()` for fallback handler compatibility.

```solidity
function check() external {
    // Account identity via TXPARAM (msg.sender = ENTRY_POINT in DEFAULT)
    address account = FrameTxLib.txSender();

    // Read execution value from SENDER frame's calldata
    uint256 senderIdx = _findSenderFrame();
    uint256 totalValue = _extractValueFromSenderFrame(senderIdx);

    // Enforce daily spending limit
    // ...
}
```

The value extraction reads the SENDER frame's `execute()` calldata layout:
```
Frame data offset:  [4B selector][32B ExecMode][32B offset][32B length][executionCalldata...]
SINGLE calldata:    [20B target][32B value][callData...]
  -> value at frame offset 120 (= 4 + 32 + 32 + 32 + 20)
BATCH calldata:     ABI-encoded Execution[] -> sum all values
```

**Where hooks are still kernel-orchestrated:**
- `executeFromExecutor()` — executor modules call through the kernel, which applies pre/post hooks
- `fallback()` — selector-routed fallback calls apply hooks from the fallback config

These paths retain kernel-orchestrated hooks because executors and fallback callers don't construct frame transactions.

#### Enable Mode (VERIFY + DEFAULT Split)

Kernel v3's enable mode writes to storage during `validateUserOp()`. In EIP-8141, VERIFY frames are read-only (`sstore` causes exceptional halt), so enable mode is split across two frames:

| Step | Frame | Function | Operations |
|------|-------|----------|------------|
| 1 | VERIFY | `validateWithEnable()` | Verify enable signature, verify tx signature, check enableInstall frame exists |
| 2 | DEFAULT | `enableInstall()` | `_requirePriorVerifyApproval()`, then `_enableMode()` with full sstore |
| 3 | SENDER | `execute()` | Normal execution |

`_requirePriorVerifyApproval()` iterates through earlier frames to find a VERIFY frame targeting this account with `frameStatus >= 2` (APPROVED_EXECUTION or higher). This prevents unauthorized DEFAULT frame calls.

#### Cross-Frame Introspection

EIP-8141's `frameDataLoad()` enables patterns impossible in ERC-4337:

**Selector ACL** — VERIFY reads the SENDER frame's function selector directly:
```solidity
bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderFrameIdx, 0));
require(vs.allowedSelectors[vId][senderSelector], "selector not allowed");
```

**Policy context** — Policies receive `senderFrameIndex` and can read any execution parameter:
```solidity
function checkFrameTxPolicy(address account, bytes32 sigHash, uint256 senderFrameIdx, ...)
  -> frameDataLoad(senderFrameIdx, offset)  // read target, value, calldata
```

**Hook value extraction** — Hooks read execution value from the SENDER frame without the account passing it:
```solidity
uint256 value = uint256(FrameTxLib.frameDataLoad(senderIdx, 120));  // SINGLE exec value
```

#### Design Constraints and Trade-offs

**Mempool VERIFY simulation:** The framepool only executes VERIFY frames during transaction validation. DEFAULT frames are skipped, and their `FrameResults` are zero-initialized. This means `_verifyHookFrames()` cannot check `frameStatus()` for DEFAULT hook frames — it can only verify structural presence (correct target and mode).

**No atomicity between DEFAULT and SENDER frames:** Each frame is an independent execution context. If a DEFAULT hook frame succeeds (records spending) but the SENDER frame reverts, the spending record persists. Conversely, if the hook reverts, the SENDER frame still executes (since VERIFY already approved). This is analogous to gas prepayment — the hook's state change is committed regardless of execution outcome.

**Transient storage discarded between frames:** `tstore`/`tload` values do not persist across frame boundaries. SENDER frames cannot read transient storage set by VERIFY frames. Instead, SENDER frames derive hook and validation context from persistent storage reads.

**Fallback and executor hooks remain kernel-orchestrated:** Only `execute()` and `validatedCall()` use frame-native hooks. `executeFromExecutor()` and `fallback()` still call `hook.preCheck()`/`hook.postCheck()` directly, because these entry points are not reached via frame transactions.

#### Bundled Modules

- `ECDSAValidator` — ECDSA signature validation via native `ecrecover` (Solady's `ECDSA.recover` is incompatible with the EIP-8141 custom compiler + `via_ir`)
- `SessionKeyValidator` — session key with time-bound validity and policy enforcement
- `SpendingLimitHook` — daily spending limit as frame-native DEFAULT target + IHook8141 fallback
- `SessionKeyPermissionHook` — session key permission checking with self-contained spending tracking
- `DefaultExecutor` / `BatchExecutor` — single and batch execution modules

#### Kernel v3 vs Kernel8141

| | Kernel v3 (ERC-4337) | Kernel8141 (EIP-8141) |
|---|---|---|
| Signature hash | Computed from UserOp struct | Protocol-provided `sigHash` via TXPARAM |
| Selector ACL | Decode from `userOp.callData` | `frameDataLoad()` cross-frame read |
| Hook execution | Account orchestrates `preCheck`/`postCheck` | Hook runs in independent DEFAULT frame |
| Hook enforcement | Account always calls hook | VERIFY structurally verifies hook frame exists |
| Enable mode | Single `validateUserOp` call (sstore during validation) | Split: VERIFY (sig verify) + DEFAULT (sstore) |
| `execute()` | Derives hook, calls preCheck/execute/postCheck | Direct execution, no hook calls |
| Policy context | Limited to UserOp fields | `senderFrameIndex` + `frameDataLoad()` for full execution context |
| Post-op | Gas tracking + refund logic | Not applicable (no `actualGasCost` available) |
| Atomicity | Hook + execution in single call (atomic) | Hook and execution in separate frames (non-atomic) |

---

## Shared Simplifications

All EIP-8141 implementations benefit from:

1. **No UserOperation encoding** — `sigHash` is a canonical protocol value, not derived from struct hashing.
2. **No EntryPoint contract** — The protocol entry point (`0x00..00aa`) is a protocol-level construct, not a deployed contract.
3. **No simulation overhead** — Validation runs natively in VERIFY frames, not via `eth_estimateGas` workarounds.
4. **Scope-based approval** — Fine-grained control over execution vs payment authorization, enabling clean separation of concerns.
5. **Cross-frame introspection** — VERIFY frames can read any non-VERIFY frame's calldata, enabling on-chain validation of execution intent without off-chain coordination.
