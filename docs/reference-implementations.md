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

`contracts/src/example/kernel/` (~845 lines core + modules)

Port of [Kernel v3](https://github.com/zerodevapp/kernel) by ZeroDev. Fully modular account with pluggable validators, executors, hooks, and policies — redesigned around EIP-8141's frame architecture.

The key architectural difference from Kernel v3: **hooks execute inline in the SENDER frame** via `executeHooked()`, which wraps execution with `preCheck()`/`postCheck()` calls. The VERIFY frame enforces that the SENDER frame calls `executeHooked()` when a hook is configured, ensuring atomic hook execution.

**Architecture:**
```
Kernel8141
  └── ValidationManager8141  (validator/permission/nonce/enable/EIP-712/ERC-1271)
        ├── SelectorManager8141   (fallback selector routing)
        ├── HookManager8141       (unified hook lifecycle)
        └── ExecutorManager8141   (executor registry)
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

**Pattern 2: Root validator + hook (inline)**
```
Frame 0: VERIFY(kernel)  -> validate(sig, scope)            -> APPROVE(both), enforces executeHooked selector
Frame 1: SENDER(kernel)  -> executeHooked(vId, mode, data)  -> hook preCheck + execute + hook postCheck (atomic)
```
The VERIFY frame uses `_enforceHookedExecution()` to verify that the SENDER frame calls `executeHooked()` with the correct `vId`. The hook's `preCheck()`/`postCheck()` run inline in the SENDER frame, making the hook and execution atomic.

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

**Pattern 5: Permission-based validation (with stateful policy consumption)**
```
Frame 0: VERIFY(kernel)  -> validatePermission(sig, scope)     -> APPROVE(both), enforces executeHooked selector
Frame 1: SENDER(kernel)  -> executeHooked(vId, mode, data)     -> policy consume + hook + execution
```
Permissions always require `executeHooked()` via `_enforcePermissionExecution()`, even without a hook, to ensure stateful policies (e.g. `GasPolicy8141`) can consume their state in the SENDER frame.

#### Inline Hook Architecture

In Kernel v3 (ERC-4337), hooks are orchestrated by the account: `execute()` calls `hook.preCheck()`, runs the execution, then calls `hook.postCheck()`. Kernel8141 preserves this same pattern but executes hooks **inline in the SENDER frame** via `executeHooked()`:

```solidity
function executeHooked(bytes21 vId, ExecMode execMode, bytes calldata executionCalldata) external payable {
    // 1. Consume stateful policies (if permission-based)
    if (getType(validationId) == VALIDATION_TYPE_PERMISSION) {
        _consumeStatefulPolicies(getPermissionId(validationId));
    }
    // 2. Hook pre/post (if configured)
    IHook8141 hook = validationConfig[validationId].hook;
    if (_isCallableHook(hook)) {
        uint256 value = _extractExecutionValue(execMode, executionCalldata);
        bytes memory context = _doPreHook(hook, value, executionCalldata);
        execute(execMode, executionCalldata);
        _doPostHook(hook, context);
    } else {
        execute(execMode, executionCalldata);
    }
}
```

**VERIFY enforces executeHooked.** When a hook is configured for a validator, `_enforceHookedExecution()` in the VERIFY frame reads the SENDER frame's selector and `vId` via `frameDataLoad()` to verify the SENDER frame calls `executeHooked()` with the correct validation ID. For permission-based validation, `_enforcePermissionExecution()` always requires `executeHooked()` regardless of hook presence, to ensure stateful policy consumption.

**Hook sentinel values.** Hook addresses use sentinel values to control behavior:
- `address(0)` — hook not installed
- `address(1)` — hook installed but no callable hook (`preCheck`/`postCheck` skipped)
- `> address(1)` — callable hook, `preCheck`/`postCheck` executed inline

The `_isCallableHook()` helper returns true only for `address(hook) > address(1)`.

**SpendingLimitHook example** (`SpendingLimitHook.sol`):

The hook implements `IHook8141` with `preCheck()`/`postCheck()`. The `executeHooked()` function extracts the ETH value from execution calldata via `_extractExecutionValue()` and passes it as `msgValue` to `preCheck()`:

```solidity
function preCheck(address, uint256 msgValue, bytes calldata)
    external payable override returns (bytes memory hookData) {
    // msg.sender = kernel account (called inline from executeHooked)
    SpendingState storage state = spendingStates[msg.sender];
    // Reset if new day, then enforce daily limit
    uint256 available = state.dailyLimit - state.spentToday;
    if (msgValue > available) revert DailyLimitExceeded(msgValue, available);
    state.spentToday += msgValue;
    return abi.encode(msgValue);
}
```

The hook also retains a deprecated `check()` function for the legacy DEFAULT frame pattern.

**Executor and fallback hooks** — `executeFromExecutor()` and `fallback()` also call `preCheck()`/`postCheck()` inline, using the same hook interface. All hook execution is kernel-orchestrated.

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

**Policy context** — Policies receive `senderFrameIndex` in the VERIFY phase and can read any execution parameter:
```solidity
function checkFrameTxPolicy(bytes32 id, address account, bytes32 sigHash, uint256 senderFrameIndex)
    external view returns (uint256 result);
  // -> frameDataLoad(senderFrameIndex, offset)  // read target, value, calldata
```

**Hook enforcement** — VERIFY reads the SENDER frame's selector and vId to enforce `executeHooked()`:
```solidity
bytes4 senderSelector = bytes4(FrameTxLib.frameDataLoad(senderFrameIdx, 0));
require(senderSelector == this.executeHooked.selector);
bytes21 senderVId = bytes21(FrameTxLib.frameDataLoad(senderFrameIdx, 4));
require(senderVId == ValidationId.unwrap(vId));
```

#### Two-Phase Policy Model

Policies use a split interface to work across EIP-8141's read-only VERIFY and stateful SENDER frames:

| Phase | Function | Context | Purpose |
|-------|----------|---------|---------|
| VERIFY | `checkFrameTxPolicy(id, account, sigHash, senderFrameIndex)` | `view` (STATICCALL) | Read-only validation |
| SENDER | `consumeFrameTxPolicy(id, account)` | stateful | State writes (e.g. budget decrement) |

Read-only policies (e.g. `SelectorPolicy8141`) implement `consumeFrameTxPolicy()` as a no-op. Stateful policies (e.g. `GasPolicy8141`) perform writes only in the SENDER phase. `_consumeStatefulPolicies()` is called at the start of `executeHooked()` for permission-based validations.

**GasPolicy8141 example:**
```solidity
// VERIFY phase: read-only budget check
function checkFrameTxPolicy(bytes32 id, address, bytes32, uint256) external view returns (uint256) {
    return FrameTxLib.maxCost() > budgets[msg.sender][id].allowed ? 1 : 0;
}

// SENDER phase: budget decrement
function consumeFrameTxPolicy(bytes32 id, address account) external {
    uint256 maxCost = FrameTxLib.maxCost();
    budgets[account][id].allowed -= uint128(maxCost);
}
```

#### Design Constraints and Trade-offs

**Inline hooks are atomic.** Since hooks run inside the SENDER frame via `executeHooked()`, hook pre/post checks and execution are atomic — if the hook reverts, execution reverts, and vice versa. This resolves the non-atomicity issue of the earlier DEFAULT frame hook model.

**Mempool VERIFY simulation:** The framepool only executes VERIFY frames during transaction validation. VERIFY enforcement of `executeHooked()` is a structural check via `frameDataLoad()` — it reads the SENDER frame's selector and vId without executing it.

**Transient storage discarded between frames:** `tstore`/`tload` values do not persist across frame boundaries. SENDER frames cannot read transient storage set by VERIFY frames. Instead, SENDER frames derive hook and validation context from persistent storage reads.

**Policy state writes require SENDER frame:** VERIFY frames are read-only (`sstore` causes exceptional halt). Stateful policies like `GasPolicy8141` can only decrement budgets in the SENDER frame via `consumeFrameTxPolicy()`, which is why `_enforcePermissionExecution()` always requires `executeHooked()`.

#### Bundled Modules

- `ECDSAValidator` — ECDSA signature validation via native `ecrecover` (Solady's `ECDSA.recover` is incompatible with the EIP-8141 custom compiler + `via_ir`)
- `SessionKeyValidator` — session key with time-bound validity and policy enforcement
- `SpendingLimitHook` — daily spending limit as inline hook (`IHook8141` `preCheck`/`postCheck`)
- `SessionKeyPermissionHook` — session key permission checking with self-contained spending tracking
- `GasPolicy8141` — stateful gas budget policy (two-phase `IPolicy8141`: check in VERIFY, consume in SENDER)
- `SelectorPolicy8141` — read-only selector whitelist policy (`IPolicy8141`)
- `DefaultExecutor` / `BatchExecutor` — single and batch execution modules

#### Kernel v3 vs Kernel8141

| | Kernel v3 (ERC-4337) | Kernel8141 (EIP-8141) |
|---|---|---|
| Signature hash | Computed from UserOp struct | Protocol-provided `sigHash` via TXPARAM |
| Selector ACL | Decode from `userOp.callData` | `frameDataLoad()` cross-frame read |
| Hook execution | Account orchestrates `preCheck`/`postCheck` | Same — inline `preCheck`/`postCheck` via `executeHooked()` |
| Hook enforcement | Account always calls hook | VERIFY enforces `executeHooked` selector via `_enforceHookedExecution()` |
| Enable mode | Single `validateUserOp` call (sstore during validation) | Split: VERIFY (sig verify) + DEFAULT (sstore) |
| `execute()` | Derives hook, calls preCheck/execute/postCheck | `execute()` for no-hook; `executeHooked()` for hooked execution |
| Policy model | Limited to UserOp fields | Two-phase: `checkFrameTxPolicy` (VERIFY) + `consumeFrameTxPolicy` (SENDER) |
| Post-op | Gas tracking + refund logic | Not applicable (no `actualGasCost` available) |
| Atomicity | Hook + execution in single call (atomic) | Same — hook + execution atomic in SENDER frame |

---

## Shared Simplifications

All EIP-8141 implementations benefit from:

1. **No UserOperation encoding** — `sigHash` is a canonical protocol value, not derived from struct hashing.
2. **No EntryPoint contract** — The protocol entry point (`0x00..00aa`) is a protocol-level construct, not a deployed contract.
3. **No simulation overhead** — Validation runs natively in VERIFY frames, not via `eth_estimateGas` workarounds.
4. **Scope-based approval** — Fine-grained control over execution vs payment authorization, enabling clean separation of concerns.
5. **Cross-frame introspection** — VERIFY frames can read any non-VERIFY frame's calldata, enabling on-chain validation of execution intent without off-chain coordination.
