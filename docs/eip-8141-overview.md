# EIP-8141: Frame Transactions

EIP-8141 introduces a new transaction type (`0x06`) that enables native account abstraction on Ethereum. Instead of a single call with a signature, a frame transaction contains a list of **frames** — ordered execution steps with different privilege modes.

## Transaction Structure

```
rlp([chain_id, nonce, sender, frames, max_priority_fee_per_gas, max_fee_per_gas,
     max_fee_per_blob_gas, blob_versioned_hashes])

frame = [mode, target, gas_limit, data]
```

Key differences from legacy transactions:
- **`sender` is explicit** — no signature recovery needed. Authentication happens inside VERIFY frames.
- **No `to`, `value`, or `data` fields** — all execution is expressed as frames.
- **No signature fields** — the sender contract validates the transaction via the APPROVE opcode.

## Frame Modes

Each frame executes in one of three modes:

| Mode | Value | Caller | Semantics | Purpose |
|------|-------|--------|-----------|---------|
| DEFAULT | 0 | `0x00..00aa` (entry point) | Regular call | Contract deployment, post-ops |
| VERIFY | 1 | `0x00..00aa` (entry point) | STATICCALL (read-only) | Signature validation |
| SENDER | 2 | `tx.sender` | Regular call | Execution on behalf of the account |

**VERIFY frames** are read-only: `sstore`, `tstore`, `create`, and any state-mutating opcode will revert. They must exit via the APPROVE opcode. Any other termination (return, revert, out-of-gas) invalidates the entire transaction.

**SENDER frames** require prior approval — the sender must have already APPROVEd execution in an earlier VERIFY frame.

## APPROVE Opcode (`0xaa`)

APPROVE terminates a VERIFY frame with an approval signal:

| Scope | Status Code | Meaning |
|-------|-------------|---------|
| 0 | 2 (APPROVED_EXECUTION) | Sender authorizes SENDER frames |
| 1 | 3 (APPROVED_PAYMENT) | Target pays gas fees |
| 2 | 4 (APPROVED_BOTH) | Both execution and payment |

Rules:
- Execution approval must come first. Payment approval cannot precede it.
- Each approval type can only occur once per transaction.
- The transaction is invalid if no payment approval is given by the end.

## Transaction Parameters (TXPARAMLOAD)

Contracts can introspect the transaction via `TXPARAMLOAD` (`0xb0`):

| Parameter | Description |
|-----------|-------------|
| `0x00` | Transaction type (6) |
| `0x01` | Nonce |
| `0x02` | Sender address |
| `0x06` | Max cost (worst-case total fee) |
| `0x08` | Signature hash (`sigHash`) |
| `0x09` | Frame count |
| `0x10` | Current frame index |
| `0x11` | Frame target (by index) |
| `0x12` | Frame data (by index) |
| `0x13` | Frame gas limit (by index) |
| `0x14` | Frame mode (by index) |
| `0x15` | Frame status (by index, past frames only) |

This enables **cross-frame introspection**: a VERIFY frame can read the calldata of any other frame (except VERIFY frames, which return size 0).

## Signature Hash

The `sigHash` is `keccak256(rlp(tx))` with VERIFY frame data zeroed out:

```python
def compute_sig_hash(tx):
    for frame in tx.frames:
        if frame.mode == VERIFY:
            frame.data = b""  # elide VERIFY data
    return keccak256(rlp(tx))
```

VERIFY data is excluded because:
1. Signatures can't be part of the data they sign (circular dependency).
2. Sponsor/paymaster data can be added after the sender signs.
3. Enables future signature aggregation schemes.

Frame targets, gas limits, and non-VERIFY calldata are all covered by the hash, protecting against manipulation.

## Gas Accounting

```
total_gas = 15,000 (intrinsic) + calldata_gas(rlp(frames)) + sum(frame.gas_limit)
```

- Each frame has an independent gas allocation. Unused gas from one frame cannot be used by another.
- The sender does **not** prepay gas. Payment is collected when a frame APPROVEs with `SCOPE_PAYMENT`.
- Unused gas is refunded to the **payer** (the contract that approved payment), not the sender.
- `maxCost` = total_gas * max_fee_per_gas + blob fees. This is the worst-case cost, accessible via TXPARAMLOAD.

## Common Frame Patterns

### Simple Transaction (2 frames)

```
Frame 0: VERIFY(sender)  -> validate(sig) -> APPROVE(both)
Frame 1: SENDER(target)  -> execute(target, value, data)
```

### Sponsored Transaction (3+ frames)

```
Frame 0: VERIFY(sender)    -> validate(sig)   -> APPROVE(execution)
Frame 1: VERIFY(paymaster)  -> validate()      -> APPROVE(payment)
Frame 2: SENDER(target)     -> execute(...)
```

### ERC-20 Sponsored Transaction (5 frames)

```
Frame 0: VERIFY(sender)     -> validate(sig, scope=0) -> APPROVE(execution)
Frame 1: VERIFY(paymaster)  -> validate()              -> APPROVE(payment)
Frame 2: SENDER(ERC20)      -> token.transfer(paymaster, amount)
Frame 3: SENDER(account)    -> account.execute(target, value, data)
Frame 4: DEFAULT(paymaster) -> postOp()
```

## EOA Default Code

When a frame targets an address with no deployed code, the protocol executes built-in default code logic based on the first byte of `frame.data`:

- **VERIFY** (low nibble `0x1`): High nibble encodes APPROVE scope. Second byte selects signature type (`0x00` ECDSA, `0x01` P256). Verifies the signature against `keccak256(sigHash || data_without_signature)`.
- **SENDER** (low nibble `0x2`): Remaining data is RLP-encoded `[[target, value, data], ...]`. Executes each call sequentially.
- **DEFAULT**: Always reverts.

This enables EOAs to participate in frame transactions — batching, gas sponsorship, and P256 signing — without deploying a smart contract.

## Transaction Receipt

```
[cumulative_gas_used, payer, [frame_receipt, ...]]
frame_receipt = [status, gas_used, logs]
```

The receipt includes a `payer` field (the address that approved payment) and per-frame receipts with individual gas usage and logs.

## Isolation Between Frames

- **Transient storage** (`tstore`/`tload`) is discarded between frames.
- **Warm/cold access lists** are shared across frames for accurate gas accounting.
- **`ORIGIN`** returns the frame's caller (entry point or sender), not `tx.origin`.

## Protocol Constants

| Constant | Value |
|----------|-------|
| Transaction type | `0x06` |
| Entry point address | `0x00..00aa` |
| Intrinsic gas | 15,000 |
| Max frames | 1,000 |
