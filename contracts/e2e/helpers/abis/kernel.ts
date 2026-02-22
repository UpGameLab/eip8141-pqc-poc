export const kernelAbi = [
  // ── Initialization ──────────────────────────────────────────────
  {
    type: "function",
    name: "initialize",
    inputs: [
      { name: "_rootValidator", type: "bytes21" },
      { name: "hook", type: "address" },
      { name: "validatorData", type: "bytes" },
      { name: "hookData", type: "bytes" },
      { name: "initConfig", type: "bytes[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  // ── VERIFY frame: Validation ────────────────────────────────────
  {
    type: "function",
    name: "validate",
    inputs: [
      { name: "sig", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validateFromSenderFrame",
    inputs: [
      { name: "sig", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validateWithEnable",
    inputs: [
      { name: "enableData", type: "bytes" },
      { name: "sig", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validatePermission",
    inputs: [
      { name: "sig", type: "bytes" },
      { name: "scope", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  // ── DEFAULT frame: Enable mode ──────────────────────────────────
  {
    type: "function",
    name: "enableInstall",
    inputs: [
      { name: "enableData", type: "bytes" },
      { name: "vId", type: "bytes21" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  // ── SENDER frame: Execution ─────────────────────────────────────
  {
    type: "function",
    name: "execute",
    inputs: [
      { name: "execMode", type: "bytes32" },
      { name: "executionCalldata", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "executeFromExecutor",
    inputs: [
      { name: "execMode", type: "bytes32" },
      { name: "executionCalldata", type: "bytes" },
    ],
    outputs: [{ name: "returnData", type: "bytes[]" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "validatedCall",
    inputs: [
      { name: "validator", type: "address" },
      { name: "data", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  // ── ERC-1271 ────────────────────────────────────────────────────
  {
    type: "function",
    name: "isValidSignature",
    inputs: [
      { name: "hash", type: "bytes32" },
      { name: "data", type: "bytes" },
    ],
    outputs: [{ name: "magicValue", type: "bytes4" }],
    stateMutability: "view",
  },
  // ── Module management ───────────────────────────────────────────
  {
    type: "function",
    name: "installModule",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "initData", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "uninstallModule",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "deInitData", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "grantAccess",
    inputs: [
      { name: "vId", type: "bytes21" },
      { name: "selector", type: "bytes4" },
      { name: "allow", type: "bool" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "invalidateNonce",
    inputs: [{ name: "nonce", type: "uint32" }],
    outputs: [],
    stateMutability: "payable",
  },
  // ── Introspection ───────────────────────────────────────────────
  {
    type: "function",
    name: "isModuleInstalled",
    inputs: [
      { name: "moduleType", type: "uint256" },
      { name: "module", type: "address" },
      { name: "additionalContext", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "accountId",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "supportsModule",
    inputs: [{ name: "moduleTypeId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "supportsExecutionMode",
    inputs: [{ name: "mode", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "changeRootValidator",
    inputs: [
      { name: "_rootValidator", type: "bytes21" },
      { name: "hook", type: "address" },
      { name: "validatorData", type: "bytes" },
      { name: "hookData", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
] as const;

export const factoryAbi = [
  {
    type: "function",
    name: "createAccount",
    inputs: [
      { name: "data", type: "bytes" },
      { name: "salt", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "getAddress",
    inputs: [
      { name: "data", type: "bytes" },
      { name: "salt", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
] as const;

export const sessionKeyValidatorAbi = [
  {
    type: "function",
    name: "addSessionKey",
    inputs: [
      { name: "sessionKey", type: "address" },
      { name: "validAfter", type: "uint48" },
      { name: "validUntil", type: "uint48" },
      { name: "spendingLimit", type: "uint256" },
      { name: "allowedSelectors", type: "bytes4[]" },
      { name: "allowedTargets", type: "address[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;
