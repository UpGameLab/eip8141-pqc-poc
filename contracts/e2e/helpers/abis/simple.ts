// Simple8141Account uses an older validate ABI: validate(uint8 v, bytes32 r, bytes32 s, uint8 scope)
// Selector: 0xf2d64fed
export const SIMPLE_VALIDATE_SELECTOR = "0xf2d64fed";

export const simpleAccountAbi = [
  {
    type: "function",
    name: "execute",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;
