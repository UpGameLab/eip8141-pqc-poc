import { falcon512padded } from "@noble/post-quantum/falcon.js";
import {
  bytesToHex,
  concatHex,
  hexToBytes,
  keccak256,
  numberToHex,
  type Address,
  type Hex,
} from "viem";

export const FALCON_PK_SIZE = 896;
export const FALCON_ENCODED_PK_SIZE = 897;
export const FALCON_SIG_SIZE = 666;
export const FALCON_MSG_SIZE = 32;

export const FALCON_SIG_TYPE_SHAKE256 = 0x04;
export const FALCON_SIG_TYPE_KECCAK_PRNG = 0x05;

export const FALCON_ALG_TYPE_SHAKE256 = 0xfa;
export const FALCON_ALG_TYPE_KECCAK_PRNG = 0xfb;

const FALCON_PUBLIC_KEY_HEADER = 0x09;
const FALCON_DETACHED_SIGNATURE_HEADER = 0x39;
const EOA_VERIFY_MODE = 0x01;

export type FalconSigType =
  | typeof FALCON_SIG_TYPE_SHAKE256
  | typeof FALCON_SIG_TYPE_KECCAK_PRNG;

export type FalconAlgType =
  | typeof FALCON_ALG_TYPE_SHAKE256
  | typeof FALCON_ALG_TYPE_KECCAK_PRNG;

export type FalconEoaScope = 1 | 2 | 3;

export interface FalconKeyPair {
  pk: Uint8Array;
  sk: Uint8Array;
}

export function toHex(bytes: Uint8Array): Hex {
  return bytesToHex(bytes);
}

export function fromHex(hex: Hex): Uint8Array {
  return hexToBytes(hex);
}

export function generateFalconKeypair(): FalconKeyPair {
  const { publicKey, secretKey } = falcon512padded.keygen();
  return {
    pk: normalizeFalconPublicKey(publicKey),
    sk: new Uint8Array(secretKey),
  };
}

export function normalizeFalconPublicKey(pubkey: Uint8Array): Uint8Array {
  if (pubkey.length === FALCON_PK_SIZE) return new Uint8Array(pubkey);
  if (
    pubkey.length === FALCON_ENCODED_PK_SIZE &&
    pubkey[0] === FALCON_PUBLIC_KEY_HEADER
  ) {
    return pubkey.slice(1);
  }
  throw new Error(
    `Invalid Falcon public key length/header: got ${pubkey.length} bytes`,
  );
}

export function encodeFalconPublicKey(pubkey: Uint8Array): Uint8Array {
  const normalized = normalizeFalconPublicKey(pubkey);
  const encoded = new Uint8Array(FALCON_ENCODED_PK_SIZE);
  encoded[0] = FALCON_PUBLIC_KEY_HEADER;
  encoded.set(normalized, 1);
  return encoded;
}

export function falconAlgTypeForSigType(sigType: FalconSigType): FalconAlgType {
  return sigType === FALCON_SIG_TYPE_KECCAK_PRNG
    ? FALCON_ALG_TYPE_KECCAK_PRNG
    : FALCON_ALG_TYPE_SHAKE256;
}

export function falconEoaPrefix(scope: FalconEoaScope): number {
  if (scope < 1 || scope > 3) {
    throw new Error(`Invalid Falcon EOA approval scope: ${scope}`);
  }
  return (scope << 4) | EOA_VERIFY_MODE;
}

export function falconEoaMessageHash(
  sigHash: Hex,
  sigType: FalconSigType = FALCON_SIG_TYPE_SHAKE256,
  scope: FalconEoaScope = 3,
): Hex {
  return keccak256(
    concatHex([
      sigHash,
      bytesToHex(new Uint8Array([falconEoaPrefix(scope), sigType])),
    ]),
  );
}

export function falconSign(
  sigHash: Hex,
  privkey: Uint8Array,
  sigType: FalconSigType = FALCON_SIG_TYPE_SHAKE256,
  scope: FalconEoaScope = 3,
): Uint8Array {
  return falconSignDigest(falconEoaMessageHash(sigHash, sigType, scope), privkey);
}

export function falconSignDigest(messageHash: Hex, privkey: Uint8Array): Uint8Array {
  const msg = hexToBytes(messageHash);
  if (msg.length !== FALCON_MSG_SIZE) {
    throw new Error(`Falcon message must be ${FALCON_MSG_SIZE} bytes`);
  }

  const sig = falcon512padded.sign(msg, privkey);
  if (sig.length !== FALCON_SIG_SIZE) {
    throw new Error(`Invalid Falcon signature length: ${sig.length}`);
  }
  if (sig[0] !== FALCON_DETACHED_SIGNATURE_HEADER) {
    throw new Error(
      `Invalid Falcon detached signature header: 0x${sig[0].toString(16)}`,
    );
  }
  return sig;
}

export function falconVerifyDigest(
  messageHash: Hex,
  signature: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  const msg = hexToBytes(messageHash);
  if (msg.length !== FALCON_MSG_SIZE || signature.length !== FALCON_SIG_SIZE) {
    return false;
  }

  try {
    return falcon512padded.verify(
      signature,
      msg,
      encodeFalconPublicKey(pubkey),
    );
  } catch {
    return false;
  }
}

export function deriveFalconAddress(
  pubkey: Uint8Array,
  algType: FalconAlgType = FALCON_ALG_TYPE_SHAKE256,
): Address {
  const normalized = normalizeFalconPublicKey(pubkey);
  const hash = keccak256(
    concatHex([
      numberToHex(algType, { size: 1 }),
      bytesToHex(normalized),
    ]),
  );
  return `0x${hash.slice(26)}` as Address;
}

export function buildFalconVerifyData(
  pubkey: Uint8Array,
  signature: Uint8Array,
  scope: FalconEoaScope = 3,
  sigType: FalconSigType = FALCON_SIG_TYPE_SHAKE256,
): Hex {
  if (signature.length !== FALCON_SIG_SIZE) {
    throw new Error(`Invalid Falcon signature length: ${signature.length}`);
  }

  return concatHex([
    bytesToHex(new Uint8Array([falconEoaPrefix(scope), sigType])),
    bytesToHex(normalizeFalconPublicKey(pubkey)),
    bytesToHex(signature),
  ]);
}
