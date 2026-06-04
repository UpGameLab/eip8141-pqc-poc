/**
 * ML-DSA-ETH (EIP-8051) key generation and signing library.
 *
 * Implements ML-DSA-44 with the Keccak PRNG variant (VERIFY_MLDSA_ETH, address 0x13).
 * Primitives ported from 8141-geth/core/vm/contracts_mldsa.go.
 *
 * Public API:
 *   keygen()  → { expandedPK, secretKey }
 *   sign(secretKey, msg32)  → signature (2420 bytes)
 *   verify(msg32, signature, expandedPK) → boolean  (for local testing)
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { randomBytes } from "crypto";
import type { Hex } from "viem";

// ─── ML-DSA-44 Parameters (NIST Level II, FIPS 204) ──────────────────

const N = 256;
const Q = 8380417;
const K = 4;
const L = 4;
const GAMMA1 = 1 << 17; // 131072
const GAMMA2 = (Q - 1) / 88; // 95232
const BETA = 78;
const TAU = 39;
const D = 13;
const OMEGA = 80;
const ETA = 2;

// Input/output sizes
const MSG_SIZE = 32;
const SIG_SIZE = 2420;
const PK_SIZE = 20512;
const AHAT_SIZE = 16384;
const TR_SIZE = 32;
const CTILDE_SIZE = 32;
const Z_SIZE = 2304;

// ─── Types ────────────────────────────────────────────────────────────

type Poly = Int32Array; // length N
type PolyVec = Poly[]; // length K or L
type PolyMat = Poly[][]; // K x L

export interface MLDSAKeyPair {
  expandedPK: Uint8Array; // 20512 bytes
  secretKey: Uint8Array; // variable length
}

export interface MLDSASecretKey {
  rho: Uint8Array; // 32
  K: Uint8Array; // 32
  tr: Uint8Array; // 32
  s1: PolyVec; // L polys
  s2: PolyVec; // K polys
  t0: PolyVec; // K polys
  aHat: PolyMat; // K x L polys
}

// ─── Keccak PRNG (EIP-8051 ETH variant) ──────────────────────────────

class KeccakPRNG {
  private seed: Uint8Array = new Uint8Array(0);
  private ctr = 0;
  private buf: Uint8Array = new Uint8Array(0);
  private pos = 0;
  private flipped = false;

  write(data: Uint8Array): void {
    const newSeed = new Uint8Array(this.seed.length + data.length);
    newSeed.set(this.seed);
    newSeed.set(data, this.seed.length);
    this.seed = newSeed;
  }

  read(n: number): Uint8Array {
    if (!this.flipped) {
      this.ctr = 0;
      this.buf = new Uint8Array(0);
      this.pos = 0;
      this.flipped = true;
    }
    const out = new Uint8Array(n);
    let written = 0;
    while (written < n) {
      if (this.pos >= this.buf.length) {
        const ctrBytes = new Uint8Array(8);
        const view = new DataView(ctrBytes.buffer);
        view.setUint32(0, Math.floor(this.ctr / 0x100000000), false);
        view.setUint32(4, this.ctr >>> 0, false);
        const input = new Uint8Array(this.seed.length + 8);
        input.set(this.seed);
        input.set(ctrBytes, this.seed.length);
        this.buf = keccak_256(input);
        this.ctr++;
        this.pos = 0;
      }
      const toCopy = Math.min(n - written, this.buf.length - this.pos);
      out.set(this.buf.subarray(this.pos, this.pos + toCopy), written);
      this.pos += toCopy;
      written += toCopy;
    }
    return out;
  }
}

function newXOF(): KeccakPRNG {
  return new KeccakPRNG();
}

// ─── Modular Arithmetic ──────────────────────────────────────────────

function modQ(x: number): number {
  let r = x % Q;
  if (r < 0) r += Q;
  return r;
}

function addModQ(a: number, b: number): number {
  return modQ(a + b);
}

function subModQ(a: number, b: number): number {
  return modQ(a - b);
}

function mulModQ(a: number, b: number): number {
  // Use BigInt for multiplication to avoid overflow
  const r = (BigInt(a) * BigInt(b)) % BigInt(Q);
  const n = Number(r);
  return n < 0 ? n + Q : n;
}

function powModQ(base: number, exp: number): number {
  let result = 1n;
  let b = BigInt(base) % BigInt(Q);
  if (b < 0n) b += BigInt(Q);
  let e = BigInt(exp);
  while (e > 0n) {
    if (e & 1n) result = (result * b) % BigInt(Q);
    b = (b * b) % BigInt(Q);
    e >>= 1n;
  }
  return Number(result);
}

// ─── NTT ─────────────────────────────────────────────────────────────

function bitRev8(x: number): number {
  x = ((x & 0xf0) >> 4) | ((x & 0x0f) << 4);
  x = ((x & 0xcc) >> 2) | ((x & 0x33) << 2);
  x = ((x & 0xaa) >> 1) | ((x & 0x55) << 1);
  return x & 0xff;
}

const zetas = new Int32Array(N);
{
  const PSI = 1753;
  for (let i = 0; i < N; i++) {
    zetas[i] = powModQ(PSI, bitRev8(i));
  }
}

function nttForward(a: Poly): Poly {
  const r = new Int32Array(a);
  let k = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      k++;
      const zeta = zetas[k];
      for (let j = start; j < start + len; j++) {
        const t = mulModQ(zeta, r[j + len]);
        r[j + len] = subModQ(r[j], t);
        r[j] = addModQ(r[j], t);
      }
    }
  }
  return r;
}

function nttInverse(a: Poly): Poly {
  const r = new Int32Array(a);
  let k = N;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      k--;
      const zeta = zetas[k];
      for (let j = start; j < start + len; j++) {
        const t = r[j];
        r[j] = addModQ(t, r[j + len]);
        r[j + len] = mulModQ(zeta, subModQ(r[j + len], t));
      }
    }
  }
  const nInv = 8347681; // 256^-1 mod q
  for (let i = 0; i < N; i++) {
    r[i] = mulModQ(r[i], nInv);
  }
  return r;
}

// ─── Polynomial Operations ───────────────────────────────────────────

function polyAdd(a: Poly, b: Poly): Poly {
  const c = new Int32Array(N);
  for (let i = 0; i < N; i++) c[i] = addModQ(a[i], b[i]);
  return c;
}

function polySub(a: Poly, b: Poly): Poly {
  const c = new Int32Array(N);
  for (let i = 0; i < N; i++) c[i] = subModQ(a[i], b[i]);
  return c;
}

function polyMulNTT(a: Poly, b: Poly): Poly {
  const c = new Int32Array(N);
  for (let i = 0; i < N; i++) c[i] = mulModQ(a[i], b[i]);
  return c;
}

function matVecMulNTT(aHat: PolyMat, v: PolyVec): PolyVec {
  const result: PolyVec = [];
  for (let i = 0; i < K; i++) {
    let acc: Poly = new Int32Array(N);
    for (let j = 0; j < L; j++) {
      const t = polyMulNTT(aHat[i][j], v[j]);
      acc = polyAdd(acc, t);
    }
    result.push(acc);
  }
  return result;
}

// ─── Decompose / Hints ───────────────────────────────────────────────

function centerMod(a: number, alpha: number): number {
  let r = a % alpha;
  if (r < 0) r += alpha;
  if (r > Math.floor(alpha / 2)) r -= alpha;
  return r;
}

function decompose(r: number): [number, number] {
  let r0 = centerMod(r, 2 * GAMMA2);
  let r1: number;
  if (r - r0 === Q - 1) {
    r1 = 0;
    r0--;
  } else {
    r1 = Math.floor((r - r0) / (2 * GAMMA2));
  }
  return [r1, r0];
}

function useHint(hint: number, r: number): number {
  const [r1, r0] = decompose(r);
  if (hint === 0) return r1;
  const m = Math.floor((Q - 1) / (2 * GAMMA2));
  if (r0 > 0) return (r1 + 1) % m;
  return ((r1 - 1 + m) % m);
}

function makeHint(z: number, r: number): number {
  const [r1_] = decompose(r);
  const v = addModQ(r, z);
  const [v1_] = decompose(v);
  return r1_ !== v1_ ? 1 : 0;
}

function power2Round(r: number): [number, number] {
  const rPlus = modQ(r);
  const r0 = centerMod(rPlus, 1 << D);
  return [Math.floor((rPlus - r0) / (1 << D)), r0];
}

// ─── Encoding / Decoding ─────────────────────────────────────────────

function encodePolys(polys: PolyVec): Uint8Array {
  const out = new Uint8Array(polys.length * N * 4);
  let off = 0;
  for (const poly of polys) {
    for (let c = 0; c < N; c++) {
      out[off] = poly[c] & 0xff;
      out[off + 1] = (poly[c] >> 8) & 0xff;
      out[off + 2] = (poly[c] >> 16) & 0xff;
      out[off + 3] = (poly[c] >> 24) & 0xff;
      off += 4;
    }
  }
  return out;
}

function encodeMat(mat: PolyMat): Uint8Array {
  const out = new Uint8Array(K * L * N * 4);
  let off = 0;
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < L; j++) {
      for (let c = 0; c < N; c++) {
        const v = mat[i][j][c];
        out[off] = v & 0xff;
        out[off + 1] = (v >> 8) & 0xff;
        out[off + 2] = (v >> 16) & 0xff;
        out[off + 3] = (v >> 24) & 0xff;
        off += 4;
      }
    }
  }
  return out;
}

function decodeAHat(data: Uint8Array): PolyMat | null {
  const m: PolyMat = [];
  let off = 0;
  for (let i = 0; i < K; i++) {
    const row: Poly[] = [];
    for (let j = 0; j < L; j++) {
      const p = new Int32Array(N);
      for (let c = 0; c < N; c++) {
        const v = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24);
        if (v < 0 || v >= Q) return null;
        p[c] = v;
        off += 4;
      }
      row.push(p);
    }
    m.push(row);
  }
  return m;
}

function decodePolysK(data: Uint8Array, count: number): PolyVec | null {
  const polys: PolyVec = [];
  let off = 0;
  for (let i = 0; i < count; i++) {
    const p = new Int32Array(N);
    for (let c = 0; c < N; c++) {
      const v = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24);
      if (v < 0 || v >= Q) return null;
      p[c] = v;
      off += 4;
    }
    polys.push(p);
  }
  return polys;
}

function encodeZ(z: PolyVec): Uint8Array {
  // 18-bit packed: each coeff stored as gamma1 - coeff (unsigned 18-bit)
  const out = new Uint8Array(L * 576);
  for (let i = 0; i < L; i++) {
    for (let j = 0; j < N / 4; j++) {
      const vals: number[] = [];
      for (let m = 0; m < 4; m++) {
        let v = z[i][j * 4 + m];
        if (v > Q / 2) v -= Q; // to signed
        vals.push(GAMMA1 - v); // unsigned encoding
      }
      const base = i * 576 + j * 9;
      const c0 = vals[0] & 0x3ffff;
      const c1 = vals[1] & 0x3ffff;
      const c2 = vals[2] & 0x3ffff;
      const c3 = vals[3] & 0x3ffff;
      out[base + 0] = c0 & 0xff;
      out[base + 1] = (c0 >> 8) & 0xff;
      out[base + 2] = ((c0 >> 16) & 0x03) | ((c1 & 0x3f) << 2);
      out[base + 3] = (c1 >> 6) & 0xff;
      out[base + 4] = ((c1 >> 14) & 0x0f) | ((c2 & 0x0f) << 4);
      out[base + 5] = (c2 >> 4) & 0xff;
      out[base + 6] = ((c2 >> 12) & 0x3f) | ((c3 & 0x03) << 6);
      out[base + 7] = (c3 >> 2) & 0xff;
      out[base + 8] = (c3 >> 10) & 0xff;
    }
  }
  return out;
}

function decodeZ(data: Uint8Array): PolyVec | null {
  const z: PolyVec = [];
  for (let i = 0; i < L; i++) {
    const p = new Int32Array(N);
    const polyData = data.subarray(i * 576, (i + 1) * 576);
    for (let j = 0; j < N / 4; j++) {
      const base = j * 9;
      const c0 =
        polyData[base] |
        (polyData[base + 1] << 8) |
        ((polyData[base + 2] & 0x03) << 16);
      const c1 =
        (polyData[base + 2] >> 2) |
        (polyData[base + 3] << 6) |
        ((polyData[base + 4] & 0x0f) << 14);
      const c2 =
        (polyData[base + 4] >> 4) |
        (polyData[base + 5] << 4) |
        ((polyData[base + 6] & 0x3f) << 12);
      const c3 =
        (polyData[base + 6] >> 6) |
        (polyData[base + 7] << 2) |
        (polyData[base + 8] << 10);
      p[j * 4 + 0] = modQ(GAMMA1 - c0);
      p[j * 4 + 1] = modQ(GAMMA1 - c1);
      p[j * 4 + 2] = modQ(GAMMA1 - c2);
      p[j * 4 + 3] = modQ(GAMMA1 - c3);
    }
    z.push(p);
  }
  return z;
}

function encodeH(h: PolyVec): Uint8Array {
  // FIPS 204 HintBitPack: omega + k = 84 bytes
  const out = new Uint8Array(OMEGA + K);
  let idx = 0;
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < N; j++) {
      if (h[i][j] !== 0) {
        out[idx] = j;
        idx++;
      }
    }
    out[OMEGA + i] = idx;
  }
  return out;
}

function decodeH(data: Uint8Array): PolyVec | null {
  const h: PolyVec = [];
  for (let i = 0; i < K; i++) h.push(new Int32Array(N));
  let idx = 0;
  for (let i = 0; i < K; i++) {
    const limit = data[OMEGA + i];
    if (limit < idx || limit > OMEGA) return null;
    let prev = -1;
    while (idx < limit) {
      const pos = data[idx];
      if (pos >= N) return null;
      if (pos <= prev) return null;
      h[i][pos] = 1;
      prev = pos;
      idx++;
    }
  }
  for (let i = idx; i < OMEGA; i++) {
    if (data[i] !== 0) return null;
  }
  return h;
}

function encodeW1(w1: PolyVec): Uint8Array {
  const out = new Uint8Array(K * 192);
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < N / 4; j++) {
      const c0 = w1[i][j * 4 + 0] & 0x3f;
      const c1 = w1[i][j * 4 + 1] & 0x3f;
      const c2 = w1[i][j * 4 + 2] & 0x3f;
      const c3 = w1[i][j * 4 + 3] & 0x3f;
      const base = i * 192 + j * 3;
      out[base + 0] = c0 | (c1 << 6);
      out[base + 1] = (c1 >> 2) | (c2 << 4);
      out[base + 2] = (c2 >> 4) | (c3 << 2);
    }
  }
  return out;
}

// ─── Hash Computations ───────────────────────────────────────────────

function computeMu(tr: Uint8Array, msg: Uint8Array): Uint8Array {
  const xof = newXOF();
  const combined = new Uint8Array(tr.length + msg.length);
  combined.set(tr);
  combined.set(msg, tr.length);
  xof.write(combined);
  return xof.read(64);
}

function sampleInBall(seed: Uint8Array): Poly {
  const xof = newXOF();
  xof.write(seed);

  const c = new Int32Array(N);
  const signBytes = xof.read(8);
  let signs =
    BigInt(signBytes[0]) |
    (BigInt(signBytes[1]) << 8n) |
    (BigInt(signBytes[2]) << 16n) |
    (BigInt(signBytes[3]) << 24n) |
    (BigInt(signBytes[4]) << 32n) |
    (BigInt(signBytes[5]) << 40n) |
    (BigInt(signBytes[6]) << 48n) |
    (BigInt(signBytes[7]) << 56n);

  for (let i = N - TAU; i < N; i++) {
    let j: number;
    for (;;) {
      const jBuf = xof.read(1);
      j = jBuf[0];
      if (j <= i) break;
    }
    c[i] = c[j];
    if (signs & 1n) {
      c[j] = Q - 1; // -1 mod q
    } else {
      c[j] = 1;
    }
    signs >>= 1n;
  }
  return c;
}

function computeCTilde(mu: Uint8Array, w1: PolyVec): Uint8Array {
  const xof = newXOF();
  const w1Enc = encodeW1(w1);
  const combined = new Uint8Array(mu.length + w1Enc.length);
  combined.set(mu);
  combined.set(w1Enc, mu.length);
  xof.write(combined);
  return xof.read(32);
}

// ─── Norm Check ──────────────────────────────────────────────────────

function checkNorm(v: PolyVec, bound: number): boolean {
  for (const poly of v) {
    for (let j = 0; j < N; j++) {
      let val = poly[j];
      if (val > Q / 2) val -= Q; // convert from [0,Q) to centered
      if (val < 0) val = -val;
      if (val >= bound) return false;
    }
  }
  return true;
}

/** Check norm for already-centered values (e.g. from decompose). */
function checkNormCentered(v: PolyVec, bound: number): boolean {
  for (const poly of v) {
    for (let j = 0; j < N; j++) {
      let val = poly[j];
      if (val < 0) val = -val;
      if (val >= bound) return false;
    }
  }
  return true;
}

// ─── ExpandA (FIPS 204 Algorithm 32) ─────────────────────────────────

function expandA(rho: Uint8Array): PolyMat {
  const mat: PolyMat = [];
  for (let i = 0; i < K; i++) {
    const row: Poly[] = [];
    for (let j = 0; j < L; j++) {
      const xof = newXOF();
      const seed = new Uint8Array(rho.length + 2);
      seed.set(rho);
      seed[rho.length] = j;
      seed[rho.length + 1] = i;
      xof.write(seed);

      // Rejection sampling: read 3 bytes, construct 24-bit candidate, accept if < Q
      const poly = new Int32Array(N);
      let c = 0;
      while (c < N) {
        const buf = xof.read(3);
        const val = (buf[0] | (buf[1] << 8) | (buf[2] << 16)) & 0x7fffff;
        if (val < Q) {
          poly[c] = val;
          c++;
        }
      }
      // Put in NTT domain
      row.push(nttForward(poly));
    }
    mat.push(row);
  }
  return mat;
}

// ─── ExpandS (FIPS 204 Algorithm 33) ─────────────────────────────────

function sampleEta(xof: KeccakPRNG): Poly {
  // eta=2: sample coefficients in [-2, 2]
  // Each coefficient uses 3 bits via rejection: read byte, split into 2 nibbles
  const poly = new Int32Array(N);
  let c = 0;
  while (c < N) {
    const buf = xof.read(1);
    const b = buf[0];
    const t0 = b & 0x0f;
    const t1 = b >> 4;
    if (t0 < 15) {
      const a0 = t0 % 5;
      poly[c] = modQ(ETA - a0);
      c++;
    }
    if (c < N && t1 < 15) {
      const a1 = t1 % 5;
      poly[c] = modQ(ETA - a1);
      c++;
    }
  }
  return poly;
}

function expandS(rhoPrime: Uint8Array): { s1: PolyVec; s2: PolyVec } {
  const s1: PolyVec = [];
  const s2: PolyVec = [];
  for (let i = 0; i < L; i++) {
    const xof = newXOF();
    const seed = new Uint8Array(rhoPrime.length + 2);
    seed.set(rhoPrime);
    seed[rhoPrime.length] = i & 0xff;
    seed[rhoPrime.length + 1] = (i >> 8) & 0xff;
    xof.write(seed);
    s1.push(sampleEta(xof));
  }
  for (let i = 0; i < K; i++) {
    const xof = newXOF();
    const seed = new Uint8Array(rhoPrime.length + 2);
    seed.set(rhoPrime);
    const idx = L + i;
    seed[rhoPrime.length] = idx & 0xff;
    seed[rhoPrime.length + 1] = (idx >> 8) & 0xff;
    xof.write(seed);
    s2.push(sampleEta(xof));
  }
  return { s1, s2 };
}

// ─── ExpandMask (FIPS 204 Algorithm 34) ──────────────────────────────

function expandMask(rhoPP: Uint8Array, kappa: number): PolyVec {
  const y: PolyVec = [];
  for (let i = 0; i < L; i++) {
    const xof = newXOF();
    const seed = new Uint8Array(rhoPP.length + 2);
    seed.set(rhoPP);
    const idx = kappa + i;
    seed[rhoPP.length] = idx & 0xff;
    seed[rhoPP.length + 1] = (idx >> 8) & 0xff;
    xof.write(seed);

    // gamma1 = 2^17: each coeff needs 18 bits, pack 4 coeffs in 9 bytes
    const poly = new Int32Array(N);
    const data = xof.read(576); // 256 * 18 / 8 = 576
    for (let j = 0; j < N / 4; j++) {
      const base = j * 9;
      const c0 =
        data[base] | (data[base + 1] << 8) | ((data[base + 2] & 0x03) << 16);
      const c1 =
        (data[base + 2] >> 2) |
        (data[base + 3] << 6) |
        ((data[base + 4] & 0x0f) << 14);
      const c2 =
        (data[base + 4] >> 4) |
        (data[base + 5] << 4) |
        ((data[base + 6] & 0x3f) << 12);
      const c3 =
        (data[base + 6] >> 6) | (data[base + 7] << 2) | (data[base + 8] << 10);
      // Decode: gamma1 - stored value
      poly[j * 4 + 0] = modQ(GAMMA1 - (c0 & 0x3ffff));
      poly[j * 4 + 1] = modQ(GAMMA1 - (c1 & 0x3ffff));
      poly[j * 4 + 2] = modQ(GAMMA1 - (c2 & 0x3ffff));
      poly[j * 4 + 3] = modQ(GAMMA1 - (c3 & 0x3ffff));
    }
    y.push(poly);
  }
  return y;
}

// ─── Serialize / Deserialize Secret Key ──────────────────────────────

function serializeSecretKey(sk: MLDSASecretKey): Uint8Array {
  // Layout: rho(32) + K(32) + tr(32) + s1(L*N*4) + s2(K*N*4) + t0(K*N*4) + aHat(K*L*N*4)
  const s1Bytes = encodePolys(sk.s1);
  const s2Bytes = encodePolys(sk.s2);
  const t0Bytes = encodePolys(sk.t0);
  const aHatBytes = encodeMat(sk.aHat);
  const total = 32 + 32 + 32 + s1Bytes.length + s2Bytes.length + t0Bytes.length + aHatBytes.length;
  const out = new Uint8Array(total);
  let off = 0;
  out.set(sk.rho, off); off += 32;
  out.set(sk.K, off); off += 32;
  out.set(sk.tr, off); off += 32;
  out.set(s1Bytes, off); off += s1Bytes.length;
  out.set(s2Bytes, off); off += s2Bytes.length;
  out.set(t0Bytes, off); off += t0Bytes.length;
  out.set(aHatBytes, off);
  return out;
}

function deserializeSecretKey(data: Uint8Array): MLDSASecretKey {
  let off = 0;
  const rho = data.slice(off, off + 32); off += 32;
  const K_ = data.slice(off, off + 32); off += 32;
  const tr = data.slice(off, off + 32); off += 32;

  const s1Size = L * N * 4;
  const s1 = decodePolysK(data.subarray(off, off + s1Size), L)!;
  off += s1Size;

  const s2Size = K * N * 4;
  const s2 = decodePolysK(data.subarray(off, off + s2Size), K)!;
  off += s2Size;

  const t0Size = K * N * 4;
  // t0 can have negative values (centered), decode manually
  const t0: PolyVec = [];
  for (let i = 0; i < K; i++) {
    const p = new Int32Array(N);
    for (let c = 0; c < N; c++) {
      p[c] = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24);
      off += 4;
    }
    t0.push(p);
  }

  const aHatSize = K * L * N * 4;
  const aHat = decodeAHat(data.subarray(off, off + aHatSize))!;

  return { rho, K: K_, tr, s1, s2, t0, aHat };
}

// ─── KeyGen (FIPS 204 Algorithm 1, ETH variant) ──────────────────────

export function keygen(): MLDSAKeyPair {
  // 1. Generate random seed
  const seed = randomBytes(32);

  // 2. Expand seed → (rho, rho', K)
  const xof = newXOF();
  xof.write(seed);
  const expanded = xof.read(128);
  const rho = expanded.slice(0, 32);
  const rhoPrime = expanded.slice(32, 96);
  const K_ = expanded.slice(96, 128);

  // 3. ExpandA
  const aHat = expandA(rho);

  // 4. ExpandS
  const { s1, s2 } = expandS(rhoPrime);

  // 5. Compute t = NTT^-1(A_hat * NTT(s1)) + s2
  const s1NTT: PolyVec = s1.map((p) => nttForward(p));
  const as1 = matVecMulNTT(aHat, s1NTT);
  const t: PolyVec = [];
  for (let i = 0; i < K; i++) {
    t.push(polyAdd(nttInverse(as1[i]), s2[i]));
  }

  // 6. Power2Round
  const t1: PolyVec = [];
  const t0: PolyVec = [];
  for (let i = 0; i < K; i++) {
    const t1p = new Int32Array(N);
    const t0p = new Int32Array(N);
    for (let j = 0; j < N; j++) {
      const [hi, lo] = power2Round(t[i][j]);
      t1p[j] = modQ(hi);
      t0p[j] = lo; // centered, can be negative — store as-is
    }
    t1.push(t1p);
    t0.push(t0p);
  }

  // 7. Convert t1 to NTT domain (ETH variant stores t1 in NTT domain)
  const t1NTT: PolyVec = t1.map((p) => nttForward(p));

  // 8. Encode expanded PK components
  const aHatBytes = encodeMat(aHat);
  const t1Bytes = encodePolys(t1NTT);

  // 9. Compute tr = hash of expanded public key (A_hat + t1_NTT)
  const xofTr = newXOF();
  const pkForTr = new Uint8Array(aHatBytes.length + t1Bytes.length);
  pkForTr.set(aHatBytes);
  pkForTr.set(t1Bytes, aHatBytes.length);
  xofTr.write(pkForTr);
  const tr = xofTr.read(32);

  // 10. Build expanded PK: A_hat(16384) + tr(32) + t1_NTT(4096) = 20512
  const expandedPK = new Uint8Array(PK_SIZE);
  expandedPK.set(aHatBytes, 0);
  expandedPK.set(tr, AHAT_SIZE);
  expandedPK.set(t1Bytes, AHAT_SIZE + TR_SIZE);

  // 9. Secret key
  const sk: MLDSASecretKey = { rho, K: K_, tr, s1, s2, t0, aHat };
  const secretKey = serializeSecretKey(sk);

  return { expandedPK, secretKey };
}

// ─── Sign (FIPS 204 Algorithm 7, ETH variant) ────────────────────────

export function sign(secretKeyBytes: Uint8Array, msg: Uint8Array): Uint8Array {
  if (msg.length !== MSG_SIZE) throw new Error(`msg must be ${MSG_SIZE} bytes`);

  const sk = deserializeSecretKey(secretKeyBytes);

  // Precompute NTT of secret vectors
  const s1NTT: PolyVec = sk.s1.map((p) => nttForward(p));
  const s2NTT: PolyVec = sk.s2.map((p) => nttForward(p));
  const t0NTT: PolyVec = sk.t0.map((p) => {
    // t0 values are centered (can be negative), convert to [0,Q) before NTT
    const pMod = new Int32Array(N);
    for (let i = 0; i < N; i++) pMod[i] = modQ(p[i]);
    return nttForward(pMod);
  });

  // 1. mu = XOF(tr || msg)
  const mu = computeMu(sk.tr, msg);

  // 2. rho'' = XOF(K || mu)
  const xofRhoPP = newXOF();
  const kmu = new Uint8Array(sk.K.length + mu.length);
  kmu.set(sk.K);
  kmu.set(mu, sk.K.length);
  xofRhoPP.write(kmu);
  const rhoPP = xofRhoPP.read(64);

  // 3. Rejection sampling loop (FIPS 204 Algorithm 7)
  let kappa = 0;
  for (;;) {
    // Step 6: y = ExpandMask(rho'', kappa)
    const y = expandMask(rhoPP, kappa);
    kappa += L;

    // Step 6: w = NTT^-1(A_hat * NTT(y))
    const yNTT: PolyVec = y.map((p) => nttForward(p));
    const ayNTT = matVecMulNTT(sk.aHat, yNTT);
    const w: PolyVec = ayNTT.map((p) => nttInverse(p));

    // Step 7: w1 = HighBits(w)
    const w1: PolyVec = [];
    for (let i = 0; i < K; i++) {
      const w1p = new Int32Array(N);
      for (let j = 0; j < N; j++) {
        const [hi] = decompose(w[i][j]);
        w1p[j] = hi;
      }
      w1.push(w1p);
    }

    // Step 8: c_tilde = XOF(mu || encodeW1(w1))
    const cTilde = computeCTilde(mu, w1);

    // Step 9: c = SampleInBall(c_tilde)
    const c = sampleInBall(cTilde);
    const cNTT = nttForward(c);

    // Step 10: z = y + c*s1
    const z: PolyVec = [];
    for (let i = 0; i < L; i++) {
      const cs1i = nttInverse(polyMulNTT(cNTT, s1NTT[i]));
      z.push(polyAdd(y[i], cs1i));
    }

    // Step 12a: Check ||z|| < gamma1 - beta
    if (!checkNorm(z, GAMMA1 - BETA)) continue;

    // Step 11: cs2 = c*s2, then r = w - cs2, r0 = LowBits(r)
    const cs2: PolyVec = [];
    for (let i = 0; i < K; i++) {
      cs2.push(nttInverse(polyMulNTT(cNTT, s2NTT[i])));
    }
    const r: PolyVec = [];
    for (let i = 0; i < K; i++) {
      r.push(polySub(w[i], cs2[i]));
    }
    // r0 = LowBits(w - c*s2)
    const r0: PolyVec = [];
    for (let i = 0; i < K; i++) {
      const r0p = new Int32Array(N);
      for (let j = 0; j < N; j++) {
        const [, lo] = decompose(r[i][j]);
        r0p[j] = lo;
      }
      r0.push(r0p);
    }

    // Step 12b: Check ||r0|| < gamma2 - beta
    // r0 values are centered (small signed), checkNorm handles this
    if (!checkNormCentered(r0, GAMMA2 - BETA)) continue;

    // Step 13: ct0 = c*t0
    const ct0: PolyVec = [];
    for (let i = 0; i < K; i++) {
      ct0.push(nttInverse(polyMulNTT(cNTT, t0NTT[i])));
    }

    // Step 15a: Check ||ct0|| < gamma2
    if (!checkNorm(ct0, GAMMA2)) continue;

    // Step 14: h = MakeHint(-ct0, w - cs2 + ct0)
    const h: PolyVec = [];
    let hintCount = 0;
    for (let i = 0; i < K; i++) {
      const hp = new Int32Array(N);
      for (let j = 0; j < N; j++) {
        const negCt0j = subModQ(0, ct0[i][j]);
        // r[i][j] = w[i][j] - cs2[i][j], so w - cs2 + ct0 = r + ct0
        const rPlusCt0j = addModQ(r[i][j], ct0[i][j]);
        hp[j] = makeHint(negCt0j, rPlusCt0j);
        hintCount += hp[j];
      }
      h.push(hp);
    }

    // Step 15b: Check hint weight <= omega
    if (hintCount > OMEGA) continue;

    // Encode signature: c_tilde(32) + z(2304) + h(84) = 2420
    const sig = new Uint8Array(SIG_SIZE);
    sig.set(cTilde, 0);
    sig.set(encodeZ(z), CTILDE_SIZE);
    sig.set(encodeH(h), CTILDE_SIZE + Z_SIZE);
    return sig;
  }
}

// ─── Verify (local, for testing) ─────────────────────────────────────

export function verify(
  msg: Uint8Array,
  sig: Uint8Array,
  expandedPK: Uint8Array,
): boolean {
  if (msg.length !== MSG_SIZE || sig.length !== SIG_SIZE || expandedPK.length !== PK_SIZE) {
    return false;
  }

  // Parse PK
  const aHat = decodeAHat(expandedPK.subarray(0, AHAT_SIZE));
  if (!aHat) return false;
  const tr = expandedPK.subarray(AHAT_SIZE, AHAT_SIZE + TR_SIZE);
  const t1 = decodePolysK(expandedPK.subarray(AHAT_SIZE + TR_SIZE), K);
  if (!t1) return false;

  // Parse signature
  const cTilde = sig.subarray(0, CTILDE_SIZE);
  const z = decodeZ(sig.subarray(CTILDE_SIZE, CTILDE_SIZE + Z_SIZE));
  if (!z) return false;
  const h = decodeH(sig.subarray(CTILDE_SIZE + Z_SIZE));
  if (!h) return false;

  // Check ||z|| < gamma1 - beta
  if (!checkNorm(z, GAMMA1 - BETA)) return false;

  // mu = XOF(tr || msg)
  const mu = computeMu(tr, msg);

  // c = SampleInBall(c_tilde)
  const c = sampleInBall(cTilde);
  const cNTT = nttForward(c);

  // NTT(z)
  const zNTT: PolyVec = z.map((p) => nttForward(p));

  // w = A_hat * NTT(z) - NTT(c) * (2^d * t1)
  const az = matVecMulNTT(aHat, zNTT);
  const w: PolyVec = [];
  for (let i = 0; i < K; i++) {
    const ct1 = new Int32Array(N);
    for (let j = 0; j < N; j++) {
      const scaled = mulModQ(t1[i][j], 1 << D);
      ct1[j] = mulModQ(cNTT[j], scaled);
    }
    const diff = polySub(az[i], ct1);
    w.push(nttInverse(diff));
  }

  // w1' = UseHint(h, w)
  const w1Prime: PolyVec = [];
  for (let i = 0; i < K; i++) {
    const p = new Int32Array(N);
    for (let j = 0; j < N; j++) {
      p[j] = useHint(h[i][j], w[i][j]);
    }
    w1Prime.push(p);
  }

  // c_tilde' = XOF(mu || encodeW1(w1'))
  const cTildeCheck = computeCTilde(mu, w1Prime);

  // Compare
  if (cTilde.length !== cTildeCheck.length) return false;
  let diff = 0;
  for (let i = 0; i < cTilde.length; i++) {
    diff |= cTilde[i] ^ cTildeCheck[i];
  }
  return diff === 0;
}

// ─── Hex Helpers ─────────────────────────────────────────────────────

export function toHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}` as Hex;
}

export function fromHex(hex: Hex): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─── Export Constants ────────────────────────────────────────────────

export const MLDSA_PK_SIZE = PK_SIZE;
export const MLDSA_SIG_SIZE = SIG_SIZE;
export const MLDSA_MSG_SIZE = MSG_SIZE;
export const MLDSA_INPUT_SIZE = MSG_SIZE + SIG_SIZE + PK_SIZE; // 22964
