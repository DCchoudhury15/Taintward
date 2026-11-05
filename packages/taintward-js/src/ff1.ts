// FF1 format-preserving encryption (NIST SP 800-38G, Algorithms 7 and 8),
// ported from taintward/sdk/ff1.py and checked against the NIST sample
// vectors and against Python tokens (test/tokens.test.ts).
//
// AES comes from node:crypto (AES-ECB on single blocks is the spec's
// CIPH_K). Numbers are BigInt. This module does not pick or store keys.

import { createCipheriv } from "node:crypto";

export const FF1_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
const MIN_DOMAIN = 1_000_000n;
const ROUNDS = 10;

/** Smallest message length allowed for this radix (radix**n >= 1e6). */
export function ff1MinLen(radix: number): number {
  if (!(radix >= 2 && radix <= 65536)) throw new RangeError("radix must be in 2..65536");
  let n = 2;
  while (BigInt(radix) ** BigInt(n) < MIN_DOMAIN) n++;
  return n;
}

function num(x: readonly number[], radix: bigint): bigint {
  let v = 0n;
  for (const d of x) v = v * radix + BigInt(d);
  return v;
}

function str(x: bigint, radix: bigint, m: number): number[] {
  const out = new Array<number>(m).fill(0);
  for (let i = m - 1; i >= 0; i--) {
    out[i] = Number(x % radix);
    x /= radix;
  }
  return out;
}

function bigToBytes(x: bigint, len: number): Buffer {
  const out = Buffer.alloc(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function bytesToBig(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

function bitLength(x: bigint): number {
  return x === 0n ? 0 : x.toString(2).length;
}

/** FF1 cipher for one (key, radix) pair. The tweak is given per call. */
export class FF1 {
  readonly radix: number;
  readonly minLen: number;
  private readonly key: Buffer;
  private readonly r: bigint;

  constructor(key: Uint8Array, radix = 10) {
    if (![16, 24, 32].includes(key.length)) {
      throw new RangeError("FF1 key must be 16, 24 or 32 bytes (AES-128/192/256)");
    }
    this.radix = radix;
    this.minLen = ff1MinLen(radix);
    this.key = Buffer.from(key);
    this.r = BigInt(radix);
  }

  private aes(block: Buffer): Buffer {
    const c = createCipheriv(`aes-${this.key.length * 8}-ecb`, this.key, null);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(block), c.final()]);
  }

  private check(x: readonly number[]): void {
    if (x.length < this.minLen || x.length > 2 ** 32 - 1) {
      throw new RangeError(`FF1 length ${x.length} outside ${this.minLen}..${2 ** 32 - 1} for radix ${this.radix}`);
    }
    for (const d of x) if (!(d >= 0 && d < this.radix)) throw new RangeError("numeral out of range for radix");
  }

  private setup(n: number, t: number) {
    const u = Math.floor(n / 2);
    const v = n - u;
    const b = Math.floor((bitLength(this.r ** BigInt(v) - 1n) + 7) / 8);
    const d = 4 * Math.floor((b + 3) / 4) + 4;
    const p = Buffer.concat([
      Buffer.from([1, 2, 1]),
      bigToBytes(this.r, 3),
      Buffer.from([10, u % 256]),
      bigToBytes(BigInt(n), 4),
      bigToBytes(BigInt(t), 4),
    ]);
    return { u, v, b, d, p };
  }

  private roundValue(p: Buffer, tweak: Buffer, i: number, bNum: bigint, b: number, d: number): bigint {
    const t = tweak.length;
    const pad = (((-t - b - 1) % 16) + 16) % 16;
    const msg = Buffer.concat([p, tweak, Buffer.alloc(pad), Buffer.from([i]), bigToBytes(bNum, b)]);
    // PRF = CBC-MAC with a zero IV: keep only the last block.
    let r: Buffer = Buffer.alloc(16);
    for (let off = 0; off < msg.length; off += 16) {
      const blk = Buffer.alloc(16);
      for (let k = 0; k < 16; k++) blk[k] = r[k]! ^ msg[off + k]!;
      r = this.aes(blk);
    }
    let s: Buffer = r;
    for (let j = 1; s.length < d; j++) {
      s = Buffer.concat([s, this.aes(bigToBytes(bytesToBig(r) ^ BigInt(j), 16))]);
    }
    return bytesToBig(s.subarray(0, d));
  }

  encryptNumerals(x: readonly number[], tweak: Uint8Array = new Uint8Array()): number[] {
    this.check(x);
    const tw = Buffer.from(tweak);
    const { u, v, b, d, p } = this.setup(x.length, tw.length);
    let a = x.slice(0, u);
    let bb = x.slice(u);
    for (let i = 0; i < ROUNDS; i++) {
      const y = this.roundValue(p, tw, i, num(bb, this.r), b, d);
      const m = i % 2 === 0 ? u : v;
      const mod = this.r ** BigInt(m);
      const c = (((num(a, this.r) + y) % mod) + mod) % mod;
      a = bb;
      bb = str(c, this.r, m);
    }
    return [...a, ...bb];
  }

  decryptNumerals(x: readonly number[], tweak: Uint8Array = new Uint8Array()): number[] {
    this.check(x);
    const tw = Buffer.from(tweak);
    const { u, v, b, d, p } = this.setup(x.length, tw.length);
    let a = x.slice(0, u);
    let bb = x.slice(u);
    for (let i = ROUNDS - 1; i >= 0; i--) {
      const y = this.roundValue(p, tw, i, num(a, this.r), b, d);
      const m = i % 2 === 0 ? u : v;
      const mod = this.r ** BigInt(m);
      const c = (((num(bb, this.r) - y) % mod) + mod) % mod;
      bb = a;
      a = str(c, this.r, m);
    }
    return [...a, ...bb];
  }

  private toNumerals(s: string): number[] {
    if (this.radix > FF1_ALPHABET.length) throw new RangeError("string API supports radix up to 36");
    return [...s].map((c) => {
      const k = FF1_ALPHABET.indexOf(c);
      if (k < 0 || k >= this.radix) throw new RangeError("character outside the alphabet for this radix");
      return k;
    });
  }

  encrypt(s: string, tweak?: Uint8Array): string {
    return this.encryptNumerals(this.toNumerals(s), tweak).map((d) => FF1_ALPHABET[d]).join("");
  }

  decrypt(s: string, tweak?: Uint8Array): string {
    return this.decryptNumerals(this.toNumerals(s), tweak).map((d) => FF1_ALPHABET[d]).join("");
  }
}
