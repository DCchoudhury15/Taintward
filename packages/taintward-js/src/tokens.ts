// Reversible tokens for internal sinks, the same as the Python SDK's
// (taintward/sdk/redact.py, Redactor): with the same key, a value gets the
// same token in both languages (test/tokens.test.ts checks this).
//
// The letters and digits of the value are encrypted with FF1 (radix 10 when
// they are all digits, else radix 36) and put back in place; separators stay
// where they were. The value's layout (digit / lower / upper / separator)
// goes into the tweak, so values that differ only in letter case get
// different tokens. A token keeps the value's length; its letters are lower
// case. Values with fewer than 6 digits or 4 letters and digits are too short
// for FF1 and are masked instead.
//
// The vault maps token -> exact original (letter case is not in a radix-36
// token). Without a vault entry only an all-digit token can be decrypted.

import { FF1 } from "./ff1.js";

const TWEAK_DOMAIN = "taintward-ff1-v1";
const ALNUM = /[0-9A-Za-z]/g;

export interface TokenVault {
  get(token: string): string | undefined;
  set(token: string, value: string): void;
  delete(token: string): boolean;
}

export interface TokenizerOptions {
  /** AES key as hex (32, 48 or 64 hex characters) or bytes. Default: TAINTWARD_FPE_KEY. */
  key?: string | Uint8Array;
  /** Extra tweak as hex, the Python Redactor's `tweak_hex`. */
  tweak?: string;
  /** Where token -> original is kept. Default: an in-memory Map. */
  vault?: TokenVault;
  /**
   * Without a vault entry, decrypt an all-digit token with the key (default
   * true for the in-memory vault). Turn it off when deleting a vault entry
   * must make the token unreversible (erasure).
   */
  structuralFallback?: boolean;
}

function layout(s: string): string {
  let out = "";
  for (const c of s) {
    if (c >= "0" && c <= "9") out += "d";
    else if (c >= "a" && c <= "z") out += "a";
    else if (c >= "A" && c <= "Z") out += "A";
    else out += c;
  }
  return out;
}

function hexBytes(hex: string, what: string): Uint8Array {
  const clean = hex.trim();
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(clean)) throw new TypeError(`${what} must be hex`);
  return Uint8Array.from(Buffer.from(clean, "hex"));
}

function envKey(): string | undefined {
  return typeof process !== "undefined" ? process.env?.TAINTWARD_FPE_KEY : undefined;
}

export class Tokenizer {
  private readonly ciphers: Record<10 | 36, FF1>;
  private readonly tweak: Uint8Array;
  readonly vault: TokenVault;
  readonly structuralFallback: boolean;

  constructor(opts: TokenizerOptions = {}) {
    const raw = opts.key ?? envKey();
    if (raw === undefined || raw === "") {
      throw new TypeError("taintward: tokens need a key: pass `key` or set TAINTWARD_FPE_KEY");
    }
    const key = typeof raw === "string" ? hexBytes(raw, "TAINTWARD_FPE_KEY") : raw;
    if (![16, 24, 32].includes(key.length)) {
      throw new RangeError("TAINTWARD_FPE_KEY must be 32, 48 or 64 hex characters");
    }
    this.ciphers = { 10: new FF1(key, 10), 36: new FF1(key, 36) };
    this.tweak = opts.tweak ? hexBytes(opts.tweak, "tweak") : new Uint8Array();
    this.vault = opts.vault ?? new Map<string, string>();
    this.structuralFallback = opts.structuralFallback ?? opts.vault === undefined;
  }

  private tweakFor(radix: number, shape: string): Uint8Array {
    const enc = new TextEncoder();
    const sep = enc.encode("|");
    const parts = [enc.encode(TWEAK_DOMAIN), this.tweak, enc.encode(String(radix)), enc.encode(shape)];
    const out: number[] = [];
    parts.forEach((p, i) => {
      if (i > 0) out.push(...sep);
      out.push(...p);
    });
    return Uint8Array.from(out);
  }

  private static radixFor(s: string): 10 | 36 | null {
    const alpha = s.match(ALNUM);
    if (!alpha) return null;
    return alpha.every((c) => c >= "0" && c <= "9") ? 10 : 36;
  }

  /** The FF1 token for `value`, or null when it has too few letters and digits. */
  encrypt(value: string): string | null {
    const radix = Tokenizer.radixFor(value);
    if (radix === null) return null;
    const cipher = this.ciphers[radix];
    const positions = [...value.matchAll(ALNUM)].map((m) => m.index!);
    if (positions.length < cipher.minLen) return null;
    const alpha = positions.map((i) => value[i]!.toLowerCase()).join("");
    const enc = cipher.encrypt(alpha, this.tweakFor(radix, layout(value)));
    const out = value.split("");
    positions.forEach((idx, n) => {
      out[idx] = enc[n]!;
    });
    return out.join("");
  }

  /**
   * Token for an internal sink, kept in the vault for exact reversal. Null
   * when the value cannot be tokenized, or its token already stands for a
   * different value (the caller masks it then).
   */
  token(value: string): string | null {
    const t = this.encrypt(value);
    if (t === null) return null;
    const existing = this.vault.get(t);
    if (existing !== undefined && existing !== value) return null;
    this.vault.set(t, value);
    return t;
  }

  /** The original value of a token, or null (masks and unknown tokens). */
  reverse(token: string): string | null {
    const found = this.vault.get(token);
    if (found !== undefined) return found;
    if (!this.structuralFallback || Tokenizer.radixFor(token) !== 10) return null;
    const cipher = this.ciphers[10];
    const positions = [...token.matchAll(ALNUM)].map((m) => m.index!);
    if (positions.length < cipher.minLen) return null;
    let dec: string;
    try {
      dec = cipher.decrypt(positions.map((i) => token[i]!).join(""), this.tweakFor(10, layout(token)));
    } catch {
      return null;
    }
    const out = token.split("");
    positions.forEach((idx, n) => {
      out[idx] = dec[n]!;
    });
    return out.join("");
  }

  /** Erase one token from the vault. */
  forget(token: string): boolean {
    return this.vault.delete(token);
  }
}
