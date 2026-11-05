// FF1 against the NIST sample vectors, and tokens against the Python SDK:
// the same key must give the same token in both languages.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FF1, ff1MinLen } from "../src/ff1.js";
import { redactPayload } from "../src/redact.js";
import { Tokenizer } from "../src/tokens.js";

const K128 = "2B7E151628AED2A6ABF7158809CF4F3C";
const K192 = K128 + "EF4359D8D580AA4F";
const K256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94";
const T10 = "39383736353433323130";
const T11 = "3737373770717273373737";
const PT10 = "0123456789";
const PT36 = "0123456789abcdefghi";
const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

// NIST FF1samples.pdf, samples 1 to 9: key, radix, tweak, plaintext, ciphertext
const NIST: Array<[string, number, string, string, string]> = [
  [K128, 10, "", PT10, "2433477484"],
  [K128, 10, T10, PT10, "6124200773"],
  [K128, 36, T11, PT36, "a9tv40mll9kdu509eum"],
  [K192, 10, "", PT10, "2830668132"],
  [K192, 10, T10, PT10, "2496655549"],
  [K192, 36, T11, PT36, "xbj3kv35jrawxv32ysr"],
  [K256, 10, "", PT10, "6657667009"],
  [K256, 10, T10, PT10, "1001623463"],
  [K256, 36, T11, PT36, "xs8a0azh2avyalyzuwd"],
];

describe("FF1", () => {
  it.each(NIST.map((v, i) => [i + 1, ...v] as const))("NIST sample %i", (_n, key, radix, tweak, pt, ct) => {
    const c = new FF1(hex(key), radix);
    expect(c.encrypt(pt, hex(tweak))).toBe(ct);
    expect(c.decrypt(ct, hex(tweak))).toBe(pt);
  });

  it("decrypts what it encrypts", () => {
    const c10 = new FF1(hex(K256), 10);
    const c36 = new FF1(hex(K256), 36);
    for (let n = 6; n < 40; n += 3) {
      const x = Array.from({ length: n }, (_, i) => (i * 7 + n) % 10);
      expect(c10.decryptNumerals(c10.encryptNumerals(x, hex("aa")), hex("aa"))).toEqual(x);
      const y = Array.from({ length: n }, (_, i) => (i * 11 + n) % 36);
      expect(c36.decryptNumerals(c36.encryptNumerals(y))).toEqual(y);
    }
  });

  it("enforces the domain size", () => {
    expect(ff1MinLen(10)).toBe(6);
    expect(ff1MinLen(36)).toBe(4);
    expect(() => new FF1(hex(K128), 10).encrypt("12345")).toThrow(RangeError);
    expect(() => new FF1(hex(K128).subarray(0, 10), 10)).toThrow(RangeError);
  });
});

const py: { key: string; cases: Array<{ tweak: string | null; value: string; token: string | null }> } =
  JSON.parse(readFileSync(new URL("./fixtures/python-tokens.json", import.meta.url), "utf8"));

describe("tokens", () => {
  it.each(py.cases.map((c) => [c.value, c.tweak, c.token] as const))(
    "%s (tweak %s) gives the Python token",
    (value, tweak, token) => {
      const t = new Tokenizer({ key: py.key, ...(tweak ? { tweak } : {}) });
      expect(t.encrypt(value)).toBe(token);
    },
  );

  it("reverses to the exact value, letter case included", () => {
    const t = new Tokenizer({ key: K128 });
    const token = t.token("Alice.Lee@Example.com")!;
    expect(token).not.toContain("Alice");
    expect(token.length).toBe("Alice.Lee@Example.com".length);
    expect(t.reverse(token)).toBe("Alice.Lee@Example.com");
    expect(t.reverse("[PII]")).toBeNull();
  });

  it("decrypts an all-digit token without the vault, unless that is turned off", () => {
    const a = new Tokenizer({ key: K128 });
    const token = a.token("234-12-1234")!;
    expect(new Tokenizer({ key: K128 }).reverse(token)).toBe("234-12-1234");
    const vault = new Map<string, string>();
    const b = new Tokenizer({ key: K128, vault });
    expect(b.token("234-12-1234")).toBe(token);
    b.forget(token);
    expect(b.reverse(token)).toBeNull(); // erased: a persistent vault has no fallback
  });

  it("never lets one token stand for two values", () => {
    const vault = new Map<string, string>();
    const t = new Tokenizer({ key: K128, vault });
    const token = t.encrypt("234-12-1234")!;
    vault.set(token, "something else");
    expect(t.token("234-12-1234")).toBeNull();
  });

  it("is what internal sinks get with internal: 'token'", () => {
    const tokenizer = new Tokenizer({ key: K128 });
    const payload = { ssn: "234-12-1234", note: "card 4111 1111 1111 1111" };
    const internal = redactPayload(payload, "internal", { internal: "token", tokenizer });
    expect(internal.ssn).toBe(py.cases.find((c) => c.value === "234-12-1234" && !c.tweak)!.token);
    expect(tokenizer.reverse(internal.ssn)).toBe("234-12-1234");
    expect(internal.note).toBe("card 5472 0454 9762 8388");
    expect(redactPayload(payload, "external", { internal: "token", tokenizer }).ssn).toBe("[PII]");
  });

  it("masks values too short for FF1", () => {
    const tokenizer = new Tokenizer({ key: K128 });
    expect(tokenizer.token("x9")).toBeNull();
  });

  it("needs a key", () => {
    const saved = process.env.TAINTWARD_FPE_KEY;
    delete process.env.TAINTWARD_FPE_KEY;
    try {
      expect(() => new Tokenizer()).toThrow(/key/);
    } finally {
      if (saved !== undefined) process.env.TAINTWARD_FPE_KEY = saved;
    }
  });
});
