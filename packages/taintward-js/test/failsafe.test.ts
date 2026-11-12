// A value the detector cannot scan must not go out as it is.
//
// * a recognizer that throws: the value is masked whole (it used to come
//   back as "nothing found", so everything in it went out raw),
// * a value over TAINTWARD_DETECT_MAX_CHARS: masked whole, not scanned,
// * a long run of e-mail characters with no "@" must not take seconds.

import { afterEach, describe, expect, it } from "vitest";
import { CONTEXT_RECOGNIZERS } from "../src/detect/context.js";
import { OVERSIZE, UNSCANNED, detectText, maxChars } from "../src/detect/index.js";
import { PlaceholderMap } from "../src/placeholders.js";
import { redactPayload, redactString } from "../src/redact.js";
import { Tokenizer } from "../src/tokens.js";

const SSN = ["234", "12", "1234"].join("-");
const recognizers = CONTEXT_RECOGNIZERS as unknown as Array<(t: string, k: string) => never[]>;
const TRIGGER = "break-the-recognizer";
const thrower = (t: string) => {
  if (t.includes(TRIGGER)) throw new Error("boom");
  return [] as never[];
};

afterEach(() => {
  const i = recognizers.indexOf(thrower);
  if (i >= 0) recognizers.splice(i, 1);
  delete process.env.TAINTWARD_DETECT_MAX_CHARS;
});

describe("a recognizer that throws", () => {
  it("masks the whole value instead of passing it raw", () => {
    recognizers.push(thrower);
    const text = `ssn ${SSN} ${TRIGGER}`;
    const dets = detectText(text);
    expect(dets).toEqual([
      { entityType: UNSCANNED, start: 0, end: text.length, score: 1.0, sensitivity: "secret", fingerprint: "" },
    ]);
    const out = redactPayload({ note: text, other: `ssn ${SSN}` }, "external");
    expect(JSON.stringify(out)).not.toContain(SSN);
    expect(out.note).toBe("[SECRET]");
    // the value next to it is still scanned as usual
    expect(out.other).toBe("ssn [PII]");
  });

  it("gives the model a placeholder and no FF1 token to internal sinks", () => {
    recognizers.push(thrower);
    const text = `ssn ${SSN} ${TRIGGER}`;
    const pmap = new PlaceholderMap();
    expect(redactString(text, "llm", { placeholders: pmap })).toBe("<UNSCANNED_1>");
    const tokenizer = new Tokenizer({ key: "00".repeat(16) });
    expect(redactString(text, "internal", { internal: "token", tokenizer })).toBe("[SECRET]");
  });
});

describe("the size limit", () => {
  it("masks a value over the limit whole", () => {
    process.env.TAINTWARD_DETECT_MAX_CHARS = "100";
    expect(maxChars()).toBe(100);
    const big = `ssn ${SSN} `.repeat(20);
    const dets = detectText(big);
    expect(dets.map((d) => [d.entityType, d.start, d.end, d.sensitivity])).toEqual([[OVERSIZE, 0, big.length, "secret"]]);
    expect(redactPayload({ doc: big }, "external")).toEqual({ doc: "[SECRET]" });
    expect(redactPayload({ doc: big }, "llm", { placeholders: new PlaceholderMap() })).toEqual({ doc: "<TOO_LARGE_1>" });
  });

  it("scans a value under the limit, and 0 turns the limit off", () => {
    process.env.TAINTWARD_DETECT_MAX_CHARS = "100";
    expect(detectText(`ssn ${SSN}`).map((d) => d.entityType)).toEqual(["US_SSN"]);
    process.env.TAINTWARD_DETECT_MAX_CHARS = "0";
    const big = `ssn ${SSN} `.repeat(20);
    expect(detectText(big).every((d) => d.entityType === "US_SSN")).toBe(true);
    expect(detectText(big).length).toBe(20);
  });

  it("defaults to 500000 and ignores a value that is not a number", () => {
    expect(maxChars()).toBe(500_000);
    process.env.TAINTWARD_DETECT_MAX_CHARS = "lots";
    expect(maxChars()).toBe(500_000);
  });
});

describe("long input", () => {
  it("does not go quadratic on e-mail characters with no @", () => {
    // 120 KB. Before the local part was bounded this took about 7 seconds.
    const text = "1-".repeat(60_000);
    const t = performance.now();
    detectText(text);
    expect(performance.now() - t).toBeLessThan(4000);
  });

  it("still finds an e-mail address with a long local part", () => {
    const local = "a".repeat(64);
    const text = `mail ${local}@example.com now`;
    const dets = detectText(text).filter((d) => d.entityType === "EMAIL_ADDRESS");
    expect(dets.map((d) => text.slice(d.start, d.end))).toEqual([`${local}@example.com`]);
  });
});
