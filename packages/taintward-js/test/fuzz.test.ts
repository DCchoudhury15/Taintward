// Property tests for detection, placeholder redaction and restore. The same
// properties as tests/test_fuzz_restore.py in the Python SDK.
//
// fast-check builds text from real-looking values, unicode noise and pieces
// that look like placeholders, then checks that:
//
// 1. detectText never throws and every span fits in the text,
// 2. redact then restore gives back the exact text, and no detected value is
//    left in the redacted text,
// 3. StreamRestorer gives the same result as restoreText, wherever the
//    stream is cut,
// 4. restoring arbitrary or mangled model output never throws,
// 5. a redacted JSON document restores to an equal document,
// 6. maskText hides every detected value.
//
// Every map uses restoreInUrls: not restoring inside a link address is a
// policy choice (gap G1), not a round trip bug.
//
// The default run is small so the file stays fast. For a longer run:
// TAINTWARD_FUZZ_EXAMPLES=5000 npx vitest run test/fuzz.test.ts

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { detectText, maskText, type Detection } from "../src/detect/index.js";
import { PlaceholderMap, StreamRestorer } from "../src/placeholders.js";
import { redactPayload, redactText } from "../src/redact.js";

const RUNS = Number(process.env.TAINTWARD_FUZZ_EXAMPLES ?? "200");
// A long run needs more time than the default test timeout.
const TIMEOUT = Math.max(5_000, RUNS * 20);

// Keys and tokens are built at runtime so no secret-shaped literal is in the
// source. The key is the AWS docs example key.
const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_" + "a1B2".repeat(9);

const VALUES = [
  "536-22-8491",
  "maria.garcia@example.com",
  "Maria Garcia",
  "+1 415 555 0134",
  "4111 1111 1111 1111",
  AWS_KEY,
  GH_TOKEN,
  "Jürgen Müller",
  "José O'Brien",
  "李小龙",
  "FR7630006000011234567890189",
  'a"b@ex.com',
  "back\\slash@ex.com",
  "<SSN_1>",
  "[PERSON_1]",
  "PERSON_1",
];
// Any code point, astral ones included (no lone surrogates).
const NOISE = fc.string({ unit: "binary", maxLength: 30 });
const FILLER = fc.constantFrom(
  " ", ", ", " and ", "\n", " my SSN is ", " email: ", " name ", '"', "<", ">",
  "{", "}", "[", "]", "_", "​", "&lt;", " call ", "\\", "'", "My name is ",
);
// A bare placeholder form glued to a value ("PERSON_1ghp_..."). It becomes a
// real placeholder form once the value after it is redacted.
const GLUED = fc
  .tuple(fc.constantFrom("PERSON_1", "SSN_1", "EMAIL_2", "Person_1"), fc.constantFrom(...VALUES))
  .map(([a, b]) => a + b);
const PIECE = fc.oneof(fc.constantFrom(...VALUES), NOISE, FILLER, GLUED);
const TEXT = fc.array(PIECE, { maxLength: 12 }).map((p) => p.join(""));

const MANGLE = fc.constantFrom(
  "<{}>", "[{}]", "{{{}}}", "&lt;{}&gt;", "<{}", "{}>", "«{}»", "\\<{}\\>", "<{} >", "< {}>",
  "<{}_>", "<{}__1>",
);
const NAMES = fc.constantFrom("SSN_1", "PERSON_1", "EMAIL_1", "SSN_99", "PERSON_0", "Person 1", "person_1");

const newMap = () => new PlaceholderMap({ restoreInUrls: true });

function prop<T extends unknown[]>(
  arbs: { [K in keyof T]: fc.Arbitrary<T[K]> },
  check: (...args: T) => void,
  examples: T[] = [],
) {
  fc.assert(
    fc.property(...(arbs as unknown as [fc.Arbitrary<unknown>]), check as (...a: unknown[]) => void),
    { numRuns: RUNS, examples: examples as unknown as [unknown][] },
  );
}

/**
 * A detected value (6+ chars) must not be in the output, unless the same
 * string is also somewhere in the text outside every detected span.
 */
function checkNoLeak(text: string, dets: readonly Detection[], out: string) {
  const rest = text.split("");
  for (const d of dets) for (let i = d.start; i < d.end; i++) rest[i] = "\0";
  const outside = rest.join("");
  for (const d of dets) {
    const v = text.slice(d.start, d.end).trim();
    if (v.length >= 6 && !outside.includes(v)) {
      expect(out.includes(v), JSON.stringify({ text, v, out })).toBe(false);
    }
  }
}

describe("fuzz: detection, redaction and restore", () => {
  it(
    "detection never throws and every span fits",
    () => {
      prop([TEXT], (text) => {
        for (const d of detectText(text)) {
          expect(0 <= d.start && d.start < d.end && d.end <= text.length, JSON.stringify({ text, d })).toBe(true);
        }
      });
    },
    TIMEOUT,
  );

  it(
    "redact then restore gives back the text, and no value leaks",
    () => {
      prop(
        [TEXT],
        (text) => {
          const m = newMap();
          const dets = detectText(text);
          const out = redactText(text, dets, "llm", { placeholders: m });
          checkNoLeak(text, dets, out);
          expect(m.restoreText(out), JSON.stringify({ text, out })).toBe(text);
        },
        // Found by the Python version: "PERSON_1" glued to a token was not
        // reserved, so the name earlier in the text also got <PERSON_1>.
        // The TS detector finds a name only with context, so the email
        // example is the one that shows it here.
        [["Maria Garcia PERSON_1" + GH_TOKEN], ["maria.garcia@example.com EMAIL_1" + GH_TOKEN]],
      );
    },
    TIMEOUT,
  );

  it(
    "redactPayload then restore gives back the payload",
    () => {
      prop([TEXT, TEXT], (a, b) => {
        // One map over two strings: a value found in one is also redacted in
        // the other (findKnown), as in a conversation.
        const m = newMap();
        const doc = { a, list: [b, a] };
        const out = redactPayload(doc, "llm", { placeholders: m });
        expect(m.restore(out), JSON.stringify({ doc, out })).toEqual(doc);
      });
    },
    TIMEOUT,
  );

  it(
    "StreamRestorer matches restoreText wherever the stream is cut",
    () => {
      prop([TEXT, fc.array(fc.nat(200), { maxLength: 6 })], (text, rawCuts) => {
        const m = newMap();
        const out = redactText(text, detectText(text), "llm", { placeholders: m });
        // The TS port has no spaced mode: restoreText is the Python
        // restore_text(spaced=False) that the Python stream uses too.
        const want = m.restoreText(out);
        const cuts = [...new Set(rawCuts.map((c) => c % (out.length + 1)))].sort((a, b) => a - b);
        const pieces: string[] = [];
        let prev = 0;
        for (const c of [...cuts, out.length]) {
          pieces.push(out.slice(prev, c));
          prev = c;
        }
        const r = new StreamRestorer(m);
        const got = pieces.map((p) => r.push(p)).join("") + r.flush();
        expect(got, JSON.stringify({ text, out, pieces })).toBe(want);
      });
    },
    TIMEOUT,
  );

  it(
    "restoring arbitrary or mangled model output never throws",
    () => {
      prop([TEXT, fc.array(fc.tuple(MANGLE, NAMES), { maxLength: 6 }), NOISE], (text, forms, tail) => {
        const m = newMap();
        redactText(text, detectText(text), "llm", { placeholders: m });
        const model = text + forms.map(([f, n]) => f.replace("{}", n)).join("") + tail;
        m.restoreText(model);
        m.restoreJsonFragment(JSON.stringify(model));
        m.restore({ a: [model, { b: model }] });
        m.diagnose(model);
        const doc = JSON.stringify({ x: model });
        const r = new StreamRestorer(m, "json");
        r.push(doc.slice(0, 7));
        r.push(doc.slice(7));
        r.flush();
      });
    },
    TIMEOUT,
  );

  it(
    "a redacted JSON document restores to an equal document",
    () => {
      prop([TEXT], (text) => {
        const m = newMap();
        const doc = JSON.stringify({ q: text, list: [text] });
        const out = redactText(doc, detectText(doc), "llm", { placeholders: m });
        try {
          JSON.parse(out);
        } catch {
          return; // redacting a JSON string does not promise to keep it JSON
        }
        const back = m.restoreText(out);
        expect(JSON.parse(back), JSON.stringify({ doc, out, back })).toEqual(JSON.parse(doc));
      });
    },
    TIMEOUT,
  );

  it(
    "maskText hides every detected value",
    () => {
      prop([TEXT], (text) => {
        const dets = detectText(text);
        checkNoLeak(text, dets, maskText(text, dets));
      });
    },
    TIMEOUT,
  );
});
