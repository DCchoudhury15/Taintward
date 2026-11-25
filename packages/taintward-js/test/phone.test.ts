// Phone numbers that needed a context word to be found. "reach me at
// 212-736-5000" and "(212) 736-5000" were missed. The same cases as the
// Python SDK (tests/test_detect_phone.py).

import { describe, expect, it } from "vitest";
import { detectText } from "../src/detect/index.js";

const phones = (text: string) =>
  detectText(text)
    .filter((d) => d.entityType === "PHONE_NUMBER")
    .map((d) => text.slice(d.start, d.end));

describe("phone numbers", () => {
  it.each([
    ["reach me at 212-736-5000", "212-736-5000"],
    ["(212) 736-5000 anytime", "(212) 736-5000"],
    ["212.736.5000", "212.736.5000"],
    ["1-212-736-5000", "1-212-736-5000"],
    ["order 212-736-5000 shipped", "212-736-5000"],
    ["dial 0151 23456789", "0151 23456789"],
    ["reach me on 030 1234567", "030 1234567"],
  ])("finds %s", (text, want) => {
    expect(phones(text)).toEqual([want]);
  });

  it.each([
    ["212-736.5000"],
    ["112-736-5000"],
    ["ver 212.736.5000.1"],
    ["x/212-736-5000"],
    ["id 2024-01-1234"],
    ["between 2019-2020 and 3-5 items"],
    ["ssn 234-12-1234"],
  ])("leaves %s alone", (text) => {
    expect(phones(text)).toEqual([]);
  });
});
