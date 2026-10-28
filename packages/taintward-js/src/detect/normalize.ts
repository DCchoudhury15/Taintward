// Text normalization before detection.
//
// Fullwidth digits and other compatibility characters are folded with NFKC,
// and zero-width characters are removed, so "２３４-１２-１２３４" or an SSN with
// an invisible character between its digits is still found. Offsets found in
// the normalized text are mapped back to the original text.

const ZERO_WIDTH = new Set(["​", "‌", "‍", "⁠", "﻿"]);

// eslint-disable-next-line no-control-regex
const ASCII_ONLY = /^[\x00-\x7f]*$/;

export interface Normalized {
  /** The text the recognizers run on. */
  text: string;
  /**
   * For each UTF-16 unit of `text`: the start and end (exclusive) of the
   * original character it came from. Null when the text was plain ASCII
   * (offsets are the same).
   */
  starts: number[] | null;
  ends: number[] | null;
}

export function normalizeForDetection(text: string): Normalized {
  if (ASCII_ONLY.test(text)) return { text, starts: null, ends: null };
  const out: string[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let i = 0;
  for (const ch of text) {
    const len = ch.length;
    if (!ZERO_WIDTH.has(ch)) {
      // Each character is folded on its own, so a character that NFKC
      // expands (the ligature U+FB01 "fi") still maps back to itself.
      const folded = ch.charCodeAt(0) > 127 ? ch.normalize("NFKC") : ch;
      for (let k = 0; k < folded.length; k++) {
        starts.push(i);
        ends.push(i + len);
      }
      out.push(folded);
    }
    i += len;
  }
  return { text: out.join(""), starts, ends };
}
