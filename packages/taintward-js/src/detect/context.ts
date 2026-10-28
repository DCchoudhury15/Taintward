// Context recognizers, ported from taintward/sdk/recognizers_extra.py.
//
// They need the JSON key of a value or a cleaned-up copy of the text, which a
// plain pattern cannot express: a 9-digit SSN without dashes next to an
// "ssn" key or word, digits spaced out one by one, US street addresses, and
// credential-looking values under a key like "api_key".

import { luhnOk, phoneOk, validSsnParts } from "./checks.js";
import { B, W, W_IN, type RawHit } from "./patterns.js";

// Words (in the JSON key, or just before the value) that say "this is an SSN".
const SSN_CONTEXT =
  /(?<![a-z])(?:ssn|ssns|ss#|social[\s_-]*security|tax[\s_-]*id|taxpayer[\s_-]*id)(?![a-z])/iu;
const SSN_CONTEXT_G = new RegExp(SSN_CONTEXT.source, "giu");
const PLAIN_NINE = new RegExp(`(?<![${W_IN}-])([0-9]{3})([0-9]{2})([0-9]{4})(?![${W_IN}-])`, "gu");

// How far back (in characters) a context word is looked for inside the value.
const CONTEXT_WINDOW = 48;

/** Python's pattern.search(text, pos, endpos). */
function searchBetween(re: RegExp, text: string, pos: number, endpos: number): boolean {
  re.lastIndex = Math.max(0, pos);
  const m = re.exec(text.slice(0, endpos));
  return m !== null;
}

/**
 * A 9-digit number with no dashes, only when the key or nearby text says SSN.
 * Without that context a bare 9-digit number is far more likely to be an
 * order id, so it is never flagged on its own.
 */
export function plainSsn(text: string, keyWords: string): RawHit[] {
  const out: RawHit[] = [];
  const keySays = keyWords !== "" && SSN_CONTEXT.test(keyWords);
  for (const m of text.matchAll(PLAIN_NINE)) {
    if (!validSsnParts(m[1]!, m[2]!, m[3]!)) continue;
    const start = m.index;
    if (keySays || searchBetween(SSN_CONTEXT_G, text, start - CONTEXT_WINDOW, start)) {
      out.push({ entityType: "US_SSN", start, end: start + m[0].length, score: 0.6 });
    }
  }
  return out;
}

// Digits written one by one with spaces (and maybe " - ") between them.
const SPACED_HINT = /[0-9] {1,3}[0-9]/u;
const SPACED_RUN = new RegExp(
  `(?<![${W_IN}+])(?:\\+ ?)?[0-9](?:(?: {1,3}- {1,3}| {1,3})[0-9]){8,18}(?!${W})`,
  "gu",
);
const SPACED_SSN = /^([0-9]{3})-([0-9]{2})-([0-9]{4})$/u;
const SPACED_PHONE = /^(?:\+[0-9]{1,3}(?: [0-9]{1,5}){1,4}|[0-9]{3}-[0-9]{3}-[0-9]{4})$/u;

function collapseSpaced(run: string): string {
  return run
    .replace(/ {1,3}- {1,3}/g, "-")
    .replace(/ {2,}/g, "\x00") // a wide gap stays a (single) space
    .replace(/ /g, "")
    .replace(/\x00/g, " ");
}

/**
 * An SSN, card or phone number typed with a space between every digit. The
 * run is collapsed and only accepted when the result passes a real check.
 */
export function spacedDigits(text: string, keyWords: string): RawHit[] {
  if (!SPACED_HINT.test(text)) return [];
  const out: RawHit[] = [];
  for (const m of text.matchAll(SPACED_RUN)) {
    const start = m.index;
    const end = start + m[0].length;
    const flat = collapseSpaced(m[0]);
    const ssn = SPACED_SSN.exec(flat);
    const digits = flat.replace(/[^0-9]/g, "");
    if (ssn && validSsnParts(ssn[1]!, ssn[2]!, ssn[3]!)) {
      out.push({ entityType: "US_SSN", start, end, score: 0.6 });
    } else if (/^[0-9]+$/.test(flat) && flat.length >= 13 && flat.length <= 19 && luhnOk(flat)) {
      out.push({ entityType: "CREDIT_CARD", start, end, score: 0.6 });
    } else if (SPACED_PHONE.test(flat) && phoneOk(flat)) {
      out.push({ entityType: "PHONE_NUMBER", start, end, score: 0.6 });
    } else if (
      digits.length === 9 &&
      plainSsn(digits, keyWords || text.slice(0, start).slice(-CONTEXT_WINDOW)).length > 0
    ) {
      out.push({ entityType: "US_SSN", start, end, score: 0.6 });
    }
  }
  return out;
}

const STREET_SUFFIX =
  "(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Way|Ct|" +
  "Court|Pl|Place|Ter|Terrace|Pkwy|Parkway|Hwy|Highway|Cir|Circle|Sq|Square)";
const STREET = new RegExp(
  `${B}[0-9]{1,6}(?: [A-Z][a-zA-Z]+){1,4} ${STREET_SUFFIX}${B}\\.?` +
    `(?:,? (?:Apt|Suite|Unit|Ste)\\.? ?#?${W}+)?` +
    `(?:, [A-Z][a-zA-Z]+(?: [A-Z][a-zA-Z]+){0,2})?` +
    `(?:, [A-Z]{2})?` +
    `(?: [0-9]{5}(?:-[0-9]{4})?)?`,
  "gu",
);
const STREET_HINT = /[0-9] [A-Z]/u;

/**
 * US-style street address: number, capitalized street name, street type,
 * then optional unit, city, state and ZIP. Case sensitive on purpose.
 */
export function streetAddress(text: string): RawHit[] {
  if (!STREET_HINT.test(text)) return [];
  const out: RawHit[] = [];
  for (const m of text.matchAll(STREET)) {
    if (m[0].length === 0) continue;
    out.push({ entityType: "STREET_ADDRESS", start: m.index, end: m.index + m[0].length, score: 0.7 });
  }
  return out;
}

// A key whose value is a credential no matter what it looks like.
export const SECRET_KEY =
  /(?:api[\s_-]?key|apikey|secret|passwd|password|pwd|private[\s_-]?key|credential|access[\s_-]?key|auth[\s_-]?token|access[\s_-]?token|refresh[\s_-]?token|bearer|(?<![a-z])token(?![a-z]))/iu;
const CREDENTIAL_SHAPE = /^[A-Za-z0-9_\-+/=.~:]{16,}$/u;
const PASSWORD_KEY = /passw(?:or)?d|(?<![a-z])pwd(?![a-z])/iu;

// Python's str.strip() whitespace set.
const PY_SPACE = "\\s\\x1c-\\x1f\\x85";
const STRIP_RE = new RegExp(`^[${PY_SPACE}]+|[${PY_SPACE}]+$`, "gu");

/**
 * A value stored under a key such as "api_key", "client_secret" or
 * "password". The key is the evidence; the value only has to look like a
 * credential (16+ token characters with letters and digits). Passwords are
 * flagged whatever their shape, as long as they are a single word.
 */
export function keyedSecret(text: string, keyWords: string): RawHit[] {
  if (!keyWords || !SECRET_KEY.test(keyWords)) return [];
  const value = text.replace(STRIP_RE, "");
  if (!value) return [];
  const start = text.indexOf(value);
  const end = start + value.length;
  const chars = [...value];
  if (PASSWORD_KEY.test(keyWords) && !value.includes(" ") && chars.length >= 4 && new Set(chars).size > 2) {
    return [{ entityType: "GENERIC_API_KEY", start, end, score: 0.6 }];
  }
  if (CREDENTIAL_SHAPE.test(value) && /[0-9]/.test(value) && /[A-Za-z]/.test(value)) {
    return [{ entityType: "GENERIC_API_KEY", start, end, score: 0.6 }];
  }
  return [];
}

export const CONTEXT_RECOGNIZERS: ReadonlyArray<(text: string, key: string) => RawHit[]> = [
  plainSsn,
  spacedDigits,
  (t) => streetAddress(t),
  keyedSecret,
];
