// Pattern recognizers, ported from the Python SDK detector
// (taintward/sdk/detect.py, taintward/sdk/recognizers_extra.py and the
// Presidio recognizers it uses for SSN, email, card, IBAN and phone).
//
// The Python side compiles these with the `regex` module, where \w, \b and
// IGNORECASE are Unicode aware. The same is done here with the `u` flag and
// an explicit Unicode word class.

import { Metadata } from "libphonenumber-js/core";
import { findPhoneNumbersInText, type CountryCode, type PhoneNumber } from "libphonenumber-js/max";
import { cardOk, emailDomainOk, ibanCheck, ssnInvalid } from "./checks.js";

/** Characters Python's `regex` module counts as \w. */
export const W_IN = String.raw`\p{Alphabetic}\p{M}\p{Nd}\p{Pc}‌‍`;
export const W = `[${W_IN}]`;
/** Unicode-aware \b. */
export const B = `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`;

export interface RawHit {
  entityType: string;
  start: number;
  end: number;
  score: number;
}

export interface PatternRecognizer {
  entity: string;
  /** Context words that can raise a low score (substring of a nearby word). */
  context: readonly string[];
  find(text: string): RawHit[];
}

interface PatternSpec {
  re: RegExp;
  score: number;
}

function regexRecognizer(
  entity: string,
  patterns: PatternSpec[],
  opts: {
    context?: readonly string[];
    /** true: score 1.0, false: drop. */
    validate?: (m: string) => boolean;
    /** true: drop. */
    invalidate?: (m: string) => boolean;
  } = {},
): PatternRecognizer {
  return {
    entity,
    context: opts.context ?? [],
    find(text) {
      const out: RawHit[] = [];
      for (const p of patterns) {
        p.re.lastIndex = 0;
        for (const m of text.matchAll(p.re)) {
          const start = m.index;
          const cur = m[0];
          if (cur.length === 0) continue;
          let score = p.score;
          if (opts.validate) score = opts.validate(cur) ? 1.0 : 0.0;
          if (opts.invalidate && opts.invalidate(cur)) score = 0.0;
          if (score > 0) out.push({ entityType: entity, start, end: start + cur.length, score });
        }
      }
      return out;
    },
  };
}

// Presidio PatternRecognizer default flags: IGNORECASE (plus DOTALL and
// MULTILINE, which these patterns do not depend on).
const I = "giu";

// --- US SSN -----------------------------------------------------------------
// Presidio's "SSN5 (medium)" pattern. Its other SSN patterns score 0.05 and
// can never reach the 0.5 threshold, even with a context word.
const SSN = regexRecognizer(
  "US_SSN",
  [{ re: new RegExp(`${B}([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})${B}`, I), score: 0.5 }],
  { context: ["social", "security", "ssn", "ssns", "ssid"], invalidate: ssnInvalid },
);

// --- Email --------------------------------------------------------------------
const EMAIL_CH = `!#$%&'*+\\-/=?^_\`{|}~${W_IN}`;
const EMAIL = regexRecognizer(
  "EMAIL_ADDRESS",
  [
    {
      re: new RegExp(
        `${B}((([${EMAIL_CH}])|([${EMAIL_CH}][${EMAIL_CH}.]{0,}[${EMAIL_CH}]))[@]${W}+(?:-+${W}+)*(?:\\.${W}+(?:-+${W}+)*)+)${B}`,
        I,
      ),
      score: 0.5,
    },
  ],
  { context: ["email"], validate: emailDomainOk },
);

// --- Credit card --------------------------------------------------------------
// Issuer prefixes 4 (Visa), 51-55 (Mastercard), 6 (Discover etc.), 3 (Amex,
// Diners, JCB), 1 (UATP). Luhn decides.
const CARD = regexRecognizer(
  "CREDIT_CARD",
  [
    {
      re: new RegExp(
        `${B}(?!1[0-9]{12}(?![0-9]))((4[0-9]{3})|(5[0-5][0-9]{2})|(6[0-9]{3})|(1[0-9]{3})|(3[0-9]{3}))[- ]?([0-9]{3,4})[- ]?([0-9]{3,4})[- ]?([0-9]{3,5})${B}`,
        I,
      ),
      score: 0.3,
    },
  ],
  {
    context: ["credit", "card", "visa", "mastercard", "cc", "amex", "discover", "jcb", "diners", "maestro", "instapayment"],
    validate: cardOk,
  },
);

// --- IBAN -----------------------------------------------------------------------
// Like Presidio, the longest candidate that passes the check wins: the
// whole match, then without the optional tail groups. A lowercase IBAN with
// valid check digits keeps the base score 0.5.
const IBAN_RE =
  /(?<![A-Z0-9])([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,6})((?:[ -]?[A-Z0-9]{4})?)((?:[ -]?[A-Z0-9]{1,3})?)(?![A-Z0-9])/dgiu;

const IBAN: PatternRecognizer = {
  entity: "IBAN_CODE",
  context: ["iban", "bank", "transaction"],
  find(text) {
    const out: RawHit[] = [];
    for (const m of text.matchAll(IBAN_RE)) {
      const start = m.index;
      const idx = m.indices!;
      for (let g = 3; g >= 1; g--) {
        const span = idx[g];
        const end = span && span[1] > 0 ? span[1] : start + m[0].length;
        const cur = text.slice(start, end);
        if (!cur) continue;
        const ok = ibanCheck(cur);
        if (ok !== false) {
          out.push({ entityType: "IBAN_CODE", start, end, score: ok ? 1.0 : 0.5 });
          break;
        }
      }
    }
    return out;
  },
};

// --- Phone ------------------------------------------------------------------------
// libphonenumber (the same metadata as Python's `phonenumbers`), VALID
// leniency, the regions Presidio uses. Score 0.4: a phone number only counts
// with a context word nearby or in the JSON key.
const PHONE_REGIONS: CountryCode[] = ["US", "GB", "DE", "FR", "IL", "IN", "CA", "BR"];
const PHONE_HINT = /(?:[0-9]\D{0,3}){7}/u;

/**
 * The part of libphonenumber's VALID leniency that libphonenumber-js leaves
 * out (Python's `phonenumbers` has it): a number written in national format
 * must carry the national prefix when its country normally writes one. So
 * "536 22 8491" is not a German number, "0536 22 8491" is.
 */
function nationalPrefixPresentIfRequired(num: PhoneNumber, candidate: string): boolean {
  const firstDigit = candidate.search(/[0-9]/);
  if (candidate.slice(0, Math.max(0, firstDigit)).includes("+")) return true; // +49 ...
  const digits = candidate.replace(/[^0-9]/g, "");
  const nsn = num.nationalNumber as string;
  const cc = num.countryCallingCode as string;
  if (digits.endsWith(cc + nsn)) return true; // 49 30 ... or 0049 30 ...
  try {
    const meta = new Metadata((num as unknown as { getMetadata(): never }).getMetadata());
    meta.selectNumberingPlan(cc as never);
    const plan = (meta as unknown as { numberingPlan: NumberingPlan }).numberingPlan;
    const format = plan.formats().find((f) => {
      const lead = f.leadingDigitsPatterns();
      if (lead.length > 0 && nsn.search(new RegExp(lead[lead.length - 1]!)) !== 0) return false;
      return new RegExp(`^(?:${f.pattern()})$`).test(nsn);
    });
    if (!format || !format.nationalPrefixFormattingRule()) return true;
    if (format.nationalPrefixIsOptionalWhenFormattingInNationalFormat()) return true;
    if (!format.usesNationalPrefix()) return true;
    const prefix = plan.nationalPrefixForParsing() || plan.nationalPrefix();
    if (!prefix) return true;
    return new RegExp(`^(?:${prefix})`).test(digits) && digits.length > nsn.length;
  } catch {
    return true;
  }
}

interface PhoneFormat {
  pattern(): string;
  leadingDigitsPatterns(): string[];
  nationalPrefixFormattingRule(): string | undefined;
  nationalPrefixIsOptionalWhenFormattingInNationalFormat(): boolean;
  usesNationalPrefix(): boolean;
}
interface NumberingPlan {
  formats(): PhoneFormat[];
  nationalPrefix(): string | undefined;
  nationalPrefixForParsing(): string | undefined;
}

const PHONE: PatternRecognizer = {
  entity: "PHONE_NUMBER",
  context: [
    "phone", "number", "telephone", "cell", "cellphone", "mobile", "call",
    "tel", "contact", "whatsapp", "fax", "sms",
  ],
  find(text) {
    if (!PHONE_HINT.test(text)) return [];
    const out: RawHit[] = [];
    for (const region of PHONE_REGIONS) {
      let found;
      try {
        found = findPhoneNumbersInText(text, { defaultCountry: region });
      } catch {
        continue;
      }
      for (const f of found) {
        if (!nationalPrefixPresentIfRequired(f.number, text.slice(f.startsAt, f.endsAt))) continue;
        out.push({ entityType: "PHONE_NUMBER", start: f.startsAt, end: f.endsAt, score: 0.4 });
      }
    }
    return out;
  },
};

// --- Secrets ------------------------------------------------------------------------
const SECRET_SPECS: Array<[string, string, number]> = [
  // AKIA = long-lived key, ASIA = temporary (STS) key.
  ["AWS_ACCESS_KEY", `${B}(?:AKIA|ASIA)[0-9A-Z]{16}`, 0.95],
  ["GITHUB_TOKEN", `gh[pousr]_[A-Za-z0-9]{36}`, 0.95],
  // Fine-grained personal access token: github_pat_<22>_<59>.
  ["GITHUB_TOKEN", `github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{40,}`, 0.95],
  ["GENERIC_API_KEY", `(api[_\\-]?key|secret|token)["' :=]{1,4}[A-Za-z0-9_\\-]{20,}`, 0.5],
  // Stripe-style and Slack-style prefixed keys.
  ["GENERIC_API_KEY", `${B}(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`, 0.9],
  ["GENERIC_API_KEY", `${B}xox[abprs]-[A-Za-z0-9\\-]{10,}`, 0.9],
  ["GENERIC_API_KEY", `${B}Bearer\\s+[A-Za-z0-9._~+/=\\-]{20,}`, 0.6],
  // header.payload.signature, base64url; header and payload are JSON objects.
  ["JWT", `${B}eyJ[A-Za-z0-9_\\-]{8,}\\.eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]*`, 0.9],
  // BEGIN line, plus body and END line when present (a truncated key still counts).
  [
    "PRIVATE_KEY",
    `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:[\\s\\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?`,
    0.95,
  ],
];

function secretRecognizers(): PatternRecognizer[] {
  const byType = new Map<string, PatternSpec[]>();
  for (const [etype, src, score] of SECRET_SPECS) {
    if (!byType.has(etype)) byType.set(etype, []);
    byType.get(etype)!.push({ re: new RegExp(src, I), score });
  }
  return [...byType].map(([etype, pats]) => regexRecognizer(etype, pats));
}

export const PATTERN_RECOGNIZERS: readonly PatternRecognizer[] = [
  CARD, SSN, EMAIL, IBAN, PHONE, ...secretRecognizers(),
];

export const SECRET_TYPES: ReadonlySet<string> = new Set([
  "AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY", "JWT", "PRIVATE_KEY",
]);

/** Secret types that are more exact than the generic "api_key=..." rule. */
export const EXACT_SECRET_TYPES: ReadonlySet<string> = new Set([
  "AWS_ACCESS_KEY", "GITHUB_TOKEN", "JWT", "PRIVATE_KEY",
]);
