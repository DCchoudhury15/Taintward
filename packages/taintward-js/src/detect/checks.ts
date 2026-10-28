// Checksums and validity rules used by the recognizers.

import { isValidPhoneNumber } from "libphonenumber-js/max";
import { parse as parseDomain } from "tldts";
import { IBAN_COUNTRY_FORMATS } from "./iban-formats.js";

/** Luhn checksum over a string of ASCII digits. */
export function luhnOk(digits: string): boolean {
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (n < 0 || n > 9) return false;
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    total += n;
  }
  return total % 10 === 0;
}

/** SSA rules for area / group / serial (used by the context recognizers). */
export function validSsnParts(area: string, group: string, serial: string): boolean {
  return !(area === "000" || area === "666" || area[0] === "9" || group === "00" || serial === "0000");
}

/**
 * The checks the Python detector applies to a dashed SSN match
 * ("234-12-1234"). Returns true when the match must be dropped.
 */
export function ssnInvalid(match: string): boolean {
  const delims = new Set<string>();
  for (const c of match) if (c === "." || c === "-" || c === " ") delims.add(c);
  if (delims.size > 1) return true; // mixed delimiters
  const d = match.replace(/[^0-9]/g, "");
  if (d.length === 0) return true;
  if ([...d].every((c) => c === d[0])) return true; // all the same digit
  if (d.slice(3, 5) === "00" || d.slice(5) === "0000") return true;
  if (d.slice(0, 3) === "000" || d.slice(0, 3) === "666") return true;
  if (d === "123456789" || d === "987654320" || d === "078051120") return true; // published samples
  return false;
}

/** Card number check: Luhn over the digits (spaces and dashes removed). */
export function cardOk(match: string): boolean {
  return luhnOk(match.replace(/[- ]/g, ""));
}

function mod97(numeric: string): number {
  let r = 0;
  for (let i = 0; i < numeric.length; i += 7) {
    r = Number(String(r) + numeric.slice(i, i + 7)) % 97;
  }
  return r;
}

const COUNTRY_RE: Record<string, RegExp> = Object.fromEntries(
  Object.entries(IBAN_COUNTRY_FORMATS).map(([k, v]) => [k, new RegExp("^" + v)]),
);

/**
 * IBAN check: mod-97 check digits and the country's format. Returns true
 * (valid), false (invalid) or null (valid only once uppercased).
 */
export function ibanCheck(match: string): boolean | null {
  const v = match.replace(/[- ]/g, "");
  if (v.length < 5) return false;
  const t = (v.slice(0, 2) + "00" + v.slice(4)).toUpperCase();
  const rearranged = t.slice(4) + t.slice(0, 4);
  let numeric = "";
  for (const c of rearranged) {
    const code = c.charCodeAt(0);
    if (code >= 48 && code <= 57) numeric += c;
    else if (code >= 65 && code <= 90) numeric += String(code - 55);
    else return false;
  }
  const check = String(98 - mod97(numeric)).padStart(2, "0");
  if (check !== v.slice(2, 4)) return false;
  if (ibanFormatOk(v)) return true;
  if (ibanFormatOk(v.toUpperCase())) return null;
  return false;
}

function ibanFormatOk(v: string): boolean {
  const re = COUNTRY_RE[v.slice(0, 2)];
  return re !== undefined && re.test(v);
}

/**
 * Email domain check: the part after the last "@" must end in a known
 * public suffix (ICANN section of the Public Suffix List) and have a
 * registrable domain in front of it.
 */
export function emailDomainOk(match: string): boolean {
  const host = match.slice(match.lastIndexOf("@") + 1);
  const r = parseDomain(host);
  return Boolean(r.domain) && r.isIcann === true && !r.isIp;
}

/** A US-style phone check used for digits written one by one. */
export function phoneOk(candidate: string): boolean {
  try {
    return isValidPhoneNumber(candidate, "US");
  } catch {
    return false;
  }
}
