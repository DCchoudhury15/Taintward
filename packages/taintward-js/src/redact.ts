// Destination-aware redaction.
//
// The same sensitive value is treated differently depending on where it is
// going:
//
//   external / log / rag -> one-way mask [PII] / [SECRET]
//   llm                  -> placeholder <SSN_1> when a PlaceholderMap is
//                           given, else the mask
//   internal             -> the mask by default, a reversible FF1 token
//                           with internal: "token" (the same token as the
//                           Python SDK for the same key), or the raw value
//                           with internal: "raw"

import {
  MASK_TOKEN,
  collectLeaves,
  detectPayload,
  detectText,
  isWalkableObject,
  isWholeValue,
  leafText,
  type Detection,
  type Sensitivity,
} from "./detect/index.js";
import { DEST_INTERNAL, DEST_LLM } from "./destinations.js";
import type { KnownSpan, PlaceholderMap } from "./placeholders.js";
import { Tokenizer } from "./tokens.js";

export type InternalMode = "mask" | "raw" | "token";

export interface RedactOptions {
  /** For the llm destination: placeholders instead of masks. For every
   * destination: values the map knows are redacted even when not detected. */
  placeholders?: PlaceholderMap | undefined;
  /**
   * What an internal sink gets: "mask" (default), "token" (a reversible FF1
   * token, see `Tokenizer`) or "raw".
   */
  internal?: InternalMode | undefined;
  /** The tokenizer for internal: "token". Default: one keyed by TAINTWARD_FPE_KEY. */
  tokenizer?: Tokenizer | undefined;
}

let defaultTokenizer: Tokenizer | null = null;

/** The tokenizer keyed by TAINTWARD_FPE_KEY (made on first use). */
export function getTokenizer(): Tokenizer {
  defaultTokenizer ??= new Tokenizer();
  return defaultTokenizer;
}

type Span = Detection | KnownSpan;

/** Redact one value for a destination. */
export function redactValue(value: string, sensitivity: Sensitivity, destination: string, opts: RedactOptions = {}): string {
  if (!value) return value;
  if (destination === DEST_INTERNAL && opts.internal === "raw") return value;
  if (destination === DEST_INTERNAL && opts.internal === "token") {
    const token = (opts.tokenizer ?? getTokenizer()).token(value);
    if (token !== null) return token;
  }
  return MASK_TOKEN[sensitivity] ?? "[REDACTED]";
}

/**
 * Apply redaction to the given spans of `text`. Overlapping spans keep the
 * longest; for equal length a secret wins over PII, then the higher score.
 * Two spans that only partly overlap are redacted together as one value.
 */
export function redactText(text: string, spans: readonly Span[], destination: string, opts: RedactOptions = {}): string {
  if (!text) return text;
  if (opts.placeholders && destination === DEST_LLM) opts.placeholders.reserve(text);
  const sorted = [...spans].sort(
    (a, b) =>
      a.start - b.start ||
      b.end - b.start - (a.end - a.start) ||
      Number(a.sensitivity !== "secret") - Number(b.sensitivity !== "secret") ||
      b.score - a.score,
  );
  // A span that starts inside the previous one is dropped when it also ends
  // inside it. When it reaches past its end, the two are redacted as one
  // value, so no part of either stays.
  const kept: Span[] = [];
  for (const d of sorted) {
    const last = kept[kept.length - 1];
    if (last && d.start < last.end) {
      if (d.end > last.end) {
        const secret = d.sensitivity === "secret" && last.sensitivity !== "secret";
        kept[kept.length - 1] = { ...(secret ? d : last), start: last.start, end: d.end };
      }
      continue;
    }
    kept.push(d);
  }
  const first = text.trimStart()[0];
  const spansOut = text.includes("\\") && (first === "{" || first === "[") ? wholeEscapes(text, kept) : kept;
  let out = text;
  for (const d of spansOut.reverse()) {
    const original = text.slice(d.start, d.end);
    // A value that was not scanned (too large, or a recognizer threw on it)
    // is masked, never passed raw or turned into an FF1 token as a whole.
    const redacted =
      opts.placeholders && destination === DEST_LLM
        ? opts.placeholders.placeholderFor(jsonUnescaped(text, original), d.entityType, d.sensitivity)
        : isWholeValue(d.entityType)
          ? MASK_TOKEN.secret
          : redactValue(original, d.sensitivity, destination, opts);
    out = out.slice(0, d.start) + redacted + out.slice(d.end);
  }
  return out;
}

/**
 * Widen spans of a JSON document so none cuts an escape ("\\n", "\\u00e9")
 * in two. A span ending inside one left a backslash in the value; one
 * starting inside one left "\\<SSN_1>", which is not valid JSON.
 */
function wholeEscapes(text: string, kept: Span[]): Span[] {
  const esc: [number, number][] = [];
  for (const m of text.matchAll(/\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\(?:u[0-9a-fA-F]{4}|[\s\S])/g)) esc.push([m.index!, m.index! + m[0].length]);
  const inside = (pos: number) => {
    let lo = 0;
    let hi = esc.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [a, b] = esc[mid]!;
      if (pos <= a) hi = mid - 1;
      else if (pos >= b) lo = mid + 1;
      else return esc[mid]!;
    }
    return undefined;
  };
  const merged: Span[] = [];
  for (const d of kept) {
    const s = inside(d.start)?.[0] ?? d.start;
    const e = inside(d.end)?.[1] ?? d.end;
    const last = merged[merged.length - 1];
    if (last && s < last.end) {
      const secret = d.sensitivity === "secret" && last.sensitivity !== "secret";
      merged[merged.length - 1] = { ...(secret ? d : last), start: last.start, end: Math.max(last.end, e) };
      continue;
    }
    merged.push({ ...d, start: s, end: e });
  }
  return merged;
}

/**
 * The real value of a span of a JSON document: "12 Main St\\nX" there is
 * "12 Main St" + newline + "X". The placeholder map keeps the real value;
 * restore escapes it again where it writes into JSON. Otherwise the value
 * came back with its escapes doubled.
 */
function jsonUnescaped(text: string, value: string): string {
  const first = text.trimStart()[0];
  if (!value.includes("\\") || (first !== "{" && first !== "[")) return value;
  try {
    JSON.parse(text);
    const real: unknown = JSON.parse(`"${value}"`);
    return typeof real === "string" ? real : value;
  } catch {
    return value; // not JSON, or the span is not inside one JSON string
  }
}

/** Detect and redact one string. `key` is its JSON key (context). */
export function redactString(text: string, destination: string, opts: RedactOptions & { key?: string } = {}): string {
  return redactWithFound(text, detectText(text, { key: opts.key ?? "" }), destination, opts);
}

function redactWithFound(text: string, found: readonly Detection[], destination: string, opts: RedactOptions): string {
  let spans: Span[] = found as Span[];
  if (opts.placeholders) spans = [...spans, ...opts.placeholders.findKnown(text)];
  if (spans.length === 0) return text;
  return redactText(text, spans, destination, opts);
}

function uniqueKey(used: Set<string>, k: string): string {
  if (!used.has(k)) return k;
  let n = 2;
  while (used.has(`${k}_${n}`)) n++;
  return `${k}_${n}`;
}

function walk(value: unknown, destination: string, opts: RedactOptions, found: Map<string, Detection[]>, depth: number): unknown {
  if (depth > 64) return value;
  const leaf = (s: string) => redactWithFound(s, found.get(s) ?? detectText(s), destination, opts);
  if (Array.isArray(value)) return value.map((v) => walk(v, destination, opts, found, depth + 1));
  if (value instanceof Set) return new Set([...value].map((v) => walk(v, destination, opts, found, depth + 1)));
  if (value instanceof Map) {
    const out = new Map();
    for (const [k, v] of value) out.set(typeof k === "string" ? leaf(k) : k, walk(v, destination, opts, found, depth + 1));
    return out;
  }
  if (isWalkableObject(value)) {
    const entries = Object.entries(value);
    const unchanged = new Set<string>();
    const newKeys = entries.map(([k]) => {
      const nk = leaf(k);
      if (nk === k) unchanged.add(k);
      return nk;
    });
    // A redacted key that clashes with another key gets a suffix:
    // [PII], [PII]_2. Keys that did not change keep their name.
    const used = new Set(unchanged);
    const out: Record<string, unknown> = {};
    entries.forEach(([k, v], i) => {
      let nk = newKeys[i]!;
      if (nk !== k) {
        nk = uniqueKey(used, nk);
        used.add(nk);
      }
      out[nk] = walk(v, destination, opts, found, depth + 1);
    });
    return out;
  }
  if (typeof value === "string") return leaf(value);
  const t = leafText(value);
  if (t !== null) {
    // A sensitive number is replaced by the redacted string.
    const r = leaf(t);
    return r === t ? value : r;
  }
  return value;
}

/**
 * Redact every sensitive value in a JSON-like payload for `destination`.
 * Structure and clean values are kept. JSON keys count as context, so
 * `{ ssn: "536228491" }` is caught, and a value flagged anywhere in the
 * payload is redacted everywhere in it. Object keys are redacted like values.
 */
export function redactPayload<T>(value: T, destination: string, opts: RedactOptions = {}): T {
  // before any value gets a name
  if (opts.placeholders && destination === DEST_LLM) opts.placeholders.reserve(value);
  const found = detectPayload(value);
  return walk(value, destination, opts, found, 0) as T;
}

/** Mask a payload (for span attributes): [PII] / [SECRET] everywhere. */
export function maskPayload<T>(value: T): T {
  return redactPayload(value, "log");
}

export { collectLeaves };
