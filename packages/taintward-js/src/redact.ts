// Destination-aware redaction.
//
// The same sensitive value is treated differently depending on where it is
// going:
//
//   external / log / rag -> one-way mask [PII] / [SECRET]
//   llm                  -> placeholder <SSN_1> when a PlaceholderMap is
//                           given, else the mask
//   internal             -> the mask by default, or the raw value with
//                           internal: "raw"
//
// The Python SDK gives internal sinks a reversible FF1 token. That is not in
// this version of the TypeScript SDK yet.

import {
  MASK_TOKEN,
  collectLeaves,
  detectPayload,
  detectText,
  isWalkableObject,
  leafText,
  type Detection,
  type Sensitivity,
} from "./detect/index.js";
import { DEST_INTERNAL, DEST_LLM } from "./destinations.js";
import type { KnownSpan, PlaceholderMap } from "./placeholders.js";

export type InternalMode = "mask" | "raw";

export interface RedactOptions {
  /** For the llm destination: placeholders instead of masks. For every
   * destination: values the map knows are redacted even when not detected. */
  placeholders?: PlaceholderMap | undefined;
  /** What an internal sink gets: "mask" (default) or "raw". */
  internal?: InternalMode | undefined;
}

type Span = Detection | KnownSpan;

/** Redact one value for a destination. */
export function redactValue(value: string, sensitivity: Sensitivity, destination: string, opts: RedactOptions = {}): string {
  if (!value) return value;
  if (destination === DEST_INTERNAL && opts.internal === "raw") return value;
  return MASK_TOKEN[sensitivity] ?? "[REDACTED]";
}

/**
 * Apply redaction to the given spans of `text`. Overlapping spans keep the
 * longest; for equal length a secret wins over PII, then the higher score.
 */
export function redactText(text: string, spans: readonly Span[], destination: string, opts: RedactOptions = {}): string {
  if (!text) return text;
  const sorted = [...spans].sort(
    (a, b) =>
      a.start - b.start ||
      b.end - b.start - (a.end - a.start) ||
      Number(a.sensitivity !== "secret") - Number(b.sensitivity !== "secret") ||
      b.score - a.score,
  );
  const kept: Span[] = [];
  for (const d of sorted) {
    if (kept.length > 0 && d.start < kept[kept.length - 1]!.end) continue;
    kept.push(d);
  }
  let out = text;
  for (const d of kept.reverse()) {
    const original = text.slice(d.start, d.end);
    const redacted =
      opts.placeholders && destination === DEST_LLM
        ? opts.placeholders.placeholderFor(original, d.entityType, d.sensitivity)
        : redactValue(original, d.sensitivity, destination, opts);
    out = out.slice(0, d.start) + redacted + out.slice(d.end);
  }
  return out;
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
  const found = detectPayload(value);
  return walk(value, destination, opts, found, 0) as T;
}

/** Mask a payload (for span attributes): [PII] / [SECRET] everywhere. */
export function maskPayload<T>(value: T): T {
  return redactPayload(value, "log");
}

export { collectLeaves };
