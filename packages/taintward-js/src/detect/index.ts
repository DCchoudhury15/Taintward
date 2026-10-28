// Sensitive-data detection: regexes and checksums, no NER.
//
// A port of the pattern and context recognizers of the Python SDK
// (taintward/sdk/detect.py). Person names and places need named-entity
// recognition, which only the Python SDK and the gateway do for now.

import { createHash } from "node:crypto";
import { CONTEXT_RECOGNIZERS } from "./context.js";
import { normalizeForDetection, type Normalized } from "./normalize.js";
import { EXACT_SECRET_TYPES, PATTERN_RECOGNIZERS, SECRET_TYPES, type RawHit } from "./patterns.js";

export type Sensitivity = "pii" | "secret";

/** One detected sensitive span. Offsets are UTF-16 indexes into the text. */
export interface Detection {
  entityType: string;
  start: number;
  end: number;
  score: number;
  sensitivity: Sensitivity;
  /** First 8 hex chars of sha256(value). Never the value itself. */
  fingerprint: string;
}

export const THRESHOLD = 0.5;

const CONTEXT_WORD = /[A-Za-z][A-Za-z0-9#]*/g;
const KEY_SPLIT = /[^A-Za-z0-9#]+/;
const CONTEXT_CHARS = 64;
const CONTEXT_WORDS = 5;
const CONTEXT_BOOST = 0.35;
const CONTEXT_MIN = 0.4;

// Never part of a sensitive value but can end up on the edge of a span.
const SPAN_EDGE_TRIM = new Set(["'", '"', "`", " ", "\t", "\r", "\n"]);

/** Short, non-reversible sha256 fingerprint of a matched value. */
export function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 8);
}

export function classify(entityType: string): Sensitivity {
  return SECRET_TYPES.has(entityType) ? "secret" : "pii";
}

interface Hit extends RawHit {
  context: readonly string[];
}

function contextHit(norm: string, key: string, start: number, ctx: readonly string[]): boolean {
  const window = norm.slice(Math.max(0, start - CONTEXT_CHARS), start);
  const words = (window.match(CONTEXT_WORD) ?? []).slice(-CONTEXT_WORDS).map((w) => w.toLowerCase());
  if (key) {
    for (const w of key.split(KEY_SPLIT)) if (w) words.push(w.toLowerCase());
    words.push(key.toLowerCase());
  }
  if (words.length === 0) return false;
  return ctx.some((c) => words.some((w) => w.includes(c)));
}

/**
 * Drop a hit that sits inside another hit of the same type with an equal or
 * higher score (what Presidio's remove_duplicates does).
 */
function dedupe(results: RawHit[]): RawHit[] {
  const byType = new Map<string, RawHit[]>();
  for (const r of results) {
    if (!byType.has(r.entityType)) byType.set(r.entityType, []);
    byType.get(r.entityType)!.push(r);
  }
  const out: RawHit[] = [];
  for (const items of byType.values()) {
    items.sort((x, y) => x.start - y.start || y.end - x.end || y.score - x.score);
    let bestEnd = -1;
    let bestScore = -1;
    let last: RawHit | null = null;
    for (const r of items) {
      if (last && r.start === last.start && r.end === last.end) continue;
      if (r.end <= bestEnd && r.score <= bestScore) continue;
      out.push(r);
      last = r;
      if (r.end > bestEnd || (r.end === bestEnd && r.score > bestScore)) {
        bestEnd = r.end;
        bestScore = r.score;
      }
    }
  }
  return out;
}

function finish(text: string, n: Normalized, key: string, hits: Hit[], threshold: number): Detection[] {
  const scored: RawHit[] = [];
  for (const h of hits) {
    let score = h.score;
    if (score < threshold && h.context.length > 0 && contextHit(n.text, key, h.start, h.context)) {
      score = Math.min(1.0, Math.max(score + CONTEXT_BOOST, CONTEXT_MIN));
    }
    if (score >= threshold && h.end > h.start) scored.push({ ...h, score });
  }
  let kept = dedupe(scored);
  // A JWT / GitHub / AWS / private-key hit is more exact than the generic
  // "api_key=..." rule firing on the same characters; keep only the exact one.
  const exact = kept.filter((r) => EXACT_SECRET_TYPES.has(r.entityType));
  if (exact.length > 0) {
    kept = kept.filter(
      (r) => r.entityType !== "GENERIC_API_KEY" || !exact.some((e) => r.start < e.end && e.start < r.end),
    );
  }
  const out: Detection[] = [];
  for (const r of kept) {
    let start: number;
    let end: number;
    if (n.starts === null || n.ends === null) {
      start = r.start;
      end = r.end;
    } else {
      start = r.start < n.starts.length ? n.starts[r.start]! : text.length;
      end = r.end - 1 < n.ends.length ? n.ends[r.end - 1]! : start;
    }
    while (start < end && SPAN_EDGE_TRIM.has(text[start]!)) start++;
    while (end > start && SPAN_EDGE_TRIM.has(text[end - 1]!)) end--;
    if (start === end) continue;
    out.push({
      entityType: r.entityType,
      start,
      end,
      score: r.score,
      sensitivity: classify(r.entityType),
      fingerprint: fingerprint(text.slice(start, end)),
    });
  }
  out.sort((a, b) => a.start - b.start || a.end - b.end);
  return out;
}

export interface DetectOptions {
  /** JSON key the value sits under. It counts as context ("ssn", "api_key"). */
  key?: string;
  threshold?: number;
}

/** Detect sensitive spans in `text`. Never throws; returns [] on error. */
export function detectText(text: string, opts: DetectOptions = {}): Detection[] {
  if (typeof text !== "string" || text.length === 0) return [];
  const key = opts.key ?? "";
  const threshold = opts.threshold ?? THRESHOLD;
  try {
    const n = normalizeForDetection(text);
    const hits: Hit[] = [];
    for (const rec of PATTERN_RECOGNIZERS) {
      for (const h of rec.find(n.text)) hits.push({ ...h, context: rec.context });
    }
    for (const fn of CONTEXT_RECOGNIZERS) {
      for (const h of fn(n.text, key)) hits.push({ ...h, context: [] });
    }
    return finish(text, n, key, hits, threshold);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Payload walking
// ---------------------------------------------------------------------------

/** A plain object or a class instance that should be walked by its fields. */
export function isWalkableObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object") return false;
  if (Array.isArray(v) || v instanceof Map || v instanceof Set) return false;
  if (v instanceof Date || v instanceof RegExp || ArrayBuffer.isView(v) || v instanceof ArrayBuffer) return false;
  return true;
}

/** Text form of a non-container leaf, or null when it is never sensitive. */
export function leafText(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "bigint") return String(v);
  return null;
}

/**
 * Every string-like leaf of a JSON-like payload with the key it sits under.
 * Object keys are leaves too (with the parent key as context). Array items
 * inherit the array's key.
 */
export function collectLeaves(payload: unknown, key = "", out: Array<[string, string]> = [], depth = 0): Array<[string, string]> {
  if (depth > 64) return out;
  if (Array.isArray(payload) || payload instanceof Set) {
    for (const v of payload) collectLeaves(v, key, out, depth + 1);
  } else if (payload instanceof Map) {
    for (const [k, v] of payload) {
      const ks = leafText(k);
      if (ks) out.push([ks, key]);
      collectLeaves(v, ks ?? "", out, depth + 1);
    }
  } else if (isWalkableObject(payload)) {
    for (const [k, v] of Object.entries(payload)) {
      if (k) out.push([k, key]);
      collectLeaves(v, k, out, depth + 1);
    }
  } else {
    const t = leafText(payload);
    if (t) out.push([t, key]);
  }
  return out;
}

/**
 * Detect in every leaf of a payload in one pass. The result maps each leaf
 * string to the union of what was found for it under any key, so a value
 * that is flagged once (a 9-digit number under "ssn") is treated as
 * sensitive everywhere in the payload.
 */
export function detectPayload(payload: unknown): Map<string, Detection[]> {
  const found = new Map<string, Detection[]>();
  const seenPairs = new Set<string>();
  for (const [text, key] of collectLeaves(payload)) {
    const pair = key + "\u0000" + text;
    if (seenPairs.has(pair)) continue;
    seenPairs.add(pair);
    const dets = detectText(text, { key });
    const prev = found.get(text);
    if (!prev) {
      found.set(text, dets);
    } else if (dets.length > 0) {
      const have = new Set(prev.map((d) => `${d.entityType}:${d.start}:${d.end}`));
      for (const d of dets) if (!have.has(`${d.entityType}:${d.start}:${d.end}`)) prev.push(d);
    }
  }
  return found;
}

/** All detections in a payload (flat list). */
export function detectAll(payload: unknown): Detection[] {
  const out: Detection[] = [];
  for (const dets of detectPayload(payload).values()) out.push(...dets);
  return out;
}

export const MASK_TOKEN: Record<Sensitivity, string> = { pii: "[PII]", secret: "[SECRET]" };

/** Replace detected spans with [PII] / [SECRET]. Overlaps keep the longest span. */
export function maskText(text: string, detections: readonly Detection[]): string {
  if (!text) return text;
  const sorted = [...detections].sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: Detection[] = [];
  for (const d of sorted) {
    if (kept.length > 0 && d.start < kept[kept.length - 1]!.end) continue;
    kept.push(d);
  }
  let out = text;
  for (const d of kept.reverse()) {
    out = out.slice(0, d.start) + MASK_TOKEN[d.sensitivity] + out.slice(d.end);
  }
  return out;
}

/** Detect and mask one string. */
export function maskString(text: string): string {
  return maskText(text, detectText(text));
}

export { normalizeForDetection } from "./normalize.js";
