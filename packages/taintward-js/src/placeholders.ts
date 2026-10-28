// Consistent placeholders for the LLM, and restore on the way back.
//
// Every sensitive value sent to the LLM is replaced by a typed, numbered,
// stable placeholder:
//
//   "234-12-1234"          -> <SSN_1>
//   "AKIAIOSFODNN7EXAMPLE" -> <AWS_KEY_1>
//   "bob@example.com"      -> <EMAIL_1>
//
// Within one map the same value always gets the same placeholder, so the
// model can still tell values apart. The model answers with placeholders and
// they are swapped back for the caller. The map lives in memory only.
//
// Port of taintward/sdk/placeholders.py (without the vault backend).

import type { Sensitivity } from "./detect/index.js";

/** <PERSON_1>, < PERSON_1 >, <person_1>, &lt;PERSON_1&gt; (HTML-escaped). */
export const PLACEHOLDER_SOURCE = String.raw`(?:<|&lt;)\s*([A-Za-z][A-Za-z0-9_]*?)_(\d{1,6})\s*(?:>|&gt;)`;
const PLACEHOLDER_G = new RegExp(PLACEHOLDER_SOURCE, "g");
const PLACEHOLDER_FULL = new RegExp(`^${PLACEHOLDER_SOURCE}$`);
const PLACEHOLDER_ANY = new RegExp(PLACEHOLDER_SOURCE);

// Tolerant restore: forms real models write instead of <PERSON_1> (measured
// for the Python SDK, see docs/placeholders-eval.md):
//
//   bracketed  [PERSON_1] {PERSON_1} {{PERSON_1}} (PERSON_1) <Person 1>
//              <PERSON-1> \<PERSON\_1\> «PERSON_1» ＜PERSON_1＞ 【PERSON_1】
//   bare       PERSON_1, Person_1, PERSON\_1 (markdown escaped)
//
// A form is restored only when it names a placeholder that is in this map,
// so text like "[Step 1]" is never touched. The Python SDK also restores
// "Person 1" when that is unambiguous; this port does not.
const WORD = String.raw`[^\P{L}][\p{L}\p{N}]*`;
const SEP = String.raw`(?:\\?[_＿]|[ \-])`;
const OPEN = String.raw`\\?(?:<|&lt;|\{\{|\[\[|\[|\{|\(|«|‹|〈|《|＜|【|「|『)`;
const CLOSE = String.raw`\\?(?:>|&gt;|\}\}|\]\]|\]|\}|\)|»|›|〉|》|＞|】|」|』)`;
const TOLERANT_SOURCE =
  String.raw`(?<exact>(?:<|&lt;)\s*(?<elabel>[A-Za-z][A-Za-z0-9_]*?)_(?<enum>\d{1,6})\s*(?:>|&gt;))` +
  String.raw`|(?<open>${OPEN})[ \t]*(?<blabel>${WORD}(?:${SEP}${WORD})*?)${SEP}?(?<bnum>\d{1,6})[ \t]*${CLOSE}` +
  String.raw`|(?<![\p{L}\p{N}_\\])(?<ulabel>${WORD}(?:\\?[_＿]${WORD})*?)\\?[_＿](?<unum>\d{1,6})(?![\p{L}\p{N}_])`;
const TOLERANT_G = new RegExp(TOLERANT_SOURCE, "gu");
const TOLERANT_ANY = new RegExp(TOLERANT_SOURCE, "u");
/** <PERSON> with no number: the model dropped the number (never restored). */
const NUMBERLESS_G = /(?:<|&lt;|\[)\s*([A-Za-z][A-Za-z_]*)\s*(?:>|&gt;|\])/g;

/** Other names models use for a label, mostly from translating it. */
const ALIASES: Record<string, string> = {
  NAME: "PERSON", PERSONA: "PERSON", PERSONNE: "PERSON", PERSONE: "PERSON",
  PERSOON: "PERSON", NOMBRE: "PERSON", NOM: "PERSON",
  MAIL: "EMAIL", E_MAIL: "EMAIL", CORREO: "EMAIL", COURRIEL: "EMAIL",
  TELEFONO: "PHONE", TELEFON: "PHONE", TELEPHONE: "PHONE", TEL: "PHONE",
  SOZIALVERSICHERUNGSNUMMER: "SSN",
  TARJETA: "CARD", CARTE: "CARD", KARTE: "CARD", CREDIT_CARD: "CARD",
  名前: "PERSON", 氏名: "PERSON", 姓名: "PERSON", 名字: "PERSON", 人物: "PERSON",
  メールアドレス: "EMAIL", メール: "EMAIL", 电子邮件: "EMAIL", 邮箱: "EMAIL",
  電話番号: "PHONE", 电话: "PHONE", 电话号码: "PHONE",
};

/** Detector entity type -> short placeholder label. */
const LABELS: Record<string, string> = {
  PERSON: "PERSON",
  US_SSN: "SSN",
  USA_SSN: "SSN",
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  AWS_ACCESS_KEY: "AWS_KEY",
  GITHUB_TOKEN: "GITHUB_TOKEN",
  GENERIC_API_KEY: "API_KEY",
  CREDIT_CARD: "CARD",
  IBAN_CODE: "IBAN",
  IP_ADDRESS: "IP",
  US_BANK_NUMBER: "BANK_ACCOUNT",
  US_DRIVER_LICENSE: "DRIVER_LICENSE",
  US_PASSPORT: "PASSPORT",
  LOCATION: "LOCATION",
  DATE_TIME: "DATE",
  URL: "URL",
  ORGANIZATION: "ORG",
  IN_AADHAAR: "AADHAAR",
  IN_PAN: "PAN",
};

// Labels that look like Taintward placeholders even when this map does not
// have them: an unknown <PHONE_1> is worth a warning, an unknown [Step 1] is not.
const VOCAB: ReadonlySet<string> = new Set([...Object.values(LABELS), ...Object.keys(ALIASES), "SECRET", "PII"]);

/** What a model answer holds besides exact placeholders (forms, never values). */
export interface RestoreReport {
  /** Rewritten forms that were still restored, e.g. [PERSON_1]. */
  repaired: string[];
  /** Forms that point at a known placeholder but are not safe to restore. */
  lost: string[];
  /** Placeholders that are not in the map, e.g. an invented <PERSON_3>. */
  unknown: string[];
}

type Kind = "exact" | "repaired" | "lost" | "unknown" | "ignore";

/** 'Aws key', 'AWS\\_KEY', full-width 'ＰＥＲＳＯＮ' -> 'AWS_KEY' / 'PERSON'. */
function normLabel(raw: string): string {
  return raw.normalize("NFKC").toUpperCase().replace(/[\s\-\\_]+/g, "_").replace(/^_+|_+$/g, "");
}

function isTitle(raw: string): boolean {
  return /^\p{Lu}[\p{Ll}\p{N}]*(?:[ _]\p{Lu}[\p{Ll}\p{N}]*)*$/u.test(raw);
}

// Known values shorter than this are not force-redacted by findKnown: a two
// letter value would match inside too many unrelated words.
const MIN_KNOWN_LEN = 3;

/** Placeholder label for a detector entity type, e.g. US_SSN -> SSN. */
export function labelFor(entityType: string | undefined, sensitivity: Sensitivity): string {
  if (entityType && LABELS[entityType]) return LABELS[entityType]!;
  if (entityType) {
    const safe = entityType.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    if (safe) return safe;
  }
  return sensitivity === "secret" ? "SECRET" : "PII";
}

/** A detection-shaped span for a value the map already knows. */
export interface KnownSpan {
  entityType: string;
  start: number;
  end: number;
  score: number;
  sensitivity: Sensitivity;
}

interface Entry {
  value: string;
  entityType: string;
  sensitivity: Sensitivity;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function canonical(label: string, num: string): string {
  return `<${label.toUpperCase()}_${parseInt(num, 10)}>`;
}

/** Placeholder <-> real value map for one run (one conversation). */
export class PlaceholderMap {
  private byValue = new Map<string, string>();
  private byPlaceholder = new Map<string, Entry>();
  private counts = new Map<string, number>();
  private knownRe: RegExp | null = null;

  /** The stable placeholder for `value`; a new one if it is unseen. */
  placeholderFor(value: string, entityType?: string, sensitivity: Sensitivity = "pii"): string {
    const have = this.byValue.get(value);
    if (have !== undefined) return have;
    const label = labelFor(entityType, sensitivity);
    let n = (this.counts.get(label) ?? 0) + 1;
    let ph = `<${label}_${n}>`;
    while (this.byPlaceholder.has(ph)) {
      n += 1;
      ph = `<${label}_${n}>`;
    }
    this.counts.set(label, n);
    this.byPlaceholder.set(ph, { value, entityType: entityType ?? "", sensitivity });
    this.byValue.set(value, ph);
    this.knownRe = null;
    return ph;
  }

  /** Real value for a placeholder (any spacing / case variant), or undefined. */
  lookup(placeholder: string): string | undefined {
    const m = PLACEHOLDER_FULL.exec(placeholder.trim());
    if (!m) return undefined;
    return this.byPlaceholder.get(canonical(m[1]!, m[2]!))?.value;
  }

  has(placeholder: string): boolean {
    return this.lookup(placeholder) !== undefined;
  }

  /**
   * Spans of values this map already knows, found by exact match. Used with
   * the detector so a known value is redacted even where the detector would
   * miss it in a new context.
   */
  findKnown(text: string): KnownSpan[] {
    if (!text || this.byValue.size === 0) return [];
    if (this.knownRe === null) {
      const vals = [...this.byValue.keys()].filter((v) => v.length >= MIN_KNOWN_LEN).sort((a, b) => b.length - a.length);
      if (vals.length === 0) return [];
      this.knownRe = new RegExp(`(?<![0-9A-Za-z])(?:${vals.map(escapeRegExp).join("|")})(?![0-9A-Za-z])`, "g");
    }
    const out: KnownSpan[] = [];
    for (const m of text.matchAll(this.knownRe)) {
      const ph = this.byValue.get(m[0]);
      const e = ph ? this.byPlaceholder.get(ph) : undefined;
      if (e) {
        out.push({ entityType: e.entityType, start: m.index, end: m.index + m[0].length, score: 1, sensitivity: e.sensitivity });
      }
    }
    return out;
  }

  /**
   * Swap every known placeholder in `text` for its real value, including the
   * rewritten forms models write ([PERSON_1], PERSON_1). Unknown placeholders
   * stay as they are. A string that is a JSON object or array (tool call
   * arguments) is restored inside the parsed JSON, so a real value with a
   * quote or backslash stays valid JSON, and a "<" escaped as \\u003c (Ollama)
   * is still found.
   */
  restoreText(text: string): string {
    if (typeof text !== "string" || !text) return text;
    const first = text.trimStart()[0];
    if ((first === "{" || first === "[") && (text.includes("\\u003c") || TOLERANT_ANY.test(text))) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
      if (parsed !== null && typeof parsed === "object") {
        const before = JSON.stringify(parsed);
        const after = JSON.stringify(this.restore(parsed));
        return after === before ? text : after;
      }
    }
    return this.replaceForms(text, (v) => v);
  }

  /**
   * Like restoreText, for text that sits inside a JSON string (a streamed
   * piece of tool call arguments): the real value is JSON-escaped.
   */
  restoreJsonFragment(text: string): string {
    return this.replaceForms(text, (v) => JSON.stringify(v).slice(1, -1));
  }

  /** What restoring `text` (a model answer, before restore) will do. */
  diagnose(text: string): RestoreReport {
    const out: RestoreReport = { repaired: [], lost: [], unknown: [] };
    if (typeof text !== "string" || !text) return out;
    for (const m of text.matchAll(TOLERANT_G)) {
      const [, kind] = this.classify(m);
      if (kind === "repaired" || kind === "lost" || kind === "unknown") out[kind].push(m[0].trim());
    }
    const labels = this.labels();
    for (const m of text.matchAll(NUMBERLESS_G)) {
      if (labels.has(normLabel(m[1]!))) out.lost.push(m[0]);
    }
    return out;
  }

  private replaceForms(text: string, encode: (v: string) => string): string {
    if (typeof text !== "string" || !text || this.byPlaceholder.size === 0 || !TOLERANT_ANY.test(text)) return text;
    return text.replace(TOLERANT_G, (...args) => {
      const m = args.slice(0, -2) as unknown as RegExpMatchArray;
      m.groups = args[args.length - 1] as Record<string, string>;
      const [value] = this.classify(m);
      return value === undefined ? (m[0] as string) : encode(value);
    });
  }

  private labels(): Set<string> {
    return new Set([...this.byPlaceholder.keys()].map((p) => p.slice(1, -1).replace(/_\d+$/, "")));
  }

  private resolve(label: string, num: string): Entry | undefined {
    const n = parseInt(num, 10);
    let e = this.byPlaceholder.get(`<${label}_${n}>`);
    if (e === undefined && ALIASES[label] && !this.labels().has(label)) {
      e = this.byPlaceholder.get(`<${ALIASES[label]}_${n}>`);
    }
    return e;
  }

  private unknownKind(label: string): Kind {
    return this.labels().has(label) || VOCAB.has(label) ? "unknown" : "ignore";
  }

  /** [real value or undefined, kind] for one match of the tolerant pattern. */
  private classify(m: RegExpMatchArray): [string | undefined, Kind] {
    const g = m.groups ?? {};
    if (g.exact) {
      const e = this.byPlaceholder.get(canonical(g.elabel!, g.enum!));
      if (e) return [e.value, "exact"];
      const r = this.resolve(normLabel(g.elabel!), g.enum!);
      if (r) return [r.value, "repaired"];
      return [undefined, this.unknownKind(normLabel(g.elabel!))];
    }
    if (g.blabel) {
      const label = normLabel(g.blabel);
      const r = this.resolve(label, g.bnum!);
      if (r) return [r.value, "repaired"];
      return [undefined, this.unknownKind(label)];
    }
    const raw = (g.ulabel ?? "").replace(/\\/g, "");
    const label = normLabel(raw);
    const r = this.resolve(label, g.unum!);
    const letters = raw.replace(/[^A-Za-z]/g, "");
    if ((letters && letters === letters.toUpperCase()) || isTitle(raw)) {
      if (r) return [r.value, "repaired"];
      return [undefined, this.unknownKind(label)];
    }
    // person_1: could be a variable name in code; never restored.
    return [undefined, r ? "lost" : "ignore"];
  }

  /** Restore placeholders in a string / array / plain object (a new value). */
  restore<T>(value: T): T {
    return this.restoreAny(value, 0) as T;
  }

  private restoreAny(value: unknown, depth: number): unknown {
    if (depth > 64) return value;
    if (typeof value === "string") return this.restoreText(value);
    if (Array.isArray(value)) return value.map((v) => this.restoreAny(v, depth + 1));
    if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.restoreAny(v, depth + 1);
      return out;
    }
    return value;
  }

  /** The placeholders issued so far (never the values). */
  placeholders(): string[] {
    return [...this.byPlaceholder.keys()];
  }

  get size(): number {
    return this.byPlaceholder.size;
  }

  /** Drop the map. */
  clear(): void {
    this.byValue.clear();
    this.byPlaceholder.clear();
    this.counts.clear();
    this.knownRe = null;
  }

  /** Never print values. */
  toString(): string {
    return `PlaceholderMap(${this.size} placeholders)`;
  }

  toJSON(): string {
    return this.toString();
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

/**
 * Buffers streamed text so a placeholder split across chunks is restored
 * whole. `push` returns the text that is safe to emit now; `flush` returns
 * the rest at the end of the stream.
 */
export class StreamRestorer {
  private pending = "";

  constructor(
    private readonly map: PlaceholderMap,
    private readonly mode: "text" | "json" = "text",
    private readonly maxHold = 64,
  ) {}

  push(delta: string): string {
    this.pending += delta;
    const cut = holdFrom(this.pending, this.maxHold);
    const ready = this.pending.slice(0, cut);
    this.pending = this.pending.slice(cut);
    return this.apply(ready);
  }

  flush(): string {
    const rest = this.pending;
    this.pending = "";
    return this.apply(rest);
  }

  private apply(s: string): string {
    if (!s) return s;
    return this.mode === "json" ? this.map.restoreJsonFragment(s) : this.map.restoreText(s);
  }
}

// The start of a placeholder that is not finished yet: "<", "&lt", "<SSN",
// "<SSN_1", "[PERSON", "{{EMAIL_1" ...
const PARTIAL_ENTITY = /^&(?:l|lt|lt;?)?$/;
const PARTIAL = new RegExp(String.raw`^(?:${OPEN})?[ \t]*[\p{L}\p{N}_ \-\\＿]*(?:&|&g|&gt)?$`, "u");
const OPENERS = new Set(["<", "&", "[", "{", "(", "\\", "«", "‹", "〈", "《", "＜", "【", "「", "『"]);

/** Index from which the text must be held back (text.length when none). */
function holdFrom(text: string, maxHold: number): number {
  const from = Math.max(0, text.length - maxHold);
  // A bare form (PERSON_1) can be cut anywhere: hold a trailing word run.
  let cut = text.length;
  while (cut > from && /[\p{L}\p{N}_＿\\]/u.test(text[cut - 1]!)) cut--;
  for (let i = from; i < cut; i++) {
    const c = text[i]!;
    if (!OPENERS.has(c)) continue;
    const rest = text.slice(i);
    if (PARTIAL_ENTITY.test(rest) || PARTIAL.test(rest)) return i;
  }
  return cut;
}

// Short on purpose: it is added to every request that has placeholders. The
// same text as the Python SDK.
export const INSTRUCTION =
  "Some values in this conversation were replaced by placeholders: {names}. " +
  "Each one stands for a real value the user already gave, so it is not a blank " +
  "to fill in and it is safe to repeat. Copy each placeholder exactly as written, " +
  "with the angle brackets, wherever you need that value: in text, lists, JSON, " +
  "code and tool call arguments. Keep placeholders unchanged when you translate. " +
  "Do not invent new placeholders and do not ask for the real values.";
const INSTRUCTION_MAX = 20; // placeholders named in the instruction

/** The system line that asks the model to copy `names` exactly. */
export function instructionFor(names: readonly string[]): string {
  const shown = names.slice(0, INSTRUCTION_MAX);
  return INSTRUCTION.replace("{names}", shown.join(", ") + (names.length > shown.length ? ", ..." : ""));
}

/**
 * Strict mode: the model's answer has placeholders that could not be
 * restored. `lost` and `unknown` hold the placeholder forms (never values).
 */
export class PlaceholderRestoreError extends Error {
  constructor(
    readonly lost: string[],
    readonly unknown: string[],
  ) {
    super(`model answer has placeholders that could not be restored: ${[...lost, ...unknown].slice(0, 10).join(", ")}`);
    this.name = "PlaceholderRestoreError";
  }
}

/** Merge reports, keeping each form once. */
export function mergeReports(reports: readonly RestoreReport[]): RestoreReport {
  const out: RestoreReport = { repaired: [], lost: [], unknown: [] };
  for (const r of reports) for (const k of ["repaired", "lost", "unknown"] as const) out[k].push(...r[k]);
  for (const k of ["repaired", "lost", "unknown"] as const) out[k] = [...new Set(out[k])];
  return out;
}
