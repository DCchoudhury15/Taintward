// OpenAI and Anthropic JS clients: the model sees placeholders, your code
// gets the real values back. The same idea as the Python SDK's
// protect_openai / protect_anthropic.
//
//   import OpenAI from "openai";
//   import { protectOpenAI } from "taintward";
//   const client = protectOpenAI(new OpenAI());
//
// Patched on the client object (other clients are not touched):
//
// * OpenAI: chat.completions.create, responses.create (and so their parse()
//   and stream() helpers, which call create), embeddings.create.
// * Anthropic: messages.create (and so parse()), messages.stream().
//
// The request's content fields are redacted (messages, system, input,
// instructions; protocol fields such as role, type, ids and tool names are
// left alone), and one system line asks the model to copy the placeholders.
// The answer is restored: message text, tool call arguments (JSON-escaped),
// Anthropic tool_use input, and the text of a JSON answer (JSON-escaped). A
// stream hands out restored copies of its chunks; a placeholder split across
// two chunks is restored whole (the start is held back for a moment).
// Embedding input is masked ([PII]), not given placeholders: see
// docs/integrations.md, "Embeddings and RAG ingestion".
//
// The calls still return the SDK's own promise type (APIPromise), so
// .withResponse() and .asResponse() keep working; .asResponse() gives the
// raw HTTP response, which is not restored.

import { PLACEHOLDER_SOURCE, PlaceholderMap, PlaceholderRestoreError, StreamRestorer, instructionFor, mergeReports, type RestoreReport } from "./placeholders.js";
import { redactPayload, redactString } from "./redact.js";

export interface ProtectClientOptions {
  /** Send <PERSON_1> style placeholders (default). `false` sends [PII] / [SECRET] masks. */
  placeholders?: boolean;
  /** Add one system line asking the model to copy placeholders exactly (default true). */
  instruction?: boolean;
  /** Throw PlaceholderRestoreError when the answer has placeholders that cannot be restored. */
  strict?: boolean;
  /** Also restore placeholders inside link and image addresses (default false, gap G1). */
  restoreInUrls?: boolean;
  /** Called after each answer with the placeholder forms that were repaired, lost, unknown or blocked. */
  onReport?: (report: RestoreReport) => void;
}

const MARK = Symbol.for("taintward.protected");
const MAP_OPTION = "__taintwardMap";
const EXACT_G = new RegExp(PLACEHOLDER_SOURCE, "g");

// Protocol keys. Their value is protocol data when it is a plain value
// ("role": "user", "id": "call_1", "data": "<base64>"), never user content.
const LEAF = new Set([
  "role", "type", "id", "call_id", "tool_call_id", "tool_use_id", "name", "model", "signature",
  "media_type", "data", "file_id", "status", "index", "finish_reason", "stop_reason", "mime_type",
  "detail", "format",
]);
// Protocol keys whose whole value is kept, also when it is an object or an array.
const OPAQUE = new Set(["cache_control", "image_url", "input_audio", "file_data", "response_format", "tool_choice"]);
// Keys that hold free data when their value is an object: the arguments of an
// earlier tool call and structured tool results. Inside them every key is the
// application's own ("name", "id", "data" are fields of a customer record
// there, not protocol), so nothing in them is skipped.
const FREE = new Set([
  "input", "args", "arguments", "response", "output", "result", "parsed", "content", "artifact",
  "structured_content", "structuredContent",
]);
// Every key that is kept as it is (not redacted as data).
const STRUCTURAL = new Set([...LEAF, ...OPAQUE, "source"]);

type Kind = "openai.chat" | "openai.responses" | "anthropic";
type AnyFn = (...args: any[]) => any;

function defaultReport(r: RestoreReport): void {
  if (r.lost.length || r.unknown.length) {
    console.warn(
      `taintward: model answer has placeholders that could not be restored (lost: ${r.lost.slice(0, 5).join(", ")}; unknown: ${r.unknown.slice(0, 5).join(", ")})`,
    );
  }
  if (r.blocked.length) {
    console.warn(`taintward: placeholders inside link addresses were not restored: ${r.blocked.slice(0, 5).join(", ")}`);
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** An Anthropic image or document `source`: url, file_id and base64 data are kept, text is content. */
function redactSource(value: unknown, map: PlaceholderMap | undefined, depth: number): unknown {
  if (!isObject(value)) return redactStructure(value, map, "source", depth);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] =
      k === "data" && value.type === "text"
        ? redactPayload(v, "llm", { placeholders: map })
        : k === "content"
          ? redactStructure(v, map, k, depth + 1)
          : v;
  }
  return out;
}

/** The value of one key of a protocol object. */
function redactItem(k: string, v: unknown, map: PlaceholderMap | undefined, depth: number): unknown {
  if (OPAQUE.has(k)) return v;
  if (k === "source") return redactSource(v, map, depth + 1);
  const container = v !== null && typeof v === "object";
  // A protocol value is a string or a number. An object or an array under
  // one of these names is the application's data.
  if (LEAF.has(k)) return container ? redactPayload(v, "llm", { placeholders: map }) : v;
  if (FREE.has(k) && isObject(v)) return redactPayload(v, "llm", { placeholders: map });
  return redactStructure(v, map, k, depth + 1);
}

/**
 * Redact content, leave protocol fields alone. Protocol fields are skipped
 * only where the protocol puts them: a plain value under a protocol key and
 * the few whole values in OPAQUE. The arguments of an earlier tool call and
 * structured tool results are redacted in full.
 */
function redactStructure(value: unknown, map: PlaceholderMap | undefined, key = "", depth = 0): unknown {
  if (depth > 64) return value;
  if (typeof value === "string") return redactString(value, "llm", { placeholders: map, key });
  if (Array.isArray(value)) return value.map((v) => redactStructure(v, map, key, depth + 1));
  if (isObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[STRUCTURAL.has(k) ? k : redactString(k, "llm", { placeholders: map })] = redactItem(k, v, map, depth);
    }
    return out;
  }
  return value;
}

function placeholdersIn(value: unknown): string[] {
  const seen = new Set<string>();
  for (const m of JSON.stringify(value).matchAll(EXACT_G)) seen.add(`<${m[1]!.toUpperCase()}_${parseInt(m[2]!, 10)}>`);
  return [...seen];
}

const FIELDS: Record<Kind, readonly string[]> = {
  "openai.chat": ["messages"],
  "openai.responses": ["input", "instructions"],
  anthropic: ["messages", "system"],
};

function withLine(kind: Kind, body: Record<string, any>, line: string): Record<string, any> {
  if (kind === "openai.chat") {
    const msgs = [...(body.messages ?? [])];
    const first = msgs[0];
    if (isObject(first) && (first.role === "system" || first.role === "developer") && typeof first.content === "string") {
      msgs[0] = { ...first, content: `${first.content}\n\n${line}` };
    } else {
      msgs.unshift({ role: "system", content: line });
    }
    return { ...body, messages: msgs };
  }
  if (kind === "openai.responses") {
    return { ...body, instructions: body.instructions ? `${body.instructions}\n\n${line}` : line };
  }
  const prev = body.system;
  const system =
    typeof prev === "string" && prev ? `${prev}\n\n${line}` : Array.isArray(prev) ? [...prev, { type: "text", text: line }] : line;
  return { ...body, system };
}

/** Does the request ask for a JSON answer? Its text is then restored JSON-escaped. */
function jsonAnswer(kind: Kind, body: Record<string, any>): boolean {
  const isJson = (f: any) => isObject(f) && (f.type === "json_schema" || f.type === "json_object");
  if (kind === "openai.chat") return isJson(body.response_format);
  if (kind === "openai.responses") return isJson(body.text?.format);
  return isJson(body.output_config?.format) || body.output_format !== undefined;
}

interface Call {
  kind: Kind;
  map: PlaceholderMap | undefined;
  json: boolean;
  options: ProtectClientOptions;
}

function redactRequest(kind: Kind, body: Record<string, any>, call: Call): Record<string, any> {
  let sent: Record<string, any> = { ...body };
  for (const f of FIELDS[kind]) if (f in body) sent[f] = redactStructure(body[f], call.map);
  if (call.map && call.map.size > 0 && call.options.instruction !== false) {
    const names = placeholdersIn(FIELDS[kind].map((f) => sent[f]));
    if (names.length) sent = withLine(kind, sent, instructionFor(names));
  }
  return sent;
}

/**
 * Restored copy of a value; `arguments` / `partial_json` and JSON answers are
 * JSON-escaped. `free`: inside tool arguments or a structured result, where
 * no key is a protocol key.
 */
function restoreDeep(v: unknown, call: Call, key = "", depth = 0, free = false): unknown {
  const map = call.map!;
  if (depth > 64) return v;
  if (typeof v === "string") {
    const json = key === "arguments" || key === "partial_json" || (call.json && (key === "content" || key === "text" || key === "output_text"));
    return json ? map.restoreJsonFragment(v) : map.restoreText(v);
  }
  if (Array.isArray(v)) return v.map((x) => restoreDeep(x, call, key, depth + 1, free));
  if (isObject(v)) {
    const out: Record<string, unknown> = Object.create(Object.getPrototypeOf(v));
    for (const [k, x] of Object.entries(v)) {
      const container = x !== null && typeof x === "object";
      if (free) out[k] = restoreDeep(x, call, k, depth + 1, true);
      // Only a plain protocol value is skipped: an object under "input" or
      // "data" holds placeholders the caller needs back.
      else if (OPAQUE.has(k) || (LEAF.has(k) && !container)) out[k] = x;
      else out[k] = restoreDeep(x, call, k, depth + 1, (LEAF.has(k) && container) || (FREE.has(k) && isObject(x)));
    }
    return out;
  }
  return v;
}

function finishReport(call: Call, texts: string[]): void {
  if (!call.map || call.map.size === 0) return;
  const report = mergeReports(texts.map((t) => call.map!.diagnose(t)));
  if (call.options.strict && (report.lost.length || report.unknown.length)) {
    throw new PlaceholderRestoreError(report.lost, report.unknown);
  }
  (call.options.onReport ?? defaultReport)(report);
}

function answerView(kind: Kind, data: Record<string, any>): unknown {
  if (kind === "openai.chat") return data.choices?.map((c: any) => c.message);
  if (kind === "openai.responses") return data.output;
  return data.content;
}

function restoreAnswer(call: Call, data: unknown): unknown {
  if (!call.map || call.map.size === 0 || !isObject(data)) return data;
  finishReport(call, [JSON.stringify(answerView(call.kind, data) ?? data)]);
  return restoreDeep(data, call);
}

// --- streams -----------------------------------------------------------------

/** Restorers keyed by the text they restore (a choice's content, one tool call's arguments, ...). */
class Pieces {
  private readonly restorers = new Map<string, StreamRestorer>();
  readonly raw = new Map<string, string>();
  constructor(private readonly map: PlaceholderMap) {}

  push(key: string, text: string, mode: "text" | "json"): string {
    let r = this.restorers.get(key);
    if (!r) {
      r = new StreamRestorer(this.map, mode);
      this.restorers.set(key, r);
    }
    this.raw.set(key, (this.raw.get(key) ?? "") + text);
    return r.push(text);
  }

  flush(key: string): string {
    const r = this.restorers.get(key);
    return r ? r.flush() : "";
  }

  keys(): string[] {
    return [...this.restorers.keys()];
  }
}

interface Handler {
  item(chunk: any): any[];
  end(): any[];
  /** Every streamed text as the model wrote it, for the placeholder check. */
  texts(): string[];
}

const clone = <T>(v: T): T => structuredClone(v);

/** OpenAI chat completion chunks. Held text goes into the choice's finish_reason chunk. */
function chatHandler(call: Call): Handler {
  const p = new Pieces(call.map!);
  let last: any = null;
  const textMode = call.json ? "json" : "text";
  const flushChoice = (out: any, idx: number) => {
    const choice = out.choices.find((c: any) => c.index === idx);
    for (const field of ["content", "refusal"]) {
      const rest = p.flush(`${idx}:${field}`);
      if (rest) choice.delta[field] = (choice.delta[field] ?? "") + rest;
    }
    for (const key of p.keys().filter((k) => k.startsWith(`${idx}:tool:`))) {
      const rest = p.flush(key);
      if (!rest) continue;
      const tIdx = Number(key.split(":")[2]);
      choice.delta.tool_calls ??= [];
      let tc = choice.delta.tool_calls.find((t: any) => t.index === tIdx);
      if (!tc) choice.delta.tool_calls.push((tc = { index: tIdx, function: {} }));
      tc.function ??= {};
      tc.function.arguments = (tc.function.arguments ?? "") + rest;
    }
  };
  return {
    item(chunk) {
      const out = clone(chunk);
      for (const c of out.choices ?? []) {
        const d = c.delta ?? {};
        for (const field of ["content", "refusal"]) {
          if (typeof d[field] === "string" && d[field]) d[field] = p.push(`${c.index}:${field}`, d[field], textMode);
        }
        for (const tc of d.tool_calls ?? []) {
          const a = tc.function?.arguments;
          if (typeof a === "string" && a) tc.function.arguments = p.push(`${c.index}:tool:${tc.index}`, a, "json");
        }
        if (c.finish_reason) flushChoice(out, c.index);
      }
      if ((out.choices ?? []).length) last = out;
      return [out];
    },
    end() {
      if (!last) return [];
      const extra = clone(last);
      for (const c of extra.choices) {
        c.delta = {};
        c.finish_reason = c.finish_reason ?? null;
        flushChoice(extra, c.index);
      }
      const any = extra.choices.some((c: any) => Object.keys(c.delta).length > 0);
      return any ? [extra] : [];
    },
    texts: () => [...p.raw.values()],
  };
}

/** Anthropic message stream events. Held text goes out as one extra delta before content_block_stop. */
function anthropicHandler(call: Call): Handler {
  const p = new Pieces(call.map!);
  const lastDelta = new Map<string, any>();
  const fields: Record<string, [string, "text" | "json"]> = {
    text_delta: ["text", call.json ? "json" : "text"],
    input_json_delta: ["partial_json", "json"],
    thinking_delta: ["thinking", "text"],
  };
  const extras = (index: number) => {
    const out: any[] = [];
    for (const field of ["text", "partial_json", "thinking"]) {
      const key = `${index}:${field}`;
      const rest = p.flush(key);
      const ev = lastDelta.get(key);
      if (rest && ev) {
        const extra = clone(ev);
        extra.delta[field] = rest;
        out.push(extra);
      }
    }
    return out;
  };
  return {
    item(ev) {
      if (ev?.type === "content_block_delta") {
        const spec = fields[ev.delta?.type];
        const value = spec ? ev.delta[spec[0]] : undefined;
        if (spec && typeof value === "string" && value) {
          const out = clone(ev);
          const key = `${ev.index}:${spec[0]}`;
          out.delta[spec[0]] = p.push(key, value, spec[1]);
          lastDelta.set(key, out);
          return [out];
        }
      }
      if (ev?.type === "content_block_stop") return [...extras(ev.index), ev];
      if (ev?.type === "content_block_start" || ev?.type === "message_start") return [restoreDeep(ev, call)];
      return [ev];
    },
    end() {
      const idx = new Set(p.keys().map((k) => Number(k.split(":")[0])));
      return [...idx].flatMap((i) => extras(i));
    },
    texts: () => [...p.raw.values()],
  };
}

/** OpenAI Responses API events. Held text goes out as one extra delta before the matching .done event. */
function responsesHandler(call: Call): Handler {
  const p = new Pieces(call.map!);
  const lastDelta = new Map<string, any>();
  const keyOf = (ev: any, prefix: string) =>
    [prefix, ev.item_id, ev.output_index, ev.content_index, ev.summary_index].join(":");
  return {
    item(ev) {
      const t: string = ev?.type ?? "";
      if (t.endsWith(".delta") && typeof ev.delta === "string" && t !== "response.audio.delta") {
        const prefix = t.slice(0, -".delta".length);
        const json = prefix.includes("arguments") || (call.json && prefix === "response.output_text");
        const out = clone(ev);
        const key = keyOf(ev, prefix);
        out.delta = p.push(key, ev.delta, json ? "json" : "text");
        lastDelta.set(key, out);
        return [out];
      }
      const out: any[] = [];
      if (t.endsWith(".done")) {
        const key = keyOf(ev, t.slice(0, -".done".length));
        const rest = p.flush(key);
        const lastEv = lastDelta.get(key);
        if (rest && lastEv) out.push({ ...clone(lastEv), delta: rest });
      }
      const done = t.endsWith(".done") || t === "response.completed" || t === "response.incomplete" || t === "response.failed";
      out.push(done ? restoreDeep(ev, call) : ev);
      return out;
    },
    end() {
      return [];
    },
    texts: () => [...p.raw.values()],
  };
}

function handlerFor(call: Call): Handler {
  if (call.kind === "openai.chat") return chatHandler(call);
  if (call.kind === "openai.responses") return responsesHandler(call);
  return anthropicHandler(call);
}

function isStream(v: unknown): v is AsyncIterable<unknown> & { controller: AbortController } {
  return isObject(v) && typeof (v as any)[Symbol.asyncIterator] === "function" && "controller" in v;
}

/** The SDK's own Stream class, handing out restored copies. */
function restoreStream(call: Call, stream: any): any {
  const handler = handlerFor(call);
  async function* restored(): AsyncGenerator<unknown> {
    for await (const chunk of stream) for (const out of handler.item(chunk)) yield out;
    for (const out of handler.end()) yield out;
    finishReport(call, handler.texts());
  }
  const Ctor = stream.constructor;
  return new Ctor(() => restored()[Symbol.asyncIterator](), stream.controller);
}

// --- patching ------------------------------------------------------------------

function wrapCreate(kind: Kind, original: AnyFn, options: ProtectClientOptions): AnyFn {
  const wrapped = function (this: unknown, body: any, reqOptions?: any) {
    if (!isObject(body)) return original.call(this, body, reqOptions);
    const given = isObject(reqOptions) ? (reqOptions[MAP_OPTION] as PlaceholderMap | undefined) : undefined;
    const map =
      given ?? (options.placeholders === false ? undefined : new PlaceholderMap({ restoreInUrls: options.restoreInUrls }));
    const call: Call = { kind, map, json: jsonAnswer(kind, body), options };
    let sendOptions = reqOptions;
    if (given) {
      const { [MAP_OPTION]: _drop, ...rest } = reqOptions;
      sendOptions = rest;
    }
    const sent = given ? body : redactRequest(kind, body, call);
    const promise = original.call(this, sent, sendOptions);
    const transform = (data: unknown) => {
      if (!call.map || call.map.size === 0) return data;
      return isStream(data) ? restoreStream(call, data) : restoreAnswer(call, data);
    };
    return typeof promise?._thenUnwrap === "function" ? promise._thenUnwrap(transform) : Promise.resolve(promise).then(transform);
  };
  (wrapped as any)[MARK] = true;
  return wrapped;
}

function wrapEmbeddings(original: AnyFn): AnyFn {
  const wrapped = function (this: unknown, body: any, reqOptions?: any) {
    if (!isObject(body)) return original.call(this, body, reqOptions);
    const input = body.input;
    const text = typeof input === "string" || (Array.isArray(input) && input.every((x) => typeof x === "string"));
    return original.call(this, text ? { ...body, input: redactPayload(input, "rag") } : body, reqOptions);
  };
  (wrapped as any)[MARK] = true;
  return wrapped;
}

/** Anthropic messages.stream(): redact here, so the SDK's own tracing gets the redacted request too. */
function wrapMessageStream(original: AnyFn, options: ProtectClientOptions): AnyFn {
  const wrapped = function (this: unknown, body: any, reqOptions?: any) {
    if (!isObject(body) || options.placeholders === false) return original.call(this, body, reqOptions);
    const map = new PlaceholderMap({ restoreInUrls: options.restoreInUrls });
    const sent = redactRequest("anthropic", body, { kind: "anthropic", map, json: false, options });
    return original.call(this, sent, { ...(reqOptions ?? {}), [MAP_OPTION]: map });
  };
  (wrapped as any)[MARK] = true;
  return wrapped;
}

function patch(resource: any, name: string, wrap: (fn: AnyFn) => AnyFn): boolean {
  const fn = resource?.[name];
  if (typeof fn !== "function") return false;
  if (fn[MARK]) return true;
  resource[name] = wrap(fn.bind(resource));
  return true;
}

/** Patch an `OpenAI` client object in place and return it. */
export function protectOpenAI<T>(client: T, options: ProtectClientOptions = {}): T {
  const c = client as any;
  let ok = patch(c?.chat?.completions, "create", (fn) => wrapCreate("openai.chat", fn, options));
  ok = patch(c?.responses, "create", (fn) => wrapCreate("openai.responses", fn, options)) || ok;
  ok = patch(c?.embeddings, "create", wrapEmbeddings) || ok;
  if (!ok) throw new TypeError("protectOpenAI: client has no chat.completions.create or responses.create");
  return client;
}

/** Patch an `Anthropic` client object in place and return it. */
export function protectAnthropic<T>(client: T, options: ProtectClientOptions = {}): T {
  const c = client as any;
  if (!patch(c?.messages, "create", (fn) => wrapCreate("anthropic", fn, options))) {
    throw new TypeError("protectAnthropic: client has no messages.create");
  }
  patch(c.messages, "stream", (fn) => wrapMessageStream(fn, options));
  return client;
}
