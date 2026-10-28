import type { LanguageModelV4GenerateResult, LanguageModelV4StreamPart, LanguageModelV4Usage } from "@ai-sdk/provider";
import { generateText, streamText, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4, convertArrayToReadableStream } from "ai/test";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { PlaceholderMap, PlaceholderRestoreError, taintwardMiddleware } from "../src/ai-sdk.js";

const usage: LanguageModelV4Usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
} as LanguageModelV4Usage;
const stop = { unified: "stop", raw: "stop" } as const;

const SSN = "234-12-1234";
const EMAIL = "alice.lee@example.com";
const ASK = `Remind the owner of ${EMAIL} (SSN ${SSN}) about the form.`;

function textModel(answer: (prompt: string) => string) {
  return new MockLanguageModelV4({
    doGenerate: async (params) =>
      ({
        content: [{ type: "text", text: answer(JSON.stringify(params.prompt)) }],
        finishReason: stop,
        usage,
        warnings: [],
      }) as unknown as LanguageModelV4GenerateResult,
  });
}

describe("generate", () => {
  it("sends placeholders and restores the answer", async () => {
    const inner = textModel(() => "I will email <EMAIL_1> about SSN <SSN_1>.");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    const { text } = await generateText({ model, prompt: ASK });

    const sent = JSON.stringify(inner.doGenerateCalls[0]!.prompt);
    expect(sent).not.toContain(SSN);
    expect(sent).not.toContain(EMAIL);
    expect(sent).toContain("<EMAIL_1>");
    expect(sent).toContain("<SSN_1>");
    expect(text).toBe(`I will email ${EMAIL} about SSN ${SSN}.`);
  });

  it("adds one system line naming the placeholders", async () => {
    const inner = textModel(() => "ok");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    await generateText({ model, system: "You are helpful.", prompt: ASK });
    const prompt = inner.doGenerateCalls[0]!.prompt;
    expect(prompt[0]!.role).toBe("system");
    expect(String(prompt[0]!.content)).toContain("<EMAIL_1>, <SSN_1>");
    expect(prompt[1]).toEqual({ role: "system", content: "You are helpful." });
  });

  it("no instruction and no change when there is nothing sensitive", async () => {
    const inner = textModel(() => "4");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    const { text } = await generateText({ model, prompt: "What is 2 + 2?" });
    expect(inner.doGenerateCalls[0]!.prompt).toHaveLength(1);
    expect(text).toBe("4");
  });

  it("instruction can be turned off", async () => {
    const inner = textModel(() => "ok");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ instruction: false }) });
    await generateText({ model, prompt: ASK });
    expect(inner.doGenerateCalls[0]!.prompt.every((m) => m.role !== "system")).toBe(true);
  });

  it("masks instead of placeholders", async () => {
    const inner = textModel(() => "ok");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ placeholders: false }) });
    await generateText({ model, prompt: ASK });
    const sent = JSON.stringify(inner.doGenerateCalls[0]!.prompt);
    expect(sent).toContain("[PII]");
    expect(sent).not.toContain("<SSN_1>");
    expect(sent).not.toContain(SSN);
  });

  it("restores rewritten forms and reports them", async () => {
    const onReport = vi.fn();
    const inner = textModel(() => "Emailed [EMAIL_1] and EMAIL_1.");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ onReport }) });
    const { text } = await generateText({ model, prompt: ASK });
    expect(text).toBe(`Emailed ${EMAIL} and ${EMAIL}.`);
    expect(onReport.mock.calls[0]![0].repaired).toEqual(["[EMAIL_1]", "EMAIL_1"]);
  });

  it("strict mode throws on an invented placeholder", async () => {
    const inner = textModel(() => "Also cc <EMAIL_7>.");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ strict: true }) });
    await expect(generateText({ model, prompt: ASK })).rejects.toBeInstanceOf(PlaceholderRestoreError);
  });

  it("restores tool call arguments, also with an escaped <", async () => {
    let received: unknown;
    const inner = new MockLanguageModelV4({
      doGenerate: [
        {
          content: [
            { type: "tool-call", toolCallId: "c1", toolName: "send_email", input: '{"to":"\\u003cEMAIL_1\\u003e","body":"hi"}' },
          ],
          finishReason: { unified: "tool-calls", raw: "tool_calls" },
          usage,
          warnings: [],
        } as unknown as LanguageModelV4GenerateResult,
      ],
    });
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    await generateText({
      model,
      prompt: ASK,
      tools: {
        send_email: tool({
          inputSchema: z.object({ to: z.string(), body: z.string() }),
          execute: async (input) => {
            received = input;
            return "sent";
          },
        }),
      },
    });
    expect(received).toEqual({ to: EMAIL, body: "hi" });
  });

  it("redacts tool results in the next request", async () => {
    const inner = textModel(() => "done");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    await generateText({
      model,
      messages: [
        { role: "user", content: "look up customer 7" },
        { role: "assistant", content: [{ type: "tool-call", toolCallId: "c1", toolName: "lookup", input: { id: 7 } }] },
        {
          role: "tool",
          content: [{ type: "tool-result", toolCallId: "c1", toolName: "lookup", output: { type: "json", value: { email: EMAIL, ssn: SSN } } }],
        },
      ],
    });
    const sent = JSON.stringify(inner.doGenerateCalls[0]!.prompt);
    expect(sent).not.toContain(EMAIL);
    expect(sent).not.toContain(SSN);
    expect(sent).toContain("<EMAIL_1>");
  });

  it("a shared map keeps numbering across calls", async () => {
    const map = new PlaceholderMap();
    const inner = textModel(() => "ok");
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ map }) });
    await generateText({ model, prompt: `first ${EMAIL}` });
    await generateText({ model, prompt: `second bob@example.org then ${EMAIL}` });
    const sent = JSON.stringify(inner.doGenerateCalls[1]!.prompt);
    expect(sent).toContain("<EMAIL_2> then <EMAIL_1>");
  });
});

describe("stream", () => {
  function streamModel(parts: LanguageModelV4StreamPart[]) {
    return new MockLanguageModelV4({ doStream: async () => ({ stream: convertArrayToReadableStream(parts) }) });
  }

  it("restores a placeholder split across chunks", async () => {
    const deltas = ["Mail sent to <EM", "AIL", "_1", "> and [SSN", "_1]", " ok"];
    const inner = streamModel([
      { type: "text-start", id: "t" },
      ...deltas.map((delta) => ({ type: "text-delta", id: "t", delta }) as LanguageModelV4StreamPart),
      { type: "text-end", id: "t" },
      { type: "finish", finishReason: stop, usage },
    ]);
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    const result = streamText({ model, prompt: ASK });
    let out = "";
    for await (const t of result.textStream) out += t;
    expect(out).toBe(`Mail sent to ${EMAIL} and ${SSN} ok`);
  });

  it("restores streamed tool input", async () => {
    let received: unknown;
    const inner = streamModel([
      { type: "tool-input-start", id: "c1", toolName: "send_email" },
      { type: "tool-input-delta", id: "c1", delta: '{"to":"<EMA' },
      { type: "tool-input-delta", id: "c1", delta: 'IL_1>"}' },
      { type: "tool-input-end", id: "c1" },
      { type: "tool-call", toolCallId: "c1", toolName: "send_email", input: '{"to":"<EMAIL_1>"}' },
      { type: "finish", finishReason: { unified: "tool-calls", raw: "tool_calls" }, usage },
    ]);
    const model = wrapLanguageModel({ model: inner, middleware: taintwardMiddleware() });
    const result = streamText({
      model,
      prompt: ASK,
      tools: {
        send_email: tool({
          inputSchema: z.object({ to: z.string() }),
          execute: async (input) => {
            received = input;
            return "sent";
          },
        }),
      },
    });
    await result.consumeStream();
    expect(received).toEqual({ to: EMAIL });
  });
});
