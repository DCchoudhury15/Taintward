// The OpenAI and Anthropic JS clients through protectOpenAI / protectAnthropic.
// A fake fetch answers like the APIs do, so the SDKs' own code (streams,
// parse(), stream() helpers) runs; no network, no API keys.

import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import { describe, expect, it } from "vitest";
import { PlaceholderRestoreError, protectAnthropic, protectOpenAI } from "../src/index.js";

const SSN = "234-12-1234";
const ASK = `my ssn is ${SSN}`;

type Answer = { json?: unknown; sse?: Array<{ event?: string; data: unknown }> };

function fakeFetch(answers: Answer[], sent: any[]) {
  return async (_url: unknown, init?: { body?: unknown }) => {
    sent.push(JSON.parse(String(init?.body)));
    const a = answers.shift()!;
    if (a.sse) {
      const body = a.sse
        .map((e) => (e.event ? `event: ${e.event}\n` : "") + `data: ${JSON.stringify(e.data)}\n\n`)
        .join("") + (a.sse[0]?.event ? "" : "data: [DONE]\n\n");
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    }
    return new Response(JSON.stringify(a.json), { headers: { "content-type": "application/json" } });
  };
}

function openai(answers: Answer[], sent: any[], opts = {}) {
  const client = new OpenAI({ apiKey: "test", baseURL: "http://fake.local/v1", fetch: fakeFetch(answers, sent) as any, maxRetries: 0 });
  return protectOpenAI(client, { onReport: () => {}, ...opts });
}

function anthropic(answers: Answer[], sent: any[]) {
  const client = new Anthropic({ apiKey: "test", baseURL: "http://fake.local", fetch: fakeFetch(answers, sent) as any, maxRetries: 0 });
  return protectAnthropic(client, { onReport: () => {} });
}

const completion = (content: string, tool?: string) => ({
  id: "c1", object: "chat.completion", created: 0, model: "gpt-test",
  choices: [{ index: 0, finish_reason: tool ? "tool_calls" : "stop", message: {
    role: "assistant", content,
    ...(tool ? { tool_calls: [{ id: "t1", type: "function", function: { name: "lookup", arguments: tool } }] } : {}),
  } }],
});
const chunk = (delta: object, finish: string | null = null) => ({
  id: "c1", object: "chat.completion.chunk", created: 0, model: "gpt-test",
  choices: [{ index: 0, delta, finish_reason: finish }],
});

describe("protectOpenAI", () => {
  it("chat: redacts the request and restores the answer", async () => {
    const sent: any[] = [];
    const client = openai([{ json: completion("Your SSN <SSN_1> is fine", '{"ssn": "<SSN_1>"}') }], sent);
    const { data, response } = await client.chat.completions
      .create({ model: "gpt-test", messages: [{ role: "user", content: ASK }] })
      .withResponse();
    expect(JSON.stringify(sent[0])).not.toContain(SSN);
    expect(sent[0].messages[1].content).toBe("my ssn is <SSN_1>");
    expect(sent[0].messages[0].role).toBe("system"); // the placeholder line
    expect(response.status).toBe(200);
    expect(data.choices[0]!.message.content).toBe(`Your SSN ${SSN} is fine`);
    expect(JSON.parse((data.choices[0]!.message.tool_calls![0] as any).function.arguments)).toEqual({ ssn: SSN });
  });

  it("chat: a stream is restored chunk by chunk", async () => {
    const sent: any[] = [];
    const pieces = ["Your <S", "SN_1> is ", "<SS", "N_1"];
    const client = openai([{ sse: [
      ...pieces.map((p) => ({ data: chunk({ content: p }) })),
      { data: chunk({ tool_calls: [{ index: 0, id: "t1", type: "function", function: { name: "lookup", arguments: '{"ssn": "<SS' } }] }) },
      { data: chunk({ tool_calls: [{ index: 0, function: { arguments: 'N_1>"}' } }] }) },
      { data: chunk({ content: "> thanks" }, "stop") },
    ] }], sent);
    const stream = await client.chat.completions.create({ model: "gpt-test", stream: true, messages: [{ role: "user", content: ASK }] });
    let text = "";
    let args = "";
    const chunks = [];
    for await (const c of stream) {
      chunks.push(c);
      text += c.choices[0]?.delta.content ?? "";
      args += c.choices[0]?.delta.tool_calls?.[0]?.function?.arguments ?? "";
    }
    // the same chunks: "thanks" (it could be the start of a placeholder) was
    // held back and went out with the finish_reason chunk
    expect(chunks.length).toBe(7);
    expect(chunks[6]!.choices[0]!.delta.content).toBe(`${SSN} thanks`);
    expect(JSON.stringify(sent[0])).not.toContain(SSN);
    expect(text).toBe(`Your ${SSN} is ${SSN} thanks`);
    expect(JSON.parse(args)).toEqual({ ssn: SSN });
  });

  it("chat: the stream() helper and parse() go through create", async () => {
    const sent: any[] = [];
    const client = openai(
      [
        { sse: [{ data: chunk({ role: "assistant", content: "ok <SS" }) }, { data: chunk({ content: "N_1>" }, "stop") }] },
        { json: completion('{"ssn": "<SSN_1>"}') },
      ],
      sent,
    );
    const runner = client.chat.completions.stream({ model: "gpt-test", messages: [{ role: "user", content: ASK }] });
    expect(await runner.finalContent()).toBe(`ok ${SSN}`);
    const parsed = await client.chat.completions.parse({
      model: "gpt-test",
      messages: [{ role: "user", content: ASK }],
      response_format: { type: "json_schema", json_schema: { name: "out", strict: true, schema: {
        type: "object", properties: { ssn: { type: "string" } }, required: ["ssn"], additionalProperties: false } } },
    });
    expect(parsed.choices[0]!.message.parsed).toEqual({ ssn: SSN });
    expect(sent.every((b) => !JSON.stringify(b).includes(SSN))).toBe(true);
  });

  it("responses: request and answer, streamed or not", async () => {
    const sent: any[] = [];
    const response = (text: string) => ({
      id: "r1", object: "response", created_at: 0, model: "gpt-test", status: "completed", output: [
        { type: "message", id: "m1", role: "assistant", status: "completed", content: [{ type: "output_text", text, annotations: [] }] },
      ],
    });
    const ev = (type: string, extra: object) => ({ data: { type, item_id: "m1", output_index: 0, content_index: 0, ...extra } });
    const client = openai([
      { json: response("SSN <SSN_1>") },
      { sse: [ev("response.output_text.delta", { delta: "SSN <SSN" }), ev("response.output_text.delta", { delta: "_1> ok" }),
        ev("response.output_text.done", { text: "SSN <SSN_1> ok" })] },
    ], sent);
    const r = await client.responses.create({ model: "gpt-test", input: ASK, instructions: "be brief" });
    expect(r.output_text).toBe(`SSN ${SSN}`);
    expect(sent[0].input).toBe("my ssn is <SSN_1>");
    expect(sent[0].instructions).toContain("be brief\n\n");
    const stream = await client.responses.create({ model: "gpt-test", input: ASK, stream: true });
    let text = "";
    let done = "";
    for await (const e of stream as any) {
      if (e.type === "response.output_text.delta") text += e.delta;
      if (e.type === "response.output_text.done") done = e.text;
    }
    expect(text).toBe(`SSN ${SSN} ok`);
    expect(done).toBe(text);
  });

  it("chat: tool call arguments are restored JSON-escaped", async () => {
    // A street address with its postal code on the next line: the newline
    // must be escaped inside the JSON string, or the arguments stop parsing.
    const address = "Kerkstraat 12a\n1012 AB Amsterdam";
    const ask = [{ role: "user" as const, content: `Send it to ${address}` }];
    const sent: any[] = [];
    const client = openai([
      { json: completion("ok", '{"to": "<STREET_ADDRESS_1>"}') },
      { sse: [
        { data: chunk({ tool_calls: [{ index: 0, id: "t1", type: "function", function: { name: "send", arguments: '{"to": "<STREET_ADD' } }] }) },
        { data: chunk({ tool_calls: [{ index: 0, function: { arguments: 'RESS_1>"}' } }] }, "tool_calls") },
      ] },
    ], sent);
    const r = await client.chat.completions.create({ model: "gpt-test", messages: ask });
    expect(sent[0].messages[1].content).toBe("Send it to <STREET_ADDRESS_1>");
    // escaped, and the model's own formatting (the space after the colon) kept
    expect((r.choices[0]!.message.tool_calls![0] as any).function.arguments).toBe(`{"to": ${JSON.stringify(address)}}`);
    const stream = await client.chat.completions.create({ model: "gpt-test", stream: true, messages: ask });
    let args = "";
    for await (const c of stream) args += c.choices[0]?.delta.tool_calls?.[0]?.function?.arguments ?? "";
    expect(JSON.parse(args)).toEqual({ to: address });
  });

  it("embeddings: input is masked", async () => {
    const sent: any[] = [];
    const client = openai([{ json: { object: "list", model: "e", data: [{ object: "embedding", index: 0, embedding: [0.1] }], usage: { prompt_tokens: 1, total_tokens: 1 } } }], sent);
    await client.embeddings.create({ model: "e", input: [ASK] });
    expect(sent[0].input).toEqual(["my ssn is [PII]"]);
  });

  it("strict mode throws on a placeholder the map does not know", async () => {
    const client = openai([{ json: completion("hello <SSN_7>") }], [], { strict: true });
    await expect(client.chat.completions.create({ model: "gpt-test", messages: [{ role: "user", content: ASK }] })).rejects.toThrow(PlaceholderRestoreError);
  });

  it("leaves a request without sensitive data alone", async () => {
    const sent: any[] = [];
    const client = openai([{ json: completion("hi") }], sent);
    await client.chat.completions.create({ model: "gpt-test", messages: [{ role: "user", content: "hello" }] });
    expect(sent[0].messages).toEqual([{ role: "user", content: "hello" }]);
  });
});

const message = (content: object[]) => ({
  id: "m", type: "message", role: "assistant", model: "claude-test", content,
  stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 3, output_tokens: 4 },
});
const anthropicEvents = (pieces: string[]) => [
  { event: "message_start", data: { type: "message_start", message: message([]) } },
  { event: "content_block_start", data: { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } } },
  ...pieces.map((t) => ({ event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t } } })),
  { event: "content_block_stop", data: { type: "content_block_stop", index: 0 } },
  { event: "message_delta", data: { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 4 } } },
  { event: "message_stop", data: { type: "message_stop" } },
];

describe("protectAnthropic", () => {
  it("create: redacts and restores text and tool input", async () => {
    const sent: any[] = [];
    const client = anthropic([{ json: message([
      { type: "text", text: "Hi <SSN_1>" },
      { type: "tool_use", id: "tu", name: "lookup", input: { ssn: "<SSN_1>" } },
    ]) }], sent);
    const r = await client.messages.create({ model: "claude-test", max_tokens: 50, system: "be brief", messages: [{ role: "user", content: ASK }] });
    expect(JSON.stringify(sent[0])).not.toContain(SSN);
    expect(sent[0].system).toContain("be brief\n\n");
    expect((r.content[0] as any).text).toBe(`Hi ${SSN}`);
    expect((r.content[1] as any).input).toEqual({ ssn: SSN });
  });

  it("create with stream: true", async () => {
    const client = anthropic([{ sse: anthropicEvents(["Hi <S", "SN_1", "> bye"]) }], []);
    const stream = await client.messages.create({ model: "claude-test", max_tokens: 50, stream: true, messages: [{ role: "user", content: ASK }] });
    let text = "";
    let atStop = "";
    for await (const e of stream) {
      if (e.type === "content_block_delta" && e.delta.type === "text_delta") text += e.delta.text;
      if (e.type === "content_block_stop") atStop = text;
    }
    expect(text).toBe(`Hi ${SSN} bye`);
    expect(atStop).toBe(text); // held text came out before its block stopped
  });

  it("the stream() helper gets the redacted request (so the SDK's own tracing does too)", async () => {
    const raw = new Anthropic({ apiKey: "test", baseURL: "http://fake.local", fetch: fakeFetch([{ sse: anthropicEvents(["ok"]) }], []) as any });
    const seen: any[] = [];
    const real = raw.messages.stream.bind(raw.messages);
    (raw.messages as any).stream = (body: any, opts: any) => {
      seen.push(body);
      return real(body, opts);
    };
    const client = protectAnthropic(raw, { onReport: () => {} });
    await client.messages.stream({ model: "claude-test", max_tokens: 5, messages: [{ role: "user", content: ASK }] }).finalMessage();
    expect(JSON.stringify(seen[0])).not.toContain(SSN);
    expect(JSON.stringify(seen[0])).toContain("<SSN_1>");
  });

  it("the stream() helper: redacted request, restored text and final message", async () => {
    const sent: any[] = [];
    const client = anthropic([{ sse: anthropicEvents(["Hi <S", "SN_1> bye <SS", "N_1>"]) }], sent);
    const stream = client.messages.stream({ model: "claude-test", max_tokens: 50, messages: [{ role: "user", content: ASK }] });
    let text = "";
    stream.on("text", (t) => (text += t));
    const final = await stream.finalMessage();
    expect(JSON.stringify(sent[0])).not.toContain(SSN);
    expect(JSON.stringify(sent[0])).not.toContain("__taintwardMap");
    expect(text).toBe(`Hi ${SSN} bye ${SSN}`);
    expect((final.content[0] as any).text).toBe(text);
  });
});
