// Every way a request leaves a protected OpenAI / Anthropic client.
//
// protectOpenAI / protectAnthropic patched create on one client object.
// These paths went around it and sent everything raw:
//
// * a copy made with client.withOptions(...),
// * Anthropic's client.beta.messages (create, stream, countTokens),
// * client.messages.countTokens,
// * request fields outside the conversation: prediction, metadata, user,
//   the variables of a stored prompt.

import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import { describe, expect, it, vi } from "vitest";
import { protectAnthropic, protectOpenAI } from "../src/index.js";

const SSN = "234-12-1234";
const EMAIL = "jo.fox@example.com";
const ASK = [{ role: "user" as const, content: `my ssn is ${SSN}` }];

const CHAT = {
  id: "c", object: "chat.completion", created: 1, model: "m",
  choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "got <SSN_1>" } }],
};
const MESSAGE = {
  id: "m", type: "message", role: "assistant", model: "m", content: [{ type: "text", text: "got <SSN_1>" }],
  stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 },
};
const RESPONSE = {
  id: "r", object: "response", created_at: 1, model: "m", status: "completed",
  output: [{ id: "o", type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "ok", annotations: [] }] }],
};
const EVENTS = [
  { type: "message_start", message: { ...MESSAGE, content: [] } },
  { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
  { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "got <SSN_1>" } },
  { type: "content_block_stop", index: 0 },
  { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } },
  { type: "message_stop" },
];

type Sent = Array<{ path: string; body: any; text: string }>;

function fakeFetch(sent: Sent, kind: "openai" | "anthropic") {
  return async (url: unknown, init?: { body?: unknown }) => {
    const path = new URL(String(url)).pathname;
    const text = String(init?.body);
    const body = JSON.parse(text);
    sent.push({ path, body, text });
    if (path.endsWith("count_tokens")) return Response.json({ input_tokens: 7 });
    if (body.stream) {
      const sse = EVENTS.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("");
      return new Response(sse, { headers: { "content-type": "text/event-stream" } });
    }
    if (path.endsWith("/responses")) return Response.json(RESPONSE);
    return Response.json(kind === "openai" ? CHAT : MESSAGE);
  };
}

function openai(sent: Sent) {
  return protectOpenAI(
    new OpenAI({ apiKey: "test", baseURL: "http://fake.local/v1", fetch: fakeFetch(sent, "openai") as any, maxRetries: 0 }),
    { onReport: () => {} },
  );
}

function anthropic(sent: Sent) {
  return protectAnthropic(
    new Anthropic({ apiKey: "test", baseURL: "http://fake.local", fetch: fakeFetch(sent, "anthropic") as any, maxRetries: 0 }),
    { onReport: () => {} },
  );
}

const last = (sent: Sent) => sent[sent.length - 1]!;

describe("copies of the client", () => {
  it("OpenAI: withOptions() gives a protected client", async () => {
    const sent: Sent = [];
    const client = openai(sent);
    for (const derived of [client.withOptions({ timeout: 5000 }), client.withOptions({}).withOptions({ maxRetries: 0 })]) {
      const out = await derived.chat.completions.create({ model: "m", messages: ASK });
      expect(last(sent).text).not.toContain(SSN);
      expect(last(sent).text).toContain("<SSN_1>");
      expect(out.choices[0]!.message.content).toBe(`got ${SSN}`);
    }
  });

  it("Anthropic: withOptions() gives a protected client", async () => {
    const sent: Sent = [];
    const out = await anthropic(sent).withOptions({ timeout: 5000 }).messages.create({ model: "m", max_tokens: 8, messages: ASK });
    expect(last(sent).text).not.toContain(SSN);
    expect((out.content[0] as any).text).toBe(`got ${SSN}`);
  });
});

describe("Anthropic: the beta namespace and token counting", () => {
  it("beta.messages.create is redacted and restored", async () => {
    const sent: Sent = [];
    const client = anthropic(sent);
    const out = await client.beta.messages.create({ model: "m", max_tokens: 8, messages: ASK });
    expect(last(sent).text).not.toContain(SSN);
    expect(last(sent).text).toContain("<SSN_1>");
    expect((out.content[0] as any).text).toBe(`got ${SSN}`);
    await client.withOptions({ timeout: 5000 }).beta.messages.create({ model: "m", max_tokens: 8, messages: ASK });
    expect(last(sent).text).not.toContain(SSN);
  });

  it("beta.messages.stream() is redacted and restored", async () => {
    const sent: Sent = [];
    const stream = anthropic(sent).beta.messages.stream({ model: "m", max_tokens: 8, messages: ASK });
    const final = await stream.finalMessage();
    expect(last(sent).text).not.toContain(SSN);
    expect(last(sent).text).toContain("<SSN_1>");
    expect((final.content[0] as any).text).toBe(`got ${SSN}`);
  });

  it.each([false, true])("countTokens is redacted (beta: %s)", async (beta) => {
    const sent: Sent = [];
    const client = anthropic(sent);
    const messages = beta ? client.beta.messages : client.messages;
    const out = await messages.countTokens({ model: "m", messages: ASK, system: `the user's mail is ${EMAIL}` });
    expect(out.input_tokens).toBe(7);
    expect(last(sent).path.endsWith("count_tokens")).toBe(true);
    expect(last(sent).text).not.toContain(SSN);
    expect(last(sent).text).not.toContain(EMAIL);
    expect(last(sent).text).toContain("<SSN_1>");
    expect(last(sent).text).not.toContain("replaced by placeholders"); // no instruction on a count
  });

  it("a batch request warns once", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const client = anthropic([]);
      for (let i = 0; i < 2; i++) await client.messages.batches.create({ requests: [] }).catch(() => {});
      expect(warn.mock.calls.filter((c) => String(c[0]).includes("messages.batches is not covered")).length).toBe(1);
    } finally {
      warn.mockRestore();
    }
  });
});

describe("request fields outside the conversation", () => {
  it("OpenAI chat: prediction, user and metadata", async () => {
    const sent: Sent = [];
    await openai(sent).chat.completions.create({
      model: "m", messages: [{ role: "user", content: "hi" }],
      prediction: { type: "content", content: `ssn ${SSN}` },
      user: EMAIL, metadata: { name: "Alice Lee", id: SSN, plan: "pro" },
    });
    const { body, text } = last(sent);
    expect(body.prediction).toEqual({ type: "content", content: "ssn <SSN_1>" });
    expect(body.user).toBe("<EMAIL_1>");
    // "name" and "id" are fields of the application's record here, not protocol
    expect(body.metadata.id).toBe("<SSN_1>");
    expect(body.metadata.plan).toBe("pro");
    expect(text).not.toContain(SSN);
    expect(text).not.toContain(EMAIL);
    expect(text).not.toContain("Alice Lee");
  });

  it("an opaque user id is left alone", async () => {
    const sent: Sent = [];
    await openai(sent).chat.completions.create({
      model: "m", messages: [{ role: "user", content: "hi" }], user: "u_8841", safety_identifier: "acct-77",
    } as any);
    expect(last(sent).body.user).toBe("u_8841");
    expect(last(sent).body.safety_identifier).toBe("acct-77");
  });

  it("OpenAI responses: the variables of a stored prompt", async () => {
    const sent: Sent = [];
    await openai(sent).responses.create({
      model: "m", input: "hi", user: EMAIL,
      prompt: { id: "pmpt_1", version: "2", variables: { name: "Alice Lee", id: SSN } },
    } as any);
    const { body, text } = last(sent);
    expect(body.prompt.id).toBe("pmpt_1");
    expect(body.prompt.version).toBe("2");
    expect(body.prompt.variables.id).toBe("<SSN_1>");
    expect(body.user).toBe("<EMAIL_1>");
    expect(text).not.toContain(SSN);
    expect(text).not.toContain("Alice Lee");
  });

  it("Anthropic: metadata.user_id", async () => {
    const sent: Sent = [];
    const client = anthropic(sent);
    await client.messages.create({ model: "m", max_tokens: 8, messages: [{ role: "user", content: "hi" }], metadata: { user_id: EMAIL } });
    expect(last(sent).body.metadata).toEqual({ user_id: "<EMAIL_1>" });
    await client.messages.create({ model: "m", max_tokens: 8, messages: [{ role: "user", content: "hi" }], metadata: { user_id: "u_8841" } });
    expect(last(sent).body.metadata).toEqual({ user_id: "u_8841" });
  });
});
