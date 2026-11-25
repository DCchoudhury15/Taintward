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

import { createReadStream, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import { describe, expect, it, vi } from "vitest";
import { BatchFileError, protectAnthropic, protectOpenAI } from "../src/index.js";

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

  it("a batch request is sent with masks, and warns once", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const sent: Sent = [];
      const client = anthropic(sent);
      const requests = [
        { custom_id: "a1", params: { model: "m", max_tokens: 8, system: `mail ${EMAIL}`, messages: ASK, metadata: { user_id: EMAIL } } },
        { custom_id: "a2", params: { model: "m", max_tokens: 8, messages: [{ role: "user" as const, content: "hello" }] } },
      ];
      for (let i = 0; i < 2; i++) await client.messages.batches.create({ requests }).catch(() => {});
      const { body, text } = last(sent);
      expect(text).not.toContain(SSN);
      expect(text).not.toContain(EMAIL);
      // masks, not placeholders: nothing could put the values back later
      expect(body.requests[0].params.messages[0].content).toBe("my ssn is [PII]");
      expect(body.requests[0].params.system).toBe("mail [PII]");
      expect(body.requests[0].params.metadata).toEqual({ user_id: "[PII]" });
      expect(body.requests[0].custom_id).toBe("a1");
      expect(body.requests[1].params.messages[0].content).toBe("hello");
      expect(warn.mock.calls.filter((c) => String(c[0]).includes("messages.batches requests are sent with one-way masks")).length).toBe(1);
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

describe("a tool result given as a list of records", () => {
  it("is redacted in full; protocol parts stay valid", async () => {
    const sent: Sent = [];
    await openai(sent).chat.completions.create({
      model: "m",
      messages: [
        { role: "user", content: [{ type: "text", text: `ssn ${SSN}` }, { type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } }] },
        // "name" and "id" are the application's fields here, not protocol
        { role: "tool", tool_call_id: "t1", content: [{ name: "Alice Lee", id: SSN, status: "active" }] as any },
      ],
    });
    const { body, text } = last(sent);
    expect(text).not.toContain(SSN);
    expect(text).not.toContain("Alice Lee");
    const user = body.messages.find((m: any) => m.role === "user");
    const tool = body.messages.find((m: any) => m.role === "tool");
    expect(user.content[0]).toEqual({ type: "text", text: "ssn <SSN_1>" });
    expect(user.content[1]).toEqual({ type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } });
    expect(tool.tool_call_id).toBe("t1");
    expect(tool.content[0].id).toBe("<SSN_1>");
    expect(tool.content[0].status).toBe("active");
  });
});

describe("OpenAI batch files", () => {
  const FILE = { id: "file-1", object: "file", bytes: 1, created_at: 1, filename: "b.jsonl", purpose: "batch", status: "processed" };
  const LINES = [
    { custom_id: "c1", method: "POST", url: "/v1/chat/completions", body: { model: "m", messages: ASK, user: EMAIL, metadata: { name: "Alice Lee", plan: "pro" } } },
    { custom_id: "r1", method: "POST", url: "/v1/responses", body: { model: "m", input: `mail ${EMAIL}`, instructions: "be short" } },
    { custom_id: "e1", method: "POST", url: "/v1/embeddings", body: { model: "m", input: [`ssn ${SSN}`, "plain"] } },
  ];
  const JSONL = LINES.map((l) => JSON.stringify(l) + "\n").join("");

  type Upload = { name: string; text: string };
  function filesClient(uploads: Upload[]) {
    const fetch = async (_url: unknown, init?: { body?: unknown }) => {
      const f = (init?.body as FormData).get("file") as File;
      uploads.push({ name: f.name, text: await f.text() });
      return Response.json(FILE);
    };
    return protectOpenAI(new OpenAI({ apiKey: "test", baseURL: "http://fake.local/v1", fetch: fetch as any, maxRetries: 0 }));
  }

  it("masks the requests in every file form, and warns once", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const uploads: Upload[] = [];
      const client = filesClient(uploads);
      const forms: Record<string, () => any> = {
        file: () => new File([JSONL], "mine.jsonl"),
        response: () => new Response(JSONL),
        "async iterable": () => (async function* () { yield JSONL.slice(0, 50); yield new TextEncoder().encode(JSONL.slice(50)); })(),
        "web stream": () => new Blob([JSONL]).stream(),
        "fs stream": () => {
          const path = join(mkdtempSync(join(tmpdir(), "tw-")), "disk.jsonl");
          writeFileSync(path, JSONL);
          return createReadStream(path);
        },
      };
      for (const [form, make] of Object.entries(forms)) {
        await client.files.create({ file: make(), purpose: "batch" });
        const { text } = uploads[uploads.length - 1]!;
        expect(text, form).not.toContain(SSN);
        expect(text, form).not.toContain(EMAIL);
        const [chat, resp, emb] = text.trim().split("\n").map((l) => JSON.parse(l));
        expect(chat.custom_id).toBe("c1");
        expect(chat.url).toBe("/v1/chat/completions");
        expect(chat.body.model).toBe("m");
        expect(chat.body.messages[0].content).toBe("my ssn is [PII]");
        expect(chat.body.user).toBe("[PII]");
        expect(chat.body.metadata).toEqual({ name: "[PII]", plan: "pro" });
        expect(resp.body.input).toBe("mail [PII]");
        expect(resp.body.instructions).toBe("be short");
        expect(emb.body.input).toEqual(["ssn [PII]", "plain"]);
      }
      expect(uploads[0]!.name).toBe("mine.jsonl");
      expect(uploads[uploads.length - 1]!.name).toBe("disk.jsonl");
      expect(warn.mock.calls.filter((c) => String(c[0]).includes("OpenAI batch files are sent with one-way masks")).length).toBe(1);
    } finally {
      warn.mockRestore();
    }
  });

  it("passes a file for another purpose through", async () => {
    const uploads: Upload[] = [];
    await filesClient(uploads).files.create({ file: new File([`keep me ${SSN}`], "notes.txt"), purpose: "assistants" });
    expect(uploads[0]!.text).toBe(`keep me ${SSN}`);
  });

  it.each([
    ['{"custom_id":"x","url":"/v1/new-thing","body":{"input":"234-12-1234"}}\n'],
    ['{"custom_id":"x","url":"/v1/chat/completions","body":{"messages":[]}}\nnot json 234-12-1234\n'],
    ['{"custom_id":"x","url":"/v1/chat/completions"}\n'],
    [new Uint8Array([0xff, 0xfe, 0x32])],
  ])("does not send a batch file it cannot read (%#)", async (bad) => {
    const uploads: Upload[] = [];
    await expect(filesClient(uploads).files.create({ file: new File([bad], "b.jsonl"), purpose: "batch" })).rejects.toThrow(BatchFileError);
    expect(uploads).toEqual([]);
  });
});
