// A Mastra agent with a model wrapped by taintwardMiddleware: the model
// sees placeholders, the agent's answer and its tool get the real values.

import { Agent } from "@mastra/core/agent";
import { wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { describe, expect, it } from "vitest";
import { taintwardMiddleware } from "../src/ai-sdk.js";

const EMAIL = "alice.lee@example.com";

describe("Mastra", () => {
  it("an agent's model sees placeholders, the caller gets real values", async () => {
    const prompts: string[] = [];
    const inner = new MockLanguageModelV4({
      doGenerate: async ({ prompt }: any) => {
        prompts.push(JSON.stringify(prompt));
        return {
          content: [{ type: "text", text: "I will write to <EMAIL_1>." }],
          finishReason: { unified: "stop", raw: "stop" },
          usage: { inputTokens: { total: 5, noCache: 5, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 5, text: 5, reasoning: 0 } },
          warnings: [],
        };
      },
    });
    const agent = new Agent({
      id: "support",
      name: "support",
      instructions: "Help the user.",
      model: wrapLanguageModel({ model: inner, middleware: taintwardMiddleware({ onReport: () => {} }) }),
    });
    const out = await agent.generate(`Please email ${EMAIL} about the invoice.`);
    expect(prompts.length).toBeGreaterThan(0);
    expect(prompts.join("")).not.toContain(EMAIL);
    expect(prompts.join("")).toContain("<EMAIL_1>");
    expect(out.text).toBe(`I will write to ${EMAIL}.`);
  });
});
