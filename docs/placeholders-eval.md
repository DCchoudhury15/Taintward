# Do real models keep placeholders intact?

Taintward sends `<PERSON_1>`, `<EMAIL_1>`, `<SSN_1>` to the model instead of the
real values, and swaps the real values back into the answer and the tool call
arguments. That only works if the model writes the placeholders back in a form
Taintward can find. Until now every test used fake models. This page measures
real ones.

All data in the tasks and on this page is fake.

## How it was measured

`bench/placeholders/` runs 47 small agent tasks through the real product path:
an OpenAI client patched with `protect_openai`, pointed at Ollama's OpenAI API
(and once through a protected LangChain `ChatOpenAI`). The app side acts like a
real app: it keeps the history, runs the fake tools with the arguments it gets
back, and sends the restored answers back in the next turn.

Task groups: emails and letters (8), summaries of records (6), JSON extraction
(6), tool calls such as `send_email(to, body)` and `lookup_customer(ssn)` (8),
multi-turn chats (5), translation into Spanish, French, German, Hindi,
Japanese and Chinese (6), lists of several people (4), code with a key (4).

Every HTTP request and response is recorded, so the harness sees what really
left the process and what the model really wrote. Per task it checks:

- **restore ok**: the final answer has the right real values, JSON fields and
  tool arguments are right, and no placeholder is left over.
- **placeholders back**: placeholders the task needed that came back in a
  form Taintward restored (anywhere in the answers or tool calls).
- **copied exactly**: of those, how many the model wrote exactly as `<PERSON_1>`.
- **rewritten, not restored**: the model wrote a changed form (`[PERSON_1]`,
  `Person 1`) that was not restored. **dropped**: the model left it out.
- **wrong restore**: a slot got a different real value and the model did not
  ask for it (a Taintward bug). **model mix-up**: the model itself used the
  wrong placeholder (for example the other person's email).
- **raw value sent**: a value Taintward knew was in a request. Must be 0.
- **failures flagged**: failed tasks where the new check put
  `taintward.placeholders.lost` / `.unknown` on the span.

Modes:

- **baseline**: Taintward 0.2.0 behaviour (exact restore only, no instruction).
- **baseline answers + tolerant restore (offline)**: the same saved baseline
  answers restored again with the new rules. No new model calls, tool tasks
  kept as they were. This shows what the restore rules alone give.
- **hardened**: the new defaults (instruction, tolerant restore, the check).

Models: `qwen2.5:3b`, `llama3.2:3b`, `qwen2.5-coder:7b`, temperature 0, on a
laptop CPU. OpenAI and Anthropic runs are supported but were skipped (no keys).

## Results

| model | mode | restore ok | placeholders back | copied exactly | rewritten, not restored | dropped | tool args ok | wrong restore | model mix-up | leftover | raw value sent |
|---|---|---|---|---|---|---|---|---|---|---|---|
| qwen2.5:3b | baseline | 25/47 | 69/92 | 69/92 | 11 | 12 | 0/9 | 0 | 0 | 17 | 0 |
| qwen2.5:3b | tolerant restore only | 29/47 | 77/92 | 69/92 | 3 | 12 | 0/9 | 0 | 0 | 10 | 0 |
| qwen2.5:3b | hardened | **37/47** | 83/95 | 74/95 | 0 | 12 | 7/9 | 0 | 1 | 0 | 0 |
| qwen2.5:3b (LangChain) | hardened | **37/47** | 83/95 | 74/95 | 0 | 12 | 7/9 | 0 | 1 | 0 | 0 |
| llama3.2:3b | baseline | 9/47 | 32/92 | 32/92 | 30 | 30 | 0/9 | 0 | 0 | 26 | 0 |
| llama3.2:3b | tolerant restore only | 21/47 | 61/92 | 32/92 | 3 | 28 | 0/9 | 0 | 0 | 12 | 0 |
| llama3.2:3b | hardened | **38/47** | 87/95 | 80/95 | 0 | 8 | 6/9 | 0 | 2 | 0 | 0 |
| qwen2.5-coder:7b | baseline | 23/47 | 66/92 | 66/92 | 15 | 11 | 0/9 | 0 | 0 | 9 | 0 |
| qwen2.5-coder:7b | hardened | **33/47** | 86/92 | 86/92 | 2 | 4 | 0/9 | 0 | 0 | 1 | 0 |

(The needed count moves from 92 to 95 because in a few tool tasks the tool
result brought new people into the run. The offline row is missing for
qwen2.5-coder because its baseline was saved before answers were kept.)

By task group, restore ok, baseline -> hardened:

| model | email | summary | json | tool | multi | translate | list | code |
|---|---|---|---|---|---|---|---|---|
| qwen2.5:3b | 3 -> 4 /8 | 5 -> 6 /6 | 5 -> 6 /6 | 0 -> 6 /8 | 1 -> 4 /5 | 6 -> 6 /6 | 3 -> 1 /4 | 2 -> 4 /4 |
| llama3.2:3b | 0 -> 6 /8 | 1 -> 5 /6 | 2 -> 6 /6 | 0 -> 5 /8 | 0 -> 3 /5 | 4 -> 6 /6 | 0 -> 3 /4 | 2 -> 4 /4 |
| qwen2.5-coder:7b | 1 -> 4 /8 | 4 -> 6 /6 | 6 -> 6 /6 | 0 -> 0 /8 | 2 -> 3 /5 | 5 -> 6 /6 | 3 -> 4 /4 | 2 -> 4 /4 |

No run sent a raw value that Taintward knew, and no run had a wrong restore.

## What the baseline showed

1. **Tool calls never worked with Ollama (0 of 9 for every model).** Ollama
   writes tool arguments as JSON with `<` escaped as `<`:
   `{"to":"<EMAIL_1>"}`. The old restore looked for `<` in the raw
   string, found nothing, and the tool got the text `<EMAIL_1>`. This was a plain
   bug, now fixed for both modes.
2. **Models rewrite placeholders.** Seen forms: `[PERSON_1]`, bare `PERSON_1`
   and `AWS_KEY_1` (very common in code and JSON), `Person 1 - Email 1`,
   `[Person_1]`, `\[PERSON_1]` (markdown), `<<EMAIL_1>>`, and translated labels
   such as `＜名前_1＞` and `＜メールアドレス_1＞` in Japanese.
3. **Models treat placeholders as blanks or as private data.** They write
   `Dear [Recipient's Full Name]` or `Dear Emily Johnson` instead of
   `<PERSON_1>`, or refuse: "I can't write a letter that includes someone's
   social security number" when they only ever saw `<SSN_1>`.
4. **Numbers follow reading order backwards.** In "Wei Chen ..., Priya
   Sharma ..." Wei gets `<PERSON_2>` and Priya `<PERSON_1>` (the redactor
   replaces spans from the end). Some models then reorder lists by number, and
   in one task llama sent the invoice to `<EMAIL_2>` when `<PERSON_1>` had asked.

## What changed

- **Placeholder instruction** (`Ward(placeholder_instruction=True)`, the
  default). When a request has placeholders, one short system line is added:
  it names the placeholders, says they stand for real values the user gave
  (not blanks, safe to repeat), and asks the model to copy them exactly, also
  in JSON, code, tool arguments and translations. It goes into the first system
  message (or a new one) for OpenAI chat, `instructions` for the Responses API,
  `system` for Anthropic, and a `SystemMessage` for LangChain. This gave the
  biggest gain, mostly by cutting refusals and template blanks.
- **Tolerant restore** (`PlaceholderMap(tolerant=True)`, the default):
  - other brackets: `[X_1]`, `{X_1}`, `{{X_1}}`, `(X_1)`, `«X_1»`, `＜X_1＞`,
    `【X_1】`, markdown escapes `\<X\_1\>` and `\[X_1]`;
  - case and separators inside brackets: `<Person 1>`, `<PERSON-1>`, `<Person1>`;
  - bare `PERSON_1` / `Person_1` (upper or title case only; `person_1` could
    be a variable name, so it is never restored);
  - `Person 1` with a space, only when the same answer has no real placeholder
    of that label and every `Person N` in it is in the map (otherwise it is
    probably a list number);
  - translated labels (`<PERSONA_1>`, `<NAME_1>`, `＜名前_1＞`, ...), only when
    the alias is not a real label in the map;
  - JSON strings are parsed first, so `<EMAIL_1>` is restored.
  A form is only restored when it names a placeholder in this run's map, so
  `[Step 1]`, `Table 2` or an invented `<PERSON_7>` are never touched.
- **Check after restore.** `check_output` looks at the model's answer before
  restore and records `taintward.placeholders.repaired`, `.lost` (a known
  placeholder in a form that is not safe to restore, like `<PERSON>` with no
  number) and `.unknown` (a placeholder not in the map) on the span, with
  placeholder forms only, never values. It logs a warning, and with
  `Ward(placeholder_strict=True)` it raises `PlaceholderRestoreError`.

## What still fails

- **Dropped values (8 to 12 per model).** The model writes `Dear [Full Name]`,
  leaves the email out, or refuses ("I can't repeat your SSN"). Restore cannot
  bring back what the model never wrote, and the check does not see it, which is
  why "failures flagged" stays low: the remaining failures are drops, not broken
  placeholders.
- **qwen2.5-coder through Ollama writes tool calls as JSON text** in the answer
  instead of real tool calls, so every tool task fails for it. Not a
  placeholder problem.
- **Model mix-ups** (1 to 2 per model): the wrong person in a list or the wrong
  email in `send_email`. Restore was right; the model picked the wrong
  placeholder. Numbering placeholders in reading order (a change in
  `redact.py`) would likely help and is left as a follow-up.
- **Detector misses** (4 values over the 47 tasks): some names, for example
  "Lukas Becker" in a table, are not detected and go to the model as they are.
  This is a detection issue, counted separately, not a placeholder issue.
- Forms such as `[Name of Person 2]` or `<YOUR_AWS_KEY_1>` are left alone on
  purpose: they could mean something else.

Small local models are a hard case. Larger hosted models will likely do better,
and the harness can measure that as soon as keys are set.

## How to run it

The real-model runs are slow and are not part of `pytest`.

```bash
ollama pull qwen2.5:3b
python bench/placeholders/run.py --provider ollama --model qwen2.5:3b --mode baseline
python bench/placeholders/run.py --provider ollama --model qwen2.5:3b --mode hardened
python bench/placeholders/run.py --provider langchain --model qwen2.5:3b   # needs langchain-openai
OPENAI_API_KEY=... python bench/placeholders/run.py --provider openai --model gpt-4o-mini
ANTHROPIC_API_KEY=... python bench/placeholders/run.py --provider anthropic --model claude-haiku-4-5
python bench/placeholders/run.py --replay    # baseline answers + tolerant restore, offline
python bench/placeholders/run.py --report    # the tables on this page
```

A provider without its key (or without a running Ollama) is skipped with a
message. Results are saved in `bench/placeholders/results/`. A small offline
smoke test of the harness with a fake model is in
`tests/test_placeholders_robust.py`.
