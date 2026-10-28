# Contributing

Thanks for helping. Small, focused pull requests are easiest to review.

## Set up

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev,mcp,langchain,openai-agents]"
python -m spacy download en_core_web_sm
```

## Before you open a pull request

```bash
python -m pytest -q                                    # Python tests
python -m ruff check .                                 # lint
cd collector/processor/taintpolicy && go test ./...   # Go policy processor
```

All three must pass. CI runs the same commands.

## Guidelines

- Use fake data only, in tests, examples and issues. Never paste real
  personal data or real keys.
- A change to detection should come with a benchmark run
  (`python bench/run_detection.py`) and the numbers in the pull request.
- A change to redaction or the vault needs a test that checks the raw value
  does not appear in the output.
- Keep docs in plain, simple English.

## Security issues

Please do not open a public issue. See [SECURITY.md](https://github.com/DCchoudhury15/Taintward/blob/main/SECURITY.md).
