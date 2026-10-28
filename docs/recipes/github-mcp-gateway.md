# Put the gateway in front of a GitHub MCP server

**Goal:** an agent uses the GitHub MCP server to read code and issues and to
open issues and comments. You want two things: secrets and personal data
found in repository content are masked before they reach the model, and data
the agent has seen does not get written into a public issue. No change to
the agent.

**Time:** about 15 minutes. **You need:** Docker, Python 3.11+, a GitHub
token for a test account, and an MCP client that starts servers as local
commands (most IDE agents and desktop chat clients do).

## 1. Install the gateway

```bash
python -m venv ~/.taintward && . ~/.taintward/bin/activate
pip install "taintward[mcp]"
python -m spacy download en_core_web_sm
```

## 2. Keep the GitHub token in a file

The gateway starts upstream servers with a minimal environment (it does not
pass your whole shell environment on), and the config file does not expand
`${VARS}`. Put the token in an env file that only you can read and let Docker
read it:

```bash
mkdir -p ~/.config/taintward
install -m 600 /dev/null ~/.config/taintward/github.env
echo "GITHUB_PERSONAL_ACCESS_TOKEN=<your token>" >> ~/.config/taintward/github.env
```

Use a fine-grained token limited to the repositories the agent needs.

## 3. Write the gateway config

`~/.config/taintward/github-gateway.yaml`:

```yaml
service_name: github-mcp-gateway

upstreams:
  - name: github
    command: docker
    args: ["run", "-i", "--rm",
           "--env-file", "/home/me/.config/taintward/github.env",
           "ghcr.io/github/github-mcp-server"]

# Anything not matched below: GitHub is a third party in the US.
defaults:
  destination: external
  jurisdiction: us
  mode: redact
  redact_results: true

tools:
  # Writes that can publish data: refuse them once the session has seen
  # sensitive data.
  - match: "create_*"
    mode: block
  - match: "add_*comment*"
    mode: block
  - match: "update_*"
    mode: block
  - match: "push_files"
    mode: block
  # Reads: the arguments (search queries, paths) go to GitHub, so they are
  # redacted; the results are masked before the model sees them.
  - match: "get_*"
  - match: "list_*"
  - match: "search_*"
```

Notes on the choices:

- **Every GitHub tool is `external`.** The arguments of every call leave
  your system. `internal` would hand GitHub reversible tokens, which is not
  what you want for a third party.
- **`redact_results: true`** (the default) masks secrets and PII in file
  contents, issues and comments before they go into the model context. A
  repository that contains an AWS key or a customer email address no longer
  hands it to the LLM.
- **`block` on writes.** The session taint is coarse on purpose: once any
  result in the session held sensitive data, every later write is blocked,
  even if its own arguments look clean. That is the point (the model may
  have rewritten the data), but it also blocks harmless writes after the
  agent read, for example, a file with an author email in it. If that is too
  strict for your use, use `redact` on writes, which masks values the
  detector finds and lets the call through.
- Tool names change between server versions. List what your version
  exposes (step 5) and adjust the globs. Pin the image to a version tag or
  digest once it works.

## 4. Point your MCP client at the gateway

Replace the GitHub server entry in your client's MCP config:

```json
{
  "mcpServers": {
    "github": {
      "command": "/home/me/.taintward/bin/taintward-gateway",
      "args": ["--config", "/home/me/.config/taintward/github-gateway.yaml",
               "--otlp-endpoint", "http://localhost:14319/v1/traces"]
    }
  }
}
```

The tools keep their names and input schemas, so prompts and the agent do
not change. Leave out `--otlp-endpoint` if you do not want spans; with the
quickstart stack running, spans go through the collector to Jaeger.

## 5. Check it

List the tools through the gateway with the MCP inspector:

```bash
npx @modelcontextprotocol/inspector \
  /home/me/.taintward/bin/taintward-gateway --config /home/me/.config/taintward/github-gateway.yaml
```

Then, in a test repository you own, commit a file with fake data:

```text
contact: alice.lee@example.com
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
```

Ask the agent to read the file and then to open an issue that quotes it.

- The model sees `[PII]` and `[SECRET]` in place of the email and key.
- The issue is not created. The agent gets an MCP error with code `-32001`
  that says `Taintward blocked tools/call create_issue: pii_egress, transfer`.
- In Jaeger, service `github-mcp-gateway`, the span
  `taintward.gateway create_issue` has `taintward.blocked=true`,
  `taintward.policy.rules=pii_egress,transfer` and `taintward.mode=block`.
  The `get_file_contents` span has `taintward.result.redacted=true`.

## 6. Run it for a team

Over HTTP the gateway can serve many clients:

```bash
export TAINTWARD_GATEWAY_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
taintward-gateway --config github-gateway.yaml --listen 0.0.0.0:8811
```

Clients then use `http://<host>:8811/mcp` with
`Authorization: Bearer <token>`. Note that every client then shares the one
GitHub token in the env file, so this fits a service account, not personal
tokens. For several replicas use Redis for sessions; see
[MCP gateway, Serving over HTTP](../mcp-gateway.md#serving-over-http) and
[Kubernetes and Helm](../deploy-kubernetes.md).

## Limits

- Only tools are proxied. Resources and prompts of the GitHub server are not
  forwarded.
- Images and binary file contents pass through unscanned.
- Detection is pattern and model based. A secret in a format the detectors
  do not know is not masked; see the [Detection benchmark](../benchmark.md).
