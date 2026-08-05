<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/lockup-on-dark-padded.png">
  <img alt="Tensorfire" src="images/lockup-ink-red-1024.png" width="480">
</picture>

An **MCP server**, shipped as a container image, for **security- and
compliance-testing AI systems**. It exposes these behind one consistent tool
interface:

- **garak vulnerability scanning** — probe any OpenAI-compatible LLM endpoint
  for jailbreaks, prompt injection, toxicity, and data leakage.
- **URL / MCP-endpoint scanning** — classify URLs for phishing/exfil traits and
  screen a remote MCP server's advertised tools for prompt-injection payloads.
- **AI compliance checklists** — NIST AI RMF 1.0 and ISO/IEC 42001 control
  checklists, plus scoring, so an agent can assess whether a pipeline or
  architecture is compliant against a real framework instead of guessing.

Point any MCP client (an agent, an IDE, CI) at the server and it gets these as
callable tools.

## What Tensorfire is, and why we built it

AI security tooling is scattered across libraries that each bring their own CLI,
config, and integration work. Wiring even one of them into an agent or a CI
pipeline is repetitive glue.

Tensorfire puts that capability behind a single **Model Context Protocol** surface,
so running a security test is a tool call rather than an integration project.
This initial release keeps the scope deliberately small — an LLM vulnerability
scan and URL/MCP screening — with room to add more tools over time.

Design principles:

- **Graceful degradation.** The server always starts and always advertises its
  catalog. If an optional dependency is missing, the tool returns a structured
  "dependency unavailable" result instead of crashing.
- **Extensible.** Tools are auto-discovered — dropping a module into
  `src/tensorfire/tools/` adds a pack with no central wiring.
- **Secrets stay out of tool calls.** Tools that hit a live model take the
  *name* of an environment variable holding the API key, never the key itself.

### Tools

| Pack | Backed by | Tools |
|------|-----------|-------|
| `garak` | [garak](https://garak.ai) | `garak_list_probes`, `garak_scan` |
| `mcp_url_scan` | built-in (MCP SDK) | `classify_url`, `scan_mcp_endpoint` |
| `prompt_injection` | built-in (offline) | `scan_text_for_injection` |
| `ai_compliance` | built-in (offline) | `list_compliance_frameworks`, `get_compliance_controls`, `assess_compliance` |

Plus `tensorfire_catalog`, which lists every pack and whether it's installed.
**Clients should call it first.**

## Deploy with Docker

```bash
# Build and run. Serves streamable HTTP on http://localhost:8000/mcp.
docker compose up --build
```

`docker-compose.yml` passes target-model secrets from your shell environment
(`OPENAI_API_KEY`, `OPENAI_BASE_URL`) into the container and mounts `./workspace`
read-only for any files your tools need to reach.

Without compose:

```bash
docker build -t tensorfire:latest .
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=your-key \
  -e OPENAI_BASE_URL=https://api.openai.com/v1 \
  tensorfire:latest
```

## Deploy locally (no container)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # installs the server + garak
tensorfire                          # serves http://localhost:8000/mcp
```

`pip install` pulls garak (and its ML dependencies), so the first install is
large. Everything runs in this one environment — there is no separate build
step.

### Configuration

All optional, via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `TENSORFIRE_HOST` | `0.0.0.0` | bind address |
| `TENSORFIRE_PORT` | `8000` | port |
| `TENSORFIRE_TRANSPORT` | `streamable-http` | set `stdio` for a stdio client |
| `TENSORFIRE_LOG_LEVEL` | `INFO` | log verbosity |

### Verify it's up

```bash
curl -fsS http://localhost:8000/health
# {"status":"ok","server":"tensorfire","packs_total":4,"packs_ready":4}
```

Use `/health` for liveness — **never** probe `/mcp` with a bare GET; it requires
the MCP handshake and returns `406 Not Acceptable` by design.

## Connecting a client

Any MCP client that supports streamable HTTP:

```json
{ "mcpServers": { "tensorfire": { "url": "http://localhost:8000/mcp" } } }
```

Clients should call `tensorfire_catalog` first, then call tools by name.

## Running a garak scan

`garak_scan` defaults to a **local Ollama** server — no API key required.

- `model` — the Ollama model name (e.g. `llama3.1`, `gemma4:26b-a4b-it-q8_0`).
- `base_url` — only if Ollama isn't on `127.0.0.1:11434` (e.g.
  `http://ollama:11434` when the server runs in another container). It's
  normalized to the `host:port` garak's Ollama client expects.
- `probes` — comma-separated probe families (e.g. `"promptinject,dan"`); omit
  for garak's default set. Use `garak_list_probes` to see what's available.

Minimal call:

```json
{ "model": "gemma4:26b-a4b-it-q8_0", "probes": "promptinject", "generations": 1 }
```

### Testing an OpenAI-compatible endpoint instead

Set `model_type` to `openai` or `openai.OpenAICompatible`, `base_url` to the
endpoint, and `api_key_env` to the name of the env var (in the server's
environment) holding the key:

```json
{
  "model": "gpt-4o-mini",
  "model_type": "openai",
  "api_key_env": "OPENAI_API_KEY",
  "probes": "promptinject"
}
```

**API keys are never tool arguments.** The agent passes `api_key_env` — the
*name* of an environment variable inside the Tensorfire container that holds the
key. Provision the actual secret via `docker-compose.yml` or `-e`.

## Assessing AI compliance (NIST AI RMF / ISO 42001)

`ai_compliance` doesn't scan your repo itself — Tensorfire only sees what's
passed to it over MCP. It supplies the grounded framework knowledge and the
scoring; the calling agent (which has your actual pipeline/architecture in
front of it) does the per-control judgment. Workflow:

1. `list_compliance_frameworks` — see what's available (`nist_ai_rmf`, `iso_42001`).
2. `get_compliance_controls` — pull the checklist, optionally filtered to one
   `group` (e.g. `"GOVERN"` for NIST, `"Annex A (controls)"` for ISO). Each
   control has an `id`, `title`, `description`, and non-exhaustive
   `illustrative_practices`.
3. Inspect the target pipeline/architecture against each control yourself.
4. `assess_compliance` — report back `{control_id, status, evidence}` per
   control you assessed (`status` is `met` / `partial` / `gap` /
   `not_applicable`; anything you didn't cover comes back `unassessed`). You
   get a per-group coverage score, a prioritized gap list, and a markdown
   report.

The raw checklists are also exposed as resources: `compliance://nist-ai-rmf`
and `compliance://iso-42001`.

**Fidelity note:** NIST AI RMF 1.0 is public domain and its Function/Category
structure (`GOVERN`/`MAP`/`MEASURE`/`MANAGE`) is represented faithfully; the
`illustrative_practices` are our own paraphrased examples, not official NIST
subcategory text. ISO/IEC 42001 is a licensed standard we don't have
redistribution rights to — what's here is a structural summary (clause
numbers, Annex A control-theme titles) for orienting a review, **not** a
substitute for the official controlled text in an actual certification audit.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Trademark notice

Cignal tensorfire™ is an open-source, community-driven project supported by
Cignal LLC. TensorFlow® is a registered trademark of Google LLC. Cignal
tensorfire and Cignal are not affiliated with, endorsed by, or sponsored by
Google LLC.
