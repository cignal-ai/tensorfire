<img alt="Tensorfire" src="https://raw.githubusercontent.com/cignal-ai/tensorfire/main/images/lockup-ink-red-1024.png" width="480">

An **MCP server** for **security- and compliance-testing AI systems**, exposed
behind one consistent tool interface:

- **garak vulnerability scanning** — probe any OpenAI-compatible (or local
  Ollama) LLM endpoint for jailbreaks, prompt injection, toxicity, and data
  leakage.
- **URL / MCP-endpoint scanning** — classify URLs for phishing/exfil traits and
  screen a remote MCP server's advertised tools for prompt-injection payloads.
- **AI compliance checklists** — NIST AI RMF 1.0 and ISO/IEC 42001 control
  checklists, plus scoring, so an agent can assess whether a pipeline or
  architecture is compliant against a real framework.

Point any MCP client (an agent, an IDE, CI) at the container and it gets these
as callable tools. Source: [github.com/cignal-ai/tensorfire](https://github.com/cignal-ai/tensorfire).

## Run it

```bash
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=your-key \
  -e OPENAI_BASE_URL=https://api.openai.com/v1 \
  cignalai/tensorfire:latest
```

This serves streamable HTTP on `http://localhost:8000/mcp`.

Or with Compose:

```yaml
services:
  tensorfire:
    image: cignalai/tensorfire:latest
    ports:
      - "8000:8000"
    environment:
      TENSORFIRE_TRANSPORT: streamable-http
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      OPENAI_BASE_URL: ${OPENAI_BASE_URL:-}
    restart: unless-stopped
```

## Tags

| Tag | Contents |
|-----|----------|
| `latest` | most recent build |
| `0.1.0` | pinned release |

## Configuration

All optional, via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `TENSORFIRE_HOST` | `0.0.0.0` | bind address |
| `TENSORFIRE_PORT` | `8000` | port |
| `TENSORFIRE_TRANSPORT` | `streamable-http` | set `stdio` for a stdio client |
| `TENSORFIRE_LOG_LEVEL` | `INFO` | log verbosity |

API keys for the models you're testing are read from the environment by
*name* — the agent passes `api_key_env` (e.g. `OPENAI_API_KEY`), never the key
itself. Provision the actual secret as a container env var.

## Verify it's up

```bash
curl -fsS http://localhost:8000/health
# {"status":"ok","server":"tensorfire","packs_total":4,"packs_ready":4}
```

Use `/health` for liveness — **never** probe `/mcp` with a bare GET; it
requires the MCP handshake and returns `406 Not Acceptable` by design.

## Connecting a client

Any MCP client that supports streamable HTTP:

```json
{ "mcpServers": { "tensorfire": { "url": "http://localhost:8000/mcp" } } }
```

Clients should call `tensorfire_catalog` first to see which tool packs are
installed, then call tools by name.

## AI compliance (NIST AI RMF / ISO 42001)

`ai_compliance` doesn't scan your repo itself — it supplies the framework
checklist and scoring; the calling agent inspects your actual pipeline and
reports back. Call `list_compliance_frameworks`, then `get_compliance_controls`
to pull the checklist for `nist_ai_rmf` or `iso_42001`, then `assess_compliance`
with your per-control findings to get a scored gap-analysis report. NIST AI RMF
is represented faithfully at the Function/Category level (public domain); ISO
42001 is a licensed standard, so only a structural summary is included — not a
substitute for the official text in an audit.

Full docs, source, and issues: [github.com/cignal-ai/tensorfire](https://github.com/cignal-ai/tensorfire).
