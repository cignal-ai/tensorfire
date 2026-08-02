"""garak — LLM vulnerability scanner (https://garak.ai).

garak ships a stable CLI, so this pack drives ``python -m garak`` in the current
interpreter and parses its JSONL report — no runner script needed. garak is a
normal dependency of the server (see pyproject.toml), so it runs in-process.

Scans are long-running (one model call per prompt × generations), so the runner
streams garak's output live: every line is logged by the server and progress is
forwarded to the MCP client via log + progress notifications.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import TYPE_CHECKING, Awaitable, Callable
from urllib.parse import urlparse

import anyio

from mcp.server.fastmcp import Context

from ._base import PackInfo, dependency_error, error_result, ok_result

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("tensorfire.garak")

# Matches a garak tqdm progress line, e.g.
#   "probes.promptinject.HijackHateHumans:  42%|████  | 21/50 [00:30<00:40, ...]"
_TQDM_RE = re.compile(r"(probes\.\S+|detectors\.\S+):\s+(\d+)%\|[^|]*\|\s*(\d+)/(\d+)")


def _ollama_host(base_url: str) -> str:
    """Normalize a URL to the ``host:port`` form garak's Ollama client wants.

    Accepts things like ``http://localhost:11434``, ``localhost:11434/v1``, or a
    bare ``localhost`` and returns ``host[:port]`` (no scheme, no path).
    """
    raw = base_url.strip()
    parsed = urlparse(raw if "//" in raw else f"//{raw}")
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host or raw


INFO = PackInfo(
    name="garak",
    title="garak LLM vulnerability scanner",
    description="Probe an LLM endpoint for jailbreaks, prompt injection, toxicity, leakage, and more.",
    requires=["garak"],
    install="pip install garak",
    docs="https://docs.garak.ai/",
    tools=["garak_list_probes", "garak_scan"],
)

# Callback invoked for each output line garak emits, so tools can stream it.
LineHandler = Callable[[str], Awaitable[None]]


async def _run(
    args: list[str],
    env: dict,
    timeout: float,
    on_line: LineHandler | None = None,
) -> tuple[int, str]:
    """Run ``garak`` streaming its combined stdout/stderr line-by-line.

    Returns ``(returncode, full_output)``. If ``on_line`` is given it is awaited
    for every completed line (split on newlines *and* carriage returns, so tqdm
    progress bars come through as they update).
    """
    cmd = [sys.executable, "-m", "garak", *args]
    chunks: list[str] = []
    rc = -1

    try:
        with anyio.fail_after(timeout):
            async with await anyio.open_process(
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            ) as proc:
                buf = ""
                assert proc.stdout is not None
                async for chunk in proc.stdout:
                    text = chunk.decode(errors="replace")
                    chunks.append(text)
                    if on_line is None:
                        continue
                    buf += text
                    parts = re.split(r"[\r\n]+", buf)
                    buf = parts.pop()  # keep trailing partial line
                    for line in parts:
                        line = line.strip()
                        if line:
                            await on_line(line)
                if on_line is not None and buf.strip():
                    await on_line(buf.strip())
                await proc.wait()
                rc = proc.returncode if proc.returncode is not None else -1
    except TimeoutError:
        raise subprocess.TimeoutExpired(cmd, timeout)

    return rc, "".join(chunks)


def _make_line_handler(ctx: Context | None) -> LineHandler:
    """Build an on_line callback: server-log everything, forward progress to MCP."""
    state = {"key": None, "pct": -100, "t": 0.0}

    async def on_line(line: str) -> None:
        logger.info("garak | %s", line)
        if ctx is None:
            return
        m = _TQDM_RE.search(line)
        if m:
            key, pct, cur, tot = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            now = time.monotonic()
            # Throttle: new probe, ≥5% jump, or every 3s — avoids flooding.
            if key != state["key"] or pct >= state["pct"] + 5 or now - state["t"] > 3:
                state.update(key=key, pct=pct, t=now)
                try:
                    await ctx.report_progress(progress=cur, total=tot, message=f"{key} {pct}%")
                    await ctx.info(f"{key}: {pct}% ({cur}/{tot})")
                except Exception:  # noqa: BLE001 - never let logging break the scan
                    pass
        elif "%|" in line or "it/s" in line or "it]" in line:
            return  # unparsed tqdm noise
        else:
            try:
                await ctx.info(line)  # milestone line (loading, reporting, etc.)
            except Exception:  # noqa: BLE001
                pass

    return on_line


def register(mcp: "FastMCP") -> PackInfo:
    @mcp.tool(
        name="garak_list_probes",
        description="List the garak probe families available in this installation.",
    )
    async def garak_list_probes() -> dict:
        if not INFO.available:
            return dependency_error(INFO)
        try:
            rc, out = await _run(["--list_probes"], dict(os.environ), timeout=120)
        except subprocess.TimeoutExpired:
            return error_result("timeout", "listing probes timed out")
        probes = sorted({
            tok for line in out.splitlines() for tok in line.split()
            if tok.startswith("probes.")
        })
        return ok_result(pack=INFO.name, returncode=rc,
                         probes=probes or out.splitlines()[-200:])

    @mcp.tool(
        name="garak_scan",
        description=(
            "Run a garak vulnerability scan against an LLM. Defaults to a local "
            "Ollama server (no API key needed): pass `model` as the Ollama model "
            "name (e.g. 'llama3.1' or 'gemma4:26b-a4b-it-q8_0'); set `base_url` "
            "only if Ollama isn't on 127.0.0.1:11434. To test an OpenAI or "
            "OpenAI-compatible endpoint instead, set `model_type` to 'openai' or "
            "'openai.OpenAICompatible', `base_url` to the endpoint, and "
            "`api_key_env` to the env var holding the key. `probes` is a "
            "comma-separated list of probe families (e.g. 'promptinject,dan'); "
            "omit for garak's default set. Scans are slow (one model call per "
            "prompt × `generations`) and stream live progress via MCP log and "
            "progress notifications. Returns per-probe pass rates from the report."
        ),
    )
    async def garak_scan(
        ctx: Context,
        model: str,
        probes: str = "",
        model_type: str = "ollama",
        base_url: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        generations: int = 5,
        timeout_seconds: float = 1800.0,
    ) -> dict:
        if not INFO.available:
            return dependency_error(INFO)

        env = dict(os.environ)
        generator_options: dict | None = None

        if model_type.startswith("ollama"):
            # Native Ollama backend — talks to Ollama's own API, no key needed.
            if base_url:
                if "." in model_type:
                    gen_module, gen_class = model_type.split(".", 1)
                else:
                    gen_module, gen_class = model_type, "OllamaGeneratorChat"
                generator_options = {gen_module: {gen_class: {"host": _ollama_host(base_url)}}}
        else:
            # OpenAI / OpenAI-compatible backend — requires a key in the env.
            env.setdefault("OPENAI_API_KEY", os.environ.get(api_key_env, ""))
            if base_url:
                env["OPENAI_BASE_URL"] = base_url

        on_line = _make_line_handler(ctx)
        await on_line(f"starting garak: model={model} type={model_type} "
                      f"probes={probes or 'default'} generations={generations}")

        with tempfile.TemporaryDirectory() as tmp:
            prefix = os.path.join(tmp, "garak_run")
            args = [
                "--model_type", model_type,
                "--model_name", model,
                "--generations", str(generations),
                "--report_prefix", prefix,
            ]
            if probes.strip():
                args += ["--probes", probes.strip()]
            if generator_options is not None:
                args += ["--generator_options", json.dumps(generator_options)]

            try:
                rc, out = await _run(args, env, timeout=timeout_seconds, on_line=on_line)
            except subprocess.TimeoutExpired:
                return error_result("timeout", f"scan exceeded {timeout_seconds}s")

            report_path = f"{prefix}.report.jsonl"
            evals = []
            if os.path.exists(report_path):
                with open(report_path, encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if rec.get("entry_type") == "eval":
                            total = rec.get("total") or 0
                            passed = rec.get("passed") or 0
                            evals.append({
                                "probe": rec.get("probe"),
                                "detector": rec.get("detector"),
                                "passed": passed,
                                "total": total,
                                "pass_rate": round(passed / total, 4) if total else None,
                            })
            failed = [e for e in evals if e["pass_rate"] is not None and e["pass_rate"] < 1.0]
            await on_line(f"garak finished: rc={rc} evals={len(evals)} failing={len(failed)}")
            return ok_result(
                pack=INFO.name,
                model=model,
                returncode=rc,
                probes_run=probes or "default",
                evaluations=evals,
                vulnerable=sorted(failed, key=lambda e: e["pass_rate"] or 0)[:50],
                summary={"eval_count": len(evals), "failing_evals": len(failed)},
                stderr_tail=out[-2000:],
            )

    return INFO
