"""Tensorfire MCP server entry point."""
from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import settings
from .registry import register_all

logger = logging.getLogger("tensorfire")

INSTRUCTIONS = """\
Tensorfire is an AI model security testing toolbench exposed over MCP.

It provides garak (LLM vulnerability scanning) plus built-in prompt-injection
and MCP-endpoint/URL scanning.

Start with the `tensorfire_catalog` tool to see which packs are installed and what
tools they expose. `garak_scan` takes a `model` and optional `base_url` naming
an OpenAI-compatible endpoint; the API key is read from an environment variable
inside the container (named by `api_key_env`, never passed as an argument)."""


def build_server() -> FastMCP:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mcp = FastMCP(
        "tensorfire",
        instructions=INSTRUCTIONS,
        host=settings.host,
        port=settings.port,
    )

    packs = register_all(mcp)

    # Expose the live catalog as both a tool (agent-callable) and a resource.
    @mcp.tool(
        name="tensorfire_catalog",
        description=(
            "List every Tensorfire tool pack, whether its dependencies are "
            "installed, and the tools it exposes. Call this first."
        ),
    )
    def tensorfire_catalog() -> dict:
        return {
            "server": "tensorfire",
            "transport": settings.transport,
            "packs": [p.as_dict() for p in packs],
            "ready": [p.name for p in packs if p.available],
            "needs_install": [p.name for p in packs if not p.available],
        }

    @mcp.resource("tensorfire://catalog")
    def catalog_resource() -> dict:
        return tensorfire_catalog()

    # Plain-HTTP liveness endpoint for container/orchestrator health checks.
    # (Do not point health checks at /mcp — that endpoint requires the MCP
    # streamable-HTTP handshake and returns 406 to a bare GET.)
    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "ok",
            "server": "tensorfire",
            "packs_total": len(packs),
            "packs_ready": sum(1 for p in packs if p.available),
        })

    ready = [p.name for p in packs if p.available]
    logger.info(
        "tensorfire ready: %d/%d packs installed (%s)",
        len(ready),
        len(packs),
        ", ".join(ready) or "none",
    )
    return mcp


def main() -> None:
    mcp = build_server()
    logger.info(
        "starting tensorfire on %s:%s transport=%s",
        settings.host,
        settings.port,
        settings.transport,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
