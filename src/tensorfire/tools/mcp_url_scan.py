"""MCP endpoint + URL classification scanning.

Two capabilities, both dependency-light (only the MCP SDK + httpx, which
Tensorfire already depends on):

* ``classify_url`` — heuristic risk classification of a single URL (suspicious
  TLDs, IP-literal / punycode hosts, embedded credentials, shorteners, exotic
  schemes, phishing keywords).
* ``scan_mcp_endpoint`` — connect to another MCP server over streamable HTTP,
  enumerate its tools/resources/prompts, and screen every description for
  *tool poisoning* / prompt-injection ("MCP rug pull") and every embedded URL
  for risk. This is the "scan an MCP server before you trust it" workflow.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ._base import PackInfo, error_result, ok_result
from .prompt_injection import _scan as scan_injection

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

INFO = PackInfo(
    name="mcp_url_scan",
    title="MCP endpoint & URL scanner",
    description="Classify URLs and screen remote MCP servers for tool poisoning and injection.",
    requires=["mcp", "httpx"],
    install="(bundled with tensorfire core)",
    docs="https://modelcontextprotocol.io/specification",
    tools=["classify_url", "scan_mcp_endpoint"],
)

_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "kim", "work", "party", "gdn", "review", "loan", "rest",
}
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly",
}
_IP_LITERAL = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PHISHING_WORDS = re.compile(
    r"\b(login|verify|account|secure|update|confirm|wallet|seed|"
    r"password|credential|invoice|gift)\b", re.I)
_URL_IN_TEXT = re.compile(r"https?://[^\s\)\]\"'<>]+", re.I)


def _classify_url(url: str) -> dict:
    findings: list[dict] = []
    score = 0

    def add(kind: str, weight: int, detail: str) -> None:
        nonlocal score
        score += weight
        findings.append({"type": kind, "weight": weight, "detail": detail})

    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    if scheme in {"data", "javascript", "vbscript", "file"}:
        add("dangerous_scheme", 40, f"scheme '{scheme}'")
    elif scheme not in {"http", "https"}:
        add("unusual_scheme", 15, f"scheme '{scheme}'")
    if scheme == "http":
        add("cleartext_http", 10, "no TLS")

    if parsed.username or parsed.password:
        add("embedded_credentials", 35, "userinfo present in URL")
    if _IP_LITERAL.match(host):
        add("ip_literal_host", 25, host)
    if "xn--" in host:
        add("punycode_host", 25, "possible homoglyph/IDN spoofing")
    if host in _SHORTENERS:
        add("url_shortener", 20, host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        add("suspicious_tld", 20, f".{tld}")
    if host.count(".") >= 4:
        add("excessive_subdomains", 15, host)
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        add("nonstandard_port", 10, str(parsed.port))
    if _PHISHING_WORDS.search(url):
        add("phishing_keywords", 10, "credential/finance keywords in URL")
    if len(url) > 200:
        add("overlong_url", 10, f"{len(url)} chars")

    score = min(score, 100)
    verdict = "high" if score >= 45 else "medium" if score >= 20 else "low" if score else "clean"
    return {"url": url, "host": host, "score": score, "verdict": verdict, "findings": findings}


def _screen_description(name: str, text: str) -> dict | None:
    """Return a finding dict if a tool/resource description looks poisoned."""
    text = text or ""
    inj = scan_injection(text)
    urls = [_classify_url(u) for u in _URL_IN_TEXT.findall(text)]
    risky_urls = [u for u in urls if u["verdict"] in {"medium", "high"}]
    if inj["verdict"] in {"medium", "high"} or risky_urls:
        return {
            "name": name,
            "injection": {"score": inj["score"], "verdict": inj["verdict"],
                          "findings": inj["findings"]},
            "risky_urls": risky_urls,
        }
    return None


def register(mcp: "FastMCP") -> PackInfo:
    @mcp.tool(
        name="classify_url",
        description=(
            "Heuristically classify a single URL for risk (suspicious TLD, "
            "IP-literal or punycode host, embedded credentials, shorteners, "
            "dangerous schemes, phishing keywords). Offline; no network call."
        ),
    )
    def classify_url(url: str) -> dict:
        return ok_result(pack=INFO.name, **_classify_url(url))

    @mcp.tool(
        name="scan_mcp_endpoint",
        description=(
            "Connect to a remote MCP server over streamable HTTP, enumerate its "
            "tools/resources/prompts, and screen every description for tool "
            "poisoning / prompt injection and every embedded URL for risk. Use "
            "before trusting a third-party MCP server."
        ),
    )
    async def scan_mcp_endpoint(url: str, timeout_seconds: float = 20.0) -> dict:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except Exception as exc:  # noqa: BLE001
            return error_result("import_error", str(exc))

        poisoned: list[dict] = []
        inventory = {"tools": [], "resources": [], "prompts": []}
        try:
            async with streamablehttp_client(url) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    tools = (await session.list_tools()).tools
                    for t in tools:
                        inventory["tools"].append(t.name)
                        finding = _screen_description(f"tool:{t.name}", t.description or "")
                        if finding:
                            poisoned.append(finding)

                    try:
                        resources = (await session.list_resources()).resources
                        for r in resources:
                            inventory["resources"].append(str(r.uri))
                            finding = _screen_description(
                                f"resource:{r.uri}", r.description or "")
                            if finding:
                                poisoned.append(finding)
                    except Exception:  # noqa: BLE001 - server may not support resources
                        pass

                    try:
                        prompts = (await session.list_prompts()).prompts
                        for p in prompts:
                            inventory["prompts"].append(p.name)
                            finding = _screen_description(
                                f"prompt:{p.name}", p.description or "")
                            if finding:
                                poisoned.append(finding)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            return error_result("connection_error", str(exc), url=url)

        verdict = "high" if poisoned else "clean"
        return ok_result(
            pack=INFO.name,
            url=url,
            verdict=verdict,
            inventory=inventory,
            counts={k: len(v) for k, v in inventory.items()},
            poisoned=poisoned,
        )

    return INFO
