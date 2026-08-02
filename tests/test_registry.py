"""Tests for pack discovery and server assembly."""
from tensorfire.registry import discover_pack_modules, register_all
from tensorfire.server import build_server
from tensorfire.tools._base import PackInfo


def test_all_expected_packs_discovered():
    modules = discover_pack_modules()
    names = {m.rsplit(".", 1)[-1] for m in modules}
    assert {"prompt_injection", "mcp_url_scan", "garak_scan"} <= names
    assert "_base" not in names  # private modules excluded


def test_server_builds_and_registers_packs():
    mcp = build_server()
    assert mcp is not None


def test_builtin_packs_report_available():
    from mcp.server.fastmcp import FastMCP

    packs = register_all(FastMCP("test"))
    by_name = {p.name: p for p in packs}
    assert isinstance(by_name["prompt_injection"], PackInfo)
    # Built-ins have no third-party deps, so they are always available.
    assert by_name["prompt_injection"].available is True
    assert by_name["mcp_url_scan"].available is True


def test_garak_pack_registers():
    """The garak pack always registers (so the catalog is complete); whether it
    is available depends on whether the garak library is installed."""
    from mcp.server.fastmcp import FastMCP

    by_name = {p.name: p for p in register_all(FastMCP("test"))}
    assert "garak" in by_name
    assert by_name["garak"].requires == ["garak"]
