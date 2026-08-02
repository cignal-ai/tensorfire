"""Shared helpers for Tensorfire tool packs.

A *tool pack* is a single module in ``tensorfire.tools`` that wraps one external
testing library (PyRIT, NeMo Guardrails, garak, ...) or a built-in capability.
Every pack exposes a module-level ``register(mcp) -> PackInfo`` function. The
registry (``tensorfire.registry``) auto-discovers and calls it at startup.

Adding a new pack = drop a new file in this directory that follows the pattern
in ``prompt_injection.py`` and (if it needs a third-party library) add that
library to the dependencies in ``pyproject.toml``. Nothing else needs editing.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PackInfo:
    """Metadata describing a tool pack, returned from ``register()``.

    A pack is available when the libraries it needs (``requires``) import in the
    server process. Built-in packs declare no requirements and are always
    available.
    """

    name: str
    title: str
    description: str
    # pip-importable module names this pack needs to run.
    requires: list[str] = field(default_factory=list)
    # pip install spec shown to the user when the pack is unavailable.
    install: str = ""
    docs: str = ""
    tools: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return not missing_modules(*self.requires)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "available": self.available,
            "missing_dependencies": [] if self.available else missing_modules(*self.requires),
            "install": self.install,
            "docs": self.docs,
            "tools": self.tools,
        }


def module_present(name: str) -> bool:
    """True if ``name`` can be imported, without importing it (fast, no side effects)."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def missing_modules(*names: str) -> list[str]:
    return [n for n in names if not module_present(n)]


def dependency_error(pack: PackInfo) -> dict[str, Any]:
    """Standard structured result when a pack's dependencies are not installed."""
    return {
        "ok": False,
        "error": "dependency_unavailable",
        "pack": pack.name,
        "missing_dependencies": missing_modules(*pack.requires),
        "hint": f"Install with: {pack.install}" if pack.install else "",
    }


def error_result(kind: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": kind, "message": message, **extra}


def ok_result(**data: Any) -> dict[str, Any]:
    return {"ok": True, **data}
