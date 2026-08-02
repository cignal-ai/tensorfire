"""Auto-discovery of tool packs.

Every module in ``tensorfire.tools`` that defines a ``register(mcp)`` callable is
imported and registered at server startup. This is the whole extensibility
story: to add support for a new testing library you only create a new module
in that package — there is no central list to edit here.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

from . import tools as tools_pkg
from .tools._base import PackInfo

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("tensorfire.registry")


def discover_pack_modules() -> list[str]:
    """Return the importable names of every candidate tool-pack module."""
    names: list[str] = []
    for mod in pkgutil.iter_modules(tools_pkg.__path__):
        if mod.name.startswith("_"):
            continue  # private helpers like _base
        names.append(f"{tools_pkg.__name__}.{mod.name}")
    return sorted(names)


def register_all(mcp: "FastMCP") -> list[PackInfo]:
    """Import and register every discoverable pack. Returns their PackInfo.

    A pack that raises during import or registration is logged and skipped so a
    single broken/incompatible library never takes down the whole server.
    """
    packs: list[PackInfo] = []
    for module_name in discover_pack_modules():
        try:
            module = importlib.import_module(module_name)
        except Exception:  # noqa: BLE001 - defensive: never crash discovery
            logger.exception("failed to import tool pack %s", module_name)
            continue

        register = getattr(module, "register", None)
        if not callable(register):
            logger.debug("skipping %s: no register(mcp) function", module_name)
            continue

        try:
            info = register(mcp)
        except Exception:  # noqa: BLE001
            logger.exception("failed to register tool pack %s", module_name)
            continue

        if isinstance(info, PackInfo):
            packs.append(info)
            status = "ready" if info.available else "deps-missing"
            logger.info("registered pack '%s' (%s)", info.name, status)
        else:
            logger.warning("%s.register did not return PackInfo", module_name)

    return sorted(packs, key=lambda p: p.name)
