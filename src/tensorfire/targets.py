"""Description of a *target* — the AI system under test.

Most packs test an OpenAI-compatible chat endpoint (OpenAI, Azure OpenAI,
vLLM, Ollama's ``/v1``, TGI, LiteLLM proxy, etc.). This module gives every
pack one consistent way to describe and reach such a target so tools take the
same parameters and secrets never travel over the wire as arguments.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class TargetSpec:
    """An OpenAI-compatible chat target.

    The API key is never passed as a tool argument; ``api_key_env`` names the
    environment variable (inside the Tensorfire container) that holds it.
    """

    model: str
    base_url: str | None = None  # None -> library default (api.openai.com)
    api_key_env: str = "OPENAI_API_KEY"

    def resolve_api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)

    def describe(self) -> dict:
        return {
            "model": self.model,
            "base_url": self.base_url or "https://api.openai.com/v1",
            "api_key_env": self.api_key_env,
            "api_key_present": self.resolve_api_key() is not None,
        }
