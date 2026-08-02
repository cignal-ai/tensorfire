"""Built-in prompt-injection / jailbreak heuristics.

This pack has zero third-party dependencies, so it is always available and
serves as the reference example for authoring new packs. It provides a fast,
offline detector for prompt-injection and jailbreak patterns in a piece of
text (a user message, a retrieved document, a tool result, ...).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ._base import PackInfo, ok_result

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

INFO = PackInfo(
    name="prompt_injection",
    title="Prompt-injection heuristics",
    description="Offline detection of prompt-injection and jailbreak patterns in text.",
    requires=[],  # always available
    docs="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    tools=["scan_text_for_injection"],
)

# (label, weight, compiled pattern). Weights are summed into a 0-100-ish score.
_SIGNATURES: list[tuple[str, int, re.Pattern[str]]] = [
    ("instruction_override", 30, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b"
        r"(previous|prior|above|earlier|all)\b.{0,20}\b(instruction|prompt|rule|direction)",
        re.I)),
    ("system_prompt_exfil", 30, re.compile(
        r"\b(reveal|show|print|repeat|leak|tell me)\b.{0,30}"
        r"\b(system prompt|initial prompt|instructions|your rules|hidden prompt)", re.I)),
    ("role_manipulation", 20, re.compile(
        r"\b(you are now|pretend|act as|roleplay|from now on you)\b.{0,40}"
        r"\b(dan|developer mode|jailbreak|unrestricted|no restrictions|no rules)", re.I)),
    ("dan_jailbreak", 25, re.compile(
        r"\b(do anything now|DAN mode|stay in character|opposite mode|AIM)\b", re.I)),
    ("safety_bypass", 25, re.compile(
        r"\b(bypass|disable|turn off|remove|ignore)\b.{0,30}"
        r"\b(safety|guardrail|filter|moderation|content policy|restriction)", re.I)),
    ("encoding_smuggling", 15, re.compile(
        r"\b(base64|rot13|hex decode|reverse the following|decode this)\b", re.I)),
    ("data_exfil_instruction", 20, re.compile(
        r"\b(send|post|exfiltrate|upload|email)\b.{0,30}"
        r"\b(to|the following url|http|api key|secret|credential)", re.I)),
    ("hidden_instruction_markers", 15, re.compile(
        r"(\[/?(system|inst|assistant)\]|<\|?im_start\|?>|###\s*(system|instruction))", re.I)),
    ("tool_hijack", 20, re.compile(
        r"\b(call|invoke|use)\b.{0,20}\b(tool|function)\b.{0,40}"
        r"\b(delete|exfiltrate|transfer|send|leak)", re.I)),
]

_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁯﻿]")


def _scan(text: str) -> dict:
    findings = []
    score = 0
    for label, weight, pattern in _SIGNATURES:
        for m in pattern.finditer(text):
            score += weight
            findings.append({
                "type": label,
                "weight": weight,
                "match": m.group(0)[:160],
                "span": [m.start(), m.end()],
            })
    invisible = _INVISIBLE.findall(text)
    if invisible:
        score += 20
        findings.append({
            "type": "invisible_unicode",
            "weight": 20,
            "match": f"{len(invisible)} hidden/bidi control characters",
            "span": None,
        })

    score = min(score, 100)
    verdict = "high" if score >= 50 else "medium" if score >= 25 else "low" if score else "clean"
    return {
        "score": score,
        "verdict": verdict,
        "finding_count": len(findings),
        "findings": findings,
    }


def register(mcp: "FastMCP") -> PackInfo:
    @mcp.tool(
        name="scan_text_for_injection",
        description=(
            "Scan a piece of text (user input, retrieved document, tool output) "
            "for prompt-injection and jailbreak patterns. Offline heuristic; "
            "returns a risk score, verdict, and matched findings."
        ),
    )
    def scan_text_for_injection(text: str) -> dict:
        return ok_result(pack=INFO.name, input_chars=len(text), **_scan(text))

    return INFO
