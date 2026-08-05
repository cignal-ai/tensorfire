"""AI compliance knowledge base: NIST AI RMF 1.0 and ISO/IEC 42001.

This pack does not (and cannot) inspect a caller's codebase itself — Tensorfire
only sees what's passed to it over MCP. Instead it supplies the grounded
framework knowledge and the scoring mechanics, and expects the *calling*
agent (which has the repo/architecture in front of it) to do the actual
per-control judgment. The intended workflow:

1. ``list_compliance_frameworks`` - see what's available.
2. ``get_compliance_controls`` - pull the checklist (optionally filtered to one
   function/group) and walk it against the target pipeline/architecture.
3. ``assess_compliance`` - report back a status per control (``met`` /
   ``partial`` / ``gap`` / ``not_applicable``) with supporting evidence, and
   get back a scored gap-analysis report.

See ``_compliance_data.py`` for a note on the fidelity of each framework's
data (NIST AI RMF is public domain and represented faithfully at the
Function/Category level; ISO/IEC 42001 is a licensed standard and represented
only as a structural summary).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._base import PackInfo, error_result, ok_result
from ._compliance_data import FRAMEWORKS

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

INFO = PackInfo(
    name="ai_compliance",
    title="AI compliance knowledge base (NIST AI RMF / ISO 42001)",
    description=(
        "Structured NIST AI RMF 1.0 and ISO/IEC 42001 control checklists, plus "
        "scoring, for assessing whether an AI pipeline/architecture is compliant."
    ),
    requires=[],  # bundled data, no third-party deps
    docs="https://www.nist.gov/itl/ai-risk-management-framework",
    tools=["list_compliance_frameworks", "get_compliance_controls", "assess_compliance"],
)

_VALID_STATUSES = {"met", "partial", "gap", "not_applicable"}
_STATUS_WEIGHT = {"met": 1.0, "partial": 0.5, "gap": 0.0}


def _framework(framework: str) -> dict[str, Any] | None:
    return FRAMEWORKS.get(framework)


def _controls_by_id(fw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in fw["controls"]}


def _build_report(fw: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    controls = _controls_by_id(fw)
    findings_by_id = {f["control_id"]: f for f in findings if f.get("control_id") in controls}

    rows: list[dict[str, Any]] = []
    for control_id, control in controls.items():
        finding = findings_by_id.get(control_id)
        status: str = finding["status"] if finding else "unassessed"
        rows.append({
            "id": control_id,
            "group": control["group"],
            "title": control["title"],
            "status": status,
            "evidence": (finding or {}).get("evidence", ""),
        })

    def group_stats(group_rows: list[dict[str, Any]]) -> dict[str, Any]:
        applicable = [r for r in group_rows if r["status"] != "not_applicable"]
        scored = sum(_STATUS_WEIGHT.get(r["status"], 0.0) for r in applicable)
        coverage = round(100 * scored / len(applicable), 1) if applicable else None
        counts: dict[str, int] = {}
        for r in group_rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return {"coverage_pct": coverage, "counts": counts, "total": len(group_rows)}

    groups = list(dict.fromkeys(c["group"] for c in fw["controls"]))  # stable order
    by_group = {
        g: {**group_stats([r for r in rows if r["group"] == g]),
            "controls": [r for r in rows if r["group"] == g]}
        for g in groups
    }
    overall = group_stats(rows)
    gaps = sorted(
        (r for r in rows if r["status"] in {"gap", "unassessed"}),
        key=lambda r: (r["group"], r["id"]),
    )

    lines = [
        f"# Compliance assessment: {fw['name']}",
        "",
        (f"Overall coverage: **{overall['coverage_pct']}%** "
         f"({overall['counts'].get('met', 0)} met, "
         f"{overall['counts'].get('partial', 0)} partial, "
         f"{overall['counts'].get('gap', 0)} gap, "
         f"{overall['counts'].get('unassessed', 0)} unassessed, "
         f"{overall['counts'].get('not_applicable', 0)} not applicable "
         f"of {overall['total']} controls)"),
        "",
    ]
    for g in groups:
        stats = by_group[g]
        lines.append(f"## {g} - {stats['coverage_pct']}%")
        for r in stats["controls"]:
            marker = {"met": "[met]", "partial": "[partial]", "gap": "[GAP]",
                      "unassessed": "[unassessed]", "not_applicable": "[n/a]"}[r["status"]]
            lines.append(f"- {marker} `{r['id']}` {r['title']}")
        lines.append("")
    if gaps:
        lines.append("## Priority gaps")
        for r in gaps:
            lines.append(f"- `{r['id']}` ({r['group']}) {r['title']}")

    return {
        "framework": fw["id"],
        "framework_name": fw["name"],
        "overall": overall,
        "by_group": by_group,
        "gaps": gaps,
        "report_markdown": "\n".join(lines),
        "note": fw["note"],
    }


def register(mcp: "FastMCP") -> PackInfo:
    @mcp.tool(
        name="list_compliance_frameworks",
        description=(
            "List the AI compliance frameworks available for assessment "
            "(currently NIST AI RMF 1.0 and ISO/IEC 42001), with a summary and "
            "control counts. Call this first."
        ),
    )
    def list_compliance_frameworks() -> dict:
        return ok_result(
            pack=INFO.name,
            frameworks=[
                {
                    "id": fw["id"],
                    "name": fw["name"],
                    "publisher": fw["publisher"],
                    "version": fw["version"],
                    "url": fw["url"],
                    "summary": fw["summary"],
                    "note": fw["note"],
                    "control_count": len(fw["controls"]),
                    "groups": list(dict.fromkeys(c["group"] for c in fw["controls"])),
                }
                for fw in FRAMEWORKS.values()
            ],
        )

    @mcp.tool(
        name="get_compliance_controls",
        description=(
            "Get the control checklist for a framework (`nist_ai_rmf` or "
            "`iso_42001`), optionally filtered to one `group` (e.g. 'GOVERN' "
            "for NIST, or 'Annex A (controls)' for ISO). Each control has an "
            "`id`, `title`, `description`, and non-exhaustive "
            "`illustrative_practices`. Walk these against the target "
            "pipeline/architecture, then call `assess_compliance` with the "
            "results."
        ),
    )
    def get_compliance_controls(framework: str, group: str | None = None) -> dict:
        fw = _framework(framework)
        if fw is None:
            return error_result(
                "unknown_framework", f"'{framework}' is not a known framework",
                known_frameworks=list(FRAMEWORKS.keys()),
            )
        controls = fw["controls"]
        if group is not None:
            controls = [c for c in controls if c["group"] == group]
            if not controls:
                known_groups = list(dict.fromkeys(c["group"] for c in fw["controls"]))
                return error_result(
                    "unknown_group", f"'{group}' is not a group in {framework}",
                    known_groups=known_groups,
                )
        return ok_result(
            pack=INFO.name,
            framework=fw["id"],
            framework_name=fw["name"],
            note=fw["note"],
            control_count=len(controls),
            controls=controls,
        )

    @mcp.tool(
        name="assess_compliance",
        description=(
            "Score a compliance assessment for a framework (`nist_ai_rmf` or "
            "`iso_42001`) given per-control findings you've made by inspecting "
            "the actual pipeline/architecture. `findings` is a list of objects: "
            "`{control_id, status, evidence}` where `status` is one of "
            "'met' | 'partial' | 'gap' | 'not_applicable', and `evidence` is a "
            "short note on what you observed (or why it's a gap). Controls with "
            "no matching finding are reported as 'unassessed'. Returns a "
            "per-group coverage score, a prioritized gap list, and a markdown "
            "report."
        ),
    )
    def assess_compliance(framework: str, findings: list[dict]) -> dict:
        fw = _framework(framework)
        if fw is None:
            return error_result(
                "unknown_framework", f"'{framework}' is not a known framework",
                known_frameworks=list(FRAMEWORKS.keys()),
            )
        controls = _controls_by_id(fw)
        bad = [
            f for f in findings
            if f.get("control_id") not in controls or f.get("status") not in _VALID_STATUSES
        ]
        if bad:
            return error_result(
                "invalid_findings",
                "each finding needs a valid control_id for this framework and a "
                "status in met/partial/gap/not_applicable",
                invalid_findings=bad,
                valid_control_ids=list(controls.keys()),
            )
        return ok_result(pack=INFO.name, **_build_report(fw, findings))

    @mcp.resource("compliance://nist-ai-rmf")
    def nist_ai_rmf_resource() -> dict:
        return FRAMEWORKS["nist_ai_rmf"]

    @mcp.resource("compliance://iso-42001")
    def iso_42001_resource() -> dict:
        return FRAMEWORKS["iso_42001"]

    return INFO
