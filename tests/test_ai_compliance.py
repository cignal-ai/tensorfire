"""Unit tests for the ai_compliance pack (no third-party deps needed)."""
from tensorfire.tools._compliance_data import FRAMEWORKS
from tensorfire.tools.ai_compliance import _build_report, _controls_by_id, _framework


def test_frameworks_have_unique_control_ids():
    for fw in FRAMEWORKS.values():
        ids = [c["id"] for c in fw["controls"]]
        assert len(ids) == len(set(ids))


def test_known_and_unknown_framework_lookup():
    assert _framework("nist_ai_rmf") is not None
    assert _framework("iso_42001") is not None
    assert _framework("does_not_exist") is None


def test_nist_groups_cover_all_four_functions():
    fw = _framework("nist_ai_rmf")
    groups = {c["group"] for c in fw["controls"]}
    assert groups == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_build_report_scores_met_and_gap():
    fw = _framework("nist_ai_rmf")
    controls = _controls_by_id(fw)
    all_ids = list(controls.keys())
    findings = [{"control_id": all_ids[0], "status": "met", "evidence": "x"}]
    report = _build_report(fw, findings)

    assert report["overall"]["counts"]["met"] == 1
    # every other control is unassessed since only one finding was supplied
    assert report["overall"]["counts"]["unassessed"] == len(all_ids) - 1
    assert 0 <= report["overall"]["coverage_pct"] <= 100
    assert "report_markdown" in report and report["framework"] == "nist_ai_rmf"


def test_build_report_not_applicable_excluded_from_denominator():
    fw = _framework("iso_42001")
    controls = _controls_by_id(fw)
    all_ids = list(controls.keys())
    findings = [
        {"control_id": all_ids[0], "status": "met", "evidence": "x"},
        {"control_id": all_ids[1], "status": "not_applicable", "evidence": "n/a here"},
    ]
    report = _build_report(fw, findings)
    # coverage denominator excludes the not_applicable control, so a single
    # 'met' among (total - 1) applicable controls is not 100%.
    assert report["overall"]["coverage_pct"] < 100
    assert report["overall"]["counts"]["not_applicable"] == 1


def test_build_report_gaps_include_unassessed_and_gap():
    fw = _framework("nist_ai_rmf")
    controls = _controls_by_id(fw)
    first_id = next(iter(controls))
    findings = [{"control_id": first_id, "status": "gap", "evidence": "missing policy"}]
    report = _build_report(fw, findings)
    gap_ids = {g["id"] for g in report["gaps"]}
    assert first_id in gap_ids
    # anything not covered by a finding shows up as a gap too (unassessed)
    assert len(gap_ids) == len(controls)
