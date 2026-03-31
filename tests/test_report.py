from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_disk_audit.config import load_config
from codex_disk_audit.exports import build_summary, write_findings_json
from codex_disk_audit.models import CleanupUnit, WebCitation
from codex_disk_audit.report import render_report_html


def make_unit() -> CleanupUnit:
    return CleanupUnit(
        unit_id="unit-1",
        name="Vendor cache",
        path=r"C:\Users\demo\AppData\Local\Vendor\Cache",
        root_path=r"C:\Users\demo\AppData\Local\Vendor\Cache",
        item_kind="folder",
        unit_type="folder_unit",
        category="cache",
        zone="medium_risk_zone",
        risk="medium",
        confidence_score=72,
        confidence_label="medium",
        total_size_bytes=1024,
        file_count=4,
        display_size="1.0 KB",
        display_modified_at="2026-03-01",
        review_priority="review_next",
        review_priority_score=58,
        decision_focus="Likely generated data; worthwhile after top wins.",
        recommendation="Probably recreatable cache/temp; review likely worthwhile.",
        reason_summary="Cache path match.",
        llm_rationale="Structured rationale.",
        uncertainty_notes=["Review before acting."],
        counterarguments=["Some cached data may still be warm state."],
        cleanup_characterization=["recreatable", "non-essential"],
        deterministic_evidence={"path_patterns": ["cache"]},
        grouping_logic="Folder unit",
        evidence_source="deterministic + codex_local + web",
        sample_files=[],
        extension_distribution=[],
        web_citations=[WebCitation(title="Doc", url="https://example.com", snippet="cache", claim="Cache path.")],
        reasoning_provider="codex_local",
        requested_reasoning_provider="codex_local",
        fallback_provider="deterministic",
        reasoning_status="fallback_error",
        used_web_support=True,
        provider_failure_reason="schema_output_failed",
        provider_failure_detail="codex_local returned invalid JSON.",
        provider_debug_artifact_path=r"D:\repos\codex-disk-audit\.cache\debug\codex-reasoning-debug.json",
    )


class ReportTests(unittest.TestCase):
    def test_report_labels_reasoning_provider_and_fallback(self) -> None:
        config = load_config("config/defaults.json")
        summary = {
            "total_units": 1,
            "total_candidate_size_display": "1.0 KB",
            "risk_counts": {"medium": 1},
            "category_counts": {"cache": 1},
            "zone_counts": {"medium_risk_zone": 1},
            "space_by_category": {"cache": {"size_bytes": 1024, "size_display": "1.0 KB"}},
        }
        with tempfile.TemporaryDirectory() as temp_dir_name:
            report_path = render_report_html(Path(temp_dir_name), [make_unit()], summary, config)
            html = report_path.read_text(encoding="utf-8")
        self.assertIn("Reasoning Mode", html)
        self.assertIn("Fallback", html)
        self.assertIn("Failure Reason", html)
        self.assertIn("codex_local", html)
        self.assertIn("deterministic", html)
        self.assertIn("schema_output_failed", html)

    def test_report_and_findings_metadata_show_reasoning_coverage_and_limit_fallback(self) -> None:
        config = load_config("config/defaults.json")
        config.reasoning.max_units = 100
        codex_unit = make_unit()
        limit_unit = make_unit()
        limit_unit.unit_id = "unit-2"
        limit_unit.reasoning_provider = "deterministic"
        limit_unit.fallback_provider = "deterministic"
        limit_unit.reasoning_status = "fallback_limit"
        limit_unit.provider_failure_reason = None
        limit_unit.provider_failure_detail = "Primary reasoning was skipped because the configured max_units limit was reached."
        limit_unit.evidence_source = "deterministic"
        summary = build_summary([codex_unit, limit_unit])
        with tempfile.TemporaryDirectory() as temp_dir_name:
            output_dir = Path(temp_dir_name)
            report_path = render_report_html(output_dir, [codex_unit, limit_unit], summary, config)
            findings_path = write_findings_json(output_dir, [codex_unit, limit_unit], summary, config)
            html = report_path.read_text(encoding="utf-8")
            findings = findings_path.read_text(encoding="utf-8")
        self.assertIn("Reasoning max units", html)
        self.assertIn("Fallback: Max Units", html)
        self.assertIn("because the max_units limit was reached", html)
        self.assertIn('"reasoning_max_units": 100', findings)
        self.assertIn('"fallback_due_to_max_units": 1', findings)
        self.assertIn('"processed_by_provider"', findings)


if __name__ == "__main__":
    unittest.main()
