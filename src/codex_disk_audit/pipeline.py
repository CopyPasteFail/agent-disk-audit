from __future__ import annotations

import json
import webbrowser
from pathlib import Path

from .duplicates import find_duplicate_groups
from .exports import (
    build_summary,
    ensure_output_directory,
    write_findings_csv,
    write_findings_json,
    write_skipped_markdown,
    write_summary_markdown,
)
from .grouping import build_duplicate_units
from .models import CleanupUnit, ScanConfig, WebCitation
from .reasoning import apply_reasoning
from .report import render_report_html
from .scanner import scan_filesystem


def run_scan_pipeline(config: ScanConfig, *, output_dir: str | None = None, open_report: bool | None = None) -> dict[str, Path]:
    results = scan_filesystem(config)
    units = list(results.units)
    duplicate_groups = find_duplicate_groups(results.duplicate_candidates, config)
    units.extend(build_duplicate_units(duplicate_groups, config))
    units = sort_units(units)[: config.max_units_in_report]
    apply_reasoning(units, config)
    output_root = ensure_output_directory(output_dir or config.output_dir)
    summary = build_summary(units)
    artifact_paths = write_artifacts(output_root, units, results.skipped, summary, config)

    should_open = config.open_report_when_done if open_report is None else open_report
    if should_open:
        webbrowser.open(artifact_paths["report_html"].resolve().as_uri())
    return artifact_paths


def write_artifacts(
    output_dir: Path,
    units: list[CleanupUnit],
    skipped,
    summary: dict,
    config: ScanConfig,
) -> dict[str, Path]:
    findings_json = write_findings_json(output_dir, units, summary, config)
    findings_csv = write_findings_csv(output_dir, units)
    summary_md = write_summary_markdown(output_dir, units, summary, config)
    skipped_md = write_skipped_markdown(output_dir, skipped)
    report_html = render_report_html(output_dir, units, summary, config)
    return {
        "findings_json": findings_json,
        "findings_csv": findings_csv,
        "summary_md": summary_md,
        "skipped_md": skipped_md,
        "report_html": report_html,
    }


def sort_units(units: list[CleanupUnit]) -> list[CleanupUnit]:
    risk_rank = {"low": 0, "medium": 1, "high": 2}
    priority_rank = {"review_first": 0, "review_next": 1, "review_later": 2, "low_yield": 3, "not_actionable": 4}
    return sorted(
        units,
        key=lambda item: (
            priority_rank.get(item.review_priority, 9),
            -item.review_priority_score,
            risk_rank.get(item.risk, 9),
            -item.total_size_bytes,
            -item.confidence_score,
            item.name.lower(),
        ),
    )


def load_units_from_findings(path: str | Path) -> list[CleanupUnit]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = payload["findings"] if isinstance(payload, dict) and "findings" in payload else payload
    units: list[CleanupUnit] = []
    for item in findings:
        unit = CleanupUnit(
            unit_id=item["unit_id"],
            name=item["name"],
            path=item["path"],
            root_path=item["root_path"],
            item_kind=item["item_kind"],
            unit_type=item["unit_type"],
            category=item["category"],
            zone=item["zone"],
            risk=item["risk"],
            confidence_score=item["confidence_score"],
            confidence_label=item["confidence_label"],
            total_size_bytes=item["total_size_bytes"],
            file_count=item["file_count"],
            display_size=item["display_size"],
            display_modified_at=item.get("display_modified_at", ""),
            review_priority=item.get("review_priority", "review_later"),
            review_priority_score=item.get("review_priority_score", 0),
            decision_focus=item.get("decision_focus", ""),
            recommendation=item["recommendation"],
            reason_summary=item["reason_summary"],
            llm_rationale=item.get("llm_rationale", "Deterministic reasoning only."),
            uncertainty_notes=item.get("uncertainty_notes", []),
            counterarguments=item.get("counterarguments", []),
            cleanup_characterization=item.get("cleanup_characterization", []),
            deterministic_evidence=item.get("deterministic_evidence", {}),
            grouping_logic=item.get("grouping_logic", ""),
            evidence_source=item.get("evidence_source", "deterministic only"),
            sample_files=item.get("sample_files", []),
            extension_distribution=item.get("extension_distribution", []),
            representative_modified_at=None,
            representative_created_at=None,
            representative_accessed_at=None,
            web_citations=[WebCitation(**citation) for citation in item.get("web_citations", [])],
            reasoning_provider=item.get("reasoning_provider", "deterministic"),
            requested_reasoning_provider=item.get("requested_reasoning_provider", item.get("reasoning_provider", "deterministic")),
            fallback_provider=item.get("fallback_provider"),
            reasoning_status=item.get("reasoning_status", "completed"),
            used_web_support=item.get("used_web_support", bool(item.get("web_citations", []))),
            provider_failure_reason=item.get("provider_failure_reason"),
            provider_failure_detail=item.get("provider_failure_detail"),
            provider_debug_artifact_path=item.get("provider_debug_artifact_path"),
        )
        units.append(unit)
    return units


def run_report_only_pipeline(
    config: ScanConfig,
    findings_path: str | Path,
    *,
    output_dir: str | None = None,
) -> dict[str, Path]:
    units = sort_units(load_units_from_findings(findings_path))[: config.max_units_in_report]
    summary = build_summary(units)
    output_root = ensure_output_directory(output_dir or config.output_dir)
    return write_artifacts(output_root, units, [], summary, config)


def artifact_summary_text(paths: dict[str, Path], config: ScanConfig) -> str:
    return "\n".join(
        [
            f"Chosen stack: PowerShell launcher + Python pipeline",
            f"Artifacts written to: {paths['report_html'].parent}",
            f"Requested reasoning provider: {config.reasoning_provider}",
            f"Fallback provider: {config.fallback_provider}",
            f"Web enrichment provider: {config.web_enrichment_provider}",
            f"- findings.json: {paths['findings_json'].name}",
            f"- findings.csv: {paths['findings_csv'].name}",
            f"- summary.md: {paths['summary_md'].name}",
            f"- skipped.md: {paths['skipped_md'].name}",
            f"- report.html: {paths['report_html'].name}",
        ]
    )
