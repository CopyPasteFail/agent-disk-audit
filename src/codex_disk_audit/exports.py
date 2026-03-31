from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from .models import CleanupUnit, ScanConfig, SkipRecord
from .utils import ensure_directory, format_bytes


def build_summary(units: list[CleanupUnit]) -> dict:
    by_risk = Counter(unit.risk for unit in units)
    by_category = Counter(unit.category for unit in units)
    by_zone = Counter(unit.zone for unit in units)
    by_priority = Counter(unit.review_priority for unit in units)
    by_reasoning_provider = Counter(unit.reasoning_provider for unit in units)
    by_reasoning_status = Counter(unit.reasoning_status for unit in units)
    size_by_category = defaultdict(int)
    for unit in units:
        size_by_category[unit.category] += unit.total_size_bytes

    total_size_bytes = sum(unit.total_size_bytes for unit in units)
    top_review_first = sorted(
        [unit for unit in units if unit.review_priority == "review_first"],
        key=lambda item: (-item.review_priority_score, -item.total_size_bytes),
    )[:5]
    fallback_units = [unit for unit in units if unit.fallback_provider]
    fallback_status_counts = Counter(unit.reasoning_status for unit in fallback_units)
    fallback_failure_reason_counts = Counter(
        unit.provider_failure_reason for unit in fallback_units if unit.provider_failure_reason
    )
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "total_units": len(units),
        "total_candidate_size_bytes": total_size_bytes,
        "total_candidate_size_display": format_bytes(total_size_bytes),
        "risk_counts": dict(by_risk),
        "category_counts": dict(by_category),
        "zone_counts": dict(by_zone),
        "priority_counts": dict(by_priority),
        "reasoning_overview": {
            "processed_by_provider": dict(by_reasoning_provider),
            "status_counts": dict(by_reasoning_status),
            "fallback_units": len(fallback_units),
            "fallback_status_counts": dict(fallback_status_counts),
            "fallback_failure_reason_counts": dict(fallback_failure_reason_counts),
            "fallback_due_to_max_units": fallback_status_counts.get("fallback_limit", 0),
            "fallback_due_to_provider_issue": sum(
                count for status, count in fallback_status_counts.items() if status != "fallback_limit"
            ),
        },
        "space_by_category": {
            category: {
                "size_bytes": size_bytes,
                "size_display": format_bytes(size_bytes),
            }
            for category, size_bytes in sorted(size_by_category.items(), key=lambda item: item[1], reverse=True)
        },
        "top_review_first": [
            {
                "name": unit.name,
                "path": unit.path,
                "size_display": unit.display_size,
                "review_priority": unit.review_priority,
                "decision_focus": unit.decision_focus,
                "recommendation": unit.recommendation,
            }
            for unit in top_review_first
        ],
    }


def write_findings_json(output_dir: Path, units: list[CleanupUnit], summary: dict, config: ScanConfig) -> Path:
    payload = {
        "summary": summary,
        "config": {
            "scan_root": config.scan_root,
            "reasoning_provider": config.reasoning_provider,
            "fallback_provider": config.fallback_provider,
            "web_enrichment_provider": config.web_enrichment_provider,
            "use_access_time": config.use_access_time,
            "max_units_in_report": config.max_units_in_report,
            "reasoning_max_units": config.reasoning.max_units,
        },
        "findings": [unit.to_dict() for unit in units],
    }
    target = output_dir / "findings.json"
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def write_findings_csv(output_dir: Path, units: list[CleanupUnit]) -> Path:
    target = output_dir / "findings.csv"
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "name",
                "path",
                "root_path",
                "unit_type",
                "category",
                "zone",
                "risk",
                "confidence_label",
                "confidence_score",
                "review_priority",
                "review_priority_score",
                "decision_focus",
                "total_size_bytes",
                "file_count",
                "reasoning_provider",
                "fallback_provider",
                "recommendation",
                "reason_summary",
                "display_modified_at",
                "evidence_source",
            ],
        )
        writer.writeheader()
        for unit in units:
            writer.writerow(
                {
                    "name": unit.name,
                    "path": unit.path,
                    "root_path": unit.root_path,
                    "unit_type": unit.unit_type,
                    "category": unit.category,
                    "zone": unit.zone,
                    "risk": unit.risk,
                    "confidence_label": unit.confidence_label,
                    "confidence_score": unit.confidence_score,
                    "review_priority": unit.review_priority,
                    "review_priority_score": unit.review_priority_score,
                    "decision_focus": unit.decision_focus,
                    "total_size_bytes": unit.total_size_bytes,
                    "file_count": unit.file_count,
                    "reasoning_provider": unit.reasoning_provider,
                    "fallback_provider": unit.fallback_provider or "",
                    "recommendation": unit.recommendation,
                    "reason_summary": unit.reason_summary,
                    "display_modified_at": unit.display_modified_at,
                    "evidence_source": unit.evidence_source,
                }
            )
    return target


def write_summary_markdown(output_dir: Path, units: list[CleanupUnit], summary: dict, config: ScanConfig) -> Path:
    top_units = sorted(units, key=lambda item: item.total_size_bytes, reverse=True)[:10]
    reasoning_overview = summary.get("reasoning_overview", {})
    lines = [
        "# Disk Audit Summary",
        "",
        f"- Scan root: `{config.scan_root}`",
        f"- Total cleanup units: `{summary['total_units']}`",
        f"- Total candidate size: `{summary['total_candidate_size_display']}`",
        f"- Requested reasoning provider: `{config.reasoning_provider}`",
        f"- Fallback provider: `{config.fallback_provider}`",
        f"- Web enrichment provider: `{config.web_enrichment_provider}`",
        f"- Reasoning max units: `{config.reasoning.max_units}`",
        "",
        "## Reasoning overview",
        "",
    ]
    for provider, count in reasoning_overview.get("processed_by_provider", {}).items():
        lines.append(f"- Processed by {provider}: `{count}`")
    lines.extend(
        [
            f"- Fallback units: `{reasoning_overview.get('fallback_units', 0)}`",
            f"- Fallback due to max_units: `{reasoning_overview.get('fallback_due_to_max_units', 0)}`",
            f"- Fallback due to provider issue: `{reasoning_overview.get('fallback_due_to_provider_issue', 0)}`",
        ]
    )
    for reason, count in reasoning_overview.get("fallback_failure_reason_counts", {}).items():
        lines.append(f"- Fallback provider issue `{reason}`: `{count}`")
    lines.extend(
        [
        "",
        "## Risk counts",
        "",
        ]
    )
    for risk, count in summary["risk_counts"].items():
        lines.append(f"- {risk}: `{count}`")
    lines.extend(["", "## Top units", ""])
    for unit in top_units:
        lines.append(
            f"- `{unit.display_size}` | `{unit.review_priority}` | `{unit.risk}` | `{unit.category}` | {unit.name} | {unit.recommendation}"
        )
    lines.extend(
        [
            "",
            "## Safety notes",
            "",
            "- This tool is audit-only and never deletes or modifies files.",
            "- High-risk zones require stricter review and should not be acted on casually.",
            "- Access times may be unavailable or unreliable on Windows and are not treated as decisive evidence.",
        ]
    )
    target = output_dir / "summary.md"
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def write_skipped_markdown(output_dir: Path, skipped: list[SkipRecord]) -> Path:
    lines = [
        "# Skipped Paths",
        "",
        f"- Total skipped entries: `{len(skipped)}`",
        "",
    ]
    if not skipped:
        lines.append("- No skipped paths were recorded.")
    else:
        for record in skipped[:500]:
            lines.append(f"- `{record.path}`: {record.reason}")
        if len(skipped) > 500:
            lines.append(f"- Additional skipped entries omitted: `{len(skipped) - 500}`")
    target = output_dir / "skipped.md"
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def ensure_output_directory(path: str | Path) -> Path:
    return ensure_directory(path)
