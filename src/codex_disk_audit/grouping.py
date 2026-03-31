from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable

from .classify import (
    ARCHIVE_EXTENSIONS,
    characterize_cleanup,
    classify_risk,
    classify_zone,
    confidence_label,
    confidence_score,
    infer_category_from_file,
    infer_vendor_hint,
    looks_generated_data,
    recommendation_for,
)
from .models import CleanupUnit, FileRecord, ScanConfig
from .utils import extension_distribution, format_bytes, is_path_under, iso_date, latest_datetime, slugify


STRUCTURAL_DUPLICATION = "structural_duplication"
NON_ACTIONABLE_REVIEW_PRIORITY = "not_actionable"
MICROSOFT_MANAGED_RUNTIME_MARKERS = (
    "edge",
    "edgecore",
    "edgewebview",
    "webview",
    "webview2",
    "webview2runtime",
)
VERSIONED_FOLDER_PATTERN = re.compile(r"^\d+(?:\.\d+){2,}$")


@dataclass(slots=True)
class DirectorySummary:
    path: str
    total_size_bytes: int = 0
    file_count: int = 0
    dir_count: int = 0
    extension_counter: Counter[str] = field(default_factory=Counter)
    sample_files: list[FileRecord] = field(default_factory=list)
    latest_modified_at: datetime | None = None
    created_at: datetime | None = None
    accessed_at: datetime | None = None

    def merge(self, other: "DirectorySummary", sample_limit: int) -> None:
        self.total_size_bytes += other.total_size_bytes
        self.file_count += other.file_count
        self.dir_count += other.dir_count + 1
        self.extension_counter.update(other.extension_counter)
        self.sample_files.extend(other.sample_files)
        self.sample_files.sort(key=lambda item: item.size_bytes, reverse=True)
        self.sample_files = self.sample_files[:sample_limit]
        self.latest_modified_at = latest_datetime(self.latest_modified_at, other.latest_modified_at)
        self.created_at = min(
            [value for value in (self.created_at, other.created_at) if value is not None],
            default=None,
        )
        self.accessed_at = latest_datetime(self.accessed_at, other.accessed_at)

    def add_file(self, file_record: FileRecord, sample_limit: int) -> None:
        self.total_size_bytes += file_record.size_bytes
        self.file_count += 1
        self.extension_counter[file_record.extension] += 1
        self.sample_files.append(file_record)
        self.sample_files.sort(key=lambda item: item.size_bytes, reverse=True)
        self.sample_files = self.sample_files[:sample_limit]
        self.latest_modified_at = latest_datetime(self.latest_modified_at, file_record.modified_at)
        self.created_at = min(
            [value for value in (self.created_at, file_record.created_at) if value is not None],
            default=None,
        )
        self.accessed_at = latest_datetime(self.accessed_at, file_record.accessed_at)


def _days_old(value: datetime | None, now: datetime) -> int | None:
    if value is None:
        return None
    delta = now - value.astimezone(UTC)
    return max(0, delta.days)


def common_unit_fields(
    *,
    unit_id_hint: str,
    name: str,
    path: str,
    root_path: str,
    item_kind: str,
    unit_type: str,
    category: str,
    total_size_bytes: int,
    file_count: int,
    extension_counter: Counter[str],
    sample_files: list[FileRecord],
    modified_at: datetime | None,
    created_at: datetime | None,
    accessed_at: datetime | None,
    now: datetime,
    strong_match: bool,
    age_hit: bool,
    duplicate_hit: bool,
    grouping_logic: str,
    config: ScanConfig,
    extra_evidence: dict,
) -> CleanupUnit:
    zone = classify_zone(path, category, config)
    generated_data = looks_generated_data(path, category)
    missing_signals = 0
    if modified_at is None:
        missing_signals += 1
    if not sample_files:
        missing_signals += 1
    confidence = confidence_score(
        strong_match=strong_match,
        age_hit=age_hit,
        generated_data=generated_data,
        duplicate_hit=duplicate_hit,
        zone=zone,
        category=category,
        missing_signals=missing_signals,
    )
    risk = classify_risk(zone, category, confidence)
    cleanup_tags = characterize_cleanup(category, risk)
    vendor_hint = infer_vendor_hint(path)
    age_days = _days_old(modified_at, now)
    mixed_content = _has_mixed_content(sample_files)
    generated_strength = _generated_strength(
        category=category,
        strong_match=strong_match,
        generated_data=generated_data,
        sample_files=sample_files,
        extension_counter=extension_counter,
    )
    reclaim_value = _reclaim_value_score(total_size_bytes, age_days, generated_strength, mixed_content, risk)
    review_priority, review_priority_score, decision_focus = _review_priority(
        category=category,
        total_size_bytes=total_size_bytes,
        age_days=age_days,
        generated_strength=generated_strength,
        mixed_content=mixed_content,
        risk=risk,
    )
    review_priority = extra_evidence.get("review_priority_override", review_priority)
    review_priority_score = extra_evidence.get("review_priority_score_override", review_priority_score)
    decision_focus = extra_evidence.get("decision_focus_override", decision_focus)
    cleanup_tags = extra_evidence.get("cleanup_characterization_override", cleanup_tags)
    recommendation = extra_evidence.get(
        "recommendation_override",
        recommendation_for(
        category,
        risk,
        total_size_bytes=total_size_bytes,
        age_days=age_days,
        mixed_content=mixed_content,
        review_priority=review_priority,
        ),
    )
    evidence = {
        "path_patterns": extra_evidence.get("path_patterns", []),
        "category_hints": extra_evidence.get("category_hints", []),
        "under_high_risk_zone": zone == "high_risk_zone",
        "vendor_hint": vendor_hint,
        "likely_generated_data": generated_data,
        "age_threshold_hit": age_hit,
        "locked_state": "not_checked",
        "duplicate_evidence": extra_evidence.get("duplicate_evidence"),
        "confidence_penalties": extra_evidence.get("confidence_penalties", []),
        "sample_count": len(sample_files),
        "age_days": age_days,
        "mixed_content": mixed_content,
        "generated_strength": generated_strength,
        "likely_reclaim_value_score": reclaim_value,
        "actionability": extra_evidence.get("actionability", "manual_review"),
        "review_priority": review_priority,
        "decision_focus": decision_focus,
        "timestamp_reliability_note": (
            "Access times may be disabled or stale on Windows; modified time is weighted more heavily."
        ),
    }
    evidence.update(extra_evidence)
    reason_summary = extra_evidence.get(
        "reason_summary",
        f"Flagged as {category.replace('_', ' ')} based on path pattern, size, and age signals.",
    )

    return CleanupUnit(
        unit_id=f"{slugify(unit_id_hint)}-{slugify(path)}",
        name=name,
        path=path,
        root_path=root_path,
        item_kind=item_kind,
        unit_type=unit_type,
        category=category,
        zone=zone,
        risk=risk,
        confidence_score=confidence,
        confidence_label=confidence_label(confidence),
        total_size_bytes=total_size_bytes,
        file_count=file_count,
        display_size=format_bytes(total_size_bytes),
        display_modified_at=iso_date(modified_at),
        review_priority=review_priority,
        review_priority_score=review_priority_score,
        decision_focus=decision_focus,
        recommendation=recommendation,
        reason_summary=reason_summary,
        llm_rationale="Deterministic reasoning only.",
        uncertainty_notes=extra_evidence.get("uncertainty_notes", []),
        counterarguments=extra_evidence.get("counterarguments", []),
        cleanup_characterization=cleanup_tags,
        deterministic_evidence=evidence,
        grouping_logic=grouping_logic,
        evidence_source="deterministic only",
        sample_files=[item.to_dict() for item in sample_files[: config.file_sample_count]],
        extension_distribution=extension_distribution(extension_counter),
        representative_modified_at=modified_at,
        representative_created_at=created_at,
        representative_accessed_at=accessed_at,
    )


def _has_mixed_content(sample_files: list[FileRecord]) -> bool:
    risky_extensions = {".exe", ".msi", ".msp", ".zip", ".7z", ".rar", ".vhd", ".vhdx", ".iso"}
    extensions = {item.extension.lower() for item in sample_files if item.extension}
    return bool(extensions & risky_extensions)


def _generated_strength(
    *,
    category: str,
    strong_match: bool,
    generated_data: bool,
    sample_files: list[FileRecord],
    extension_counter: Counter[str],
) -> int:
    score = 0
    if strong_match:
        score += 35
    if generated_data:
        score += 20
    if category in {"cache", "temp", "logs", "crash_dump"}:
        score += 15
    dominant_extension_count = extension_counter.most_common(1)[0][1] if extension_counter else 0
    if sample_files and dominant_extension_count >= max(2, int(len(sample_files) * 0.6)):
        score += 10
    if category == "cache" and any(item.extension.lower() in {"", ".body"} for item in sample_files):
        score += 10
    return min(100, score)


def _reclaim_value_score(
    total_size_bytes: int,
    age_days: int | None,
    generated_strength: int,
    mixed_content: bool,
    risk: str,
) -> int:
    size_score = 0
    if total_size_bytes >= 1024 * 1024 * 1024:
        size_score = 40
    elif total_size_bytes >= 256 * 1024 * 1024:
        size_score = 30
    elif total_size_bytes >= 64 * 1024 * 1024:
        size_score = 20
    elif total_size_bytes >= 8 * 1024 * 1024:
        size_score = 10
    age_score = 0 if age_days is None else min(20, age_days // 14 * 4)
    ambiguity_penalty = 12 if mixed_content else 0
    risk_penalty = 10 if risk == "high" else 0
    return max(0, min(100, size_score + age_score + generated_strength - ambiguity_penalty - risk_penalty))


def _review_priority(
    *,
    category: str,
    total_size_bytes: int,
    age_days: int | None,
    generated_strength: int,
    mixed_content: bool,
    risk: str,
) -> tuple[str, int, str]:
    reclaim_score = _reclaim_value_score(total_size_bytes, age_days, generated_strength, mixed_content, risk)
    if mixed_content and total_size_bytes >= 256 * 1024 * 1024:
        return "review_first", max(75, reclaim_score), "Big reclaim potential, but mixed contents need caution."
    if reclaim_score >= 70 and total_size_bytes >= 32 * 1024 * 1024:
        return "review_first", reclaim_score, "Large likely win with strong generated-data signals."
    if total_size_bytes <= 1024 * 1024 and category in {"logs", "obsolete_artifact"}:
        return "low_yield", min(35, reclaim_score), "Small reclaim value; lower priority unless troubleshooting cleanup matters."
    if category in {"cache", "temp", "logs", "crash_dump"} and reclaim_score >= 45:
        return "review_next", reclaim_score, "Likely generated data; worthwhile after top wins."
    return "review_later", max(20, reclaim_score), "More ambiguous or lower-yield than the top review targets."


def build_folder_unit(
    *,
    path: str,
    summary: DirectorySummary,
    category: str,
    rule_note: str,
    config: ScanConfig,
    now: datetime,
) -> CleanupUnit | None:
    min_bytes = config.strong_signal_min_unit_size_mb * 1024 * 1024
    if summary.total_size_bytes < min_bytes and summary.file_count < 25:
        return None

    age_hit = False
    age_threshold = getattr(config.age_threshold_days, category, config.age_threshold_days.obsolete_artifact)
    if summary.latest_modified_at is not None:
        age_hit = _days_old(summary.latest_modified_at, now) >= age_threshold

    return common_unit_fields(
        unit_id_hint=f"{category}-folder",
        name=f"{os.path.basename(path) or path} ({category.replace('_', ' ')})",
        path=path,
        root_path=path,
        item_kind="folder",
        unit_type="folder_unit",
        category=category,
        total_size_bytes=summary.total_size_bytes,
        file_count=summary.file_count,
        extension_counter=summary.extension_counter,
        sample_files=summary.sample_files,
        modified_at=summary.latest_modified_at,
        created_at=summary.created_at,
        accessed_at=summary.accessed_at,
        now=now,
        strong_match=True,
        age_hit=age_hit,
        duplicate_hit=False,
        grouping_logic="Entire folder grouped as one cleanup unit because the path strongly matches a known cache/temp/log/dump pattern.",
        config=config,
        extra_evidence={
            "path_patterns": [rule_note],
            "category_hints": [category],
            "reason_summary": f"Entire folder matches a known {category.replace('_', ' ')} pattern and is large enough to review as one unit.",
            "uncertainty_notes": [
                "Folder names alone do not guarantee the contents are disposable; review sample files before acting."
            ],
            "counterarguments": [
                "Some applications keep useful history or diagnostic data inside folders that look like caches or logs."
            ],
        },
    )


def group_files_in_directory(
    directory_path: str,
    files: Iterable[FileRecord],
    config: ScanConfig,
    now: datetime,
) -> list[CleanupUnit]:
    file_list = list(files)
    groups: dict[tuple[str, str], list[FileRecord]] = defaultdict(list)
    directory_lower = directory_path.lower()

    for file_record in file_list:
        category = infer_category_from_file(file_record.path, directory_path)
        modified_at = file_record.modified_at
        age_days = _days_old(modified_at, now)

        if "\\downloads" in directory_lower and age_days is not None and age_days >= config.age_threshold_days.downloads_old:
            if file_record.size_bytes >= 50 * 1024 * 1024 or file_record.extension in ARCHIVE_EXTENSIONS:
                category = "downloads_old"

        if category == "unknown" and file_record.size_bytes >= config.large_file_min_size_mb * 1024 * 1024:
            if file_record.extension in ARCHIVE_EXTENSIONS:
                category = "obsolete_artifact"

        if category == "unknown":
            continue

        threshold_name = category if hasattr(config.age_threshold_days, category) else "obsolete_artifact"
        threshold_days = getattr(config.age_threshold_days, threshold_name)
        age_hit = age_days is not None and age_days >= threshold_days
        if category not in {"obsolete_artifact", "downloads_old"} and not age_hit:
            continue

        group_kind = "hybrid" if len(file_list) > 1 else "standalone"
        groups[(category, group_kind)].append(file_record)

    units: list[CleanupUnit] = []
    min_bytes = config.min_unit_size_mb * 1024 * 1024
    for (category, group_kind), items in groups.items():
        total_size_bytes = sum(item.size_bytes for item in items)
        if total_size_bytes < min_bytes and len(items) < 2:
            continue
        extension_counter = Counter(item.extension for item in items)
        modified_at = max((item.modified_at for item in items if item.modified_at is not None), default=None)
        created_at = min((item.created_at for item in items if item.created_at is not None), default=None)
        accessed_at = max((item.accessed_at for item in items if item.accessed_at is not None), default=None)
        sample_files = sorted(items, key=lambda item: item.size_bytes, reverse=True)[: config.file_sample_count]
        descriptor = category.replace("_", " ")
        if len(items) == 1:
            name = os.path.basename(items[0].path)
            unit_type = "grouped_files_unit"
            grouping_logic = f"Single large artifact kept as its own grouped cleanup unit because it is a clearly standalone {descriptor} file."
        elif group_kind == "hybrid":
            name = f"{os.path.basename(directory_path) or directory_path} {descriptor} subset"
            unit_type = "hybrid_unit"
            grouping_logic = f"Subset of files grouped by shared {descriptor} pattern inside one parent folder."
        else:
            name = f"{os.path.basename(directory_path) or directory_path} {descriptor} files"
            unit_type = "grouped_files_unit"
            grouping_logic = "Files grouped by directory and category to avoid noisy per-file recommendations."

        units.append(
            common_unit_fields(
                unit_id_hint=f"{category}-files",
                name=name,
                path=directory_path,
                root_path=directory_path,
                item_kind="grouped_files",
                unit_type=unit_type,
                category=category,
                total_size_bytes=total_size_bytes,
                file_count=len(items),
                extension_counter=extension_counter,
                sample_files=sample_files,
                modified_at=modified_at,
                created_at=created_at,
                accessed_at=accessed_at,
                now=now,
                strong_match=category in {"logs", "crash_dump", "leftover_installer", "downloads_old"},
                age_hit=True,
                duplicate_hit=False,
                grouping_logic=grouping_logic,
                config=config,
                extra_evidence={
                    "path_patterns": [descriptor],
                    "category_hints": [category],
                    "reason_summary": f"Grouped {len(items)} file(s) under one folder because they share a {descriptor} pattern and are large or old enough to review together.",
                    "uncertainty_notes": [
                        "Files in a mixed folder may still include items the user wants to keep."
                    ],
                    "counterarguments": [
                        "A large installer, archive, or dump may still be intentionally retained for rollback or troubleshooting."
                    ],
                },
            )
        )

    return units


def build_duplicate_units(
    duplicate_groups: dict[str, list[FileRecord]],
    config: ScanConfig,
) -> list[CleanupUnit]:
    units: list[CleanupUnit] = []
    now = datetime.now(UTC)
    for file_hash, items in duplicate_groups.items():
        common_root = os.path.commonpath([item.path for item in items])
        if os.path.isfile(common_root):
            common_root = os.path.dirname(common_root)
        extension_counter = Counter(item.extension for item in items)
        total_size_bytes = sum(item.size_bytes for item in items)
        modified_at = max((item.modified_at for item in items if item.modified_at is not None), default=None)
        created_at = min((item.created_at for item in items if item.created_at is not None), default=None)
        accessed_at = max((item.accessed_at for item in items if item.accessed_at is not None), default=None)
        sample_files = sorted(items, key=lambda item: item.size_bytes, reverse=True)[: config.file_sample_count]
        duplicate_policy = _classify_duplicate_group(common_root, items, config)
        units.append(
            common_unit_fields(
                unit_id_hint=f"duplicate-{file_hash[:10]}",
                name=f"Duplicate group ({len(items)} files)",
                path=common_root,
                root_path=common_root,
                item_kind="grouped_files",
                unit_type="grouped_files_unit",
                category=duplicate_policy["category"],
                total_size_bytes=total_size_bytes,
                file_count=len(items),
                extension_counter=extension_counter,
                sample_files=sample_files,
                modified_at=modified_at,
                created_at=created_at,
                accessed_at=accessed_at,
                now=now,
                strong_match=duplicate_policy["strong_match"],
                age_hit=False,
                duplicate_hit=True,
                grouping_logic="Duplicate files grouped by exact SHA-256 match and common root path.",
                config=config,
                extra_evidence={
                    "path_patterns": ["exact duplicate content"],
                    "category_hints": [duplicate_policy["category"]],
                    "duplicate_evidence": {
                        "hash": file_hash,
                        "duplicate_count": len(items),
                    },
                    **duplicate_policy,
                },
            )
        )
    return units


def _classify_duplicate_group(common_root: str, items: list[FileRecord], config: ScanConfig) -> dict:
    structural = _is_structural_duplicate_layout(items)
    high_risk_location = _is_high_risk_duplicate_location(common_root, items, config)

    if structural:
        review_priority = "review_later" if config.expert_system_review_mode else NON_ACTIONABLE_REVIEW_PRIORITY
        review_score = 18 if config.expert_system_review_mode else 0
        decision_focus = (
            "Known Microsoft-managed packaging layout; keep out of normal cleanup triage unless expert system review is enabled."
        )
        return {
            "category": "system_component",
            "strong_match": True,
            "duplicate_disposition": STRUCTURAL_DUPLICATION,
            "known_non_actionable_duplicate": True,
            "system_managed_duplicate": True,
            "skip_reasoning": True,
            "actionability": "none",
            "review_priority_override": review_priority,
            "review_priority_score_override": review_score,
            "decision_focus_override": decision_focus,
            "reason_summary": (
                "Exact duplicate content was detected, but the files match a known Microsoft browser/runtime packaging layout that intentionally carries separate copies."
            ),
            "recommendation_override": "System-managed duplication by design; not a cleanup candidate.",
            "cleanup_characterization_override": ["ambiguous"],
            "uncertainty_notes": [
                "Independent Edge, EdgeCore, EdgeWebView, and WebView runtimes can legitimately carry their own version-pinned copies.",
                "Updater-managed and optimized runtime layouts may intentionally duplicate binaries for startup, servicing, or patch behavior.",
            ],
            "counterarguments": [
                "If the vendor-managed layout match is incomplete, leave the files alone and escalate to expert review instead of treating them as cleanup."
            ],
            "confidence_penalties": [
                "Intentional structural duplication in a system-managed runtime layout is non-actionable by default."
            ],
        }

    if high_risk_location:
        review_priority = "review_later" if config.expert_system_review_mode else NON_ACTIONABLE_REVIEW_PRIORITY
        review_score = 20 if config.expert_system_review_mode else 0
        return {
            "category": "duplicate_group",
            "strong_match": False,
            "duplicate_disposition": "high_risk_duplicate",
            "known_non_actionable_duplicate": not config.expert_system_review_mode,
            "system_managed_duplicate": False,
            "skip_reasoning": False,
            "actionability": "expert_review_only",
            "review_priority_override": review_priority,
            "review_priority_score_override": review_score,
            "decision_focus_override": "High-risk system-managed location; exact duplicate content alone does not justify cleanup.",
            "reason_summary": (
                "Exact duplicate content was detected in a high-risk system-managed location, so the group is suppressed from normal cleanup targeting."
            ),
            "recommendation_override": (
                "Exact duplicate content in a high-risk system-managed location is not enough to justify cleanup; expert review only."
            ),
            "cleanup_characterization_override": ["ambiguous"],
            "uncertainty_notes": [
                "Program Files and Windows layouts often contain side-by-side copies, rollback assets, or shared runtime files.",
            ],
            "counterarguments": [
                "A duplicate in a system directory may still be intentional packaging rather than waste.",
            ],
            "confidence_penalties": [
                "Duplicate evidence was down-ranked because the files live in a high-risk system-managed location."
            ],
        }

    return {
        "category": "duplicate_group",
        "strong_match": False,
        "duplicate_disposition": "content_duplicate",
        "known_non_actionable_duplicate": False,
        "system_managed_duplicate": False,
        "skip_reasoning": False,
        "actionability": "manual_review",
        "review_priority_override": "review_later",
        "review_priority_score_override": 28,
        "decision_focus_override": "Exact duplicate content is worth noting, but removability is still ambiguous without context.",
        "reason_summary": "Exact duplicate files share the same SHA-256 hash, but duplicate content alone does not make them cleanup candidates.",
        "recommendation_override": (
            "Exact duplicate content alone is not enough to justify cleanup; verify ownership and purpose before any manual action."
        ),
        "cleanup_characterization_override": ["ambiguous"],
        "uncertainty_notes": [
            "Duplicate content does not prove the copies are equally disposable; location and workflow still matter."
        ],
        "counterarguments": [
            "One copy may be an active working file while another is a backup, rollback asset, or application dependency."
        ],
    }


def _is_high_risk_duplicate_location(common_root: str, items: list[FileRecord], config: ScanConfig) -> bool:
    if any(is_path_under(common_root, path) for path in config.high_risk_paths):
        return True
    return any(
        any(is_path_under(item.path, high_risk_path) for high_risk_path in config.high_risk_paths)
        for item in items
    )


def _is_structural_duplicate_layout(items: list[FileRecord]) -> bool:
    lowered_paths = [item.path.lower() for item in items]
    path_text = " ".join(lowered_paths)
    if not any("\\program files" in path for path in lowered_paths):
        return False
    if "\\microsoft\\" not in path_text:
        return False

    runtime_marker_hits = sum(
        1 for marker in MICROSOFT_MANAGED_RUNTIME_MARKERS if f"\\{marker}\\" in path_text
    )
    if runtime_marker_hits == 0:
        return False

    has_managed_layout = any(
        marker in path_text for marker in ("\\application\\", "\\updater\\", "\\optimized\\")
    )
    has_versioned_layout = any(
        VERSIONED_FOLDER_PATTERN.fullmatch(part or "") is not None
        for item in items
        for part in item.path.split("\\")
    )
    has_multiple_runtime_roots = len(
        {
            part.lower()
            for item in items
            for part in item.path.split("\\")
            if part.lower() in MICROSOFT_MANAGED_RUNTIME_MARKERS
        }
    ) >= 2

    return has_multiple_runtime_roots and (has_managed_layout or has_versioned_layout)
