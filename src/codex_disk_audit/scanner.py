from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .classify import match_folder_rule
from .grouping import DirectorySummary, build_folder_unit, common_unit_fields, group_files_in_directory
from .models import CleanupUnit, FileRecord, ScanConfig, SkipRecord
from .utils import casefold_path, dt_from_timestamp, is_path_under


@dataclass(slots=True)
class ScanResults:
    units: list[CleanupUnit]
    skipped: list[SkipRecord]
    duplicate_candidates: list[FileRecord]
    scanned_root: str


@dataclass(slots=True)
class ScanState:
    config: ScanConfig
    now: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    units: list[CleanupUnit] = field(default_factory=list)
    skipped: list[SkipRecord] = field(default_factory=list)
    duplicate_candidates: list[FileRecord] = field(default_factory=list)

    def should_skip(self, path: str) -> bool:
        return any(is_path_under(path, excluded) for excluded in self.config.exclude_paths)

    def record_skip(self, path: str, reason: str) -> None:
        self.skipped.append(SkipRecord(path=path, reason=reason))


def scan_filesystem(config: ScanConfig) -> ScanResults:
    state = ScanState(config=config)
    root = Path(config.scan_root)
    if not root.exists():
        raise FileNotFoundError(f"Scan root does not exist: {config.scan_root}")

    _scan_directory(str(root), state, allow_units=True)
    return ScanResults(
        units=state.units,
        skipped=state.skipped,
        duplicate_candidates=state.duplicate_candidates,
        scanned_root=str(root),
    )


def _scan_directory(path: str, state: ScanState, *, allow_units: bool) -> DirectorySummary:
    summary = DirectorySummary(path=path)
    if state.should_skip(path):
        state.record_skip(path, "Excluded by configuration.")
        return summary

    rule = match_folder_rule(path) if allow_units else None
    child_allow_units = allow_units and rule is None
    direct_files: list[FileRecord] = []

    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                entry_path = entry.path
                try:
                    if entry.is_symlink() and not state.config.follow_symlinks:
                        state.record_skip(entry_path, "Skipped symlink or reparse point.")
                        continue

                    if entry.is_dir(follow_symlinks=state.config.follow_symlinks):
                        child_summary = _scan_directory(entry_path, state, allow_units=child_allow_units)
                        summary.merge(child_summary, state.config.file_sample_count)
                        continue

                    if entry.is_file(follow_symlinks=state.config.follow_symlinks):
                        stat_result = entry.stat(follow_symlinks=state.config.follow_symlinks)
                        file_record = FileRecord(
                            path=entry_path,
                            size_bytes=stat_result.st_size,
                            created_at=dt_from_timestamp(getattr(stat_result, "st_ctime", None)),
                            modified_at=dt_from_timestamp(getattr(stat_result, "st_mtime", None)),
                            accessed_at=dt_from_timestamp(getattr(stat_result, "st_atime", None))
                            if state.config.use_access_time
                            else None,
                            extension=Path(entry_path).suffix.lower(),
                        )
                        summary.add_file(file_record, state.config.file_sample_count)
                        direct_files.append(file_record)
                        if file_record.size_bytes >= state.config.duplicate_detection.min_file_size_mb * 1024 * 1024:
                            state.duplicate_candidates.append(file_record)
                except PermissionError:
                    state.record_skip(entry_path, "Permission denied.")
                except OSError as error:
                    state.record_skip(entry_path, f"{type(error).__name__}: {error}")
    except PermissionError:
        state.record_skip(path, "Permission denied.")
        return summary
    except OSError as error:
        state.record_skip(path, f"{type(error).__name__}: {error}")
        return summary

    if rule is not None:
        unit = build_folder_unit(
            path=path,
            summary=summary,
            category=rule.category,
            rule_note=rule.note,
            config=state.config,
            now=state.now,
        )
        if unit is not None:
            state.units.append(unit)
        return summary

    if allow_units:
        if summary.file_count == 0 and summary.dir_count == 0:
            maybe_add_empty_folder_unit(path, summary, state)
        state.units.extend(group_files_in_directory(path, direct_files, state.config, state.now))

    return summary


def maybe_add_empty_folder_unit(path: str, summary: DirectorySummary, state: ScanState) -> None:
    if casefold_path(path) == casefold_path(state.config.scan_root):
        return

    try:
        stat_result = os.stat(path)
    except OSError:
        return

    modified_at = dt_from_timestamp(getattr(stat_result, "st_mtime", None))
    age_days = None
    if modified_at is not None:
        age_days = (state.now - modified_at.astimezone(UTC)).days
    if age_days is None or age_days < state.config.age_threshold_days.empty_folder:
        return

    unit = common_unit_fields(
        unit_id_hint="empty-folder",
        name=f"{os.path.basename(path) or path} (empty folder)",
        path=path,
        root_path=path,
        item_kind="folder",
        unit_type="folder_unit",
        category="obsolete_artifact",
        total_size_bytes=0,
        file_count=0,
        extension_counter=summary.extension_counter,
        sample_files=[],
        modified_at=modified_at,
        created_at=dt_from_timestamp(getattr(stat_result, "st_ctime", None)),
        accessed_at=dt_from_timestamp(getattr(stat_result, "st_atime", None)) if state.config.use_access_time else None,
        now=state.now,
        strong_match=True,
        age_hit=True,
        duplicate_hit=False,
        grouping_logic="Entire empty folder grouped as one unit because empty directories are best reviewed at folder level.",
        config=state.config,
        extra_evidence={
            "path_patterns": ["empty folder"],
            "category_hints": ["obsolete_artifact"],
            "reason_summary": "Empty folder appears to be a leftover artifact worth reviewing as a whole.",
            "uncertainty_notes": [
                "Some empty folders are intentionally kept by installers or applications."
            ],
            "counterarguments": [
                "An empty folder can still be a placeholder expected by future updates or scripts."
            ],
        },
    )
    state.units.append(unit)
