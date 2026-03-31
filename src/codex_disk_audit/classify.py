from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PureWindowsPath

from .models import ScanConfig
from .utils import casefold_path, clamp, is_path_under


@dataclass(frozen=True, slots=True)
class FolderRule:
    pattern: str
    category: str
    note: str
    generated: bool = True


FOLDER_RULES: list[FolderRule] = [
    FolderRule("*\\appdata\\local\\temp", "temp", "User temp directory."),
    FolderRule("*\\appdata\\local\\microsoft\\windows\\inetcache", "cache", "Internet cache path."),
    FolderRule("*\\appdata\\local\\microsoft\\windows\\explorer", "cache", "Explorer thumbnail cache path."),
    FolderRule("*\\appdata\\local\\crashdumps", "crash_dump", "Crash dump directory."),
    FolderRule("*\\appdata\\local\\d3dscache", "cache", "Direct3D shader cache."),
    FolderRule("*\\appdata\\local\\packages\\*\\localcache", "cache", "Application local cache."),
    FolderRule("*\\appdata\\local\\packages\\*\\tempstate", "temp", "Application temp state."),
    FolderRule("*\\appdata\\local\\nvidia\\dxcache", "cache", "NVIDIA shader cache."),
    FolderRule("*\\appdata\\local\\nvidia\\glcache", "cache", "NVIDIA GL cache."),
    FolderRule("*\\appdata\\roaming\\npm-cache", "cache", "npm cache."),
    FolderRule("*\\appdata\\local\\pip\\cache", "cache", "pip cache."),
    FolderRule("*\\appdata\\local\\yarn\\cache", "cache", "Yarn cache."),
    FolderRule("*\\.gradle\\caches", "cache", "Gradle caches."),
    FolderRule("*\\.nuget\\packages", "runtime_dependency", "NuGet package cache reused across projects.", generated=False),
    FolderRule("*\\logs", "logs", "Log directory."),
    FolderRule("*\\log", "logs", "Log directory."),
    FolderRule("*\\crashdumps", "crash_dump", "Crash dump directory."),
    FolderRule("*\\dumps", "crash_dump", "Dump directory."),
    FolderRule("*\\cache", "cache", "Generic cache directory."),
    FolderRule("*\\caches", "cache", "Generic cache directory."),
    FolderRule("*\\temp", "temp", "Generic temp directory."),
    FolderRule("*\\tmp", "temp", "Generic temp directory."),
]


ARCHIVE_EXTENSIONS = {".iso", ".zip", ".7z", ".rar", ".vhd", ".vhdx", ".bak", ".tar", ".gz", ".bz2"}
INSTALLER_EXTENSIONS = {".msi", ".msp", ".exe", ".cab"}
LOG_EXTENSIONS = {".log", ".etl", ".trace"}
DUMP_EXTENSIONS = {".dmp", ".mdmp", ".hdmp", ".wer"}


def match_folder_rule(path: str) -> FolderRule | None:
    lowered = casefold_path(path)
    for rule in FOLDER_RULES:
        if fnmatch.fnmatch(lowered, rule.pattern):
            return rule
    return None


def infer_category_from_file(file_name: str, parent_path: str) -> str:
    extension = PureWindowsPath(file_name).suffix.lower()
    lowered_parent = casefold_path(parent_path)

    if extension in LOG_EXTENSIONS or "\\logs" in lowered_parent or lowered_parent.endswith("\\log"):
        return "logs"
    if extension in DUMP_EXTENSIONS or "dump" in lowered_parent:
        return "crash_dump"
    if extension in ARCHIVE_EXTENSIONS:
        return "obsolete_artifact"
    if extension in INSTALLER_EXTENSIONS:
        if "download" in lowered_parent or "installer" in lowered_parent or "package cache" in lowered_parent:
            return "leftover_installer"
    return "unknown"


def classify_zone(path: str, category: str, config: ScanConfig) -> str:
    lowered = casefold_path(path)
    for high_risk_path in config.high_risk_paths:
        if is_path_under(path, high_risk_path):
            return "high_risk_zone"

    if "\\users\\" in lowered and "\\appdata\\" in lowered:
        if category in {"cache", "temp", "logs", "crash_dump"}:
            return "medium_risk_zone"
        return "medium_risk_zone"

    if "\\downloads" in lowered or category in {"cache", "temp", "logs", "crash_dump", "duplicate_group"}:
        return "low_risk_zone"

    return "medium_risk_zone"


def infer_vendor_hint(path: str) -> str | None:
    pure = PureWindowsPath(path)
    parts = [part for part in pure.parts if part not in {pure.drive, "\\"}]
    lowered = [part.lower() for part in parts]

    if "appdata" in lowered:
        index = lowered.index("appdata")
        tail = parts[index + 2 :]
        if tail:
            return tail[0]
    for anchor in ("Program Files", "Program Files (x86)", "ProgramData"):
        if anchor in parts:
            index = parts.index(anchor)
            if len(parts) > index + 1:
                return parts[index + 1]
    return None


def confidence_score(
    *,
    strong_match: bool,
    age_hit: bool,
    generated_data: bool,
    duplicate_hit: bool,
    zone: str,
    category: str,
    missing_signals: int,
) -> int:
    score = 40
    if strong_match:
        score += 22
    if age_hit:
        score += 14
    if generated_data:
        score += 12
    if duplicate_hit:
        score += 18
    if zone == "high_risk_zone":
        score -= 25
    if category in {"unknown", "system_component", "runtime_dependency", "app_support_data"}:
        score -= 15
    score -= missing_signals * 5
    return clamp(score, 10, 95)


def confidence_label(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def classify_risk(zone: str, category: str, confidence: int) -> str:
    if zone == "high_risk_zone":
        return "high"
    if category in {"unknown", "system_component", "runtime_dependency", "app_support_data"}:
        return "high"
    if confidence < 45:
        return "high"
    if category in {"temp", "cache", "logs", "crash_dump"} and zone == "low_risk_zone":
        return "low"
    return "medium"


def recommendation_for(
    category: str,
    risk: str,
    *,
    total_size_bytes: int = 0,
    age_days: int | None = None,
    mixed_content: bool = False,
    review_priority: str = "review_later",
) -> str:
    large = total_size_bytes >= 256 * 1024 * 1024
    old = age_days is not None and age_days >= 30
    if category in {"runtime_dependency", "system_component"} or risk == "high":
        return "Do not touch without expert validation."
    if category == "duplicate_group":
        return "Exact duplicate content alone is not enough to justify cleanup; verify ownership and purpose before any manual action."
    if category == "crash_dump":
        return "Review next: likely non-essential diagnostic output unless recent crashes still need investigation."
    if category == "logs":
        if total_size_bytes < 10 * 1024 * 1024:
            return "Lower priority: likely disposable logs, but reclaim value is modest."
        return "Review next: likely non-essential log data with meaningful reclaim value."
    if category in {"temp", "cache"}:
        if review_priority == "review_first" and mixed_content:
            return "Review first: large reclaim potential, but mixed contents need caution before any manual cleanup."
        if review_priority == "review_first":
            return "Review first: large likely-recreatable cache/temp data with strong reclaim potential."
        if large or old:
            return "Review next: likely generated cache/temp data, but still confirm it is not tied to active workflows."
        return "Review later: likely generated cache/temp data, but reclaim value appears modest."
    if category in {"leftover_installer", "app_residue"}:
        return "Review next: likely removable if the related application or update residue is no longer needed."
    if category in {"downloads_old", "obsolete_artifact"}:
        if total_size_bytes < 10 * 1024 * 1024:
            return "Lower priority: likely removable if unwanted, but reclaim value is small."
        return "Review next: likely removable if still unwanted."
    return "Ambiguous, manual review required."


def characterize_cleanup(category: str, risk: str) -> list[str]:
    if category in {"temp", "cache"} and risk != "high":
        return ["recreatable", "non-essential"]
    if category in {"logs", "crash_dump"} and risk != "high":
        return ["non-essential", "probably_unused"]
    if category == "duplicate_group":
        return ["ambiguous"]
    if category in {"leftover_installer", "downloads_old", "obsolete_artifact"}:
        return ["probably_unused", "ambiguous"]
    if category in {"runtime_dependency", "system_component", "unknown"}:
        return ["ambiguous"]
    return ["ambiguous"]


def looks_generated_data(path: str, category: str) -> bool:
    lowered = casefold_path(path)
    if category in {"temp", "cache", "logs", "crash_dump"}:
        return True
    if re.search(r"\\(cache|temp|tmp|logs?|crashdumps?|dump[s]?)\\", lowered):
        return True
    return False
