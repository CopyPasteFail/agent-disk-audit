from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath


def normalize_windows_path(path: str) -> str:
    normalized = path.replace("/", "\\").rstrip("\\")
    if len(normalized) == 2 and normalized.endswith(":"):
        return normalized + "\\"
    return normalized


def casefold_path(path: str) -> str:
    return normalize_windows_path(path).lower()


def is_path_under(path: str, parent: str) -> bool:
    folded_path = casefold_path(path)
    folded_parent = casefold_path(parent)
    return folded_path == folded_parent or folded_path.startswith(folded_parent.rstrip("\\") + "\\")


def format_bytes(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def dt_from_timestamp(timestamp: float | None) -> datetime | None:
    if timestamp in (None, 0):
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None


def latest_datetime(*values: datetime | None) -> datetime | None:
    candidates = [value for value in values if value is not None]
    return max(candidates) if candidates else None


def oldest_datetime(*values: datetime | None) -> datetime | None:
    candidates = [value for value in values if value is not None]
    return min(candidates) if candidates else None


def iso_date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


def safe_relpath(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def windows_path_to_file_uri(path: str) -> str:
    normalized = normalize_windows_path(path)
    return PureWindowsPath(normalized).as_uri()


def extension_distribution(counter: Counter[str], top_n: int = 6) -> list[dict[str, int | str]]:
    items = []
    for extension, count in counter.most_common(top_n):
        label = extension if extension else "[no extension]"
        items.append({"extension": label, "count": count})
    return items


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def slugify(value: str) -> str:
    cleaned = []
    for character in value.lower():
        if character.isalnum():
            cleaned.append(character)
        elif cleaned and cleaned[-1] != "-":
            cleaned.append("-")
    return "".join(cleaned).strip("-") or "unit"


def ensure_directory(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory
