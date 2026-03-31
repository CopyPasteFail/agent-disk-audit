from __future__ import annotations

from collections import defaultdict

from .models import FileRecord, ScanConfig
from .utils import sha256_file


def find_duplicate_groups(files: list[FileRecord], config: ScanConfig) -> dict[str, list[FileRecord]]:
    if not config.duplicate_detection.enabled:
        return {}

    min_size_bytes = config.duplicate_detection.min_file_size_mb * 1024 * 1024
    eligible = [file for file in files if file.size_bytes >= min_size_bytes]
    if len(eligible) > config.duplicate_detection.max_hash_candidates:
        eligible = eligible[: config.duplicate_detection.max_hash_candidates]

    by_size: dict[int, list[FileRecord]] = defaultdict(list)
    for file in eligible:
        by_size[file.size_bytes].append(file)

    groups: dict[str, list[FileRecord]] = {}
    for same_size_files in by_size.values():
        if len(same_size_files) < 2:
            continue
        by_hash: dict[str, list[FileRecord]] = defaultdict(list)
        for file in same_size_files:
            try:
                file_hash = sha256_file(file.path)
            except OSError:
                continue
            by_hash[file_hash].append(file)
        for file_hash, matching_files in by_hash.items():
            if len(matching_files) > 1:
                groups[file_hash] = matching_files
    return groups
