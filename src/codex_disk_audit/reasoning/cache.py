from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..models import CacheConfig
from ..utils import ensure_directory


class LocalResultCache:
    def __init__(self, config: CacheConfig, repo_root: Path) -> None:
        self.config = config
        self.root = ensure_directory(repo_root / config.directory)

    def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        if not self.config.enabled:
            return None
        path = self._entry_path(namespace, key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, namespace: str, key: str, payload: dict[str, Any]) -> None:
        if not self.config.enabled:
            return
        path = self._entry_path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def make_key(self, namespace: str, payload: dict[str, Any]) -> str:
        blob = json.dumps({"namespace": namespace, "payload": payload}, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _entry_path(self, namespace: str, key: str) -> Path:
        return self.root / namespace / f"{key}.json"

