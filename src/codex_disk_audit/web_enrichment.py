from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .models import CleanupUnit, ScanConfig, WebCitation
from .reasoning.cache import LocalResultCache
from .reasoning.providers import CodexExecAdapter


class WebEnrichmentProvider(ABC):
    name: str

    @abstractmethod
    def enrich(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path, cache: LocalResultCache) -> None:
        raise NotImplementedError


class DisabledWebProvider(WebEnrichmentProvider):
    name = "disabled"

    def enrich(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path, cache: LocalResultCache) -> None:
        return


class DuckDuckGoLiteProvider(WebEnrichmentProvider):
    name = "duckduckgo_lite"

    def enrich(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path, cache: LocalResultCache) -> None:
        for unit in units:
            cache_key = cache.make_key(
                config.cache.web_namespace,
                {"provider": self.name, "path": unit.path, "category": unit.category},
            )
            cached = cache.get(config.cache.web_namespace, cache_key)
            if cached is not None:
                citations = [WebCitation(**citation) for citation in cached.get("citations", [])]
                if citations:
                    unit.web_citations = citations
                    unit.used_web_support = True
                continue

            citations = _search_duckduckgo_lite(unit, config)
            if citations:
                unit.web_citations = citations
                unit.used_web_support = True
                cache.set(
                    config.cache.web_namespace,
                    cache_key,
                    {"citations": [citation.to_dict() for citation in citations]},
                )


class CodexLocalWebProvider(WebEnrichmentProvider):
    name = "codex_local"

    def __init__(self, adapter: CodexExecAdapter, config: ScanConfig) -> None:
        self.adapter = adapter
        self.config = config

    def enrich(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path, cache: LocalResultCache) -> None:
        status = self.adapter.status(
            auth_file=config.codex_local.auth_file,
            config_file=config.codex_local.config_file,
            timeout_seconds=config.codex_local.healthcheck_timeout_seconds,
            healthcheck_enabled=config.codex_local.healthcheck_enabled,
        )
        if not status.usable:
            return

        prompt_template = (repo_root / "prompts" / "web_support_prompt.md").read_text(encoding="utf-8")
        target_units = [unit for unit in units if unit.category in {"temp", "cache", "logs", "crash_dump", "leftover_installer"}]
        for unit in target_units:
            cache_key = cache.make_key(
                config.cache.web_namespace,
                {"provider": self.name, "path": unit.path, "category": unit.category, "vendor_hint": unit.deterministic_evidence.get("vendor_hint")},
            )
            cached = cache.get(config.cache.web_namespace, cache_key)
            if cached is not None:
                citations = [WebCitation(**citation) for citation in cached.get("citations", [])]
                if citations:
                    unit.web_citations = citations
                    unit.used_web_support = True
                continue

            prompt = "\n\n".join(
                [
                    prompt_template,
                    json.dumps(
                        {
                            "unit_id": unit.unit_id,
                            "path": unit.path,
                            "category": unit.category,
                            "vendor_hint": unit.deterministic_evidence.get("vendor_hint"),
                            "path_patterns": unit.deterministic_evidence.get("path_patterns", []),
                        },
                        indent=2,
                    ),
                ]
            )
            try:
                payload = self.adapter.run_structured(
                    prompt=prompt,
                    schema=_web_schema(),
                    cwd=repo_root,
                    timeout_seconds=config.reasoning.timeout_seconds,
                    operation="web-enrichment",
                )
            except Exception:
                continue

            citations_payload = payload.get("citations", [])
            if not isinstance(citations_payload, list):
                continue
            citations = []
            try:
                for citation in citations_payload:
                    citations.append(
                        WebCitation(
                            title=str(citation["title"]),
                            url=str(citation["url"]),
                            snippet=str(citation["snippet"]),
                            claim=str(citation["claim"]),
                        )
                    )
            except (KeyError, TypeError, ValueError):
                continue

            if citations:
                unit.web_citations = citations
                unit.used_web_support = True
                cache.set(
                    config.cache.web_namespace,
                    cache_key,
                    {"citations": [citation.to_dict() for citation in citations]},
                )


def enrich_units_with_web(units: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> None:
    cache = LocalResultCache(config.cache, repo_root)
    provider = build_web_provider(config)
    provider.enrich(units, config, repo_root, cache)


def build_web_provider(config: ScanConfig) -> WebEnrichmentProvider:
    if config.web_enrichment_provider == "disabled":
        return DisabledWebProvider()
    if config.web_enrichment_provider == "duckduckgo_lite":
        return DuckDuckGoLiteProvider()
    if config.web_enrichment_provider == "codex_local":
        repo_root = Path(__file__).resolve().parents[2]
        return CodexLocalWebProvider(
            adapter=CodexExecAdapter(
                executable=config.codex_local.executable,
                repo_root=repo_root,
                cache_directory=repo_root / config.cache.directory / config.cache.debug_namespace,
            ),
            config=config,
        )
    raise ValueError(f"Unsupported web enrichment provider: {config.web_enrichment_provider}")


def _search_duckduckgo_lite(unit: CleanupUnit, config: ScanConfig) -> list[WebCitation]:
    if unit.category not in {"temp", "cache", "logs", "crash_dump", "leftover_installer"}:
        return []

    query = _query_for_unit(unit)
    if not query:
        return []

    try:
        html = _fetch_duckduckgo_lite(query, config)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return []

    results = []
    pattern = re.compile(r'<a[^>]+href="(?P<url>[^"]+)"[^>]*>(?P<title>.*?)</a>', re.IGNORECASE)
    for match in pattern.finditer(html):
        title = re.sub(r"<.*?>", "", match.group("title")).strip()
        url = urllib.parse.unquote(match.group("url"))
        if not title or not url.startswith("http"):
            continue
        results.append(
            WebCitation(
                title=title,
                url=url,
                snippet="Supporting search result fetched from DuckDuckGo Lite.",
                claim=f"Supports the local classification of this unit as {unit.category.replace('_', ' ')}.",
            )
        )
        if len(results) >= config.duckduckgo_lite.max_results:
            break
    return results


def _query_for_unit(unit: CleanupUnit) -> str:
    vendor_hint = unit.deterministic_evidence.get("vendor_hint") or ""
    if unit.category == "cache":
        return f"{vendor_hint} cache folder Windows".strip()
    if unit.category == "temp":
        return f"{vendor_hint} temp files Windows".strip()
    if unit.category == "logs":
        return f"{vendor_hint} log files Windows".strip()
    if unit.category == "crash_dump":
        return "Windows crash dump files dmp"
    if unit.category == "leftover_installer":
        return f"{vendor_hint} installer cache Windows".strip()
    return ""


def _fetch_duckduckgo_lite(query: str, config: ScanConfig) -> str:
    params = urllib.parse.urlencode({"q": query})
    request = urllib.request.Request(
        f"https://lite.duckduckgo.com/lite/?{params}",
        headers={"User-Agent": "codex-disk-audit/0.2"},
    )
    with urllib.request.urlopen(request, timeout=config.duckduckgo_lite.timeout_seconds) as response:
        return response.read().decode("utf-8", errors="replace")


def _web_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "url": {"type": "string"},
                        "snippet": {"type": "string"},
                        "claim": {"type": "string"}
                    },
                    "required": ["title", "url", "snippet", "claim"],
                    "additionalProperties": False
                }
            }
        },
        "required": ["citations"],
        "additionalProperties": False
    }
