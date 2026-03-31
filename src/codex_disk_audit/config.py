from __future__ import annotations

import json
from pathlib import Path

from .models import (
    AgeThresholds,
    CacheConfig,
    CodexLocalConfig,
    DuckDuckGoLiteConfig,
    DuplicateDetectionConfig,
    OpenAIAPIConfig,
    ReasoningRuntimeConfig,
    ReportConfig,
    ScanConfig,
)


def load_config(config_path: str | Path) -> ScanConfig:
    path = Path(config_path)
    payload = json.loads(path.read_text(encoding="utf-8"))

    reasoning_provider = payload.get("reasoning_provider")
    fallback_provider = payload.get("fallback_provider")
    web_enrichment_provider = payload.get("web_enrichment_provider")

    if reasoning_provider is None:
        reasoning_provider = "openai_api" if payload.get("llm_reasoning_enabled") else "deterministic"
    if fallback_provider is None:
        fallback_provider = "deterministic"
    if web_enrichment_provider is None:
        web_enrichment_provider = "duckduckgo_lite" if payload.get("web_enrichment_enabled") else "disabled"

    codex_local_payload = dict(payload.get("codex_local", {}))
    codex_local_payload.pop("model", None)

    return ScanConfig(
        scan_root=payload.get("scan_root", "C:\\"),
        exclude_paths=payload.get("exclude_paths", []),
        high_risk_paths=payload.get("high_risk_paths", []),
        expert_system_review_mode=payload.get("expert_system_review_mode", False),
        min_unit_size_mb=payload.get("min_unit_size_mb", 256),
        strong_signal_min_unit_size_mb=payload.get("strong_signal_min_unit_size_mb", 32),
        large_file_min_size_mb=payload.get("large_file_min_size_mb", 512),
        file_sample_count=payload.get("file_sample_count", 5),
        max_units_in_report=payload.get("max_units_in_report", 250),
        use_access_time=payload.get("use_access_time", False),
        follow_symlinks=payload.get("follow_symlinks", False),
        open_report_when_done=payload.get("open_report_when_done", True),
        output_dir=payload.get("output_dir", "output\\latest"),
        reasoning_provider=reasoning_provider,
        fallback_provider=fallback_provider,
        web_enrichment_provider=web_enrichment_provider,
        age_threshold_days=AgeThresholds(**payload.get("age_threshold_days", {})),
        duplicate_detection=DuplicateDetectionConfig(**payload.get("duplicate_detection", {})),
        cache=CacheConfig(**payload.get("cache", {})),
        reasoning=ReasoningRuntimeConfig(
            max_units=payload.get("reasoning", {}).get("max_units", payload.get("llm", {}).get("max_units", 100)),
            batch_size=payload.get("reasoning", {}).get("batch_size", 4),
            timeout_seconds=payload.get("reasoning", {}).get("timeout_seconds", 90),
            retries=payload.get("reasoning", {}).get("retries", 1),
        ),
        codex_local=CodexLocalConfig(**codex_local_payload),
        openai_api=OpenAIAPIConfig(
            model=payload.get("openai_api", {}).get("model", payload.get("llm", {}).get("model", "gpt-5.4")),
            temperature=payload.get("openai_api", {}).get("temperature", payload.get("llm", {}).get("temperature", 0.1)),
            timeout_seconds=payload.get("openai_api", {}).get("timeout_seconds", 90),
            batch_size=payload.get("openai_api", {}).get("batch_size", 4),
            retries=payload.get("openai_api", {}).get("retries", 1),
            api_key_env=payload.get("openai_api", {}).get("api_key_env", "OPENAI_API_KEY"),
        ),
        duckduckgo_lite=DuckDuckGoLiteConfig(
            timeout_seconds=payload.get("duckduckgo_lite", {}).get("timeout_seconds", payload.get("web", {}).get("timeout_seconds", 8)),
            max_results=payload.get("duckduckgo_lite", {}).get("max_results", payload.get("web", {}).get("max_results", 2)),
        ),
        report=ReportConfig(**payload.get("report", {})),
    )
