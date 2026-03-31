from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


REASONING_PROVIDERS = {"deterministic", "codex_local", "openai_api"}
WEB_ENRICHMENT_PROVIDERS = {"disabled", "duckduckgo_lite", "codex_local"}
PROVIDER_FAILURE_REASONS = {
    "executable_missing",
    "no_subprocess_safe_codex_executable_found",
    "auth_missing",
    "auth_invalid_or_expired",
    "cli_invocation_failed",
    "schema_output_failed",
    "timeout",
}
CATEGORIES = {
    "temp",
    "cache",
    "logs",
    "crash_dump",
    "leftover_installer",
    "duplicate_group",
    "downloads_old",
    "obsolete_artifact",
    "app_residue",
    "app_support_data",
    "runtime_dependency",
    "system_component",
    "unknown",
}
RISKS = {"low", "medium", "high"}
CONFIDENCE_LABELS = {"low", "medium", "high"}


@dataclass(slots=True)
class AgeThresholds:
    cache: int = 14
    logs: int = 30
    downloads_old: int = 90
    leftover_installer: int = 60
    crash_dump: int = 14
    empty_folder: int = 30
    obsolete_artifact: int = 45


@dataclass(slots=True)
class DuplicateDetectionConfig:
    enabled: bool = True
    min_file_size_mb: int = 256
    max_hash_candidates: int = 2000


@dataclass(slots=True)
class CacheConfig:
    enabled: bool = True
    directory: str = ".cache"
    reasoning_namespace: str = "reasoning"
    web_namespace: str = "web"
    debug_namespace: str = "debug"


@dataclass(slots=True)
class ReasoningRuntimeConfig:
    max_units: int = 100
    batch_size: int = 4
    timeout_seconds: int = 90
    retries: int = 1


@dataclass(slots=True)
class CodexLocalConfig:
    transport: str = "cli_exec_adapter"
    executable: str = "codex"
    timeout_seconds: int = 90
    healthcheck_timeout_seconds: int = 20
    batch_size: int = 4
    retries: int = 1
    sandbox: str = "read-only"
    approval_policy: str = "never"
    include_plan_tool: bool = False
    auth_file: str = "~/.codex/auth.json"
    config_file: str = "~/.codex/config.toml"
    healthcheck_enabled: bool = True


@dataclass(slots=True)
class OpenAIAPIConfig:
    model: str = "gpt-5.4"
    temperature: float = 0.1
    timeout_seconds: int = 90
    batch_size: int = 4
    retries: int = 1
    api_key_env: str = "OPENAI_API_KEY"


@dataclass(slots=True)
class DuckDuckGoLiteConfig:
    timeout_seconds: int = 8
    max_results: int = 2


@dataclass(slots=True)
class ReportConfig:
    chart_category_count: int = 8


@dataclass(slots=True)
class ScanConfig:
    scan_root: str = "C:\\"
    exclude_paths: list[str] = field(default_factory=list)
    high_risk_paths: list[str] = field(default_factory=list)
    expert_system_review_mode: bool = False
    min_unit_size_mb: int = 256
    strong_signal_min_unit_size_mb: int = 32
    large_file_min_size_mb: int = 512
    file_sample_count: int = 5
    max_units_in_report: int = 250
    use_access_time: bool = False
    follow_symlinks: bool = False
    open_report_when_done: bool = True
    output_dir: str = "output\\latest"
    reasoning_provider: str = "codex_local"
    fallback_provider: str = "deterministic"
    web_enrichment_provider: str = "disabled"
    age_threshold_days: AgeThresholds = field(default_factory=AgeThresholds)
    duplicate_detection: DuplicateDetectionConfig = field(default_factory=DuplicateDetectionConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    reasoning: ReasoningRuntimeConfig = field(default_factory=ReasoningRuntimeConfig)
    codex_local: CodexLocalConfig = field(default_factory=CodexLocalConfig)
    openai_api: OpenAIAPIConfig = field(default_factory=OpenAIAPIConfig)
    duckduckgo_lite: DuckDuckGoLiteConfig = field(default_factory=DuckDuckGoLiteConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


@dataclass(slots=True)
class FileRecord:
    path: str
    size_bytes: int
    created_at: datetime | None
    modified_at: datetime | None
    accessed_at: datetime | None
    extension: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "created_at": isoformat_or_none(self.created_at),
            "modified_at": isoformat_or_none(self.modified_at),
            "accessed_at": isoformat_or_none(self.accessed_at),
            "extension": self.extension,
        }


@dataclass(slots=True)
class WebCitation:
    title: str
    url: str
    snippet: str
    claim: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class CleanupUnit:
    unit_id: str
    name: str
    path: str
    root_path: str
    item_kind: str
    unit_type: str
    category: str
    zone: str
    risk: str
    confidence_score: int
    confidence_label: str
    total_size_bytes: int
    file_count: int
    display_size: str
    display_modified_at: str
    review_priority: str
    review_priority_score: int
    decision_focus: str
    recommendation: str
    reason_summary: str
    llm_rationale: str
    uncertainty_notes: list[str]
    counterarguments: list[str]
    cleanup_characterization: list[str]
    deterministic_evidence: dict[str, Any]
    grouping_logic: str
    evidence_source: str
    sample_files: list[dict[str, Any]]
    extension_distribution: list[dict[str, Any]]
    representative_modified_at: datetime | None = None
    representative_created_at: datetime | None = None
    representative_accessed_at: datetime | None = None
    web_citations: list[WebCitation] = field(default_factory=list)
    reasoning_provider: str = "deterministic"
    requested_reasoning_provider: str = "deterministic"
    fallback_provider: str | None = None
    reasoning_status: str = "completed"
    used_web_support: bool = False
    provider_failure_reason: str | None = None
    provider_failure_detail: str | None = None
    provider_debug_artifact_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["representative_modified_at"] = isoformat_or_none(self.representative_modified_at)
        payload["representative_created_at"] = isoformat_or_none(self.representative_created_at)
        payload["representative_accessed_at"] = isoformat_or_none(self.representative_accessed_at)
        payload["web_citations"] = [citation.to_dict() for citation in self.web_citations]
        return payload


@dataclass(slots=True)
class SkipRecord:
    path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def isoformat_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
