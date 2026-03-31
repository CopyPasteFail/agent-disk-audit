from __future__ import annotations

from pathlib import Path

from ..models import CleanupUnit, ScanConfig, WebCitation
from ..utils import clamp
from ..web_enrichment import enrich_units_with_web
from .cache import LocalResultCache
from .contract import ReasoningResult
from .providers import ProviderStatus, build_provider, describe_exception


def apply_reasoning(units: list[CleanupUnit], config: ScanConfig) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    cache = LocalResultCache(config.cache, repo_root)
    reasoning_eligible: list[CleanupUnit] = []
    skipped_units: list[CleanupUnit] = []
    for unit in units:
        if unit.deterministic_evidence.get("skip_reasoning"):
            skipped_units.append(unit)
        else:
            reasoning_eligible.append(unit)

    for unit in skipped_units:
        unit.requested_reasoning_provider = config.reasoning_provider
        unit.reasoning_provider = "deterministic"
        unit.fallback_provider = None
        unit.reasoning_status = "skipped_known_non_actionable"
        unit.provider_failure_reason = None
        unit.provider_failure_detail = None
        unit.provider_debug_artifact_path = None
        unit.evidence_source = "deterministic only"

    if not reasoning_eligible:
        return

    limited_units = reasoning_eligible[: config.reasoning.max_units]
    enrich_units_with_web(limited_units, config, repo_root)

    primary = build_provider(config.reasoning_provider, config, repo_root)
    fallback = build_provider(config.fallback_provider, config, repo_root)
    primary_status = primary.status()

    pending: list[CleanupUnit] = []
    for unit in limited_units:
        unit.requested_reasoning_provider = config.reasoning_provider
        cached = _load_cached_result(unit, config, cache)
        if cached is None:
            pending.append(unit)
            continue
        (
            result,
            actual_provider,
            fallback_provider,
            reasoning_status,
            provider_failure_reason,
            provider_failure_detail,
            provider_debug_artifact_path,
        ) = cached
        apply_reasoning_result(
            unit,
            result,
            actual_provider=actual_provider,
            fallback_provider=fallback_provider,
            reason_status=reasoning_status,
            provider_failure_reason=provider_failure_reason,
            provider_failure_detail=provider_failure_detail,
            provider_debug_artifact_path=provider_debug_artifact_path,
        )

    if pending:
        provider_to_use = primary
        if not primary_status.usable:
            provider_to_use = fallback
            print(
                f"[codex_local] falling back before reasoning: "
                f"{primary_status.failure_reason or 'not_usable'} - {primary_status.detail}"
            )
        if provider_to_use is fallback:
            _apply_provider_status(pending, primary_status)
        for batch in _batched(pending, _batch_size_for(provider_to_use.name, config)):
            try:
                batch_results = _invoke_with_retries(provider_to_use, batch, config, repo_root)
                batch_provider = provider_to_use.name
                batch_fallback = None if batch_provider == config.reasoning_provider else config.fallback_provider
                batch_status = "completed" if batch_provider == config.reasoning_provider else "fallback_unavailable"
                batch_failure_reason = None if batch_provider == config.reasoning_provider else primary_status.failure_reason
                batch_failure_detail = None if batch_provider == config.reasoning_provider else primary_status.detail
                batch_debug_artifact_path = None if batch_provider == config.reasoning_provider else primary_status.debug_artifact_path
            except Exception as error:
                failure_reason, failure_detail, debug_artifact_path = describe_exception(error)
                print(
                    f"[{config.reasoning_provider}] reasoning batch failed; using fallback: "
                    f"{failure_reason or 'provider_error'} - {failure_detail}"
                )
                _apply_failure(batch, failure_reason, failure_detail, debug_artifact_path)
                batch_results = _invoke_with_retries(fallback, batch, config, repo_root)
                batch_provider = fallback.name
                batch_fallback = fallback.name if fallback.name != config.reasoning_provider else None
                batch_status = "fallback_error"
                batch_failure_reason = failure_reason
                batch_failure_detail = failure_detail
                batch_debug_artifact_path = debug_artifact_path

            for unit in batch:
                result = batch_results.get(unit.unit_id)
                if result is None:
                    result = _invoke_with_retries(fallback, [unit], config, repo_root)[unit.unit_id]
                    actual_provider = fallback.name
                    fallback_provider = fallback.name if fallback.name != config.reasoning_provider else None
                    reasoning_status = "fallback_missing_result"
                    provider_failure_reason = batch_failure_reason or "schema_output_failed"
                    provider_failure_detail = batch_failure_detail or f"{config.reasoning_provider} returned no result for this unit."
                    provider_debug_artifact_path = batch_debug_artifact_path
                else:
                    actual_provider = batch_provider
                    fallback_provider = batch_fallback
                    reasoning_status = batch_status
                    provider_failure_reason = batch_failure_reason
                    provider_failure_detail = batch_failure_detail
                    provider_debug_artifact_path = batch_debug_artifact_path
                apply_reasoning_result(
                    unit,
                    result,
                    actual_provider=actual_provider,
                    fallback_provider=fallback_provider,
                    reason_status=reasoning_status,
                    provider_failure_reason=provider_failure_reason,
                    provider_failure_detail=provider_failure_detail,
                    provider_debug_artifact_path=provider_debug_artifact_path,
                )
                _store_cached_result(unit, result, config, cache)

    for unit in reasoning_eligible[config.reasoning.max_units :]:
        result = _invoke_with_retries(fallback, [unit], config, repo_root)[unit.unit_id]
        apply_reasoning_result(
            unit,
            result,
            actual_provider=fallback.name,
            fallback_provider=fallback.name,
            reason_status="fallback_limit",
            provider_failure_reason=None,
            provider_failure_detail="Primary reasoning was skipped because the configured max_units limit was reached."
            if config.reasoning_provider != fallback.name
            else None,
            provider_debug_artifact_path=None,
        )


def apply_reasoning_result(
    unit: CleanupUnit,
    result: ReasoningResult,
    *,
    actual_provider: str,
    fallback_provider: str | None,
    reason_status: str,
    provider_failure_reason: str | None,
    provider_failure_detail: str | None,
    provider_debug_artifact_path: str | None,
) -> None:
    if unit.category == "unknown" and result.category != "unknown":
        unit.category = result.category
    unit.risk = _max_risk(unit.risk, result.risk)
    unit.confidence_label = _min_confidence(unit.confidence_label, result.confidence)
    unit.confidence_score = _clamp_score_for_label(unit.confidence_score, unit.confidence_label)
    unit.recommendation = result.recommendation
    unit.reason_summary = result.reason_summary
    unit.llm_rationale = result.llm_rationale
    unit.uncertainty_notes = result.uncertainty_notes
    unit.counterarguments = result.counterarguments
    unit.cleanup_characterization = result.cleanup_characterization
    unit.used_web_support = result.used_web_support
    unit.web_citations = result.citations or unit.web_citations
    unit.reasoning_provider = actual_provider
    unit.fallback_provider = fallback_provider
    unit.reasoning_status = reason_status
    unit.evidence_source = _compose_evidence_source(actual_provider, bool(unit.web_citations))
    unit.provider_failure_reason = provider_failure_reason
    unit.provider_failure_detail = provider_failure_detail
    unit.provider_debug_artifact_path = provider_debug_artifact_path


def _load_cached_result(
    unit: CleanupUnit,
    config: ScanConfig,
    cache: LocalResultCache,
) -> tuple[ReasoningResult, str, str | None, str, str | None, str | None, str | None] | None:
    cache_key = cache.make_key(
        config.cache.reasoning_namespace,
        {
            "provider": config.reasoning_provider,
            "fallback_provider": config.fallback_provider,
            "unit": _cache_payload(unit),
        },
    )
    cached = cache.get(config.cache.reasoning_namespace, cache_key)
    if cached is None:
        return None
    result = _result_from_cache(cached)
    return (
        result,
        cached.get("actual_provider", result.evidence_source),
        cached.get("fallback_provider"),
        cached.get("reasoning_status", "cached"),
        cached.get("provider_failure_reason"),
        cached.get("provider_failure_detail"),
        cached.get("provider_debug_artifact_path"),
    )


def _store_cached_result(
    unit: CleanupUnit,
    result: ReasoningResult,
    config: ScanConfig,
    cache: LocalResultCache,
) -> None:
    cache_key = cache.make_key(
        config.cache.reasoning_namespace,
        {
            "provider": config.reasoning_provider,
            "fallback_provider": config.fallback_provider,
            "unit": _cache_payload(unit),
        },
    )
    cache.set(
        config.cache.reasoning_namespace,
        cache_key,
        {
            "actual_provider": unit.reasoning_provider,
            "fallback_provider": unit.fallback_provider,
            "reasoning_status": unit.reasoning_status,
            "provider_failure_reason": unit.provider_failure_reason,
            "provider_failure_detail": unit.provider_failure_detail,
            "provider_debug_artifact_path": unit.provider_debug_artifact_path,
            "result": result.to_dict(),
        },
    )


def _cache_payload(unit: CleanupUnit) -> dict:
    return {
        "unit_id": unit.unit_id,
        "category": unit.category,
        "risk": unit.risk,
        "confidence_label": unit.confidence_label,
        "deterministic_evidence": unit.deterministic_evidence,
        "sample_files": unit.sample_files,
        "extension_distribution": unit.extension_distribution,
        "web_citations": [citation.to_dict() for citation in unit.web_citations],
    }


def _result_from_cache(payload: dict) -> ReasoningResult:
    result_payload = payload["result"]
    return ReasoningResult(
        unit_id=result_payload["unit_id"],
        category=result_payload["category"],
        risk=result_payload["risk"],
        confidence=result_payload["confidence"],
        recommendation=result_payload["recommendation"],
        reason_summary=result_payload["reason_summary"],
        llm_rationale=result_payload["llm_rationale"],
        uncertainty_notes=result_payload["uncertainty_notes"],
        counterarguments=result_payload["counterarguments"],
        evidence_source=result_payload["evidence_source"],
        used_web_support=result_payload["used_web_support"],
        citations=[WebCitation(**citation) for citation in result_payload["citations"]],
        cleanup_characterization=result_payload["cleanup_characterization"],
    )


def _batch_size_for(provider_name: str, config: ScanConfig) -> int:
    if provider_name == "codex_local":
        return max(1, config.codex_local.batch_size)
    if provider_name == "openai_api":
        return max(1, config.openai_api.batch_size)
    return max(1, config.reasoning.batch_size)


def _retries_for(provider_name: str, config: ScanConfig) -> int:
    if provider_name == "codex_local":
        return max(0, config.codex_local.retries)
    if provider_name == "openai_api":
        return max(0, config.openai_api.retries)
    return max(0, config.reasoning.retries)


def _invoke_with_retries(provider, batch: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> dict[str, ReasoningResult]:
    attempts = _retries_for(provider.name, config) + 1
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            return provider.reason_batch(batch, config, repo_root)
        except Exception as error:
            last_error = error
    if last_error is not None:
        raise last_error
    raise RuntimeError("Provider invocation failed without an exception.")


def _apply_provider_status(units: list[CleanupUnit], status: ProviderStatus) -> None:
    for unit in units:
        unit.provider_failure_reason = status.failure_reason
        unit.provider_failure_detail = status.detail
        unit.provider_debug_artifact_path = status.debug_artifact_path


def _apply_failure(
    units: list[CleanupUnit],
    failure_reason: str | None,
    failure_detail: str,
    debug_artifact_path: str | None,
) -> None:
    for unit in units:
        unit.provider_failure_reason = failure_reason
        unit.provider_failure_detail = failure_detail
        unit.provider_debug_artifact_path = debug_artifact_path


def _batched(units: list[CleanupUnit], batch_size: int) -> list[list[CleanupUnit]]:
    return [units[index : index + batch_size] for index in range(0, len(units), batch_size)]


def _compose_evidence_source(provider: str, used_web_support: bool) -> str:
    if provider == "deterministic":
        return "deterministic + web" if used_web_support else "deterministic"
    if used_web_support:
        return f"deterministic + {provider} + web"
    return f"deterministic + {provider}"


def _max_risk(current: str, proposed: str) -> str:
    rank = {"low": 0, "medium": 1, "high": 2}
    return current if rank[current] >= rank[proposed] else proposed


def _min_confidence(current: str, proposed: str) -> str:
    rank = {"low": 0, "medium": 1, "high": 2}
    return current if rank[current] <= rank[proposed] else proposed


def _clamp_score_for_label(score: int, label: str) -> int:
    if label == "low":
        return clamp(score, 10, 49)
    if label == "medium":
        return clamp(score, 50, 74)
    return clamp(score, 75, 95)
