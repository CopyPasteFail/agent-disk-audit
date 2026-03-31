from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ..models import CATEGORIES, CONFIDENCE_LABELS, RISKS, CleanupUnit, WebCitation


@dataclass(slots=True)
class ReasoningResult:
    unit_id: str
    category: str
    risk: str
    confidence: str
    recommendation: str
    reason_summary: str
    llm_rationale: str
    uncertainty_notes: list[str]
    counterarguments: list[str]
    evidence_source: str
    used_web_support: bool
    citations: list[WebCitation]
    cleanup_characterization: list[str]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["citations"] = [citation.to_dict() for citation in self.citations]
        return payload


def reasoning_schema() -> dict[str, Any]:
    citation_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "url": {"type": "string"},
            "snippet": {"type": "string"},
            "claim": {"type": "string"},
        },
        "required": ["title", "url", "snippet", "claim"],
        "additionalProperties": False,
    }
    item_schema = {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            "category": {"type": "string", "enum": sorted(CATEGORIES)},
            "risk": {"type": "string", "enum": sorted(RISKS)},
            "confidence": {"type": "string", "enum": sorted(CONFIDENCE_LABELS)},
            "recommendation": {"type": "string"},
            "reason_summary": {"type": "string"},
            "llm_rationale": {"type": "string"},
            "uncertainty_notes": {"type": "array", "items": {"type": "string"}},
            "counterarguments": {"type": "array", "items": {"type": "string"}},
            "evidence_source": {"type": "string"},
            "used_web_support": {"type": "boolean"},
            "citations": {"type": "array", "items": citation_schema},
            "cleanup_characterization": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "unit_id",
            "category",
            "risk",
            "confidence",
            "recommendation",
            "reason_summary",
            "llm_rationale",
            "uncertainty_notes",
            "counterarguments",
            "evidence_source",
            "used_web_support",
            "citations",
            "cleanup_characterization",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "results": {"type": "array", "items": item_schema}
        },
        "required": ["results"],
        "additionalProperties": False,
    }


def validate_reasoning_payload(payload: Any) -> dict[str, ReasoningResult]:
    if not isinstance(payload, dict):
        raise ValueError("Reasoning payload must be an object.")
    items = payload.get("results")
    if not isinstance(items, list):
        raise ValueError("Reasoning payload must contain a results array.")
    results: dict[str, ReasoningResult] = {}
    for item in items:
        result = validate_reasoning_result(item)
        results[result.unit_id] = result
    return results


def validate_reasoning_result(item: Any) -> ReasoningResult:
    if not isinstance(item, dict):
        raise ValueError("Reasoning result entry must be an object.")
    _require_str(item, "unit_id")
    category = _require_enum(item, "category", CATEGORIES)
    risk = _require_enum(item, "risk", RISKS)
    confidence = _require_enum(item, "confidence", CONFIDENCE_LABELS)
    recommendation = _require_str(item, "recommendation")
    reason_summary = _require_str(item, "reason_summary")
    llm_rationale = _require_str(item, "llm_rationale")
    uncertainty_notes = _require_str_list(item, "uncertainty_notes")
    counterarguments = _require_str_list(item, "counterarguments")
    evidence_source = _require_str(item, "evidence_source")
    used_web_support = item.get("used_web_support")
    if not isinstance(used_web_support, bool):
        raise ValueError("used_web_support must be a boolean.")
    cleanup_characterization = _require_str_list(item, "cleanup_characterization")
    citations_payload = item.get("citations")
    if not isinstance(citations_payload, list):
        raise ValueError("citations must be a list.")
    citations = []
    for citation in citations_payload:
        if not isinstance(citation, dict):
            raise ValueError("Citation entries must be objects.")
        citations.append(
            WebCitation(
                title=_require_str(citation, "title"),
                url=_require_str(citation, "url"),
                snippet=_require_str(citation, "snippet"),
                claim=_require_str(citation, "claim"),
            )
        )
    return ReasoningResult(
        unit_id=item["unit_id"],
        category=category,
        risk=risk,
        confidence=confidence,
        recommendation=recommendation,
        reason_summary=reason_summary,
        llm_rationale=llm_rationale,
        uncertainty_notes=uncertainty_notes,
        counterarguments=counterarguments,
        evidence_source=evidence_source,
        used_web_support=used_web_support,
        citations=citations,
        cleanup_characterization=cleanup_characterization,
    )


def deterministic_prompt_payload(unit: CleanupUnit) -> dict[str, Any]:
    return {
        "unit_id": unit.unit_id,
        "name": unit.name,
        "path": unit.path,
        "root_path": unit.root_path,
        "category": unit.category,
        "zone": unit.zone,
        "risk": unit.risk,
        "confidence_label": unit.confidence_label,
        "confidence_score": unit.confidence_score,
        "recommendation": unit.recommendation,
        "grouping_logic": unit.grouping_logic,
        "cleanup_characterization": unit.cleanup_characterization,
        "deterministic_evidence": unit.deterministic_evidence,
        "sample_files": unit.sample_files,
        "extension_distribution": unit.extension_distribution,
        "uncertainty_notes": unit.uncertainty_notes,
        "counterarguments": unit.counterarguments,
        "web_citations": [citation.to_dict() for citation in unit.web_citations],
    }


def _require_str(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string.")
    return value


def _require_enum(item: dict[str, Any], key: str, allowed: set[str]) -> str:
    value = _require_str(item, key)
    if value not in allowed:
        raise ValueError(f"{key} must be one of {sorted(allowed)}.")
    return value


def _require_str_list(item: dict[str, Any], key: str) -> list[str]:
    value = item.get(key)
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise ValueError(f"{key} must be a list of strings.")
    return value
