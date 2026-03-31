from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codex_disk_audit.config import load_config
from codex_disk_audit.models import CleanupUnit
from codex_disk_audit.reasoning.contract import ReasoningResult, validate_reasoning_payload
from codex_disk_audit.reasoning.orchestrator import apply_reasoning
from codex_disk_audit.reasoning.providers import (
    CodexExecAdapter,
    CodexProviderError,
    ProviderStatus,
    build_provider,
)


def make_unit() -> CleanupUnit:
    return CleanupUnit(
        unit_id="unit-1",
        name="Temp cache",
        path=r"C:\Users\demo\AppData\Local\Temp",
        root_path=r"C:\Users\demo\AppData\Local\Temp",
        item_kind="folder",
        unit_type="folder_unit",
        category="temp",
        zone="medium_risk_zone",
        risk="medium",
        confidence_score=78,
        confidence_label="high",
        total_size_bytes=1024,
        file_count=10,
        display_size="1.0 KB",
        display_modified_at="2026-03-01",
        review_priority="review_next",
        review_priority_score=55,
        decision_focus="Likely generated data; worthwhile after top wins.",
        recommendation="Probably recreatable cache/temp; review likely worthwhile.",
        reason_summary="Temp folder matched.",
        llm_rationale="Deterministic reasoning only.",
        uncertainty_notes=["Folder names alone are not proof."],
        counterarguments=["Some temp folders contain staging data."],
        cleanup_characterization=["recreatable", "non-essential"],
        deterministic_evidence={"path_patterns": ["User temp directory."], "vendor_hint": "demo"},
        grouping_logic="Folder unit",
        evidence_source="deterministic",
        sample_files=[],
        extension_distribution=[],
    )


def make_result(unit_id: str, *, provider_source: str = "deterministic") -> ReasoningResult:
    return ReasoningResult(
        unit_id=unit_id,
        category="temp",
        risk="medium",
        confidence="medium",
        recommendation="Probably recreatable cache/temp; review likely worthwhile.",
        reason_summary="Structured reasoning result.",
        llm_rationale="Structured rationale.",
        uncertainty_notes=["Still review before acting."],
        counterarguments=["Staging files may still exist."],
        evidence_source=provider_source,
        used_web_support=False,
        citations=[],
        cleanup_characterization=["recreatable", "non-essential"],
    )


def make_status(name: str, *, usable: bool, failure_reason: str | None = None, detail: str = "Ready") -> ProviderStatus:
    authenticated = failure_reason not in {"auth_missing", "auth_invalid_or_expired"} and usable
    available = failure_reason != "executable_missing"
    return ProviderStatus(
        name=name,
        available=available,
        authenticated=authenticated,
        usable=usable,
        detail=detail,
        failure_reason=failure_reason,
    )


class FakeProvider:
    def __init__(self, name: str, status: ProviderStatus, result: ReasoningResult | None = None, error: Exception | None = None) -> None:
        self.name = name
        self._status = status
        self._result = result
        self._error = error

    def status(self) -> ProviderStatus:
        return self._status

    def reason_batch(self, units, config, repo_root):
        if self._error:
            raise self._error
        result = self._result or make_result(units[0].unit_id, provider_source=self.name)
        return {unit.unit_id: make_result(unit.unit_id, provider_source=result.evidence_source) for unit in units}


class ReasoningProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config("config/demo.json")

    def test_default_provider_selection_prefers_codex_local(self) -> None:
        config = load_config("config/defaults.json")
        provider = build_provider(config.reasoning_provider, config, Path.cwd())
        self.assertEqual(provider.name, "codex_local")

    def test_codex_resolution_rejects_windowsapps_packaged_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            windowsapps_path = r"C:\Program Files\WindowsApps\OpenAI.Codex_x64\app\resources\codex.exe"
            with mock.patch("shutil.which", return_value=windowsapps_path), mock.patch.object(
                adapter,
                "_where_candidates",
                return_value=[windowsapps_path],
            ), mock.patch.object(
                adapter,
                "_common_windows_candidates",
                return_value=[],
            ):
                selected, candidates = adapter.resolve_executable()
        self.assertIsNone(selected)
        self.assertEqual(candidates[0]["status"], "rejected")
        self.assertIn("WindowsApps", candidates[0]["reason"])

    def test_codex_resolution_prefers_explicit_config_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            explicit_path = Path(temp_dir_name) / "codex.exe"
            explicit_path.write_text("", encoding="utf-8")
            adapter = CodexExecAdapter(
                executable=str(explicit_path),
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            with mock.patch("shutil.which", return_value=r"C:\tools\other-codex.exe"):
                selected, candidates = adapter.resolve_executable()
        self.assertEqual(selected, str(explicit_path))
        self.assertEqual(candidates[0]["source"], "explicit_config")
        self.assertEqual(candidates[0]["status"], "selected")

    def test_codex_resolution_prefers_non_windowsapps_path_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            non_windowsapps = r"C:\Users\demo\.codex\.sandbox-bin\codex.exe"
            with mock.patch("shutil.which", return_value=non_windowsapps):
                selected, candidates = adapter.resolve_executable()
        self.assertEqual(selected, non_windowsapps)
        self.assertEqual(candidates[0]["source"], "path_lookup")
        self.assertEqual(candidates[0]["status"], "selected")

    def test_codex_status_reports_rejected_candidates_when_no_safe_executable_found(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            windowsapps_path = r"C:\Program Files\WindowsApps\OpenAI.Codex_x64\app\resources\codex.exe"
            with mock.patch("shutil.which", return_value=windowsapps_path), mock.patch.object(
                adapter,
                "_where_candidates",
                return_value=[windowsapps_path],
            ), mock.patch.object(
                adapter,
                "_common_windows_candidates",
                return_value=[],
            ):
                status = adapter.status(
                    auth_file="missing.json",
                    config_file="missing.toml",
                    timeout_seconds=5,
                    healthcheck_enabled=True,
                )
        self.assertEqual(status.failure_reason, "no_subprocess_safe_codex_executable_found")
        self.assertIsNotNone(status.executable_candidates)
        self.assertGreaterEqual(len(status.executable_candidates or []), 1)

    def test_codex_status_detects_missing_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            with mock.patch("shutil.which", return_value=None), mock.patch.object(
                adapter,
                "_where_candidates",
                return_value=[],
            ), mock.patch.object(
                adapter,
                "_common_windows_candidates",
                return_value=[],
            ):
                status = adapter.status(
                    auth_file="missing.json",
                    config_file="missing.toml",
                    timeout_seconds=5,
                    healthcheck_enabled=True,
                )
        self.assertFalse(status.available)
        self.assertEqual(status.failure_reason, "executable_missing")

    def test_codex_status_detects_missing_auth_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            with mock.patch("shutil.which", return_value=r"C:\tools\codex.exe"):
                status = adapter.status(
                    auth_file=str(Path(temp_dir_name) / "missing-auth.json"),
                    config_file=str(Path(temp_dir_name) / "config.toml"),
                    timeout_seconds=5,
                    healthcheck_enabled=True,
                )
        self.assertFalse(status.usable)
        self.assertEqual(status.failure_reason, "auth_missing")

    def test_codex_status_runs_preflight_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            auth_path = Path(temp_dir_name) / "auth.json"
            auth_path.write_text(json.dumps({"tokens": {"access_token": "token"}}), encoding="utf-8")
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            with mock.patch("shutil.which", return_value=r"C:\tools\codex.exe"), mock.patch.object(
                adapter,
                "run_structured",
                return_value={"ok": True, "message": "ready"},
            ) as run_structured:
                status = adapter.status(
                    auth_file=str(auth_path),
                    config_file=str(Path(temp_dir_name) / "config.toml"),
                    timeout_seconds=5,
                    healthcheck_enabled=True,
                )
        self.assertTrue(status.usable)
        self.assertTrue(status.probe_performed)
        run_structured.assert_called_once()

    def test_codex_status_classifies_auth_probe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            auth_path = Path(temp_dir_name) / "auth.json"
            auth_path.write_text(json.dumps({"tokens": {"access_token": "token"}}), encoding="utf-8")
            adapter = CodexExecAdapter(
                executable="codex",
                repo_root=Path(temp_dir_name),
                cache_directory=Path(temp_dir_name) / ".cache" / "debug",
            )
            with mock.patch("shutil.which", return_value=r"C:\tools\codex.exe"), mock.patch.object(
                adapter,
                "run_structured",
                side_effect=CodexProviderError("auth_invalid_or_expired", "Token expired."),
            ):
                status = adapter.status(
                    auth_file=str(auth_path),
                    config_file=str(Path(temp_dir_name) / "config.toml"),
                    timeout_seconds=5,
                    healthcheck_enabled=True,
                )
        self.assertFalse(status.usable)
        self.assertEqual(status.failure_reason, "auth_invalid_or_expired")

    def test_validate_reasoning_payload_enforces_contract(self) -> None:
        payload = {
            "results": [
                {
                    "unit_id": "unit-1",
                    "category": "temp",
                    "risk": "medium",
                    "confidence": "medium",
                    "recommendation": "Review likely worthwhile.",
                    "reason_summary": "Temp path and age signals.",
                    "llm_rationale": "Structured rationale.",
                    "uncertainty_notes": ["Review sample files."],
                    "counterarguments": ["Some files may still be needed."],
                    "evidence_source": "deterministic + codex_local",
                    "used_web_support": False,
                    "citations": [],
                    "cleanup_characterization": ["recreatable", "non-essential"],
                }
            ]
        }
        results = validate_reasoning_payload(payload)
        self.assertIn("unit-1", results)

    def test_apply_reasoning_falls_back_when_primary_unusable(self) -> None:
        config = load_config("config/defaults.json")
        config.reasoning.max_units = 1
        unit = make_unit()
        primary = FakeProvider(
            "codex_local",
            make_status("codex_local", usable=False, failure_reason="auth_missing", detail="No auth."),
        )
        fallback = FakeProvider("deterministic", make_status("deterministic", usable=True))
        with mock.patch("codex_disk_audit.reasoning.orchestrator.build_provider", side_effect=[primary, fallback]), mock.patch(
            "codex_disk_audit.reasoning.orchestrator.enrich_units_with_web",
            return_value=None,
        ):
            apply_reasoning([unit], config)
        self.assertEqual(unit.reasoning_provider, "deterministic")
        self.assertEqual(unit.fallback_provider, "deterministic")
        self.assertEqual(unit.reasoning_status, "fallback_unavailable")
        self.assertEqual(unit.provider_failure_reason, "auth_missing")

    def test_apply_reasoning_records_provider_failure_debug_artifact(self) -> None:
        config = load_config("config/defaults.json")
        config.reasoning.max_units = 1
        unit = make_unit()
        primary = FakeProvider(
            "codex_local",
            make_status("codex_local", usable=True),
            error=CodexProviderError(
                "schema_output_failed",
                "Invalid JSON from codex_local.",
                debug_artifact_path=r"D:\repos\codex-disk-audit\.cache\debug\codex-reasoning-debug.json",
            ),
        )
        fallback = FakeProvider("deterministic", make_status("deterministic", usable=True))
        with mock.patch("codex_disk_audit.reasoning.orchestrator.build_provider", side_effect=[primary, fallback]), mock.patch(
            "codex_disk_audit.reasoning.orchestrator.enrich_units_with_web",
            return_value=None,
        ):
            apply_reasoning([unit], config)
        self.assertEqual(unit.reasoning_provider, "deterministic")
        self.assertEqual(unit.reasoning_status, "fallback_error")
        self.assertEqual(unit.provider_failure_reason, "schema_output_failed")
        self.assertTrue(unit.provider_debug_artifact_path.endswith(".json"))

    def test_apply_reasoning_marks_units_beyond_max_units_as_limit_fallback(self) -> None:
        config = load_config("config/defaults.json")
        config.reasoning.max_units = 1
        first = make_unit()
        second = make_unit()
        second.unit_id = "unit-2"
        primary = FakeProvider("codex_local", make_status("codex_local", usable=True))
        fallback = FakeProvider("deterministic", make_status("deterministic", usable=True))
        with mock.patch("codex_disk_audit.reasoning.orchestrator.build_provider", side_effect=[primary, fallback]), mock.patch(
            "codex_disk_audit.reasoning.orchestrator.enrich_units_with_web",
            return_value=None,
        ):
            apply_reasoning([first, second], config)
        self.assertEqual(first.reasoning_provider, "codex_local")
        self.assertEqual(first.reasoning_status, "completed")
        self.assertEqual(second.reasoning_provider, "deterministic")
        self.assertEqual(second.fallback_provider, "deterministic")
        self.assertEqual(second.reasoning_status, "fallback_limit")
        self.assertIsNone(second.provider_failure_reason)
        self.assertIn("max_units", second.provider_failure_detail or "")

    def test_apply_reasoning_skips_known_non_actionable_units(self) -> None:
        config = load_config("config/defaults.json")
        unit = make_unit()
        unit.category = "system_component"
        unit.recommendation = "System-managed duplication by design; not a cleanup candidate."
        unit.deterministic_evidence["skip_reasoning"] = True
        unit.deterministic_evidence["system_managed_duplicate"] = True
        with mock.patch("codex_disk_audit.reasoning.orchestrator.build_provider") as build_provider, mock.patch(
            "codex_disk_audit.reasoning.orchestrator.enrich_units_with_web",
            return_value=None,
        ):
            apply_reasoning([unit], config)
        build_provider.assert_not_called()
        self.assertEqual(unit.reasoning_provider, "deterministic")
        self.assertEqual(unit.reasoning_status, "skipped_known_non_actionable")
        self.assertEqual(unit.recommendation, "System-managed duplication by design; not a cleanup candidate.")

    def test_codex_contract_failure_writes_debug_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root = Path(temp_dir_name)
            (repo_root / "prompts").mkdir(parents=True, exist_ok=True)
            (repo_root / "prompts" / "reasoning_prompt.md").write_text("Reason carefully.", encoding="utf-8")
            config = load_config("config/defaults.json")
            provider = build_provider("codex_local", config, repo_root)
            provider.adapter.run_structured = mock.Mock(  # type: ignore[method-assign]
                return_value={"results": [{"unit_id": "unit-1", "category": "temp"}]}
            )
            with self.assertRaises(CodexProviderError) as context:
                provider.reason_batch([make_unit()], config, repo_root)
            self.assertEqual(context.exception.failure_reason, "schema_output_failed")
            self.assertIsNotNone(context.exception.debug_artifact_path)
            artifact = Path(context.exception.debug_artifact_path)
            self.assertTrue(artifact.exists())


if __name__ == "__main__":
    unittest.main()
