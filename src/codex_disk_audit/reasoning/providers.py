from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import CleanupUnit, PROVIDER_FAILURE_REASONS, ScanConfig
from ..utils import ensure_directory
from .contract import ReasoningResult, deterministic_prompt_payload, reasoning_schema, validate_reasoning_payload


AUTH_FAILURE_MARKERS = (
    "login required",
    "not authenticated",
    "authentication",
    "auth",
    "sign in",
    "signin",
    "expired",
    "token",
    "session",
)

WINDOWSAPPS_MARKER = "\\program files\\windowsapps\\"


@dataclass(slots=True)
class ProviderStatus:
    name: str
    available: bool
    authenticated: bool
    usable: bool
    detail: str
    failure_reason: str | None = None
    executable_path: str | None = None
    auth_path: str | None = None
    config_path: str | None = None
    configured_model: str | None = None
    executable_candidates: list[dict[str, str]] | None = None
    debug_artifact_path: str | None = None
    probe_performed: bool = False


class CodexProviderError(RuntimeError):
    def __init__(
        self,
        failure_reason: str,
        detail: str,
        *,
        debug_artifact_path: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.failure_reason = failure_reason
        self.detail = detail
        self.debug_artifact_path = debug_artifact_path


class ReasoningProvider(ABC):
    name: str

    @abstractmethod
    def status(self) -> ProviderStatus:
        raise NotImplementedError

    @abstractmethod
    def reason_batch(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> dict[str, ReasoningResult]:
        raise NotImplementedError


class DeterministicReasoningProvider(ReasoningProvider):
    name = "deterministic"

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            name=self.name,
            available=True,
            authenticated=True,
            usable=True,
            detail="Always available.",
        )

    def reason_batch(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> dict[str, ReasoningResult]:
        results: dict[str, ReasoningResult] = {}
        for unit in units:
            results[unit.unit_id] = ReasoningResult(
                unit_id=unit.unit_id,
                category=unit.category,
                risk=unit.risk,
                confidence=unit.confidence_label,
                recommendation=unit.recommendation,
                reason_summary=unit.reason_summary,
                llm_rationale=build_deterministic_rationale(unit),
                uncertainty_notes=unit.uncertainty_notes,
                counterarguments=unit.counterarguments,
                evidence_source="deterministic",
                used_web_support=bool(unit.web_citations),
                citations=list(unit.web_citations),
                cleanup_characterization=list(unit.cleanup_characterization),
            )
        return results


class OpenAIAPIReasoningProvider(ReasoningProvider):
    name = "openai_api"

    def status(self) -> ProviderStatus:
        api_key = os.getenv(self._api_key_env)
        if not api_key:
            return ProviderStatus(
                name=self.name,
                available=True,
                authenticated=False,
                usable=False,
                detail=f"Missing {self._api_key_env}.",
                failure_reason="auth_missing",
            )
        return ProviderStatus(
            name=self.name,
            available=True,
            authenticated=True,
            usable=True,
            detail=f"Using {self._api_key_env}.",
        )

    def __init__(self, api_key_env: str, model: str, temperature: float) -> None:
        self._api_key_env = api_key_env
        self._model = model
        self._temperature = temperature

    def reason_batch(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> dict[str, ReasoningResult]:
        api_key = os.getenv(self._api_key_env)
        if not api_key:
            raise RuntimeError(f"{self._api_key_env} is not set.")

        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError("openai package is not installed.") from error

        client = OpenAI(api_key=api_key)
        prompt_path = repo_root / "prompts" / "reasoning_prompt.md"
        prompt_template = prompt_path.read_text(encoding="utf-8")
        input_payload = {"results": [deterministic_prompt_payload(unit) for unit in units]}

        response = client.responses.create(
            model=self._model,
            temperature=self._temperature,
            input=[
                {"role": "system", "content": prompt_template},
                {"role": "user", "content": json.dumps(input_payload, indent=2)},
            ],
        )
        output_text = getattr(response, "output_text", None)
        if not output_text:
            raise RuntimeError("OpenAI API returned no output_text.")
        return validate_reasoning_payload(json.loads(output_text))


class CodexExecAdapter:
    def __init__(self, executable: str, *, repo_root: Path, cache_directory: Path) -> None:
        self.executable = executable
        self.repo_root = repo_root
        self.debug_directory = ensure_directory(cache_directory)
        self._resolution_cache: tuple[str | None, list[dict[str, str]]] | None = None

    def executable_path(self) -> str | None:
        selected, _ = self.resolve_executable()
        return selected

    def executable_candidates(self) -> list[dict[str, str]]:
        _, candidates = self.resolve_executable()
        return [dict(item) for item in candidates]

    def resolve_executable(self) -> tuple[str | None, list[dict[str, str]]]:
        if self._resolution_cache is not None:
            selected, candidates = self._resolution_cache
            return selected, [dict(item) for item in candidates]

        candidates: list[dict[str, str]] = []
        selected: str | None = None
        seen: set[str] = set()

        def record(path: str | None, *, source: str, reason: str, selected_candidate: bool) -> None:
            nonlocal selected
            if not path:
                return
            normalized = os.path.normcase(os.path.normpath(path))
            if normalized in seen:
                return
            seen.add(normalized)
            entry = {
                "path": path,
                "source": source,
                "status": "selected" if selected_candidate else "rejected",
                "reason": reason,
            }
            candidates.append(entry)
            if selected_candidate and selected is None:
                selected = path

        explicit_path = self._explicit_executable_path()
        if explicit_path is not None:
            if not os.path.exists(explicit_path):
                record(explicit_path, source="explicit_config", reason="Configured executable path does not exist.", selected_candidate=False)
            elif self._is_problematic_windowsapps_path(explicit_path):
                record(explicit_path, source="explicit_config", reason="Rejected WindowsApps packaged executable; not considered subprocess-safe.", selected_candidate=False)
            else:
                record(explicit_path, source="explicit_config", reason="Using explicit configured executable path.", selected_candidate=True)

        if selected is None:
            path_resolved = shutil.which(self.executable)
            if path_resolved is not None:
                if self._is_problematic_windowsapps_path(path_resolved):
                    record(path_resolved, source="path_lookup", reason="Rejected PATH-resolved WindowsApps packaged executable.", selected_candidate=False)
                else:
                    record(path_resolved, source="path_lookup", reason="Using PATH-resolved non-WindowsApps executable.", selected_candidate=True)

        if selected is None:
            for path in self._where_candidates():
                if self._is_problematic_windowsapps_path(path):
                    record(path, source="where.exe", reason="Rejected where.exe WindowsApps packaged executable.", selected_candidate=False)
                    continue
                record(path, source="where.exe", reason="Using where.exe non-WindowsApps candidate.", selected_candidate=True)
                break

        if selected is None:
            for path in self._common_windows_candidates():
                if self._is_problematic_windowsapps_path(path):
                    record(path, source="common_wrapper", reason="Rejected common wrapper candidate because it points into WindowsApps.", selected_candidate=False)
                    continue
                if not os.path.exists(path):
                    continue
                record(path, source="common_wrapper", reason="Using common subprocess-safe Codex wrapper candidate.", selected_candidate=True)
                break

        self._resolution_cache = (selected, [dict(item) for item in candidates])
        return selected, [dict(item) for item in candidates]

    def auth_file_payload(self, auth_file: str) -> dict[str, Any] | None:
        path = Path(os.path.expanduser(auth_file))
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def configured_model(self, config_file: str) -> str | None:
        path = Path(os.path.expanduser(config_file))
        if not path.exists():
            return None
        try:
            payload = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return None
        model = payload.get("model")
        return str(model) if isinstance(model, str) and model.strip() else None

    def status(
        self,
        *,
        auth_file: str,
        config_file: str,
        timeout_seconds: int,
        healthcheck_enabled: bool,
    ) -> ProviderStatus:
        executable_path, executable_candidates = self.resolve_executable()
        auth_path = str(Path(os.path.expanduser(auth_file)))
        config_path = str(Path(os.path.expanduser(config_file)))
        configured_model = self.configured_model(config_file)

        if executable_path is None:
            failure_reason = (
                "no_subprocess_safe_codex_executable_found"
                if executable_candidates
                else "executable_missing"
            )
            detail = (
                "No subprocess-safe Codex executable was found. Diagnostics include rejected candidates."
                if executable_candidates
                else "codex executable not found on PATH."
            )
            return ProviderStatus(
                name="codex_local",
                available=False,
                authenticated=False,
                usable=False,
                detail=detail,
                failure_reason=failure_reason,
                executable_path=None,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
            )

        auth_payload = self.auth_file_payload(auth_file)
        if auth_payload is None:
            return ProviderStatus(
                name="codex_local",
                available=True,
                authenticated=False,
                usable=False,
                detail=f"codex executable found, but auth file was not found or unreadable at {auth_path}.",
                failure_reason="auth_missing",
                executable_path=executable_path,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
            )

        if not isinstance(auth_payload.get("tokens"), dict) or not auth_payload.get("tokens"):
            return ProviderStatus(
                name="codex_local",
                available=True,
                authenticated=False,
                usable=False,
                detail=f"codex executable found, but cached auth in {auth_path} is missing usable tokens.",
                failure_reason="auth_invalid_or_expired",
                executable_path=executable_path,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
            )

        if not healthcheck_enabled:
            return ProviderStatus(
                name="codex_local",
                available=True,
                authenticated=True,
                usable=True,
                detail="codex executable and cached auth detected; preflight health check disabled by config.",
                executable_path=executable_path,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
                probe_performed=False,
            )

        try:
            probe_payload = self.run_structured(
                prompt=_healthcheck_prompt(),
                schema=_healthcheck_schema(),
                cwd=self.repo_root,
                timeout_seconds=timeout_seconds,
                operation="healthcheck",
            )
        except CodexProviderError as error:
            authenticated = error.failure_reason not in {"auth_missing", "auth_invalid_or_expired"}
            return ProviderStatus(
                name="codex_local",
                available=True,
                authenticated=authenticated,
                usable=False,
                detail=error.detail,
                failure_reason=error.failure_reason,
                executable_path=executable_path,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
                debug_artifact_path=error.debug_artifact_path,
                probe_performed=True,
            )

        if not isinstance(probe_payload.get("ok"), bool) or not probe_payload.get("ok"):
            detail = str(probe_payload.get("message") or "codex preflight probe did not return an affirmative readiness result.")
            debug_artifact_path = self._write_debug_artifact(
                operation="healthcheck-contract",
                command=[executable_path, "exec", "<healthcheck prompt omitted>"],
                prompt=_healthcheck_prompt(),
                schema=_healthcheck_schema(),
                stdout="",
                stderr="",
                output_text=json.dumps(probe_payload, indent=2),
                detail=detail,
            )
            return ProviderStatus(
                name="codex_local",
                available=True,
                authenticated=True,
                usable=False,
                detail=detail,
                failure_reason="schema_output_failed",
                executable_path=executable_path,
                auth_path=auth_path,
                config_path=config_path,
                configured_model=configured_model,
                executable_candidates=executable_candidates,
                debug_artifact_path=debug_artifact_path,
                probe_performed=True,
            )

        return ProviderStatus(
            name="codex_local",
            available=True,
            authenticated=True,
            usable=True,
            detail="codex preflight probe succeeded.",
            executable_path=executable_path,
            auth_path=auth_path,
            config_path=config_path,
            configured_model=configured_model,
            executable_candidates=executable_candidates,
            probe_performed=True,
        )

    def run_structured(
        self,
        *,
        prompt: str,
        schema: dict[str, Any],
        cwd: Path,
        timeout_seconds: int,
        operation: str,
    ) -> dict[str, Any]:
        executable_path = self.executable_path()
        if executable_path is None:
            failure_reason = "no_subprocess_safe_codex_executable_found" if self.executable_candidates() else "executable_missing"
            raise CodexProviderError(failure_reason, "codex executable is not available.")

        with tempfile.TemporaryDirectory(prefix="codex-disk-audit-") as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            schema_path = temp_dir / "schema.json"
            output_path = temp_dir / "output.json"
            schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")

            command = [
                executable_path,
                "exec",
                prompt,
                "--output-schema",
                str(schema_path),
                "-o",
                str(output_path),
            ]

            try:
                completed = subprocess.run(
                    command,
                    cwd=str(cwd),
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                debug_artifact_path = self._write_debug_artifact(
                    operation=operation,
                    command=command,
                    prompt=prompt,
                    schema=schema,
                    stdout=(error.stdout or ""),
                    stderr=(error.stderr or ""),
                    detail=f"codex exec timed out after {timeout_seconds} seconds.",
                )
                raise CodexProviderError(
                    "timeout",
                    f"codex exec timed out after {timeout_seconds} seconds.",
                    debug_artifact_path=debug_artifact_path,
                ) from error
            except OSError as error:
                detail = _format_launch_failure_detail(error, executable_path)
                debug_artifact_path = self._write_debug_artifact(
                    operation=operation,
                    command=command,
                    prompt=prompt,
                    schema=schema,
                    stdout="",
                    stderr=str(error),
                    detail=detail,
                )
                raise CodexProviderError(
                    "cli_invocation_failed",
                    detail,
                    debug_artifact_path=debug_artifact_path,
                ) from error

            if completed.returncode != 0:
                failure_reason = self._classify_cli_failure(completed.stdout, completed.stderr)
                detail = completed.stderr.strip() or completed.stdout.strip() or "Unknown codex exec failure."
                debug_artifact_path = self._write_debug_artifact(
                    operation=operation,
                    command=command,
                    prompt=prompt,
                    schema=schema,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    detail=detail,
                )
                raise CodexProviderError(
                    failure_reason,
                    detail,
                    debug_artifact_path=debug_artifact_path,
                )

            if not output_path.exists():
                debug_artifact_path = self._write_debug_artifact(
                    operation=operation,
                    command=command,
                    prompt=prompt,
                    schema=schema,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    detail="codex exec did not produce the expected schema output file.",
                )
                raise CodexProviderError(
                    "schema_output_failed",
                    "codex exec did not produce the expected schema output file.",
                    debug_artifact_path=debug_artifact_path,
                )

            raw_output = output_path.read_text(encoding="utf-8")
            try:
                return json.loads(raw_output)
            except json.JSONDecodeError as error:
                debug_artifact_path = self._write_debug_artifact(
                    operation=operation,
                    command=command,
                    prompt=prompt,
                    schema=schema,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    output_text=raw_output,
                    detail=f"codex exec returned invalid JSON: {error}",
                )
                raise CodexProviderError(
                    "schema_output_failed",
                    f"codex exec returned invalid JSON: {error}",
                    debug_artifact_path=debug_artifact_path,
                ) from error

    def _classify_cli_failure(self, stdout: str, stderr: str) -> str:
        message = f"{stderr}\n{stdout}".lower()
        if any(marker in message for marker in AUTH_FAILURE_MARKERS):
            if "expired" in message or "invalid" in message:
                return "auth_invalid_or_expired"
            return "auth_missing"
        return "cli_invocation_failed"

    def _write_debug_artifact(
        self,
        *,
        operation: str,
        command: list[str],
        prompt: str,
        schema: dict[str, Any],
        stdout: str,
        stderr: str,
        detail: str,
        output_text: str | None = None,
    ) -> str:
        artifact_key = self._artifact_key(operation)
        artifact_path = self.debug_directory / f"{artifact_key}.json"
        artifact_path.write_text(
            json.dumps(
                {
                    "operation": operation,
                    "command": command,
                    "detail": detail,
                    "stdout": stdout,
                    "stderr": stderr,
                    "output_text": output_text,
                    "schema": schema,
                    "prompt": prompt,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return str(artifact_path)

    def _artifact_key(self, operation: str) -> str:
        suffix = next(tempfile._get_candidate_names())
        return f"codex-{operation}-{suffix}"

    def _explicit_executable_path(self) -> str | None:
        expanded = os.path.expanduser(self.executable)
        if os.path.isabs(expanded):
            return expanded
        if any(separator in self.executable for separator in ("\\", "/")):
            return str((self.repo_root / expanded).resolve())
        return None

    def _where_candidates(self) -> list[str]:
        if platform.system() != "Windows":
            return []
        try:
            completed = subprocess.run(
                ["where.exe", self.executable],
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if completed.returncode != 0:
            return []
        results = []
        for line in completed.stdout.splitlines():
            value = line.strip()
            if value:
                results.append(value)
        return results

    def _common_windows_candidates(self) -> list[str]:
        if platform.system() != "Windows":
            return []
        home = Path.home()
        return [
            str(home / ".codex" / ".sandbox-bin" / "codex.exe"),
            str(home / ".codex" / ".sandbox-bin" / "codex-command-runner.exe"),
            str(home / ".local" / "bin" / "codex.exe"),
            str(home / "bin" / "codex.exe"),
        ]

    def _is_problematic_windowsapps_path(self, path: str) -> bool:
        return WINDOWSAPPS_MARKER in path.lower().replace("/", "\\")


class CodexLocalReasoningProvider(ReasoningProvider):
    name = "codex_local"

    def __init__(self, adapter: CodexExecAdapter, config: ScanConfig, repo_root: Path) -> None:
        self.adapter = adapter
        self.config = config
        self.repo_root = repo_root
        self._status: ProviderStatus | None = None

    def status(self) -> ProviderStatus:
        if self._status is None:
            self._status = self.adapter.status(
                auth_file=self.config.codex_local.auth_file,
                config_file=self.config.codex_local.config_file,
                timeout_seconds=self.config.codex_local.healthcheck_timeout_seconds,
                healthcheck_enabled=self.config.codex_local.healthcheck_enabled,
            )
        return self._status

    def reason_batch(self, units: list[CleanupUnit], config: ScanConfig, repo_root: Path) -> dict[str, ReasoningResult]:
        prompt_template = (repo_root / "prompts" / "reasoning_prompt.md").read_text(encoding="utf-8")
        payload = {"results": [deterministic_prompt_payload(unit) for unit in units]}
        prompt = "\n\n".join(
            [
                prompt_template,
                "Return exactly one JSON object that matches the provided schema.",
                json.dumps(payload, indent=2),
            ]
        )
        response_payload = self.adapter.run_structured(
            prompt=prompt,
            schema=reasoning_schema(),
            cwd=repo_root,
            timeout_seconds=self.config.codex_local.timeout_seconds,
            operation="reasoning",
        )
        try:
            return validate_reasoning_payload(response_payload)
        except ValueError as error:
            debug_artifact_path = self.adapter._write_debug_artifact(
                operation="reasoning-contract",
                command=[self.adapter.executable_path() or self.adapter.executable, "exec", "<prompt omitted>"],
                prompt=prompt,
                schema=reasoning_schema(),
                stdout="",
                stderr="",
                output_text=json.dumps(response_payload, indent=2),
                detail=f"codex_local returned schema-constrained JSON that failed contract validation: {error}",
            )
            raise CodexProviderError(
                "schema_output_failed",
                f"codex_local returned schema-constrained JSON that failed contract validation: {error}",
                debug_artifact_path=debug_artifact_path,
            ) from error


def build_provider(name: str, config: ScanConfig, repo_root: Path) -> ReasoningProvider:
    if name == "deterministic":
        return DeterministicReasoningProvider()
    if name == "codex_local":
        if config.codex_local.transport != "cli_exec_adapter":
            raise ValueError(
                "The current codex_local implementation ships with the interim cli_exec_adapter transport only."
            )
        cache_directory = repo_root / config.cache.directory / config.cache.debug_namespace
        return CodexLocalReasoningProvider(
            adapter=CodexExecAdapter(
                executable=config.codex_local.executable,
                repo_root=repo_root,
                cache_directory=cache_directory,
            ),
            config=config,
            repo_root=repo_root,
        )
    if name == "openai_api":
        return OpenAIAPIReasoningProvider(
            api_key_env=config.openai_api.api_key_env,
            model=config.openai_api.model,
            temperature=config.openai_api.temperature,
        )
    raise ValueError(f"Unsupported reasoning provider: {name}")


def build_deterministic_rationale(unit: CleanupUnit) -> str:
    evidence = unit.deterministic_evidence
    category = unit.category.replace("_", " ")
    zone = unit.zone.replace("_", " ")
    tags = ", ".join(unit.cleanup_characterization)
    path_patterns = ", ".join(evidence.get("path_patterns", [])) or "no strong path pattern"
    ext_summary = ", ".join(
        f"{item['extension']} x{item['count']}" for item in unit.extension_distribution[:3]
    ) or "mixed extensions"

    explanation = [
        f"Flagged as {category} in a {zone} based on deterministic local evidence.",
        f"Primary signals: {path_patterns}; size={unit.display_size}; files={unit.file_count}; extensions={ext_summary}.",
        f"Review priority: {unit.review_priority.replace('_', ' ')}. {unit.decision_focus}",
        f"Cleanup characterization: {tags}.",
    ]
    if unit.web_citations:
        explanation.append("Supporting web evidence was attached, but deterministic local evidence remains the deciding factor.")
    explanation.append("Counterarguments and uncertainty are preserved in the details panel.")
    return " ".join(explanation)


def describe_exception(error: Exception) -> tuple[str | None, str, str | None]:
    if isinstance(error, CodexProviderError):
        if error.failure_reason not in PROVIDER_FAILURE_REASONS:
            return "cli_invocation_failed", error.detail, error.debug_artifact_path
        return error.failure_reason, error.detail, error.debug_artifact_path
    return None, str(error), None


def _healthcheck_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "message": {"type": "string"},
        },
        "required": ["ok", "message"],
        "additionalProperties": False,
    }


def _healthcheck_prompt() -> str:
    return "\n".join(
        [
            "You are running a Codex local transport health check for codex-disk-audit.",
            "Return exactly one JSON object that matches the provided schema.",
            'Set "ok" to true.',
            'Set "message" to a short readiness confirmation.',
        ]
    )


def _format_launch_failure_detail(error: OSError, executable_path: str) -> str:
    if getattr(error, "winerror", None) == 5:
        return (
            f"Failed to launch codex exec: [WinError 5] Access is denied. "
            f"This appears to be a Windows permission problem when launching {executable_path}."
        )
    return f"Failed to launch codex exec: {error}"
