from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .models import CleanupUnit
from .pipeline import artifact_summary_text, run_report_only_pipeline, run_scan_pipeline
from .reasoning.providers import build_provider, describe_exception


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit-only Windows disk triage tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan the configured filesystem root and generate artifacts.")
    scan_parser.add_argument("--config", default="config/defaults.json", help="Path to the JSON config file.")
    scan_parser.add_argument("--output-dir", help="Override the configured output directory.")
    scan_parser.add_argument(
        "--no-open-report",
        action="store_true",
        help="Do not open report.html after generation.",
    )

    report_parser = subparsers.add_parser("report", help="Render report artifacts from an existing findings JSON file.")
    report_parser.add_argument("--config", default="config/demo.json", help="Path to the JSON config file.")
    report_parser.add_argument("--input-findings", required=True, help="Existing findings JSON file.")
    report_parser.add_argument("--output-dir", help="Override the configured output directory.")

    diagnose_parser = subparsers.add_parser(
        "codex-local-diagnose",
        help="Run codex_local readiness checks without scanning the filesystem.",
    )
    diagnose_parser.add_argument("--config", default="config/defaults.json", help="Path to the JSON config file.")

    smoke_parser = subparsers.add_parser(
        "codex-local-smoke",
        help="Run a tiny real codex_local reasoning batch to validate the transport path.",
    )
    smoke_parser.add_argument("--config", default="config/defaults.json", help="Path to the JSON config file.")
    smoke_parser.add_argument("--output-dir", default="output/codex-local-smoke", help="Directory for the smoke-test artifact.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.command == "scan":
        paths = run_scan_pipeline(
            config,
            output_dir=args.output_dir,
            open_report=not args.no_open_report,
        )
        print(artifact_summary_text(paths, config))
        return 0

    if args.command == "report":
        findings_path = Path(args.input_findings)
        paths = run_report_only_pipeline(config, findings_path, output_dir=args.output_dir)
        print(artifact_summary_text(paths, config))
        return 0

    if args.command == "codex-local-diagnose":
        return _run_codex_local_diagnose(config)

    if args.command == "codex-local-smoke":
        return _run_codex_local_smoke(config, Path(args.output_dir))

    parser.print_help()
    return 1


def _run_codex_local_diagnose(config) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    provider = build_provider("codex_local", config, repo_root)
    status = provider.status()
    payload = {
        "provider": status.name,
        "usable": status.usable,
        "available": status.available,
        "authenticated": status.authenticated,
        "failure_reason": status.failure_reason,
        "detail": status.detail,
        "executable_path": status.executable_path,
        "auth_path": status.auth_path,
        "config_path": status.config_path,
        "configured_model": status.configured_model,
        "executable_candidates": status.executable_candidates,
        "probe_performed": status.probe_performed,
        "debug_artifact_path": status.debug_artifact_path,
    }
    print(json.dumps(payload, indent=2))
    return 0 if status.usable else 2


def _run_codex_local_smoke(config, output_dir: Path) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    provider = build_provider("codex_local", config, repo_root)
    status = provider.status()
    output_dir.mkdir(parents=True, exist_ok=True)
    smoke_path = output_dir / "codex_local_smoke.json"

    if not status.usable:
        smoke_path.write_text(
            json.dumps(
                {
                    "status": "not_usable",
                    "provider_status": _status_payload(status),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"codex_local is not usable. Inspect {smoke_path}")
        return 2

    unit = _smoke_test_unit()
    try:
        results = provider.reason_batch([unit], config, repo_root)
        result = results[unit.unit_id]
    except Exception as error:
        failure_reason, failure_detail, debug_artifact_path = describe_exception(error)
        smoke_path.write_text(
            json.dumps(
                {
                    "status": "provider_error",
                    "provider_status": _status_payload(status),
                    "failure_reason": failure_reason,
                    "failure_detail": failure_detail,
                    "debug_artifact_path": debug_artifact_path,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"codex_local smoke test failed. Inspect {smoke_path}")
        return 2

    smoke_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "provider_status": _status_payload(status),
                "result": result.to_dict(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"codex_local smoke test succeeded. Inspect {smoke_path}")
    return 0


def _status_payload(status) -> dict:
    return {
        "provider": status.name,
        "usable": status.usable,
        "available": status.available,
        "authenticated": status.authenticated,
        "failure_reason": status.failure_reason,
        "detail": status.detail,
        "executable_path": status.executable_path,
        "auth_path": status.auth_path,
        "config_path": status.config_path,
        "configured_model": status.configured_model,
        "executable_candidates": status.executable_candidates,
        "probe_performed": status.probe_performed,
        "debug_artifact_path": status.debug_artifact_path,
    }


def _smoke_test_unit() -> CleanupUnit:
    return CleanupUnit(
        unit_id="codex-local-smoke-unit",
        name="Smoke temp cache",
        path=r"C:\Users\demo\AppData\Local\Temp\SmokeCache",
        root_path=r"C:\Users\demo\AppData\Local\Temp",
        item_kind="folder",
        unit_type="folder_unit",
        category="temp",
        zone="medium_risk_zone",
        risk="medium",
        confidence_score=70,
        confidence_label="medium",
        total_size_bytes=134217728,
        file_count=12,
        display_size="128.0 MB",
        display_modified_at="2026-03-01",
        recommendation="Probably recreatable cache/temp; review likely worthwhile.",
        reason_summary="Synthetic smoke-test unit for codex_local transport validation.",
        llm_rationale="Not yet populated.",
        uncertainty_notes=["Synthetic unit for smoke testing only."],
        counterarguments=["Synthetic data does not prove a real scan path."],
        cleanup_characterization=["recreatable", "non-essential"],
        deterministic_evidence={
            "path_patterns": ["user temp directory", "cache-like subtree"],
            "category_hints": ["temp", "cache"],
            "is_system_critical": False,
            "vendor_hint": "smoke",
        },
        grouping_logic="Smoke-test folder unit",
        evidence_source="deterministic",
        sample_files=[
            {"path": r"C:\Users\demo\AppData\Local\Temp\SmokeCache\a.tmp", "size_bytes": 67108864},
            {"path": r"C:\Users\demo\AppData\Local\Temp\SmokeCache\b.log", "size_bytes": 67108864},
        ],
        extension_distribution=[
            {"extension": ".tmp", "count": 8},
            {"extension": ".log", "count": 4},
        ],
    )


if __name__ == "__main__":
    sys.exit(main())
