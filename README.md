# codex-disk-audit

`codex-disk-audit` is an audit-only Windows disk triage tool for drive `C:\` by default. It scans the local filesystem, groups findings into realistic cleanup units, applies deterministic evidence first, optionally adds runtime reasoning, and exports a fully static `report.html` that opens directly from disk via `file://`.

The report is designed to help a local user find a few meaningful cleanup opportunities without flooding them with per-file noise. The tool never deletes, moves, renames, compresses, quarantines, executes, or otherwise modifies anything on disk.

## The implementation problem this refactor fixes

Earlier versions of this repo treated live reasoning as API-key-first:

- `OPENAI_API_KEY` was effectively the main runtime path for model-backed reasoning.
- If the API key was missing, the tool dropped to deterministic reasoning.

That is not the intended product behavior.

This repo now uses a provider architecture where:

- `codex_local` is the intended primary reasoning path.
- `deterministic` is the default fallback.
- `openai_api` remains available as an optional secondary provider.

`OPENAI_API_KEY` is no longer required for the main reasoning path.

## What it does

- Scans `C:\` by default, including user folders, `AppData`, `ProgramData`, `Windows`, `Program Files`, and `Program Files (x86)`.
- Groups findings into cleanup units such as entire folders, grouped file sets, or hybrid subsets.
- Collects deterministic evidence such as size, file count, timestamps, extension distribution, representative samples, category hints, and zone/risk classification.
- Treats high-risk system and app-support zones more cautiously than user temp/cache areas.
- Detects duplicate groups for large files using exact SHA-256 hashes.
- Supports reasoning provider modes:
  - `deterministic`
  - `codex_local`
  - `openai_api`
- Supports optional web-support provider modes:
  - `disabled`
  - `duckduckgo_lite`
  - `codex_local`
- Generates:
  - `findings.json`
  - `findings.csv`
  - `summary.md`
  - `skipped.md`
  - `report.html`
- Produces a self-contained static report with search, filters, sorting, counters, charts, badges, and a details drawer.
- Shows which reasoning mode produced each finding, how many units were processed by each provider, and whether deterministic fallback happened because `max_units` was reached or because the primary provider was unavailable or failed.
- Uses `file://` links so folder-based units open the folder itself, while grouped file units open the unit root folder instead of any specific file.

## What it does not do

- It never deletes anything.
- It never moves, renames, compresses, quarantines, or modifies files or folders.
- It never changes ACLs, attributes, services, scheduled tasks, registry values, or configuration.
- It never executes unknown binaries or installers.
- It never promises Explorer pre-selection.
- It never claims something is removable based only on path, age, size, or extension.

## Safety principles

- Audit only, never mutate.
- Prefer false negatives over false positives.
- Unknown findings default to high risk.
- High-risk zones are treated with stricter standards.
- Runtime reasoning sits on top of deterministic evidence.
- Supporting web evidence can reinforce known cache/temp/log/dump patterns, but it never overrides contradictory local evidence.
- Strict JSON contracts are enforced for model-backed reasoning results. Invalid provider output degrades to safer fallback behavior.

## Architecture

- `scripts/`
  - PowerShell entry points for scans, demo report generation, and tests.
- `config/`
  - JSON config files for default and demo runs.
- `src/codex_disk_audit/`
  - `scanner.py`: filesystem collection and skip tracking.
  - `grouping.py`: cleanup unit construction and grouping logic.
  - `classify.py`: category, zone, confidence, and risk heuristics.
  - `duplicates.py`: exact duplicate detection for large files.
  - `web_enrichment.py`: provider-based supporting web evidence.
  - `reasoning/`
    - `providers.py`: reasoning providers and the `codex_local` adapter boundary.
    - `contract.py`: strict JSON contract and validation.
    - `cache.py`: local cache for provider results.
    - `orchestrator.py`: provider selection, batching, fallback, and unit updates.
  - `exports.py`: JSON/CSV/Markdown exporters.
  - `report.py`: standalone static HTML report generator.
  - `pipeline.py`: orchestration.
  - `cli.py`: command line entry point.
- `prompts/`
  - Internal reasoning and web-support instructions.
- `tests/`
  - Unit tests for classification, grouping, provider selection, fallback, contract validation, and report labels.
- `sample_data/`
  - Mock findings for demo/UI development.
- `examples/demo-output/`
  - Example generated artifacts.

## Reasoning provider architecture

### Primary path: `codex_local`

`codex_local` is the intended runtime reasoning mode.

Current implementation:

- The architecture is MCP-ready but the current adapter is an interim `codex exec` bridge.
- The bridge is not ad hoc text scraping.
- It requests strict schema-constrained JSON output and validates the returned contract before updating findings.
- It is isolated behind a clean provider boundary so it can be replaced later by an MCP-native transport without changing scanner, grouping, report generation, or the rest of the pipeline.
- It currently relies on the user’s configured local Codex environment for the active model selection instead of forcing a CLI model flag, because this repo does not yet have a verified CLI-level model override contract for the chosen invocation path.

### Fallback path: `deterministic`

If `codex_local` is unavailable, unauthenticated, returns invalid JSON, or fails at runtime, the tool degrades safely to deterministic reasoning.

### Optional secondary path: `openai_api`

`openai_api` remains available as an optional provider for environments that explicitly want API-backed reasoning. It is not the default and it is not required for normal use.

## What `codex_local` requires

`codex_local` does not require `OPENAI_API_KEY`.

It expects:

- A local Codex installation available on `PATH`
- Existing local Codex authentication, typically via the shared Codex CLI/App/IDE login state
- Permission for the local environment to launch `codex exec`

The current availability check is stricter than simple executable or auth-file discovery.

`codex_local` is considered available for runtime use only when all of the following are true:

- the configured `codex` executable resolves on `PATH`
- the configured auth file exists and contains usable cached tokens
- an actual lightweight structured preflight probe succeeds through `codex exec`

The preflight classifies failures into:

- `executable_missing`
- `auth_missing`
- `auth_invalid_or_expired`
- `cli_invocation_failed`
- `schema_output_failed`
- `timeout`

These reasons are surfaced in diagnostics, debug artifacts, and fallback metadata when relevant.

## Why the current `codex_local` implementation is adapter-based

OpenAI’s Codex docs describe Codex CLI as both an MCP client and an MCP server, and also document schema-constrained non-interactive execution. For this repo’s current shape:

- a full in-process MCP client would add more protocol surface than the project needs today
- the non-interactive `codex exec` path already supports structured output cleanly
- a bounded adapter behind a provider interface keeps the runtime simple and local-first

So the current design is:

- architecture designed to support an eventual MCP-native Codex provider
- current implementation uses a strict structured-output CLI adapter as the interim bridge

## Codex-local diagnostics and smoke testing

Use the diagnostic command to check readiness without scanning `C:\`:

```powershell
.\scripts\diagnose_codex_local.ps1
```

Or:

```powershell
python -m codex_disk_audit.cli codex-local-diagnose --config config/defaults.json
```

This prints structured status including:

- whether `codex_local` is usable
- the exact failure reason when it is not
- the resolved executable path
- all executable candidates found, including why rejected candidates were skipped
- the auth/config file paths being checked
- the configured local Codex model read from `~/.codex/config.toml` when available
- whether the live preflight probe was actually performed
- the debug artifact path for probe failures

Use the smoke test to validate the real transport path on a tiny bounded batch:

```powershell
.\scripts\smoke_codex_local.ps1
```

Or:

```powershell
python -m codex_disk_audit.cli codex-local-smoke --config config/defaults.json --output-dir output/codex-local-smoke
```

This runs a real `codex_local` reasoning request against a synthetic cleanup unit and writes:

- `output/codex-local-smoke/codex_local_smoke.json`

If the transport fails or contract validation fails, raw debugging context is written under:

- `.cache/debug/`

Those artifacts include the command, schema, prompt, stdout/stderr, and raw output when safe to preserve locally.

On this machine, the preferred explicit launcher is:

```json
{
  "codex_local": {
    "executable": "%USERPROFILE%\\.codex\\.sandbox-bin\\codex.exe"
  }
}
```

That path is preferred over the packaged WindowsApps Codex binary because the WindowsApps executable may resolve from `PATH` but still fail to launch via `subprocess`, while the `.codex\\.sandbox-bin` launcher is subprocess-safe for this repo's local runtime path.

## Install

The project runs on Python 3.11+ and now expects a local repo virtual environment at `.venv`.

### Bootstrap the repo virtual environment

```powershell
.\scripts\bootstrap_venv.ps1
```

This creates `.venv`, upgrades `pip` and `setuptools`, and installs the package in editable mode.

### Enable the tracked pre-push hook

This repo includes a tracked Git hook at `.githooks/pre-push` that runs the same local quality gates used by CI:

```powershell
git config core.hooksPath .githooks
```

The hook executes `scripts/run_pre_push_checks.ps1`, which requires the repo `.venv` and runs:

- `python -m compileall src tests scripts`
- `python -m unittest discover -s tests -v`

### Install the pinned optional OpenAI stack

```powershell
.\scripts\bootstrap_venv.ps1 -WithOpenAI
```

This installs the exact versions pinned in `requirements.lock` for the optional `openai_api` provider path.

### Run commands through the repo venv

The PowerShell scripts now require `.venv` and will stop with a clear message if it is missing:

```powershell
.\scripts\run_scan.ps1
.\scripts\run_demo.ps1
.\scripts\run_tests.ps1
```

## Run a real scan

Default config scans `C:\` and writes output to `output\latest`.

```powershell
.\scripts\run_scan.ps1
```

Or explicitly:

```powershell
python -m codex_disk_audit.cli scan --config config/defaults.json --no-open-report
```

## Generate the demo report

The demo path renders a report from the included mock findings dataset:

```powershell
.\scripts\run_demo.ps1
```

Or:

```powershell
python -m codex_disk_audit.cli report --config config/demo.json --input-findings sample_data/demo_findings.json
```

## Open the report

After a scan or demo render completes, open `report.html` directly from disk. The report is standalone and does not require a backend, localhost server, CDN, or extra build step.

Example:

```text
output\latest\report.html
```

## How `file://` navigation works

- Folder-based cleanup units link to the folder itself.
- File-based and grouped-files cleanup units link to the unit root folder or parent folder.
- The report intentionally does not link directly to individual files.

Why:

- grouped review units should navigate to grouped review context
- the tool must not imply that a single file is independently safe to remove
- browser and Explorer file-selection behavior is inconsistent across environments

## `file://` limitations

- Different browsers handle `file://` folder links differently.
- Some browsers open Explorer directly, while others show a directory view or rely on shell associations.
- No browser behavior should be assumed identical across systems.

## Configuration

Key settings live in `config/defaults.json`.

For normal use, `reasoning.max_units` now defaults to `100`. Lower limits remain in the validation and demo configs so smoke paths stay bounded.
The repo uses a local `.venv` workflow, and the optional OpenAI dependency path is pinned in `requirements.lock`.

### General scan settings

- `scan_root`
- `exclude_paths`
- `high_risk_paths`
- `min_unit_size_mb`
- `strong_signal_min_unit_size_mb`
- `large_file_min_size_mb`
- `age_threshold_days`
- `file_sample_count`
- `use_access_time`
- `follow_symlinks`
- `duplicate_detection`
- `output_dir`
- `max_units_in_report`

### Provider settings

- `reasoning_provider`
  - `codex_local`, `deterministic`, or `openai_api`
- `fallback_provider`
  - usually `deterministic`
- `web_enrichment_provider`
  - `disabled`, `duckduckgo_lite`, or `codex_local`
- `cache`
  - local cache settings for reasoning and web-support results
- `reasoning`
  - shared max-units, batching, timeout, and retry settings
  - default `max_units` is `100` for normal scans
- `codex_local`
  - local Codex adapter settings such as executable, auth file, config file, preflight timeout, and batch size
- `openai_api`
  - optional API-backed provider settings
- `duckduckgo_lite`
  - best-effort web citation settings

Example provider shape:

```json
{
  "reasoning_provider": "codex_local",
  "fallback_provider": "deterministic",
  "web_enrichment_provider": "codex_local"
}
```

## Strict JSON reasoning contract

Model-backed reasoning is requested and stored as structured JSON with fields such as:

- `category`
- `risk`
- `confidence`
- `recommendation`
- `reason_summary`
- `llm_rationale`
- `uncertainty_notes`
- `counterarguments`
- `evidence_source`
- `used_web_support`
- `citations`

If a provider returns invalid JSON or violates the contract:

- the payload is rejected
- the unit degrades to fallback reasoning
- the report shows the actual provider that produced the final result
- the report and exported metadata distinguish fallback caused by the `max_units` cap from fallback caused by provider unavailability or runtime failure
- the provider failure reason and debug artifact path are preserved when available

## Web support

Supporting web evidence is optional.

Allowed use:

- known cache/temp/log/dump locations
- documented recreatable folders
- vendor/app cache behavior
- known artifact types

Rules:

- web support must never override contradictory local evidence
- web support must be clearly labeled
- the tool must still work fully without web support

## Grouping philosophy

- Prefer whole folders when the folder itself is the realistic review unit.
- Group files by directory plus category instead of spamming individual rows.
- Use hybrid units when only a subset of a mixed folder matches a clear rule.
- Allow single-file-style units only for genuinely large standalone artifacts.
- Default ordering prioritizes larger units first, then lower risk, then higher confidence.

## Limitations

- A full `C:\` scan can take time on large systems.
- Some paths will be skipped because of permissions, locks, or inaccessible reparse points.
- Access times are not assumed reliable.
- Folder names alone are not treated as proof that contents are disposable.
- Duplicate grouping uses exact hashes for large files only and is intentionally conservative.
- The current `codex_local` runtime is an MCP-ready adapter design, not a full MCP-native client yet.
- The current `codex_local` runtime uses a real preflight probe, but it still depends on the behavior of the installed `codex exec` CLI transport.
- On Windows, the packaged Codex app path under `C:\Program Files\WindowsApps\...` may resolve from `PATH` but still fail to launch via `subprocess`. The repo now rejects those packaged executable paths during discovery and prefers subprocess-safe launchers such as explicit CLI paths or non-WindowsApps wrapper binaries.
- The current `codex_local` auth detection still starts from the configured local Codex auth file path. If a future Codex install stores credentials elsewhere, detection may conservatively classify the provider as unusable.
- The repo currently reads the active local Codex model from the configured Codex config file for diagnostics, but it does not force a model flag on the CLI invocation because that contract has not been verified for this transport path.
- If no subprocess-safe executable is found, diagnostics fail clearly with `no_subprocess_safe_codex_executable_found`. In that case, set `codex_local.executable` to a real CLI or wrapper path that can be launched by `subprocess`.
- `openai_api` remains optional and requires its own environment setup if explicitly selected.

## Future ideas

- Replace the interim `codex exec` bridge with an MCP-native Codex transport.
- Add richer local Codex health/auth probes for credential-store variants.
- Persist raw scan inventories for delta comparisons.
- Add stronger vendor/app association from installed application metadata.
- Expand developer-artifact coverage for Docker, WSL, model caches, and language ecosystems.
