# AGENTS.md

## Project purpose

This repository is an audit-only Windows disk triage tool. It scans local storage, groups findings into realistic cleanup units, applies deterministic evidence first, optionally layers runtime reasoning on top, and emits a standalone static `report.html` that opens via `file://`.

## Primary runtime reasoning path

`codex_local` is the intended primary runtime reasoning provider.

Design intent:

- prefer local Codex integration over API-key-first assumptions
- use the user’s existing local Codex authentication when available
- keep the design local-first and backend-free
- preserve a clean provider boundary so `codex_local` can move from the current adapter bridge to a future MCP-native transport without changing the rest of the app

Provider order:

- primary: `codex_local`
- fallback: `deterministic`
- optional secondary: `openai_api`

Do not regress this repo back to an `OPENAI_API_KEY`-first design.

## Safety constraints

- Never delete anything.
- Never move, rename, compress, quarantine, or modify files or folders.
- Never change ACLs, registry values, services, scheduled tasks, configuration, or file attributes.
- Never execute unknown binaries, installers, or scripts discovered during scanning.
- Never present guesses as facts.

## Never-delete rule

This repo must remain an audit/reporting tool only. Any future change that mutates the target machine is out of scope unless product direction changes explicitly and safely.

## Grouping philosophy

- The primary output unit is a cleanup unit, not a single tiny file.
- Prefer grouping by directory plus category.
- Use `folder_unit` when the whole folder is what a user would realistically review.
- Use `grouped_files_unit` when a set of large or strongly related files should be reviewed together.
- Use `hybrid_unit` when only a subset of a mixed folder matches a clear rule.
- Avoid noisy per-file recommendations for lots of small files.
- Only allow single-file-style units for clearly standalone artifacts such as ISO, ZIP, VHDX, dump, installer, or backup files.

## Reasoning contract

- Maintain strict JSON contracts for model-backed reasoning.
- Do not accept or propagate free-form-only output from providers.
- Validate provider output before applying it to findings.
- If validation fails, degrade safely to fallback reasoning.
- Keep conservative guardrails when merging provider output back into a finding.

## Output expectations

Every run should be able to produce:

- `findings.json`
- `findings.csv`
- `summary.md`
- `skipped.md`
- `report.html`

The report must remain static, self-contained, and usable directly from disk without a backend.

## No overclaiming

- Do not claim something is removable based only on path, age, size, or extension.
- Distinguish between recreatable, probably unused, unreferenced, non-essential, and ambiguous.
- Unknown findings should default to high risk or manual review wording.
- Prefer false negatives over false positives.

## UI/report expectations

- Keep the report local-first and `file://` friendly.
- Do not link directly to individual files for cleanup-unit navigation.
- Folder units should open the folder.
- Grouped-file and hybrid units should open the parent/root folder.
- Preserve search, filters, sorting, counters, charts, badges, and details drawer behavior.
- Show the actual reasoning mode used for each finding.
- If deterministic fallback was used, make it visible in the report.
- Avoid remote CDNs or a localhost dependency.

## High-risk zones

Treat these areas cautiously:

- `C:\Windows`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\ProgramData`
- driver stores
- shared runtimes
- installer/component stores

If a path is ambiguous and in a critical location, default toward high risk.

## False-negative preference

If evidence is weak, missing, or contradictory, suppress the finding or mark it high risk. The tool should miss some opportunities rather than mislead the user into deleting something important.

## Code style guidance

- Keep the stack simple and Windows-friendly.
- Prefer Python standard library unless an added dependency materially improves reliability.
- Keep naming explicit and boring over clever.
- Add comments when they clarify a safety-sensitive or non-obvious decision.
- Preserve separation of concerns between scanning, grouping, classification, reasoning, enrichment, exports, and reporting.

## Provider guidance

- `codex_local` is the intended primary runtime provider.
- `openai_api` is optional secondary, not the default mental model.
- `deterministic` is the safe fallback.
- Keep `codex_local` behind a stable provider boundary.
- Keep the `codex_local` live preflight probe intact. Do not regress availability checks to executable/auth-file inspection alone.
- If the `codex_local` transport changes, preserve the provider interface and the JSON contract.
- Avoid ad hoc CLI scraping. If the CLI is used, require schema-constrained output and validate it.
- Preserve explicit failure classification and debug artifacts for `codex_local` probe/runtime failures.
- Do not reintroduce misleading dead config for a CLI model override unless the invocation contract is verified and tested.
- Keep batching, caching, timeout, and retry behavior explicit in config.

## Testing guidance

- Add unit tests for provider selection, availability detection, fallback behavior, contract validation, and report labels when touching the reasoning layer.
- Add tests for preflight behavior, failure classification, and debug artifact creation when touching `codex_local`.
- Add unit tests for classification and grouping behavior when changing heuristics.
- Prefer deterministic tests that do not require a live scan of `C:\`.
- Keep tests focused on safety-sensitive behavior such as risk downgrades/upgrades, grouping thresholds, fallback behavior, and strict contract handling.

## Optional web evidence

- Web evidence must stay optional and easily disabled.
- Treat web results as supporting citations only.
- Never let web evidence override contradictory local evidence.
- The tool must still function fully with deterministic evidence alone.
- If `codex_local` is used for web support, keep the same strict JSON validation standards as the reasoning path.
