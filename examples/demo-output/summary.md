# Disk Audit Summary

- Scan root: `C:\`
- Total cleanup units: `6`
- Total candidate size: `22.9 GB`
- Requested reasoning provider: `deterministic`
- Fallback provider: `deterministic`
- Web enrichment provider: `disabled`

## Risk counts

- high: `1`
- medium: `4`
- low: `1`

## Top units

- `8.0 GB` | `high` | `runtime_dependency` | Package Cache (runtime dependency) | Do not touch without expert validation.
- `5.7 GB` | `medium` | `downloads_old` | Downloads downloads old subset | Review likely worthwhile; likely removable if still unwanted.
- `4.5 GB` | `low` | `duplicate_group` | Duplicate group (3 files) | Likely redundant duplicates; verify the canonical copy before any manual cleanup.
- `2.3 GB` | `medium` | `temp` | Temp (temp) | Probably recreatable cache/temp; review likely worthwhile.
- `1.7 GB` | `medium` | `cache` | DXCache (cache) | Probably recreatable cache/temp; review likely worthwhile.
- `870.4 MB` | `medium` | `logs` | logs logs subset | Probably non-essential log data; review likely worthwhile.

## Safety notes

- This tool is audit-only and never deletes or modifies files.
- High-risk zones require stricter review and should not be acted on casually.
- Access times may be unavailable or unreliable on Windows and are not treated as decisive evidence.