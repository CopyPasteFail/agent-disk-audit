from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from codex_disk_audit.config import load_config
from codex_disk_audit.grouping import DirectorySummary, build_folder_unit, build_duplicate_units, group_files_in_directory
from codex_disk_audit.models import FileRecord


class GroupingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config("config/demo.json")
        self.now = datetime.now(tz=UTC)

    def test_logs_are_grouped_as_hybrid_unit(self) -> None:
        files = [
            FileRecord(
                path=r"C:\Users\Example\AppData\Local\Vendor\logs\app.log",
                size_bytes=90 * 1024 * 1024,
                created_at=self.now - timedelta(days=45),
                modified_at=self.now - timedelta(days=45),
                accessed_at=None,
                extension=".log",
            ),
            FileRecord(
                path=r"C:\Users\Example\AppData\Local\Vendor\logs\trace.etl",
                size_bytes=20 * 1024 * 1024,
                created_at=self.now - timedelta(days=40),
                modified_at=self.now - timedelta(days=40),
                accessed_at=None,
                extension=".etl",
            ),
        ]
        units = group_files_in_directory(r"C:\Users\Example\AppData\Local\Vendor\logs", files, self.config, self.now)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].unit_type, "hybrid_unit")
        self.assertEqual(units[0].category, "logs")

    def test_folder_rule_prefers_whole_folder(self) -> None:
        summary = DirectorySummary(
            path=r"C:\Users\Example\AppData\Local\Temp",
            total_size_bytes=200 * 1024 * 1024,
            file_count=120,
            dir_count=5,
        )
        unit = build_folder_unit(
            path=summary.path,
            summary=summary,
            category="temp",
            rule_note="User temp directory.",
            config=self.config,
            now=self.now,
        )
        self.assertIsNotNone(unit)
        self.assertEqual(unit.unit_type, "folder_unit")
        self.assertEqual(unit.root_path, summary.path)

    def test_duplicate_group_has_duplicate_category(self) -> None:
        record = FileRecord(
            path=r"C:\Users\Example\Downloads\big.iso",
            size_bytes=300 * 1024 * 1024,
            created_at=self.now - timedelta(days=100),
            modified_at=self.now - timedelta(days=100),
            accessed_at=None,
            extension=".iso",
        )
        units = build_duplicate_units({"abc123": [record, record]}, self.config)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].category, "duplicate_group")
        self.assertEqual(units[0].review_priority, "review_later")
        self.assertEqual(units[0].deterministic_evidence["actionability"], "manual_review")
        self.assertEqual(units[0].deterministic_evidence["duplicate_disposition"], "content_duplicate")

    def test_known_microsoft_runtime_duplicates_are_marked_system_managed(self) -> None:
        records = [
            FileRecord(
                path=path,
                size_bytes=300 * 1024 * 1024,
                created_at=self.now - timedelta(days=10),
                modified_at=self.now - timedelta(days=10),
                accessed_at=None,
                extension=".dll",
            )
            for path in [
                r"C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.84\msedge.dll",
                r"C:\Program Files (x86)\Microsoft\EdgeCore\146.0.3856.84\msedge.dll",
                r"C:\Program Files (x86)\Microsoft\EdgeCore\Optimized\msedge.dll",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\146.0.3856.84\msedge.dll",
            ]
        ]
        units = build_duplicate_units({"hash123": records}, self.config)
        self.assertEqual(len(units), 1)
        unit = units[0]
        self.assertEqual(unit.category, "system_component")
        self.assertEqual(unit.zone, "high_risk_zone")
        self.assertEqual(unit.risk, "high")
        self.assertEqual(unit.review_priority, "not_actionable")
        self.assertEqual(unit.review_priority_score, 0)
        self.assertTrue(unit.deterministic_evidence["system_managed_duplicate"])
        self.assertTrue(unit.deterministic_evidence["skip_reasoning"])
        self.assertEqual(unit.deterministic_evidence["actionability"], "none")
        self.assertEqual(unit.deterministic_evidence["duplicate_disposition"], "structural_duplication")
        self.assertEqual(unit.recommendation, "System-managed duplication by design; not a cleanup candidate.")

    def test_high_risk_duplicate_under_program_files_stays_out_of_cleanup_ranking(self) -> None:
        records = [
            FileRecord(
                path=path,
                size_bytes=280 * 1024 * 1024,
                created_at=self.now - timedelta(days=30),
                modified_at=self.now - timedelta(days=30),
                accessed_at=None,
                extension=".dll",
            )
            for path in [
                r"C:\Program Files (x86)\Vendor\App\bin\shared.dll",
                r"C:\Program Files (x86)\Vendor\App\backup\shared.dll",
            ]
        ]
        units = build_duplicate_units({"hash456": records}, self.config)
        self.assertEqual(len(units), 1)
        unit = units[0]
        self.assertEqual(unit.category, "duplicate_group")
        self.assertEqual(unit.zone, "high_risk_zone")
        self.assertEqual(unit.risk, "high")
        self.assertEqual(unit.review_priority, "not_actionable")
        self.assertEqual(unit.deterministic_evidence["actionability"], "expert_review_only")


if __name__ == "__main__":
    unittest.main()
