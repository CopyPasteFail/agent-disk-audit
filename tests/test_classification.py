from __future__ import annotations

import unittest

from codex_disk_audit.classify import classify_risk, classify_zone, confidence_label, confidence_score
from codex_disk_audit.config import load_config


class ClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config("config/demo.json")

    def test_high_risk_path_stays_high_zone(self) -> None:
        zone = classify_zone(r"C:\Windows\Installer", "leftover_installer", self.config)
        self.assertEqual(zone, "high_risk_zone")

    def test_low_zone_cache_can_score_low_risk(self) -> None:
        score = confidence_score(
            strong_match=True,
            age_hit=True,
            generated_data=True,
            duplicate_hit=False,
            zone="low_risk_zone",
            category="cache",
            missing_signals=0,
        )
        self.assertEqual(confidence_label(score), "high")
        self.assertEqual(classify_risk("low_risk_zone", "cache", score), "low")

    def test_unknown_category_is_high_risk(self) -> None:
        self.assertEqual(classify_risk("medium_risk_zone", "unknown", 60), "high")


if __name__ == "__main__":
    unittest.main()

