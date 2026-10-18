"""Focused test for the cross-dataset transfer evaluation module."""

import unittest
from pathlib import Path
from scripts.cross_dataset_eval import run_cross_dataset_analysis

BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports" / "cross_dataset_evaluation"


class CrossDatasetEvalTests(unittest.TestCase):
    def test_cross_dataset_summary_generation(self):
        summary = run_cross_dataset_analysis()
        self.assertIn("datasets", summary)
        self.assertIn("nsl_kdd", summary["datasets"])
        self.assertIn("unsw_nb15", summary["datasets"])
        self.assertIn("cicids2017", summary["datasets"])
        self.assertIn("transfer_experiments", summary)
        self.assertTrue(len(summary["transfer_experiments"]) > 0)
        self.assertTrue((REPORTS_DIR / "summary.md").exists())
        self.assertTrue((REPORTS_DIR / "cross_dataset_transfer.json").exists())


if __name__ == "__main__":
    unittest.main()

