"""Focused tests for drift monitoring, PSI, KS-test, and data quality checks."""

import unittest
import numpy as np
import pandas as pd

from scripts.drift_monitor import (
    calculate_psi,
    ModelDriftMonitor,
    DriftReport,
)


class DriftMonitorTests(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)
        n = 1000
        self.ref_df = pd.DataFrame({
            "num_feat1": np.random.normal(loc=10.0, scale=2.0, size=n),
            "num_feat2": np.random.exponential(scale=5.0, size=n),
            "cat_feat1": np.random.choice(["tcp", "udp", "icmp"], size=n, p=[0.7, 0.2, 0.1]),
        })

    def test_psi_identical_distributions(self):
        # Sample another batch from exact same distribution
        np.random.seed(123)
        current = np.random.normal(loc=10.0, scale=2.0, size=1000)
        psi = calculate_psi(self.ref_df["num_feat1"].to_numpy(), current)
        self.assertLess(psi, 0.10)

    def test_psi_shifted_distribution(self):
        # Shifted mean and variance (covariate shift)
        np.random.seed(999)
        shifted = np.random.normal(loc=25.0, scale=6.0, size=1000)
        psi = calculate_psi(self.ref_df["num_feat1"].to_numpy(), shifted)
        self.assertGreater(psi, 0.25)

    def test_drift_monitor_workflow(self):
        monitor = ModelDriftMonitor(
            reference_data=self.ref_df,
            numeric_features=["num_feat1", "num_feat2"],
            categorical_features=["cat_feat1"],
        )

        # 1. Clean batch -> NOMINAL
        np.random.seed(55)
        clean_batch = pd.DataFrame({
            "num_feat1": np.random.normal(loc=10.0, scale=2.0, size=500),
            "num_feat2": np.random.exponential(scale=5.0, size=500),
            "cat_feat1": np.random.choice(["tcp", "udp", "icmp"], size=500, p=[0.7, 0.2, 0.1]),
        })
        report_clean = monitor.evaluate_batch(clean_batch)
        self.assertIsInstance(report_clean, DriftReport)
        self.assertEqual(report_clean.drift_warning_level, "NOMINAL")
        self.assertEqual(report_clean.drifted_features_count, 0)

        # 2. Shifted batch -> ELEVATED or CRITICAL
        corrupt_batch = pd.DataFrame({
            "num_feat1": np.random.normal(loc=40.0, scale=10.0, size=500),
            "num_feat2": np.random.exponential(scale=50.0, size=500),
            "cat_feat1": ["new_proto_x"] * 500,
        })
        report_corrupt = monitor.evaluate_batch(corrupt_batch)
        self.assertIn(report_corrupt.drift_warning_level, ["ELEVATED", "CRITICAL"])
        self.assertGreater(report_corrupt.drifted_features_count, 0)

    def test_missing_data_quality_alert(self):
        monitor = ModelDriftMonitor(reference_data=self.ref_df)
        df_corrupt = self.ref_df.copy()
        df_corrupt.loc[:200, "num_feat1"] = np.nan
        report = monitor.evaluate_batch(df_corrupt)
        self.assertGreater(len(report.data_quality_issues), 0)


if __name__ == "__main__":
    unittest.main()

