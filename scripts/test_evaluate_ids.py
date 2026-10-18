"""Focused tests for the standalone IDS evaluation helpers."""

import unittest

import numpy as np
import pandas as pd

from scripts.evaluate_ids import (
    build_pipeline,
    duplicate_analysis,
    evaluate_split,
    partition_overlap,
)


class EvaluateIdsTests(unittest.TestCase):
    def setUp(self):
        self.predictor_columns = [
            "protocol_type",
            "service",
            "flag",
            "duration",
        ]
        self.features = pd.DataFrame(
            [
                ["tcp", "http", "SF", 0],
                ["udp", "domain_u", "SF", 1],
                ["icmp", "eco_i", "S0", 2],
                ["tcp", "ftp", "REJ", 3],
                ["tcp", "http", "SF", 4],
                ["udp", "domain_u", "SF", 5],
                ["icmp", "eco_i", "S0", 6],
                ["tcp", "ftp", "REJ", 7],
                ["tcp", "http", "SF", 8],
                ["udp", "domain_u", "SF", 9],
                ["icmp", "eco_i", "S0", 10],
                ["tcp", "ftp", "REJ", 11],
            ],
            columns=self.predictor_columns,
        )
        self.target = pd.Series(
            [
                "Normal",
                "DoS",
                "Probe",
                "R2L",
                "Normal",
                "DoS",
                "Probe",
                "R2L",
                "Normal",
                "DoS",
                "Probe",
                "R2L",
            ],
            name="label",
        )

    def test_preprocessor_is_fitted_only_by_pipeline_fit(self):
        pipeline = build_pipeline(self.predictor_columns)
        self.assertFalse(hasattr(pipeline.named_steps["preprocess"], "transformers_"))
        pipeline.fit(self.features, self.target)
        self.assertTrue(hasattr(pipeline.named_steps["preprocess"], "transformers_"))

    def test_duplicate_analysis_counts_conflicting_predictors(self):
        dataframe = self.features.iloc[:4].copy()
        dataframe.loc[3, self.predictor_columns] = dataframe.loc[0, self.predictor_columns]
        dataframe["label"] = ["normal", "neptune", "satan", "neptune"]
        result = duplicate_analysis(dataframe, self.predictor_columns)
        self.assertEqual(result["duplicate_predictor_groups"], 1)
        self.assertEqual(result["conflicting_label_predictor_groups"], 1)
        self.assertEqual(result["conflicting_label_predictor_rows"], 2)

    def test_partition_overlap_detects_shared_predictors(self):
        dataframe = self.features.copy()
        dataframe.loc[3, self.predictor_columns] = dataframe.loc[0, self.predictor_columns]
        dataframe["label"] = self.target
        result = partition_overlap(
            dataframe,
            self.predictor_columns,
            np.array([0, 1, 2]),
            np.array([3, 4, 5]),
        )
        self.assertEqual(result["shared_predictor_groups"], 1)
        self.assertEqual(result["test_rows_with_predictor_seen_in_train"], 1)

    def test_evaluation_metrics_are_calculated_from_predictions(self):
        labels = ["DoS", "Normal", "Probe", "R2L"]
        train_indices = np.array([0, 1, 2, 3, 4, 5, 6, 7])
        test_indices = np.array([8, 9, 10, 11])
        metrics, _, matrix = evaluate_split(
            "test",
            self.features,
            self.target,
            self.predictor_columns,
            train_indices,
            test_indices,
            labels,
            {"strategy": "unit_test"},
        )
        self.assertEqual(sum(sum(row) for row in matrix), len(test_indices))
        self.assertGreaterEqual(metrics["overall_accuracy"], 0.0)
        self.assertLessEqual(metrics["overall_accuracy"], 1.0)
        self.assertIn("false_positive_rate", metrics["binary_intrusion_metrics"])
        self.assertIn("macro_f1", metrics["six_class_metrics"])


if __name__ == "__main__":
    unittest.main()
