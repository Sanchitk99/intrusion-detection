"""Focused tests for model comparison and threshold-selection helpers."""

import unittest

import numpy as np

from scripts.compare_ids_models import (
    binary_metrics,
    choose_binary_threshold,
    select_cv_winner,
)


class CompareIdsModelTests(unittest.TestCase):
    def test_binary_metrics_use_normal_as_negative(self):
        truth = np.array(["Normal", "Normal", "DoS", "U2R"])
        predictions = np.array(["Normal", "DoS", "DoS", "Normal"])
        result = binary_metrics(__import__("pandas").Series(truth), predictions)
        self.assertEqual(result["confusion_matrix"]["true_negative"], 1)
        self.assertEqual(result["confusion_matrix"]["false_positive"], 1)
        self.assertEqual(result["confusion_matrix"]["false_negative"], 1)
        self.assertEqual(result["confusion_matrix"]["true_positive"], 1)

    def test_threshold_is_selected_from_validation_predictions(self):
        truth = np.array([0, 0, 1, 1])
        probabilities = np.array([0.05, 0.20, 0.80, 0.95])
        result = choose_binary_threshold(truth, probabilities)
        self.assertGreaterEqual(result["threshold"], 0.05)
        self.assertLessEqual(result["threshold"], 0.95)
        self.assertEqual(result["validation_f1"], 1.0)

    def test_cv_selection_prioritizes_macro_f1_then_balanced_accuracy(self):
        results = [
            {
                "candidate": "a",
                "min_samples_leaf": 1,
                "mean_macro_f1": 0.80,
                "mean_balanced_accuracy": 0.90,
                "mean_binary_recall": 0.99,
                "mean_binary_fpr": 0.01,
            },
            {
                "candidate": "b",
                "min_samples_leaf": 2,
                "mean_macro_f1": 0.81,
                "mean_balanced_accuracy": 0.70,
                "mean_binary_recall": 0.80,
                "mean_binary_fpr": 0.05,
            },
        ]
        self.assertEqual(select_cv_winner(results)["candidate"], "b")


if __name__ == "__main__":
    unittest.main()
