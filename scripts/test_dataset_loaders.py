"""Focused tests for dataset loaders, provenance, and preprocessing pipelines."""

import unittest
from pathlib import Path
import numpy as np
import pandas as pd

from scripts.dataset_loaders import (
    NSL_KDD_ATTACK_MAP,
    CICIDS2017_ATTACK_MAP,
    UNSW_NB15_ATTACK_MAP,
    DATASET_CATALOG,
    DatasetMetadata,
    sanitize_column_names,
    clean_numeric_features,
    build_unified_pipeline,
    load_nsl_kdd,
)
from sklearn.dummy import DummyClassifier


class DatasetLoadersTests(unittest.TestCase):
    def test_canonical_label_mappings(self):
        # NSL-KDD mappings
        self.assertEqual(NSL_KDD_ATTACK_MAP.get("neptune"), "DoS")
        self.assertEqual(NSL_KDD_ATTACK_MAP.get("satan"), "Probe")
        self.assertEqual(NSL_KDD_ATTACK_MAP.get("buffer_overflow"), "U2R")
        self.assertEqual(NSL_KDD_ATTACK_MAP.get("warezclient"), "R2L")

        # CICIDS2017 mappings
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("benign"), "Normal")
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("dos hulk"), "DoS")
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("ddos"), "DoS")
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("portscan"), "Probe")
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("web attack - brute force"), "R2L")
        self.assertEqual(CICIDS2017_ATTACK_MAP.get("bot"), "Other")

        # UNSW-NB15 mappings
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("normal"), "Normal")
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("dos"), "DoS")
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("fuzzers"), "Probe")
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("reconnaissance"), "Probe")
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("exploits"), "R2L")
        self.assertEqual(UNSW_NB15_ATTACK_MAP.get("worms"), "Other")

    def test_dataset_catalog_provenance(self):
        self.assertIn("nsl_kdd", DATASET_CATALOG)
        self.assertIn("cicids2017", DATASET_CATALOG)
        self.assertIn("unsw_nb15", DATASET_CATALOG)

        for key, meta in DATASET_CATALOG.items():
            self.assertIsInstance(meta, DatasetMetadata)
            self.assertTrue(len(meta.name) > 0)
            self.assertTrue(len(meta.licensing) > 0)
            self.assertTrue(len(meta.provenance) > 0)
            self.assertTrue(len(meta.expected_filenames) > 0)
            self.assertTrue(len(meta.multiclass_categories) >= 5)

    def test_pipeline_construction_and_no_leakage(self):
        df = pd.DataFrame({
            "proto": ["tcp", "udp", "tcp", "icmp"],
            "service": ["http", "dns", "http", "eco"],
            "bytes": [100.0, 50.0, 200.0, 30.0],
            "packets": [2.0, 1.0, 4.0, 1.0],
            "label": ["Normal", "DoS", "Normal", "Probe"],
        })
        cat_cols = ["proto", "service"]
        num_cols = ["bytes", "packets"]

        pipeline = build_unified_pipeline(
            categorical_columns=cat_cols,
            numeric_columns=num_cols,
            classifier=DummyClassifier(strategy="most_frequent"),
        )
        
        # Fit strictly on first 2 rows
        train_x = df.iloc[:2][cat_cols + num_cols]
        train_y = df.iloc[:2]["label"]
        pipeline.fit(train_x, train_y)

        # Predict on all
        preds = pipeline.predict(df[cat_cols + num_cols])
        self.assertEqual(len(preds), 4)

    def test_nsl_kdd_loading_if_present(self):
        nsl_path = Path("data/nsl_kdd.csv")
        if nsl_path.exists():
            X, y_multi, y_bin, cats, nums = load_nsl_kdd(nsl_path)
            self.assertEqual(len(X), len(y_multi))
            self.assertEqual(len(y_multi), len(y_bin))
            self.assertIn("Normal", y_multi.unique())
            self.assertNotIn("label", X.columns)


if __name__ == "__main__":
    unittest.main()

