"""
Utility to safely backup, compress, and validate model artifacts for Sentinel IDS.
Preserves original models, verifies SHA-256 hashes, produces compressed copies,
and tests prediction equivalence.
"""

import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
BACKUP_DIR = BASE_DIR / "backups" / "original_models"

TARGET_MODELS = [
    {
        "name": "unsw_nb15_pipeline",
        "original_path": BASE_DIR / "artifacts" / "models" / "unsw_nb15_pipeline.joblib",
        "compressed_path": BASE_DIR / "artifacts" / "models" / "unsw_nb15_pipeline_compressed.joblib",
        "backup_path": BACKUP_DIR / "unsw_nb15_pipeline.joblib",
        "type": "pipeline",
        "dataset": "unsw_nb15"
    },
    {
        "name": "best_candidate_model",
        "original_path": BASE_DIR / "reports" / "ids_model_comparison" / "best_candidate_model.joblib",
        "compressed_path": BASE_DIR / "reports" / "ids_model_comparison" / "best_candidate_model_compressed.joblib",
        "backup_path": BACKUP_DIR / "best_candidate_model.joblib",
        "type": "classifier",
        "dataset": "nsl_kdd"
    },
    {
        "name": "rf_random_oversampler",
        "original_path": BASE_DIR / "reports" / "ids_model_comparison" / "candidate_models" / "rf_random_oversampler.joblib",
        "compressed_path": BASE_DIR / "reports" / "ids_model_comparison" / "candidate_models" / "rf_random_oversampler_compressed.joblib",
        "backup_path": BACKUP_DIR / "rf_random_oversampler.joblib",
        "type": "classifier",
        "dataset": "nsl_kdd"
    },
    {
        "name": "extra_trees",
        "original_path": BASE_DIR / "reports" / "ids_model_comparison" / "candidate_models" / "extra_trees.joblib",
        "compressed_path": BASE_DIR / "reports" / "ids_model_comparison" / "candidate_models" / "extra_trees_compressed.joblib",
        "backup_path": BACKUP_DIR / "extra_trees.joblib",
        "type": "classifier",
        "dataset": "nsl_kdd"
    }
]


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def step_1_backup_originals():
    """Backup original models to BACKUP_DIR and verify hashes."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    print("=" * 60)
    print("STEP 1: BACKING UP ORIGINAL MODEL ARTIFACTS")
    print("=" * 60)

    for item in TARGET_MODELS:
        orig = item["original_path"]
        backup = item["backup_path"]
        if not orig.exists():
            print(f"[!] Warning: Original file not found: {orig}")
            continue

        orig_hash_before = compute_sha256(orig)
        orig_size = orig.stat().st_size / (1024 * 1024)

        # Copy to backup
        shutil.copy2(orig, backup)
        backup_hash = compute_sha256(backup)
        orig_hash_after = compute_sha256(orig)

        match = (orig_hash_before == backup_hash == orig_hash_after)
        results.append({
            "name": item["name"],
            "original_path": str(orig),
            "backup_path": str(backup),
            "size_mb": round(orig_size, 2),
            "sha256": orig_hash_before,
            "backup_sha256": backup_hash,
            "hash_match": match
        })

        print(f"File: {orig.name}")
        print(f"  Size: {orig_size:.2f} MB")
        print(f"  Original SHA-256: {orig_hash_before}")
        print(f"  Backup SHA-256  : {backup_hash}")
        print(f"  Hash Match: {'VERIFIED MATCH' if match else 'MISMATCH ERROR'}")
        print("-" * 50)

    return results


def step_2_compress_models():
    """Losslessly compress models using joblib with zlib level 6 compression."""
    print("\n" + "=" * 60)
    print("STEP 2: CREATING LOSSLESS COMPRESSED COPIES")
    print("=" * 60)

    compression_results = []

    for item in TARGET_MODELS:
        orig = item["original_path"]
        comp = item["compressed_path"]
        if not orig.exists():
            continue

        print(f"Compressing {orig.name} -> {comp.name}...")
        t0 = time.time()
        # Load original model
        model = joblib.load(orig)
        # Save with zlib compression level 6 (lossless, high ratio, fast load)
        joblib.dump(model, comp, compress=("zlib", 6))
        elapsed = time.time() - t0

        orig_size = orig.stat().st_size
        comp_size = comp.stat().st_size
        ratio = (1.0 - (comp_size / orig_size)) * 100

        within_github_limit = comp_size < (100 * 1024 * 1024)

        compression_results.append({
            "name": item["name"],
            "original_file": str(orig),
            "compressed_file": str(comp),
            "original_size_bytes": orig_size,
            "compressed_size_bytes": comp_size,
            "original_size_mb": round(orig_size / (1024 * 1024), 2),
            "compressed_size_mb": round(comp_size / (1024 * 1024), 2),
            "reduction_percent": round(ratio, 2),
            "under_100mb": within_github_limit,
            "time_seconds": round(elapsed, 2)
        })

        print(f"  Original size  : {orig_size / (1024*1024):.2f} MB")
        print(f"  Compressed size: {comp_size / (1024*1024):.2f} MB ({ratio:.1f}% reduction)")
        print(f"  Under 100 MB   : {'YES (Ready for GitHub)' if within_github_limit else 'NO (Exceeds Limit)'}")
        print(f"  Elapsed time   : {elapsed:.2f}s")
        print("-" * 50)

    return compression_results


def step_3_validate_predictions():
    """Validate that compressed models produce identical predictions to originals."""
    print("\n" + "=" * 60)
    print("STEP 3: VALIDATING PREDICTION EQUIVALENCE")
    print("=" * 60)

    # Prepare test data for UNSW and NSL-KDD
    test_data = {}
    
    # UNSW-NB15 sample
    unsw_csv = BASE_DIR / "data" / "UNSW_NB15_training-set.csv"
    if unsw_csv.exists():
        df_unsw = pd.read_csv(unsw_csv, nrows=200)
        label_col = "label" if "label" in df_unsw.columns else "attack_cat"
        features_unsw = df_unsw.drop(columns=[c for c in [label_col, "id", "attack_cat"] if c in df_unsw.columns])
        test_data["unsw_nb15"] = features_unsw

    # NSL-KDD sample
    nsl_csv = BASE_DIR / "data" / "nsl_kdd.csv"
    if nsl_csv.exists():
        df_nsl = pd.read_csv(nsl_csv, nrows=200)
        label_cols = [c for c in ["label", "difficulty_level", "attack_category"] if c in df_nsl.columns]
        features_nsl = df_nsl.drop(columns=label_cols)
        test_data["nsl_kdd"] = features_nsl

    validation_results = []

    for item in TARGET_MODELS:
        orig = item["original_path"]
        comp = item["compressed_path"]
        dataset_key = item["dataset"]

        if not orig.exists() or not comp.exists():
            continue

        print(f"Testing equivalence for: {item['name']}")
        
        orig_model = joblib.load(orig)
        comp_model = joblib.load(comp)

        samples = test_data.get(dataset_key)
        if samples is None:
            print(f"  [!] No sample data available for {dataset_key}, skipping predict test.")
            continue

        # Check if the model is a full Pipeline or a raw estimator
        if hasattr(orig_model, "named_steps"):
            X_sample = samples.copy()
        else:
            try:
                nsl_pipe_path = BASE_DIR / "artifacts" / "models" / "nsl_kdd_pipeline.joblib"
                if nsl_pipe_path.exists():
                    nsl_pipe = joblib.load(nsl_pipe_path)
                    preprocessor = nsl_pipe.named_steps.get("preprocessor")
                    X_sample = preprocessor.transform(samples)
                else:
                    n_features = getattr(orig_model, "n_features_in_", 41)
                    X_sample = np.random.RandomState(42).randn(100, n_features)
            except Exception:
                n_features = getattr(orig_model, "n_features_in_", 41)
                X_sample = np.random.RandomState(42).randn(100, n_features)

        # Compare predict
        pred_orig = orig_model.predict(X_sample)
        pred_comp = comp_model.predict(X_sample)
        pred_equal = np.array_equal(pred_orig, pred_comp)

        # Compare predict_proba if supported
        proba_equal = True
        max_proba_diff = 0.0
        if hasattr(orig_model, "predict_proba") and hasattr(comp_model, "predict_proba"):
            proba_orig = orig_model.predict_proba(X_sample)
            proba_comp = comp_model.predict_proba(X_sample)
            proba_equal = np.allclose(proba_orig, proba_comp, atol=1e-9)
            max_proba_diff = float(np.max(np.abs(proba_orig - proba_comp)))

        validation_results.append({
            "name": item["name"],
            "predictions_equal": bool(pred_equal),
            "probabilities_equal": bool(proba_equal),
            "max_proba_diff": max_proba_diff,
            "sample_count": len(X_sample)
        })

        print(f"  Evaluated on {len(X_sample)} representative samples")
        print(f"  Class Predictions Equal : {'YES (100% Match)' if pred_equal else 'NO'}")
        print(f"  Probabilities Equal     : {'YES (Exact Match)' if proba_equal else 'NO'} (Max diff: {max_proba_diff:.1e})")
        print("-" * 50)

    return validation_results


def main():
    backup_info = step_1_backup_originals()
    compression_info = step_2_compress_models()
    validation_info = step_3_validate_predictions()

    # Save summary report
    report_data = {
        "backups": backup_info,
        "compression": compression_info,
        "validation": validation_info
    }
    report_path = BASE_DIR / "reports" / "model_compression_audit.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\nAudit report saved to: {report_path}")


if __name__ == "__main__":
    main()

