"""Multi-Dataset Model Training and Evaluation Pipeline.

Trains and evaluates independent, leak-free models for:
1. NSL-KDD
2. UNSW-NB15
3. CICIDS2017

Ensures:
- Strict isolation of incompatible feature spaces.
- Preprocessing (scaling and encoding) fitted strictly on training partitions.
- Class-imbalance mitigation (class-weighted training).
- Full enterprise evaluation: Precision, Recall, FPR, ROC-AUC, PR-AUC, Macro F1, Balanced Accuracy, Timing.
- Generation of standalone artifact models and evaluation reports.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    auc,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from scripts.dataset_loaders import (
    load_nsl_kdd,
    load_unsw_nb15,
    load_cicids2017,
    DATASET_CATALOG,
)

BASE_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = BASE_DIR / "artifacts" / "models"
REPORTS_DIR = BASE_DIR / "reports"


def json_ready(value: Any) -> Any:
    if isinstance(value, (np.integer, np.int64, np.int32)):
        return int(value)
    if isinstance(value, (np.floating, np.float64, np.float32)):
        return float(value)
    if isinstance(value, dict):
        return {str(k): json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(v) for v in value]
    if isinstance(value, np.ndarray):
        return json_ready(value.tolist())
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(json_ready(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def train_and_evaluate_dataset(
    dataset_key: str,
    max_train_samples: int = 100000,
    n_estimators: int = 100,
    random_state: int = 42,
) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"Starting Training & Evaluation for: {dataset_key.upper()}")
    print(f"=======================================================")

    # 1. Load Dataset
    if dataset_key == "nsl_kdd":
        X, y_multi, y_bin, cat_cols, num_cols = load_nsl_kdd()
    elif dataset_key == "unsw_nb15":
        X, y_multi, y_bin, cat_cols, num_cols = load_unsw_nb15()
    elif dataset_key == "cicids2017":
        X, y_multi, y_bin, cat_cols, num_cols = load_cicids2017()
    else:
        raise ValueError(f"Unknown dataset key: {dataset_key}")

    total_samples = len(X)
    print(f"Loaded {total_samples} samples with {X.shape[1]} features ({len(cat_cols)} cat, {len(num_cols)} num).")
    print(f"Multiclass class distribution:\n{y_multi.value_counts().to_dict()}")

    # 2. Stratified Train / Test Holdout Split (80 / 20)
    train_idx, test_idx = train_test_split(
        np.arange(len(X)),
        test_size=0.20,
        random_state=random_state,
        stratify=y_multi,
    )

    # Subsample training set if specified to keep runtime bounded while maintaining full test set
    if len(train_idx) > max_train_samples:
        np.random.seed(random_state)
        # Stratified subsample of training indices
        y_train_full = y_multi.iloc[train_idx]
        sub_train_idx, _ = train_test_split(
            train_idx,
            train_size=max_train_samples,
            random_state=random_state,
            stratify=y_train_full,
        )
        train_idx = sub_train_idx
        print(f"Subsampled training fold to {len(train_idx)} samples for computational efficiency.")

    X_train = X.iloc[train_idx]
    y_train = y_multi.iloc[train_idx]
    X_test = X.iloc[test_idx]
    y_test = y_multi.iloc[test_idx]
    y_test_bin = y_bin.iloc[test_idx]

    labels = sorted(y_multi.unique().tolist())

    # 3. Build Leakage-Free Preprocessing Pipeline
    transformers = []
    if cat_cols:
        transformers.append(
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols)
        )
    if num_cols:
        transformers.append(("num", StandardScaler(), num_cols))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")

    # Class-weighted Random Forest to counteract class imbalance on minority classes
    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1,
    )

    pipeline = Pipeline(steps=[("preprocess", preprocessor), ("classifier", classifier)])

    # 4. Train Pipeline
    print(f"Fitting pipeline on training partition ({len(X_train)} samples)...")
    t_train_start = time.perf_counter()
    pipeline.fit(X_train, y_train)
    training_time_seconds = round(time.perf_counter() - t_train_start, 3)
    print(f"Training completed in {training_time_seconds}s.")

    # 5. Inference & Evaluation
    print(f"Evaluating on held-out test partition ({len(X_test)} samples)...")
    t_inf_start = time.perf_counter()
    predictions = pipeline.predict(X_test)
    inference_time_seconds = round(time.perf_counter() - t_inf_start, 3)
    throughput = round(len(X_test) / max(inference_time_seconds, 1e-6), 1)

    probabilities = pipeline.predict_proba(X_test)
    class_to_idx = {cls: idx for idx, cls in enumerate(pipeline.classes_)}

    # Binary Metrics (Normal vs Any Attack)
    binary_preds = (predictions != "Normal").astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test_bin, binary_preds, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Binary probabilities for ROC-AUC & PR-AUC
    if "Normal" in class_to_idx:
        norm_idx = class_to_idx["Normal"]
        attack_prob = 1.0 - probabilities[:, norm_idx]
    else:
        attack_prob = np.ones(len(X_test))

    try:
        bin_roc_auc = float(roc_auc_score(y_test_bin, attack_prob))
    except Exception:
        bin_roc_auc = None

    try:
        pr_curve_p, pr_curve_r, _ = precision_recall_curve(y_test_bin, attack_prob)
        bin_pr_auc = float(auc(pr_curve_r, pr_curve_p))
    except Exception:
        bin_pr_auc = None

    # Multiclass Metrics
    acc = float(accuracy_score(y_test, predictions))
    macro_f1 = float(f1_score(y_test, predictions, labels=labels, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, predictions, labels=labels, average="weighted", zero_division=0))
    balanced_acc = float(balanced_accuracy_score(y_test, predictions))

    report = classification_report(
        y_test, predictions, labels=labels, target_names=labels, output_dict=True, zero_division=0
    )
    c_matrix = confusion_matrix(y_test, predictions, labels=labels).tolist()

    metrics = {
        "dataset": dataset_key,
        "provenance": DATASET_CATALOG.get(dataset_key, {}).__dict__ if dataset_key in DATASET_CATALOG else {},
        "samples": {
            "total_dataset_rows": total_samples,
            "train_rows": len(X_train),
            "test_rows": len(X_test),
        },
        "timing": {
            "training_time_seconds": training_time_seconds,
            "inference_time_seconds": inference_time_seconds,
            "inference_throughput_samples_per_sec": throughput,
        },
        "binary_metrics": {
            "accuracy": acc,
            "precision": float(precision_score(y_test_bin, binary_preds, zero_division=0)),
            "recall": float(recall_score(y_test_bin, binary_preds, zero_division=0)),
            "f1": float(f1_score(y_test_bin, binary_preds, zero_division=0)),
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "roc_auc": bin_roc_auc,
            "pr_auc": bin_pr_auc,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
        "multiclass_metrics": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "balanced_accuracy": balanced_acc,
            "labels": labels,
            "per_class": report,
            "confusion_matrix": c_matrix,
        },
    }

    # 6. Save Model Artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_artifact_path = MODELS_DIR / f"{dataset_key}_pipeline.joblib"
    joblib.dump(pipeline, model_artifact_path)

    metadata = {
        "dataset_key": dataset_key,
        "feature_names": list(X.columns),
        "categorical_columns": cat_cols,
        "numerical_columns": num_cols,
        "classes": labels,
        "model_type": "Pipeline(ColumnTransformer, RandomForestClassifier)",
        "class_weight": "balanced_subsample",
        "training_time_seconds": training_time_seconds,
        "metrics_summary": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "balanced_accuracy": balanced_acc,
            "fpr": fpr,
            "roc_auc": bin_roc_auc,
            "pr_auc": bin_pr_auc,
        },
    }
    write_json(MODELS_DIR / f"{dataset_key}_metadata.json", metadata)

    # 7. Write Markdown & JSON Reports
    report_dir = REPORTS_DIR / f"{dataset_key}_evaluation"
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(report_dir / "metrics.json", metrics)

    md_lines = [
        f"# {dataset_key.upper()} Independent Evaluation Report",
        "",
        f"**Dataset:** {DATASET_CATALOG.get(dataset_key).name if dataset_key in DATASET_CATALOG else dataset_key}",
        f"**Model:** Random Forest (100 Trees, `class_weight='balanced_subsample'`, Random State 42)",
        f"**Partition:** Stratified 80/20 Holdout ({len(X_train)} train, {len(X_test)} test)",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| **Overall Accuracy** | {acc:.4f} |",
        f"| **Binary Precision** | {metrics['binary_metrics']['precision']:.4f} |",
        f"| **Binary Recall** | {metrics['binary_metrics']['recall']:.4f} |",
        f"| **Binary F1 Score** | {metrics['binary_metrics']['f1']:.4f} |",
        f"| **False Positive Rate (FPR)** | {fpr:.4f} |",
        f"| **Binary ROC-AUC** | {f'{bin_roc_auc:.4f}' if bin_roc_auc is not None else 'N/A'} |",
        f"| **Binary PR-AUC** | {f'{bin_pr_auc:.4f}' if bin_pr_auc is not None else 'N/A'} |",
        f"| **Macro F1 Score** | {macro_f1:.4f} |",
        f"| **Balanced Accuracy** | {balanced_acc:.4f} |",
        f"| **Inference Throughput** | {throughput:.1f} samples/sec |",
        "",
        "## Per-Class Performance",
        "",
        "| Class | Precision | Recall | F1-Score | Support |",
        "|---|---:|---:|---:|---:|",
    ]
    for lbl in labels:
        if lbl in report:
            c_rep = report[lbl]
            md_lines.append(
                f"| **{lbl}** | {c_rep['precision']:.4f} | {c_rep['recall']:.4f} | {c_rep['f1-score']:.4f} | {int(c_rep['support'])} |"
            )

    md_lines.extend([
        "",
        "## Confusion Matrix",
        "",
        f"Labels (rows=true, cols=pred): `{labels}`",
        "",
        "```text",
        np.array2string(np.array(c_matrix), separator=", "),
        "```",
        "",
        "## Reproduction Command",
        "",
        "```powershell",
        f"python scripts/train_dataset_models.py --dataset {dataset_key}",
        "```",
    ])
    (report_dir / "summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    roc_str = f"{bin_roc_auc:.4f}" if bin_roc_auc is not None else "N/A"
    pr_str = f"{bin_pr_auc:.4f}" if bin_pr_auc is not None else "N/A"
    print(f"Results for {dataset_key.upper()}:")
    print(f"  Accuracy: {acc:.4f} | Binary F1: {metrics['binary_metrics']['f1']:.4f} | FPR: {fpr:.4f}")
    print(f"  ROC-AUC: {roc_str} | PR-AUC: {pr_str} | Macro F1: {macro_f1:.4f}")
    print(f"Artifacts saved to {model_artifact_path}")
    print(f"Report written to {report_dir / 'summary.md'}")

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        choices=["all", "nsl_kdd", "unsw_nb15", "cicids2017"],
        default="all",
        help="Dataset to train and evaluate (default: all)",
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=80000,
        help="Max training samples to keep runtime bounded",
    )
    args = parser.parse_args()

    targets = (
        ["nsl_kdd", "unsw_nb15", "cicids2017"]
        if args.dataset == "all"
        else [args.dataset]
    )

    for target in targets:
        try:
            train_and_evaluate_dataset(target, max_train_samples=args.max_train_samples)
        except Exception as exc:
            print(f"Error training {target}: {exc}")


if __name__ == "__main__":
    main()
