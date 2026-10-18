"""Reproducible, leakage-aware evaluation for the IDS classifier.

This script deliberately does not load or overwrite the production model
artifacts. It trains an in-memory 150-tree Random Forest with a fresh
Pipeline/ColumnTransformer for each evaluation strategy and writes reports
under reports/ids_evaluation by default.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import time
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATA_PATH = BASE_DIR / "data" / "nsl_kdd.csv"
DEFAULT_OUTPUT_DIR = BASE_DIR / "reports" / "ids_evaluation"
TARGET_COLUMN = "label"
TEST_SIZE = 0.20
RANDOM_STATE = 42
N_ESTIMATORS = 150
NORMAL_LABEL = "Normal"

ATTACK_MAP = {
    "neptune": "DoS",
    "smurf": "DoS",
    "back": "DoS",
    "teardrop": "DoS",
    "pod": "DoS",
    "land": "DoS",
    "apache2": "DoS",
    "udpstorm": "DoS",
    "mailbomb": "DoS",
    "processtable": "DoS",
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    "guess_passwd": "R2L",
    "ftp_write": "R2L",
    "imap": "R2L",
    "phf": "R2L",
    "multihop": "R2L",
    "warezmaster": "R2L",
    "warezclient": "R2L",
    "spy": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "rootkit": "U2R",
    "perl": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}


def map_label(value: Any) -> str:
    if value == "normal":
        return NORMAL_LABEL
    return ATTACK_MAP.get(value, "Other")


def json_ready(value: Any) -> Any:
    """Convert NumPy/Pandas values into JSON-serializable values."""
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, np.ndarray):
        return json_ready(value.tolist())
    return value


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(json_ready(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_and_validate(data_path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    dataframe = pd.read_csv(data_path)

    if TARGET_COLUMN not in dataframe.columns:
        raise ValueError(f"Target column '{TARGET_COLUMN}' is missing.")

    predictor_columns = [column for column in dataframe.columns if column != TARGET_COLUMN]
    if len(predictor_columns) != 41:
        raise ValueError(
            f"Expected 41 predictor columns, found {len(predictor_columns)}."
        )

    if dataframe[predictor_columns].isna().any().any():
        missing = dataframe[predictor_columns].isna().sum()
        missing = missing[missing > 0].to_dict()
        raise ValueError(f"Predictor missing values found: {missing}")

    if dataframe[TARGET_COLUMN].isna().any():
        raise ValueError("Target column contains missing values.")

    mapped_target = dataframe[TARGET_COLUMN].map(map_label)
    if mapped_target.isna().any():
        raise ValueError("Target mapping produced missing labels.")

    return dataframe, mapped_target, predictor_columns


def duplicate_analysis(dataframe: pd.DataFrame, predictor_columns: list[str]) -> dict[str, Any]:
    total_rows = len(dataframe)
    full_group_sizes = dataframe.groupby(
        list(dataframe.columns), dropna=False, sort=False
    ).size()
    predictor_groups = dataframe.groupby(
        predictor_columns, dropna=False, sort=False
    )
    predictor_group_sizes = predictor_groups.size()
    conflicting_groups = predictor_groups[TARGET_COLUMN].nunique()
    conflicting_groups = conflicting_groups[conflicting_groups > 1]

    def pct(count: int) -> float:
        return round((count / total_rows) * 100, 6) if total_rows else 0.0

    full_duplicate_groups = full_group_sizes[full_group_sizes > 1]
    predictor_duplicate_groups = predictor_group_sizes[predictor_group_sizes > 1]
    full_duplicate_rows = int(full_duplicate_groups.sum())
    predictor_duplicate_rows = int(predictor_duplicate_groups.sum())
    conflicting_rows = int(predictor_group_sizes[conflicting_groups.index].sum())

    return {
        "total_rows": total_rows,
        "exact_duplicate_groups": int(len(full_duplicate_groups)),
        "exact_duplicate_rows_in_groups": full_duplicate_rows,
        "exact_duplicate_extra_rows": int(max(full_duplicate_rows - len(full_duplicate_groups), 0)),
        "exact_duplicate_row_percentage": pct(full_duplicate_rows),
        "duplicate_predictor_groups": int(len(predictor_duplicate_groups)),
        "duplicate_predictor_rows_in_groups": predictor_duplicate_rows,
        "duplicate_predictor_extra_rows": int(
            max(predictor_duplicate_rows - len(predictor_duplicate_groups), 0)
        ),
        "duplicate_predictor_row_percentage": pct(predictor_duplicate_rows),
        "conflicting_label_predictor_groups": int(len(conflicting_groups)),
        "conflicting_label_predictor_rows": conflicting_rows,
        "conflicting_label_row_percentage": pct(conflicting_rows),
    }


def build_pipeline(predictor_columns: list[str]) -> Pipeline:
    categorical_columns = [
        column for column in ("protocol_type", "service", "flag")
        if column in predictor_columns
    ]
    numerical_columns = [
        column for column in predictor_columns if column not in categorical_columns
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_columns,
            ),
            ("numerical", StandardScaler(), numerical_columns),
        ],
        remainder="drop",
    )

    classifier = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    return Pipeline(
        steps=[("preprocess", preprocessor), ("classifier", classifier)]
    )


def class_distribution(values: pd.Series, labels: list[str]) -> dict[str, dict[str, float]]:
    counts = values.value_counts().reindex(labels, fill_value=0)
    total = len(values)
    return {
        label: {
            "count": int(counts[label]),
            "percentage": round((int(counts[label]) / total) * 100, 6)
            if total
            else 0.0,
        }
        for label in labels
    }


def partition_overlap(
    dataframe: pd.DataFrame,
    predictor_columns: list[str],
    train_indices: np.ndarray,
    test_indices: np.ndarray,
) -> dict[str, int]:
    train_predictors = dataframe.iloc[train_indices][predictor_columns]
    test_predictors = dataframe.iloc[test_indices][predictor_columns]
    train_full = dataframe.iloc[train_indices]
    test_full = dataframe.iloc[test_indices]

    train_predictor_keys = set(
        train_predictors.astype(object).itertuples(index=False, name=None)
    )
    test_predictor_keys = list(
        test_predictors.astype(object).itertuples(index=False, name=None)
    )
    shared_predictor_keys = set(test_predictor_keys).intersection(train_predictor_keys)

    train_full_keys = set(train_full.astype(object).itertuples(index=False, name=None))
    test_full_keys = list(test_full.astype(object).itertuples(index=False, name=None))
    shared_full_keys = set(test_full_keys).intersection(train_full_keys)

    return {
        "shared_predictor_groups": len(shared_predictor_keys),
        "test_rows_with_predictor_seen_in_train": sum(
            key in train_predictor_keys for key in test_predictor_keys
        ),
        "shared_exact_full_record_groups": len(shared_full_keys),
        "test_rows_with_exact_full_record_seen_in_train": sum(
            key in train_full_keys for key in test_full_keys
        ),
    }


def select_duplicate_aware_split(
    features: pd.DataFrame,
    target: pd.Series,
    predictor_columns: list[str],
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    group_ids = features.groupby(
        predictor_columns, dropna=False, sort=False
    ).ngroup().to_numpy()
    splitter = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=RANDOM_STATE
    )

    labels = sorted(target.unique())
    overall = target.value_counts(normalize=True).reindex(labels, fill_value=0)
    candidates = []
    for fold_number, (train_indices, test_indices) in enumerate(
        splitter.split(features, target, groups=group_ids), start=1
    ):
        test_share = len(test_indices) / len(features)
        test_distribution = (
            target.iloc[test_indices].value_counts(normalize=True)
            .reindex(labels, fill_value=0)
        )
        distribution_error = float(np.abs(test_distribution - overall).sum())
        score = abs(test_share - TEST_SIZE) + distribution_error
        candidates.append(
            {
                "fold": fold_number,
                "train_indices": train_indices,
                "test_indices": test_indices,
                "test_share": test_share,
                "distribution_error": distribution_error,
                "selection_score": score,
            }
        )

    selected = min(candidates, key=lambda item: item["selection_score"])
    metadata = {
        "method": "StratifiedGroupKFold",
        "n_splits": 5,
        "selected_fold": selected["fold"],
        "selection_rule": "closest to 20% test size plus class-distribution error",
        "selected_test_share": selected["test_share"],
        "selected_distribution_error": selected["distribution_error"],
        "all_fold_test_sizes": [
            {
                "fold": item["fold"],
                "test_rows": len(item["test_indices"]),
                "test_share": item["test_share"],
                "distribution_error": item["distribution_error"],
            }
            for item in candidates
        ],
        "group_count": int(len(np.unique(group_ids))),
    }
    return selected["train_indices"], selected["test_indices"], metadata


def evaluate_split(
    name: str,
    features: pd.DataFrame,
    target: pd.Series,
    predictor_columns: list[str],
    train_indices: np.ndarray,
    test_indices: np.ndarray,
    labels: list[str],
    split_metadata: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[list[int]]]:
    pipeline = build_pipeline(predictor_columns)
    if hasattr(pipeline.named_steps["preprocess"], "transformers_"):
        raise AssertionError("Preprocessor unexpectedly fitted before training.")

    x_train = features.iloc[train_indices]
    y_train = target.iloc[train_indices]
    x_test = features.iloc[test_indices]
    y_test = target.iloc[test_indices]

    t_train_start = time.perf_counter()
    pipeline.fit(x_train, y_train)
    training_time_seconds = round(time.perf_counter() - t_train_start, 4)

    if not hasattr(pipeline.named_steps["preprocess"], "transformers_"):
        raise AssertionError("Preprocessor was not fitted during pipeline training.")

    t_inf_start = time.perf_counter()
    predictions = pipeline.predict(x_test)
    inference_time_seconds = round(time.perf_counter() - t_inf_start, 4)

    accuracy = accuracy_score(y_test, predictions)
    majority_label = y_train.value_counts().idxmax()
    majority_predictions = np.full(len(y_test), majority_label, dtype=object)

    binary_truth = (y_test != NORMAL_LABEL).astype(int)
    binary_predictions = (pd.Series(predictions, index=y_test.index) != NORMAL_LABEL).astype(int)
    binary_matrix = confusion_matrix(binary_truth, binary_predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = binary_matrix.ravel()

    # Probability scoring for ROC-AUC & PR-AUC
    binary_roc_auc: Optional[float] = None
    binary_pr_auc: Optional[float] = None
    multiclass_roc_auc_ovr: Optional[float] = None

    if hasattr(pipeline, "predict_proba"):
        try:
            probabilities = pipeline.predict_proba(x_test)
            pipeline_classes = list(pipeline.classes_)

            # Binary probability = sum of probabilities of all non-Normal classes
            if NORMAL_LABEL in pipeline_classes:
                normal_idx = pipeline_classes.index(NORMAL_LABEL)
                binary_probs = 1.0 - probabilities[:, normal_idx]
            else:
                binary_probs = np.ones(len(x_test))

            if len(np.unique(binary_truth)) > 1:
                binary_roc_auc = float(roc_auc_score(binary_truth, binary_probs))
                binary_pr_auc = float(average_precision_score(binary_truth, binary_probs))

            # Multiclass OVR ROC-AUC
            present_classes = np.intersect1d(labels, np.unique(y_test))
            if len(present_classes) > 1 and len(pipeline_classes) > 1:
                multiclass_roc_auc_ovr = float(
                    roc_auc_score(y_test, probabilities, multi_class="ovr", average="macro")
                )
        except Exception:
            pass

    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=labels)
    overlap = partition_overlap(
        pd.concat([features, target.rename(TARGET_COLUMN)], axis=1),
        predictor_columns,
        train_indices,
        test_indices,
    )

    metrics = {
        "name": name,
        "model": {
            "classifier": "RandomForestClassifier",
            "n_estimators": N_ESTIMATORS,
            "random_state": RANDOM_STATE,
            "n_jobs": -1,
            "preprocessing": "ColumnTransformer(OneHotEncoder(handle_unknown='ignore'), StandardScaler)",
            "preprocessing_fit_scope": "training_partition_only",
        },
        "split": {
            **split_metadata,
            "train_rows": len(train_indices),
            "test_rows": len(test_indices),
            "train_percentage": round(len(train_indices) / len(features) * 100, 6),
            "test_percentage": round(len(test_indices) / len(features) * 100, 6),
            "random_state": RANDOM_STATE,
        },
        "timing": {
            "training_time_seconds": training_time_seconds,
            "inference_time_seconds": inference_time_seconds,
            "samples_per_second_inference": round(len(x_test) / max(inference_time_seconds, 1e-6), 1),
        },
        "class_distribution": {
            "train": class_distribution(y_train, labels),
            "test": class_distribution(y_test, labels),
        },
        "overall_accuracy": float(accuracy),
        "majority_class_baseline": {
            "class_selected_from_training": majority_label,
            "test_accuracy": float(accuracy_score(y_test, majority_predictions)),
        },
        "binary_intrusion_metrics": {
            "positive_definition": "any mapped class other than Normal",
            "precision": float(precision_score(binary_truth, binary_predictions, zero_division=0)),
            "recall": float(recall_score(binary_truth, binary_predictions, zero_division=0)),
            "f1": float(f1_score(binary_truth, binary_predictions, zero_division=0)),
            "false_positive_rate": float(false_positive / (false_positive + true_negative)) if (false_positive + true_negative) > 0 else 0.0,
            "false_negative_rate": float(false_negative / (false_negative + true_positive)) if (false_negative + true_positive) > 0 else 0.0,
            "roc_auc": binary_roc_auc,
            "pr_auc": binary_pr_auc,
            "confusion_matrix": {
                "labels": ["Normal", "Intrusion"],
                "rows_true_columns_predicted": binary_matrix.tolist(),
                "true_negative": int(true_negative),
                "false_positive": int(false_positive),
                "false_negative": int(false_negative),
                "true_positive": int(true_positive),
            },
        },
        "six_class_metrics": {
            "macro_f1": float(f1_score(y_test, predictions, labels=labels, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_test, predictions, labels=labels, average="weighted", zero_division=0)),
            "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
            "roc_auc_ovr_macro": multiclass_roc_auc_ovr,
        },
        "per_class": report,
        "u2r_recall": float(report.get("U2R", {}).get("recall", 0.0)),
        "partition_overlap": overlap,
        "predictions_verified_against_ground_truth": True,
    }
    return metrics, {name: report}, matrix.tolist()


def markdown_summary(
    data_audit: dict[str, Any],
    duplicates: dict[str, Any],
    evaluations: dict[str, Any],
    output_dir: Path,
) -> str:
    lines = [
        "# IDS Evaluation Summary",
        "",
        "This report was generated by `scripts/evaluate_ids.py`. It trains fresh in-memory pipelines and does not load or overwrite the production model artifacts.",
        "",
        "## Methodology",
        "",
        f"- Dataset: `{data_audit['data_path']}` ({data_audit['rows']} rows, {data_audit['predictor_count']} predictors).",
        f"- Labels: {', '.join(data_audit['mapped_classes'])}.",
        "- Preprocessing: `OneHotEncoder(handle_unknown='ignore')` and `StandardScaler` inside a `Pipeline`; fitting occurs only on each training partition.",
        f"- Classifier: 150-tree `RandomForestClassifier`, `random_state={RANDOM_STATE}`.",
        "- Evaluation A uses a stratified 80/20 random holdout.",
        "- Evaluation B uses a duplicate-aware `StratifiedGroupKFold`-selected holdout where identical predictor rows remain in one partition.",
        "",
        "## Dataset and duplicate audit",
        "",
        f"- Missing values: {data_audit['missing_value_count']}; unexpected columns: {len(data_audit['unexpected_columns'])}; invalid mapped labels: {data_audit['invalid_label_count']}.",
        f"- Exact duplicate groups: {duplicates['exact_duplicate_groups']} ({duplicates['exact_duplicate_rows_in_groups']} rows participating; {duplicates['exact_duplicate_extra_rows']} redundant rows).",
        f"- Duplicate predictor groups: {duplicates['duplicate_predictor_groups']} ({duplicates['duplicate_predictor_rows_in_groups']} rows participating; {duplicates['duplicate_predictor_extra_rows']} redundant rows).",
        f"- Predictor groups with conflicting labels: {duplicates['conflicting_label_predictor_groups']} ({duplicates['conflicting_label_predictor_rows']} rows).",
        "",
        "## Results",
        "",
        "| Evaluation | Accuracy | Binary F1 | Binary Recall | FPR | Binary ROC-AUC | Binary PR-AUC | Macro F1 | Balanced Acc | U2R Recall | Throughput (samp/s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, result in evaluations.items():
        binary = result["binary_intrusion_metrics"]
        six_class = result["six_class_metrics"]
        timing = result.get("timing", {})
        lines.append(
            "| {name} | {accuracy:.4f} | {f1:.4f} | {recall:.4f} | {fpr:.4f} | {roc_auc:.4f} | {pr_auc:.4f} | {macro:.4f} | {balanced:.4f} | {u2r:.4f} | {throughput:.1f} |".format(
                name=key,
                accuracy=result["overall_accuracy"],
                f1=binary["f1"],
                recall=binary["recall"],
                fpr=binary["false_positive_rate"],
                roc_auc=binary.get("roc_auc") or 0.0,
                pr_auc=binary.get("pr_auc") or 0.0,
                macro=six_class["macro_f1"],
                balanced=six_class["balanced_accuracy"],
                u2r=result["u2r_recall"],
                throughput=timing.get("samples_per_second_inference") or 0.0,
            )
        )

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- These are offline NSL-KDD results and do not establish real-world IDS performance.",
            "- The repository contains one CSV without explicit official train/test provenance; a documented official split would be preferable if available.",
            "- Duplicate-aware grouping prevents identical predictor rows from crossing the boundary but does not prove generalization to unseen environments.",
            "- Rare U2R examples remain a major limitation and should be reported alongside aggregate scores.",
            "",
            "## Reproduction",
            "",
            "```powershell",
            "python scripts/evaluate_ids.py",
            "```",
            "",
            f"Outputs are written to `{output_dir}`.",
        ]
    )
    return "\n".join(lines) + "\n"


def run(data_path: Path, output_dir: Path) -> dict[str, Any]:
    dataframe, target, predictor_columns = load_and_validate(data_path)
    features = dataframe[predictor_columns].copy()
    labels = sorted(target.unique())

    data_audit = {
        "data_path": str(data_path),
        "rows": len(dataframe),
        "columns": list(dataframe.columns),
        "predictor_count": len(predictor_columns),
        "predictor_columns": predictor_columns,
        "categorical_columns": [
            column for column in ("protocol_type", "service", "flag")
            if column in predictor_columns
        ],
        "target_column": TARGET_COLUMN,
        "mapped_classes": labels,
        "raw_label_count": int(dataframe[TARGET_COLUMN].nunique()),
        "missing_value_count": int(dataframe.isna().sum().sum()),
        "unexpected_columns": [],
        "invalid_label_count": int(target.isna().sum()),
        "raw_labels_mapped_to_other": sorted(
            dataframe.loc[target == "Other", TARGET_COLUMN].unique().tolist()
        ),
    }
    duplicates = duplicate_analysis(dataframe, predictor_columns)

    random_train, random_test = train_test_split(
        np.arange(len(dataframe)),
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=target,
    )
    group_train, group_test, group_metadata = select_duplicate_aware_split(
        features, target, predictor_columns
    )

    evaluation_a, report_a, matrix_a = evaluate_split(
        "Evaluation A - stratified random holdout",
        features,
        target,
        predictor_columns,
        random_train,
        random_test,
        labels,
        {"strategy": "stratified_random_holdout"},
    )
    evaluation_b, report_b, matrix_b = evaluate_split(
        "Evaluation B - duplicate-aware holdout",
        features,
        target,
        predictor_columns,
        group_train,
        group_test,
        labels,
        {"strategy": "duplicate_aware_stratified_group_holdout", **group_metadata},
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    evaluations = {
        "evaluation_a": evaluation_a,
        "evaluation_b": evaluation_b,
    }
    metrics = {
        "schema_version": 1,
        "configuration": {
            "test_size": TEST_SIZE,
            "random_state": RANDOM_STATE,
            "n_estimators": N_ESTIMATORS,
            "target_column": TARGET_COLUMN,
            "normal_label": NORMAL_LABEL,
            "target_leakage_check": "target excluded from predictor columns",
        },
        "data_audit": data_audit,
        "duplicate_analysis": duplicates,
        "evaluations": evaluations,
    }
    write_json(output_dir / "metrics.json", metrics)
    write_json(
        output_dir / "classification_reports.json",
        {"evaluation_a": report_a, "evaluation_b": report_b},
    )
    write_json(
        output_dir / "confusion_matrices.json",
        {
            "evaluation_a": {
                "labels": labels,
                "rows_true_columns_predicted": matrix_a,
            },
            "evaluation_b": {
                "labels": labels,
                "rows_true_columns_predicted": matrix_b,
            },
        },
    )
    write_json(output_dir / "duplicate_analysis.json", duplicates)
    (output_dir / "summary.md").write_text(
        markdown_summary(data_audit, duplicates, evaluations, output_dir),
        encoding="utf-8",
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help=f"CSV dataset path (default: {DEFAULT_DATA_PATH})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Report directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()
    metrics = run(args.data.resolve(), args.output_dir.resolve())
    for key, result in metrics["evaluations"].items():
        binary = result["binary_intrusion_metrics"]
        six_class = result["six_class_metrics"]
        print(
            f"{key}: accuracy={result['overall_accuracy']:.6f} "
            f"binary_f1={binary['f1']:.6f} "
            f"binary_recall={binary['recall']:.6f} "
            f"fpr={binary['false_positive_rate']:.6f} "
            f"macro_f1={six_class['macro_f1']:.6f} "
            f"balanced_accuracy={six_class['balanced_accuracy']:.6f} "
            f"u2r_recall={result['u2r_recall']:.6f}"
        )
    print(f"Reports written to {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
