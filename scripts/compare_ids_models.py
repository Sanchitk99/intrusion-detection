"""Train and compare leakage-aware IDS model candidates.

The production model and reports are never loaded for replacement or
overwritten. A duplicate-aware outer test partition is created once, model
selection happens only inside the outer training partition, and final
candidate metrics are computed on the same untouched test partition.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold

try:
    from scripts.evaluate_ids import (
        BASE_DIR,
        NORMAL_LABEL,
        RANDOM_STATE,
        TEST_SIZE,
        build_pipeline,
        class_distribution,
        duplicate_analysis,
        json_ready,
        load_and_validate,
        partition_overlap,
        select_duplicate_aware_split,
    )
except ModuleNotFoundError:  # Supports `python scripts/compare_ids_models.py`.
    from evaluate_ids import (
        BASE_DIR,
        NORMAL_LABEL,
        RANDOM_STATE,
        TEST_SIZE,
        build_pipeline,
        class_distribution,
        duplicate_analysis,
        json_ready,
        load_and_validate,
        partition_overlap,
        select_duplicate_aware_split,
    )


DEFAULT_DATA_PATH = BASE_DIR / "data" / "nsl_kdd.csv"
DEFAULT_OUTPUT_DIR = BASE_DIR / "reports" / "ids_model_comparison"
SEARCH_ESTIMATORS = 50
FINAL_ESTIMATORS = 150
INNER_FOLDS = 3
SEARCH_LEAF_VALUES = (1, 2)


def imblearn_available() -> bool:
    return importlib.util.find_spec("imblearn") is not None


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(json_ready(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def make_classifier(model_name: str, min_samples_leaf: int, n_estimators: int):
    if model_name == "rf_baseline":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            min_samples_leaf=min_samples_leaf,
        )
    if model_name == "rf_balanced":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced",
            min_samples_leaf=min_samples_leaf,
        )
    if model_name == "rf_balanced_subsample":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced_subsample",
            min_samples_leaf=min_samples_leaf,
        )
    if model_name == "extra_trees":
        return ExtraTreesClassifier(
            n_estimators=n_estimators,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced",
            min_samples_leaf=min_samples_leaf,
        )
    raise ValueError(f"Unknown model candidate: {model_name}")


def make_candidate_pipeline(
    predictor_columns: list[str],
    model_name: str,
    min_samples_leaf: int,
    n_estimators: int,
    use_oversampling: bool = False,
):
    # Reuse the same train-only preprocessing structure as the corrected
    # evaluator, then replace only the estimator.
    base_pipeline = build_pipeline(predictor_columns)
    preprocessor = base_pipeline.named_steps["preprocess"]
    classifier = make_classifier(model_name, min_samples_leaf, n_estimators)

    if use_oversampling:
        if not imblearn_available():
            raise RuntimeError("RandomOverSampler requested but imbalanced-learn is unavailable.")
        from imblearn.over_sampling import RandomOverSampler
        from imblearn.pipeline import Pipeline as ImbPipeline

        return ImbPipeline(
            steps=[
                ("preprocess", preprocessor),
                ("oversample", RandomOverSampler(random_state=RANDOM_STATE)),
                ("classifier", classifier),
            ]
        )

    from sklearn.pipeline import Pipeline

    return Pipeline(
        steps=[("preprocess", preprocessor), ("classifier", classifier)]
    )


def candidate_specs() -> list[dict[str, Any]]:
    specs = [
        {"name": "rf_baseline", "model_name": "rf_baseline", "oversample": False},
        {"name": "rf_balanced", "model_name": "rf_balanced", "oversample": False},
        {
            "name": "rf_balanced_subsample",
            "model_name": "rf_balanced_subsample",
            "oversample": False,
        },
        {"name": "extra_trees", "model_name": "extra_trees", "oversample": False},
    ]
    if imblearn_available():
        specs.append(
            {
                "name": "rf_random_oversampler",
                "model_name": "rf_baseline",
                "oversample": True,
            }
        )
    return specs


def inner_group_splits(
    features: pd.DataFrame,
    target: pd.Series,
    predictor_columns: list[str],
    outer_train_indices: np.ndarray,
) -> list[tuple[np.ndarray, np.ndarray]]:
    inner_features = features.iloc[outer_train_indices].reset_index(drop=True)
    inner_target = target.iloc[outer_train_indices].reset_index(drop=True)
    groups = inner_features.groupby(
        predictor_columns, dropna=False, sort=False
    ).ngroup().to_numpy()
    splitter = StratifiedGroupKFold(
        n_splits=INNER_FOLDS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )
    return [
        (outer_train_indices[train], outer_train_indices[valid])
        for train, valid in splitter.split(inner_features, inner_target, groups)
    ]


def binary_metrics(
    truth: pd.Series,
    predictions: np.ndarray,
    threshold: float | None = None,
    probabilities: np.ndarray | None = None,
) -> dict[str, Any]:
    if threshold is None:
        binary_predictions = (pd.Series(predictions, index=truth.index) != NORMAL_LABEL).astype(int)
    else:
        if probabilities is None:
            raise ValueError("Probabilities are required for thresholded metrics.")
        binary_predictions = (probabilities >= threshold).astype(int)

    binary_truth = (truth != NORMAL_LABEL).astype(int)
    matrix = confusion_matrix(binary_truth, binary_predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "threshold": threshold,
        "precision": float(precision_score(binary_truth, binary_predictions, zero_division=0)),
        "recall": float(recall_score(binary_truth, binary_predictions, zero_division=0)),
        "f1": float(f1_score(binary_truth, binary_predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)),
        "false_negative_rate": float(fn / (fn + tp)),
        "confusion_matrix": {
            "labels": ["Normal", "Intrusion"],
            "rows_true_columns_predicted": matrix.tolist(),
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def score_predictions(
    truth: pd.Series,
    predictions: np.ndarray,
    labels: list[str],
    probabilities: np.ndarray | None = None,
    threshold: float | None = None,
) -> dict[str, Any]:
    report = classification_report(
        truth,
        predictions,
        labels=labels,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    return {
        "accuracy": float(accuracy_score(truth, predictions)),
        "binary": binary_metrics(truth, predictions, threshold, probabilities),
        "macro_f1": float(f1_score(truth, predictions, labels=labels, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(truth, predictions, labels=labels, average="weighted", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(truth, predictions)),
        "per_class": report,
        "confusion_matrix": {
            "labels": labels,
            "rows_true_columns_predicted": confusion_matrix(truth, predictions, labels=labels).tolist(),
        },
        "u2r_recall": float(report.get("U2R", {}).get("recall", 0.0)),
        "r2l_recall": float(report.get("R2L", {}).get("recall", 0.0)),
    }


def cv_score_candidate(
    spec: dict[str, Any],
    leaf: int,
    features: pd.DataFrame,
    target: pd.Series,
    predictor_columns: list[str],
    folds: list[tuple[np.ndarray, np.ndarray]],
    labels: list[str],
) -> dict[str, Any]:
    fold_scores = []
    for fold_number, (train_indices, valid_indices) in enumerate(folds, start=1):
        pipeline = make_candidate_pipeline(
            predictor_columns,
            spec["model_name"],
            leaf,
            SEARCH_ESTIMATORS,
            use_oversampling=spec["oversample"],
        )
        pipeline.fit(features.iloc[train_indices], target.iloc[train_indices])
        predictions = pipeline.predict(features.iloc[valid_indices])
        scored = score_predictions(
            target.iloc[valid_indices], predictions, labels
        )
        fold_scores.append(
            {
                "fold": fold_number,
                "macro_f1": scored["macro_f1"],
                "balanced_accuracy": scored["balanced_accuracy"],
                "binary_recall": scored["binary"]["recall"],
                "binary_fpr": scored["binary"]["false_positive_rate"],
                "u2r_recall": scored["u2r_recall"],
                "r2l_recall": scored["r2l_recall"],
            }
        )

    frame = pd.DataFrame(fold_scores)
    return {
        "candidate": spec["name"],
        "min_samples_leaf": leaf,
        "search_estimators": SEARCH_ESTIMATORS,
        "folds": fold_scores,
        "mean_macro_f1": float(frame["macro_f1"].mean()),
        "std_macro_f1": float(frame["macro_f1"].std(ddof=0)),
        "mean_balanced_accuracy": float(frame["balanced_accuracy"].mean()),
        "std_balanced_accuracy": float(frame["balanced_accuracy"].std(ddof=0)),
        "mean_binary_recall": float(frame["binary_recall"].mean()),
        "mean_binary_fpr": float(frame["binary_fpr"].mean()),
        "mean_u2r_recall": float(frame["u2r_recall"].mean()),
        "mean_r2l_recall": float(frame["r2l_recall"].mean()),
    }


def select_cv_winner(results: list[dict[str, Any]]) -> dict[str, Any]:
    # Primary: macro F1. Secondary: balanced accuracy. Then favor recall while
    # minimizing false positives. No final-test scores participate here.
    return max(
        results,
        key=lambda result: (
            result["mean_macro_f1"],
            result["mean_balanced_accuracy"],
            result["mean_binary_recall"],
            -result["mean_binary_fpr"],
        ),
    )


def collect_oof_binary_probabilities(
    spec: dict[str, Any],
    leaf: int,
    features: pd.DataFrame,
    target: pd.Series,
    predictor_columns: list[str],
    folds: list[tuple[np.ndarray, np.ndarray]],
) -> tuple[np.ndarray, np.ndarray]:
    probabilities = np.zeros(len(target), dtype=float)
    observed = np.zeros(len(target), dtype=bool)
    for train_indices, valid_indices in folds:
        pipeline = make_candidate_pipeline(
            predictor_columns,
            spec["model_name"],
            leaf,
            SEARCH_ESTIMATORS,
            use_oversampling=spec["oversample"],
        )
        pipeline.fit(features.iloc[train_indices], target.iloc[train_indices])
        class_order = list(pipeline.classes_)
        normal_index = class_order.index(NORMAL_LABEL)
        probabilities[valid_indices] = 1.0 - pipeline.predict_proba(
            features.iloc[valid_indices]
        )[:, normal_index]
        observed[valid_indices] = True
    validation_indices = np.flatnonzero(observed)
    if not len(validation_indices):
        raise AssertionError("OOF probability collection produced no validation rows.")
    return target.iloc[validation_indices].to_numpy(), probabilities[validation_indices]


def choose_binary_threshold(binary_truth: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    candidates = []
    for threshold in np.linspace(0.05, 0.95, 181):
        predictions = (probabilities >= threshold).astype(int)
        f1 = f1_score(binary_truth, predictions, zero_division=0)
        recall = recall_score(binary_truth, predictions, zero_division=0)
        matrix = confusion_matrix(binary_truth, predictions, labels=[0, 1])
        tn, fp, _, _ = matrix.ravel()
        fpr = fp / (fp + tn)
        candidates.append((f1, recall, -fpr, -threshold, threshold, fpr))
    selected = max(candidates)
    return {
        "threshold": float(selected[4]),
        "validation_f1": float(selected[0]),
        "validation_recall": float(selected[1]),
        "validation_fpr": float(selected[5]),
        "selection_rule": "maximize validation binary F1; tie-break recall, lower FPR, then lower threshold",
    }


def comparison_markdown(
    data_audit: dict[str, Any],
    duplicate_stats: dict[str, Any],
    outer_overlap: dict[str, Any],
    cv_winner: dict[str, Any],
    final_results: dict[str, Any],
    baseline_name: str,
    output_dir: Path,
) -> str:
    baseline = final_results[baseline_name]
    lines = [
        "# IDS Model Comparison",
        "",
        "This comparison trains fresh candidate models and does not replace the deployed model or baseline artifacts.",
        "",
        "## Methodology",
        "",
        f"- Dataset: `{data_audit['data_path']}` ({data_audit['rows']} rows, {data_audit['predictor_count']} predictors).",
        "- Outer test set: duplicate-aware stratified group holdout selected once and reused for every candidate.",
        f"- Inner model selection: {INNER_FOLDS}-fold `StratifiedGroupKFold` on the outer training partition only.",
        f"- Search: `min_samples_leaf` in {list(SEARCH_LEAF_VALUES)} with {SEARCH_ESTIMATORS}-tree proxy forests; final candidates refit with {FINAL_ESTIMATORS} trees.",
        "- Selection priority: mean validation macro F1, balanced accuracy, binary recall, then lower false-positive rate.",
        "- RandomOverSampler, when available, is inside the training pipeline and never touches validation or test rows.",
        "",
        "## Duplicate and partition checks",
        "",
        f"- Exact duplicate groups: {duplicate_stats['exact_duplicate_groups']} ({duplicate_stats['exact_duplicate_rows_in_groups']} rows).",
        f"- Duplicate predictor groups: {duplicate_stats['duplicate_predictor_groups']} ({duplicate_stats['duplicate_predictor_rows_in_groups']} rows).",
        f"- Conflicting-label predictor groups: {duplicate_stats['conflicting_label_predictor_groups']} ({duplicate_stats['conflicting_label_predictor_rows']} rows).",
        f"- Outer test overlap: {outer_overlap['shared_predictor_groups']} shared predictor groups and {outer_overlap['test_rows_with_predictor_seen_in_train']} affected test rows.",
        "",
        "## Cross-validation winner",
        "",
        f"- Candidate: `{cv_winner['candidate']}` with `min_samples_leaf={cv_winner['min_samples_leaf']}`.",
        f"- Mean validation macro F1: {cv_winner['mean_macro_f1']:.4f} ± {cv_winner['std_macro_f1']:.4f}.",
        f"- Mean validation balanced accuracy: {cv_winner['mean_balanced_accuracy']:.4f} ± {cv_winner['std_balanced_accuracy']:.4f}.",
        "",
        "## Final outer-test comparison",
        "",
        "| Candidate | Accuracy | Binary F1 | Binary recall | FPR | Macro F1 | Balanced accuracy | U2R recall |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, result in final_results.items():
        lines.append(
            "| {name} | {accuracy:.4f} | {f1:.4f} | {recall:.4f} | {fpr:.4f} | {macro:.4f} | {balanced:.4f} | {u2r:.4f} |".format(
                name=name,
                accuracy=result["accuracy"],
                f1=result["binary"]["f1"],
                recall=result["binary"]["recall"],
                fpr=result["binary"]["false_positive_rate"],
                macro=result["macro_f1"],
                balanced=result["balanced_accuracy"],
                u2r=result["u2r_recall"],
            )
        )
    lines.extend(
        [
            "",
            "### Change from baseline",
            "",
            f"Baseline is `{baseline_name}`. The selected candidate is `{cv_winner['candidate']}`.",
            f"- Macro F1 change: {final_results[cv_winner['candidate']]['macro_f1'] - baseline['macro_f1']:+.4f}",
            f"- Balanced accuracy change: {final_results[cv_winner['candidate']]['balanced_accuracy'] - baseline['balanced_accuracy']:+.4f}",
            f"- Binary F1 change: {final_results[cv_winner['candidate']]['binary']['f1'] - baseline['binary']['f1']:+.4f}",
            f"- U2R recall change: {final_results[cv_winner['candidate']]['u2r_recall'] - baseline['u2r_recall']:+.4f}",
            "",
            "## Limitations",
            "",
            "- U2R and R2L supports are small; apparent changes should not be treated as stable without additional data.",
            "- Results are offline NSL-KDD results and do not establish real-world IDS performance.",
            "- The repository does not expose a documented official train/test partition.",
            "- The tuned binary threshold is for binary reporting only; multiclass predictions remain argmax predictions.",
            "",
            "## Reproduction",
            "",
            "```powershell",
            "python scripts/compare_ids_models.py",
            "python -m unittest scripts/test_evaluate_ids.py scripts/test_compare_ids_models.py -v",
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
    duplicate_stats = duplicate_analysis(dataframe, predictor_columns)

    data_audit = {
        "data_path": str(data_path),
        "rows": len(dataframe),
        "predictor_count": len(predictor_columns),
        "predictor_columns": predictor_columns,
        "categorical_columns": [
            column for column in ("protocol_type", "service", "flag")
            if column in predictor_columns
        ],
        "target_column": "label",
        "mapped_classes": labels,
        "class_distribution": class_distribution(target, labels),
        "random_oversampler_available": imblearn_available(),
    }

    outer_train, outer_test, outer_metadata = select_duplicate_aware_split(
        features, target, predictor_columns
    )
    outer_overlap = partition_overlap(
        dataframe, predictor_columns, outer_train, outer_test
    )
    inner_folds = inner_group_splits(
        features, target, predictor_columns, outer_train
    )

    specs = candidate_specs()
    cv_results = []
    for spec in specs:
        for leaf in SEARCH_LEAF_VALUES:
            print(f"CV search: {spec['name']} min_samples_leaf={leaf}")
            cv_results.append(
                cv_score_candidate(
                    spec,
                    leaf,
                    features,
                    target,
                    predictor_columns,
                    inner_folds,
                    labels,
                )
            )
    cv_winner = select_cv_winner(cv_results)
    winner_spec = next(spec for spec in specs if spec["name"] == cv_winner["candidate"])

    final_results = {}
    final_models = {}
    for spec in specs:
        selected_cv = min(
            [item for item in cv_results if item["candidate"] == spec["name"]],
            key=lambda item: (-item["mean_macro_f1"], -item["mean_balanced_accuracy"]),
        )
        print(f"Final fit: {spec['name']} min_samples_leaf={selected_cv['min_samples_leaf']}")
        pipeline = make_candidate_pipeline(
            predictor_columns,
            spec["model_name"],
            selected_cv["min_samples_leaf"],
            FINAL_ESTIMATORS,
            use_oversampling=spec["oversample"],
        )
        pipeline.fit(features.iloc[outer_train], target.iloc[outer_train])
        predictions = pipeline.predict(features.iloc[outer_test])
        probabilities = pipeline.predict_proba(features.iloc[outer_test])
        final_metrics = score_predictions(
            target.iloc[outer_test], predictions, labels
        )
        final_metrics.update(
            {
                "candidate": spec["name"],
                "selected_min_samples_leaf": selected_cv["min_samples_leaf"],
                "cv_selection": selected_cv,
                "test_rows": len(outer_test),
                "test_class_distribution": class_distribution(
                    target.iloc[outer_test], labels
                ),
            }
        )
        final_results[spec["name"]] = final_metrics
        final_models[spec["name"]] = pipeline

    # Threshold selection is performed only on OOF predictions from the outer
    # training partition for the CV-selected winner.
    winner_oof_target, winner_oof_probability = collect_oof_binary_probabilities(
        winner_spec,
        cv_winner["min_samples_leaf"],
        features,
        target,
        predictor_columns,
        inner_folds,
    )
    # The helper above returns outer-training-local rows; convert the labels and
    # probabilities into validation-only binary threshold selection.
    threshold_info = choose_binary_threshold(
        (winner_oof_target != NORMAL_LABEL).astype(int), winner_oof_probability
    )
    winner_test = final_results[winner_spec["name"]]
    winner_pipeline = final_models[winner_spec["name"]]
    winner_class_order = list(winner_pipeline.classes_)
    normal_index = winner_class_order.index(NORMAL_LABEL)
    winner_test_probability = 1.0 - winner_pipeline.predict_proba(
        features.iloc[outer_test]
    )[:, normal_index]
    winner_test["binary_threshold_tuned"] = binary_metrics(
        target.iloc[outer_test],
        winner_pipeline.predict(features.iloc[outer_test]),
        threshold_info["threshold"],
        winner_test_probability,
    )
    winner_test["threshold_selection_from_training_oof"] = threshold_info

    output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = output_dir / "candidate_models"
    models_dir.mkdir(parents=True, exist_ok=True)
    for name, model in final_models.items():
        joblib.dump(model, models_dir / f"{name}.joblib")
    best_path = output_dir / "best_candidate_model.joblib"
    shutil.copyfile(models_dir / f"{winner_spec['name']}.joblib", best_path)

    baseline_name = "rf_baseline"
    comparison = {
        "configuration": {
            "random_state": RANDOM_STATE,
            "test_size": TEST_SIZE,
            "inner_folds": INNER_FOLDS,
            "search_estimators": SEARCH_ESTIMATORS,
            "final_estimators": FINAL_ESTIMATORS,
            "search_leaf_values": list(SEARCH_LEAF_VALUES),
            "selection_priority": [
                "mean_macro_f1",
                "mean_balanced_accuracy",
                "mean_binary_recall",
                "lower_mean_binary_fpr",
            ],
        },
        "data_audit": data_audit,
        "duplicate_analysis": duplicate_stats,
        "outer_split": {
            **outer_metadata,
            "train_rows": len(outer_train),
            "test_rows": len(outer_test),
            "overlap": outer_overlap,
        },
        "candidate_specs": specs,
        "cross_validation_results": cv_results,
        "cv_winner": cv_winner,
        "final_test_results": final_results,
        "baseline_name": baseline_name,
        "selected_candidate": winner_spec["name"],
        "threshold_selection": threshold_info,
        "production_artifacts_changed": False,
    }
    write_json(output_dir / "model_comparison.json", comparison)
    write_json(
        output_dir / "classification_reports.json",
        {name: result["per_class"] for name, result in final_results.items()},
    )
    write_json(
        output_dir / "confusion_matrices.json",
        {name: result["confusion_matrix"] for name, result in final_results.items()},
    )
    write_json(output_dir / "cv_results.json", cv_results)
    write_json(output_dir / "duplicate_analysis.json", duplicate_stats)
    (output_dir / "summary.md").write_text(
        comparison_markdown(
            data_audit,
            duplicate_stats,
            outer_overlap,
            cv_winner,
            final_results,
            baseline_name,
            output_dir,
        ),
        encoding="utf-8",
    )

    return comparison


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    comparison = run(args.data.resolve(), args.output_dir.resolve())
    print(
        f"Selected candidate: {comparison['selected_candidate']}; "
        f"reports written to {args.output_dir.resolve()}"
    )


if __name__ == "__main__":
    main()
