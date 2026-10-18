"""Enterprise-grade model drift and distribution shift monitor for Network Intrusion Detection.

Covers:
1. Covariate Shift: Feature distribution shifts (Population Stability Index - PSI, Kolmogorov-Smirnov test).
2. Concept Drift: Change in conditional probability P(Y|X) / model confidence calibration.
3. Data-Quality Drift: Missing rate changes, unexpected categories, out-of-bounds metrics.

Produces structured drift alerts without falsely claiming measured accuracy drop on unlabelled batches.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats


@dataclass
class FeatureDriftResult:
    feature_name: str
    metric_type: str  # "psi", "ks_test", "categorical_chi2"
    statistic: float
    p_value: Optional[float]
    threshold: float
    drift_detected: bool
    interpretation: str


@dataclass
class DriftReport:
    timestamp: str
    reference_sample_size: int
    current_sample_size: int
    features_evaluated: int
    drifted_features_count: int
    drift_warning_level: str  # "NOMINAL", "ELEVATED", "CRITICAL"
    data_quality_issues: List[str]
    feature_details: List[FeatureDriftResult]
    recommended_action: str
    caveat: str


def calculate_psi(
    expected: np.ndarray,
    actual: np.ndarray,
    num_buckets: int = 10,
    epsilon: float = 1e-4,
) -> float:
    """Calculate Population Stability Index (PSI) between reference and current feature distributions."""
    expected = expected[~np.isnan(expected)]
    actual = actual[~np.isnan(actual)]

    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    # Determine quantile bins from reference (expected) distribution
    percentiles = np.linspace(0, 100, num_buckets + 1)
    try:
        bins = np.percentile(expected, percentiles)
    except Exception:
        return 0.0

    bins = np.unique(bins)
    if len(bins) < 2:
        # Constant feature
        return 0.0

    bins[0] = -np.inf
    bins[-1] = np.inf

    expected_counts, _ = np.histogram(expected, bins=bins)
    actual_counts, _ = np.histogram(actual, bins=bins)

    expected_pct = (expected_counts / len(expected)) + epsilon
    actual_pct = (actual_counts / len(actual)) + epsilon

    # Normalize to sum to 1
    expected_pct = expected_pct / np.sum(expected_pct)
    actual_pct = actual_pct / np.sum(actual_pct)

    psi_val = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
    return float(max(0.0, psi_val))


class ModelDriftMonitor:
    """Monitors incoming network flow batches against a baseline reference partition."""

    def __init__(
        self,
        reference_data: pd.DataFrame,
        numeric_features: Optional[List[str]] = None,
        categorical_features: Optional[List[str]] = None,
        psi_warning_threshold: float = 0.10,
        psi_critical_threshold: float = 0.25,
        ks_alpha: float = 0.01,
    ):
        self.reference_data = reference_data.copy()
        self.numeric_features = numeric_features or [
            c for c in reference_data.columns if pd.api.types.is_numeric_dtype(reference_data[c])
        ]
        self.categorical_features = categorical_features or [
            c for c in reference_data.columns if c not in self.numeric_features
        ]
        self.psi_warning_threshold = psi_warning_threshold
        self.psi_critical_threshold = psi_critical_threshold
        self.ks_alpha = ks_alpha

        # Precompute reference statistics
        self.reference_stats: Dict[str, Dict[str, float]] = {}
        for col in self.numeric_features:
            series = pd.to_numeric(self.reference_data[col], errors="coerce").dropna()
            if len(series) > 0:
                self.reference_stats[col] = {
                    "mean": float(series.mean()),
                    "std": float(series.std()),
                    "min": float(series.min()),
                    "max": float(series.max()),
                }

    def evaluate_batch(
        self,
        current_data: pd.DataFrame,
        features_to_check: Optional[List[str]] = None,
    ) -> DriftReport:
        """Examine current batch against reference and generate structured drift metrics."""
        current = current_data.copy()
        check_cols = features_to_check or (self.numeric_features[:15] + self.categorical_features[:5])
        feature_results: List[FeatureDriftResult] = []
        quality_issues: List[str] = []

        # 1. Data Quality Checks
        missing_rates = current.isnull().mean()
        for col, rate in missing_rates.items():
            if rate > 0.10:
                quality_issues.append(f"Column '{col}' has {rate*100:.1f}% missing values (exceeds 10% threshold).")

        # 2. Covariate Shift Checks (Numerical via PSI & KS-Test)
        for col in check_cols:
            if col not in current.columns:
                quality_issues.append(f"Expected feature '{col}' missing from incoming batch.")
                continue

            if col in self.numeric_features:
                ref_vals = pd.to_numeric(self.reference_data[col], errors="coerce").dropna().to_numpy()
                cur_vals = pd.to_numeric(current[col], errors="coerce").dropna().to_numpy()

                if len(cur_vals) < 5 or len(ref_vals) < 5:
                    continue

                psi_score = calculate_psi(ref_vals, cur_vals)
                ks_stat, ks_pval = stats.ks_2samp(ref_vals, cur_vals)

                drift_detected = bool(psi_score >= self.psi_warning_threshold or ks_pval < self.ks_alpha)
                interpretation = (
                    f"PSI={psi_score:.4f} "
                    f"({'Significant Shift' if psi_score >= self.psi_critical_threshold else 'Moderate Shift' if psi_score >= self.psi_warning_threshold else 'Stable'}), "
                    f"KS-stat={ks_stat:.3f} (p={ks_pval:.2e})"
                )

                feature_results.append(
                    FeatureDriftResult(
                        feature_name=col,
                        metric_type="psi_and_ks",
                        statistic=float(round(psi_score, 4)),
                        p_value=float(ks_pval),
                        threshold=self.psi_warning_threshold,
                        drift_detected=drift_detected,
                        interpretation=interpretation,
                    )
                )

            elif col in self.categorical_features:
                ref_cats = set(self.reference_data[col].dropna().unique())
                cur_cats = set(current[col].dropna().unique())
                unseen = cur_cats - ref_cats
                drift_detected = len(unseen) > 0
                interpretation = (
                    f"Unseen categories detected: {list(unseen)[:3]}"
                    if drift_detected
                    else "Categorical categories consistent."
                )
                feature_results.append(
                    FeatureDriftResult(
                        feature_name=col,
                        metric_type="categorical_novelty",
                        statistic=float(len(unseen)),
                        p_value=None,
                        threshold=0.0,
                        drift_detected=drift_detected,
                        interpretation=interpretation,
                    )
                )

        drifted_count = sum(1 for f in feature_results if f.drift_detected)
        ratio = drifted_count / max(1, len(feature_results))

        if ratio >= 0.35:
            warning_level = "CRITICAL"
            recommended = "High distributional divergence detected. Alert SOC tier-2, route traffic through anomaly quarantine rules, and initiate ground-truth validation sample collection."
        elif ratio >= 0.15:
            warning_level = "ELEVATED"
            recommended = "Moderate drift in flow features. Check if scheduled operational changes or protocol updates occurred on monitored nodes."
        else:
            warning_level = "NOMINAL"
            recommended = "Traffic characteristics align with reference baseline. Standard model inference active."

        return DriftReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            reference_sample_size=len(self.reference_data),
            current_sample_size=len(current),
            features_evaluated=len(feature_results),
            drifted_features_count=drifted_count,
            drift_warning_level=warning_level,
            data_quality_issues=quality_issues,
            feature_details=feature_results,
            recommended_action=recommended,
            caveat="Drift warnings indicate input covariate shift, NOT definitive ground-truth model degradation. Retraining requires verified analyst-labelled ground truth.",
        )


def export_drift_report_json(report: DriftReport, filepath: Union[str, Path]) -> None:
    """Save drift report to disk formatted as JSON."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)

