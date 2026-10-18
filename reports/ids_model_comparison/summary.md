# IDS Model Comparison

This comparison trains fresh candidate models and does not replace the deployed model or baseline artifacts.

## Methodology

- Dataset: `D:\Project\intrusion-detection\data\nsl_kdd.csv` (148517 rows, 41 predictors).
- Outer test set: duplicate-aware stratified group holdout selected once and reused for every candidate.
- Inner model selection: 3-fold `StratifiedGroupKFold` on the outer training partition only.
- Search: `min_samples_leaf` in [1, 2] with 50-tree proxy forests; final candidates refit with 150 trees.
- Selection priority: mean validation macro F1, balanced accuracy, binary recall, then lower false-positive rate.
- RandomOverSampler, when available, is inside the training pipeline and never touches validation or test rows.

## Duplicate and partition checks

- Exact duplicate groups: 610 (1220 rows).
- Duplicate predictor groups: 712 (1439 rows).
- Conflicting-label predictor groups: 116 (247 rows).
- Outer test overlap: 0 shared predictor groups and 0 affected test rows.

## Cross-validation winner

- Candidate: `extra_trees` with `min_samples_leaf=1`.
- Mean validation macro F1: 0.9146 ± 0.0102.
- Mean validation balanced accuracy: 0.9002 ± 0.0069.

## Final outer-test comparison

| Candidate | Accuracy | Binary F1 | Binary recall | FPR | Macro F1 | Balanced accuracy | U2R recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| rf_baseline | 0.9959 | 0.9958 | 0.9937 | 0.0019 | 0.8900 | 0.8540 | 0.4286 |
| rf_balanced | 0.9946 | 0.9947 | 0.9962 | 0.0064 | 0.9089 | 0.9285 | 0.7143 |
| rf_balanced_subsample | 0.9946 | 0.9947 | 0.9964 | 0.0064 | 0.9012 | 0.9278 | 0.7143 |
| extra_trees | 0.9953 | 0.9953 | 0.9940 | 0.0031 | 0.9054 | 0.8872 | 0.5714 |
| rf_random_oversampler | 0.9960 | 0.9960 | 0.9952 | 0.0030 | 0.9255 | 0.9160 | 0.7143 |

### Change from baseline

Baseline is `rf_baseline`. The selected candidate is `extra_trees`.
- Macro F1 change: +0.0154
- Balanced accuracy change: +0.0331
- Binary F1 change: -0.0005
- U2R recall change: +0.1429

## Limitations

- U2R and R2L supports are small; apparent changes should not be treated as stable without additional data.
- Results are offline NSL-KDD results and do not establish real-world IDS performance.
- The repository does not expose a documented official train/test partition.
- The tuned binary threshold is for binary reporting only; multiclass predictions remain argmax predictions.

## Reproduction

```powershell
python scripts/compare_ids_models.py
python -m unittest scripts/test_evaluate_ids.py scripts/test_compare_ids_models.py -v
```

Outputs are written to `D:\Project\intrusion-detection\reports\ids_model_comparison`.
